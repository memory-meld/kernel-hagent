// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021-2024 Junliang Hu
 *
 * Author: Junliang Hu <jlhu@cse.cuhk.edu.hk>
 *
 */

#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/mempolicy.h>

#include "hagent.h"
#include "module.h"

DEFINE_LOCK_GUARD_1(mmap_read_lock, struct mm_struct, mmap_read_lock(_T->lock),
		    mmap_read_unlock(_T->lock));
extern void perf_prepare_sample(struct perf_sample_data *data,
				struct perf_event *event, struct pt_regs *regs);
extern int folio_exchange(struct folio *old, struct folio *new,
			  enum migrate_mode mode);
extern int folio_exchange_isolated(struct folio *old, struct folio *new,
				   enum migrate_mode mode);

extern void resolve_folio_cleanup(struct folio **foliop);

noinline static inline void
hagent_target_event_overflow(struct perf_event *event,
			     struct perf_sample_data *data,
			     struct pt_regs *regs)
{
	struct hagent_target *self = event->overflow_handler_context;
	bool batch_last = regs->cx == 0;

	// for locking see: __perf_event_output
	scoped_guard(rcu) scoped_guard(irqsave)
	{
		perf_prepare_sample(data, event, regs);
		struct perf_sample s = {
			.pid = data->tid_entry.pid,
			.tid = data->tid_entry.tid,
			.time = data->time,
			.addr = data->addr,
			.weight = data->weight.full,
			.phys_addr = data->phys_addr,
		};
		if (mpsc_send(self->chan, &s, sizeof(s)) < 0) {
			// This should never happen as we created the mpsc using
			// overwritting mode.
			pr_warn_ratelimited(
				"%s: discard sample due to ring buffer overflow\n",
				__func__);
		};
	}
	if (static_branch_likely(&use_asynchronous_architecture) &&
	    batch_last) {
		queue_delayed_work(system_wq, &self->works[THREAD_POLICY], 1);
	}
}
static void hagnet_target_events_release(struct hagent_target *self)
{
	for (int i = 0; i < EVENT_MAX; ++i) {
		if (self->events[i])
			perf_event_disable(self->events[i]);
	}
	for (int i = 0; i < EVENT_MAX; ++i) {
		if (self->events[i])
			perf_event_release_kernel(self->events[i]);
	}
}
static int hagnet_target_events_create(struct hagent_target *self,
				       struct task_struct *task)
{
	for (int i = 0; i < EVENT_MAX; ++i) {
		struct perf_event *e = perf_event_create_kernel_counter(
			&event_attrs[i], -1, task, hagent_target_event_overflow,
			self);
		if (IS_ERR(e)) {
			hagnet_target_events_release(self);
			return PTR_ERR(e);
		}
		self->events[i] = e;

		pr_info("%s: created config=0x%llx sample_period=%lld\n",
			__func__, event_attrs[i].config,
			event_attrs[i].sample_period);
	}
	return 0;
}
static struct folio *uvirt_to_folio(struct mm_struct *mm, u64 user_addr)
{
	guard(mmap_read_lock)(mm);
	struct vm_area_struct *vma = vma_lookup(mm, user_addr);
	if (!vma)
		return ERR_PTR(-EFAULT);
	// if (vma->vm_flags & VM_MAYEXEC) {
	// 	// Ignore exectuable pages
	// 	return ERR_PTR(-EFAULT);
	// }
	struct page *page = follow_page(vma, user_addr, FOLL_GET | FOLL_DUMP);
	if (IS_ERR_OR_NULL(page))
		return ERR_CAST(page);
	return page_folio(page);
}

static void cleanup_mmput(struct mm_struct **mm)
{
	if (!mm || IS_ERR_OR_NULL(*mm))
		return;
	mmput(*mm);
}

static bool hagent_target_managed(struct hagent_target *self, u64 vpfn)
{
	return HashMapU64Ptr_contains(&self->map, &vpfn);
}
static struct folio *hagent_target_managed_folio(struct hagent_target *self,
						 u64 vpfn)
{
	HashMapU64Ptr_Iter iter = HashMapU64Ptr_find(&self->map, &vpfn);
	HashMapU64Ptr_Entry *entry = HashMapU64Ptr_Iter_get(&iter);
	return entry ? entry->val : NULL;
}
extern bool folio_isolate_lru(struct folio *folio);
extern void folio_putback_lru(struct folio *folio);
DEFINE_CLASS(folio_get, struct folio *, folio_put(_T), ({
		     folio_get(folio);
		     folio;
	     }),
	     struct folio *folio);
static int hagent_target_manage(struct hagent_target *self, u64 vpfn,
				struct folio *folio)
{
	// if (hagent_target_managed(self, vpfn))
	// 	return -EEXIST;

	CLASS(folio_get, __folio)(folio);
	if (!folio_isolate_lru(folio))
		return -EAGAIN;
	/*
	 * Isolating the folio has taken another reference, so the
	 * caller's reference can be safely dropped without the folio
	 * disappearing underneath us during migration.
	 */
	// folio_put(folio);
	list_add_tail(&folio->lru, &self->managed);
	HashMapU64Ptr_Entry const entry = { vpfn, folio };
	HashMapU64Ptr_insert(&self->map, &entry);
	node_stat_mod_folio(folio, NR_ISOLATED_ANON + folio_is_file_lru(folio),
			    folio_nr_pages(folio));
	return 0;
}
static int hagent_target_unmanage(struct hagent_target *self,
				  struct folio *folio, u64 vpfn)
{
	if (!hagent_target_managed(self, vpfn))
		return -ENOENT;

	HashMapU64Ptr_erase(&self->map, &vpfn);
	list_del(&folio->lru);
	node_stat_mod_folio(folio, NR_ISOLATED_ANON + folio_is_file_lru(folio),
			    -folio_nr_pages(folio));
	folio_putback_lru(folio);
	// folio_add_lru(folio);
	return 0;
}
static int hagent_target_unmanage_all(struct hagent_target *self)
{
	struct folio *folio, *next;
	size_t size = HashMapU64Ptr_size(&self->map);
	pr_info("%s: size=%zu\n", __func__, size);
	list_for_each_entry_safe(folio, next, &self->managed, lru) {
		list_del(&folio->lru);
		node_stat_mod_folio(folio,
				    NR_ISOLATED_ANON + folio_is_file_lru(folio),
				    -folio_nr_pages(folio));
		folio_putback_lru(folio);
		// folio_add_lru(folio);
	}
	BUG_ON(!list_empty(&folio->lru));
	HashMapU64Ptr_clear(&self->map);
	return 0;
}

noinline static void hagent_target_work_fn_policy(struct work_struct *work)
{
	struct hagent_target *self =
		container_of(work, typeof(*self), works[THREAD_POLICY].work);

	struct mm_struct *mm __cleanup(cleanup_mmput) = get_task_mm(self->task);
	if (IS_ERR_OR_NULL(mm)) {
		pr_err("%s: get_task_mm()=%pe failed\n", __func__, mm);
		return;
	}
	// FIXME: implement additional vmstat counters
	// guard(vmevent)(HOTNESS_IDENTIFICATION_COST);
	scoped_cond_guard(mutex_try, return, &self->lock)
	{
		u64 total_samples = 0, dram_samples = 0, pmem_samples = 0;
		struct perf_sample s;
		// Make two pass over each CPU's send buffer
		for (u64 failure = 0, retry = 2 * num_online_cpus(),
			 cpu = cpumask_first(cpu_online_mask);
		     failure < retry;) {
			if (sizeof(s) !=
			    mpsc_recv_cpu(self->chan, cpu, &s, sizeof(s))) {
				++failure;
				cpu = cpumask_next(cpu, cpu_online_mask);
				if (cpu >= nr_cpu_ids) {
					cpu = cpumask_first(cpu_online_mask);
				}
				continue;
			}
			u64 vpfn = s.addr >> PAGE_SHIFT;
			if (s.pid != self->task->tgid || !vpfn) {
				count_vm_event(PEBS_NR_DISCARDED);
				count_vm_event(PEBS_NR_DISCARDED_INCOMPLETE);
				continue;
			}
			total_samples++;
			struct folio *folio __cleanup(resolve_folio_cleanup) =
				uvirt_to_folio(mm, s.addr);
			if (IS_ERR_OR_NULL(folio) || folio_mapping(folio)) {
				count_vm_event(PEBS_NR_DISCARDED);
				count_vm_event(PEBS_NR_DISCARDED_FILE);
				// Ignore file pages for now
				continue;
			}
			bool managed = hagent_target_managed(self, vpfn);
			if (!folio_test_lru(folio) && !managed) {
				count_vm_event(PEBS_NR_DISCARDED);
				count_vm_event(PEBS_NR_DISCARDED_NONLRU);
				continue;
			}
			if (!managed &&
			    hagent_target_manage(self, vpfn, folio)) {
				count_vm_event(PEBS_NR_DISCARDED);
				count_vm_event(PEBS_NR_DISCARDED_ISOLATE);
				continue;
			}
			bool in_dram = folio_nid(folio) == DRAM_NID;
			in_dram ? dram_samples++ : pmem_samples++;
			u64 count = sds_push(&self->sds, vpfn);
			struct indexable_heap *heap =
				&self->heap[in_dram ? DIRECTION_DEMOTION :
						      DIRECTION_PROMOTION];
			if (indexable_heap_contains(heap, vpfn)) {
				if (count) {
					indexable_heap_update(heap, vpfn,
							      count);
					// pr_info_ratelimited(
					// 	"%s: updated vpfn=%llu count=%llu\n",
					// 	__func__, vpfn, count);
				} else {
					// DRAM folios without access means they
					// are cold and are great candidates for
					// demotion
					if (!in_dram)
						indexable_heap_erase(heap,
								     vpfn);
				}
			} else {
				if (count) {
					indexable_heap_push(heap, vpfn, count);
					// pr_info_ratelimited(
					// 	"%s: pushed vpfn=%llu count=%llu\n",
					// 	__func__, vpfn, count);
				} else {
					// ignore
				}
			}
		}
		self->total_samples += total_samples;
		self->dram_samples += dram_samples;
		self->pmem_samples += pmem_samples;
		count_vm_events(PEBS_NR_SAMPLED, total_samples);
		count_vm_events(PEBS_NR_SAMPLED_FMEM, dram_samples);
		count_vm_events(PEBS_NR_SAMPLED_SMEM, pmem_samples);
	}
	if (self->total_samples > self->next_migration) {
		self->next_migration += 10000;
		pr_info("%s: collected samples dram=%llu pmem=%llu managed=%zu dheap=%zu pheap=%zu\n",
			__func__, self->dram_samples, self->pmem_samples,
			HashMapU64Ptr_size(&self->map),
			indexable_heap_size(&self->heap[DIRECTION_DEMOTION]),
			indexable_heap_size(&self->heap[DIRECTION_PROMOTION]));
		queue_delayed_work(system_wq, &self->works[THREAD_MIGRATION],
				   1);
	}
}
noinline static void hagent_target_work_fn_migration(struct work_struct *work)
{
	struct hagent_target *self =
		container_of(work, typeof(*self), works[THREAD_MIGRATION].work);

	lru_add_drain_all();

	struct mm_struct *mm __cleanup(cleanup_mmput) = get_task_mm(self->task);
	if (IS_ERR_OR_NULL(mm)) {
		pr_err("%s: get_task_mm()=%pe failed\n", __func__, mm);
		return;
	}
	// FIXME: implement additional vmstat counters
	// guard(vmevent)(PAGE_MIGRATION_COST);
	scoped_cond_guard(mutex_try, return, &self->lock)
	{
		u64 found_pair = 0, total_exchanges = 0, failed = 0;
		struct indexable_heap *dheap = &self->heap[DIRECTION_DEMOTION],
				      *pheap = &self->heap[DIRECTION_PROMOTION];
		if (self->total_samples > self->next_dump) {
			self->next_dump += 100000;
			// indexable_heap_dump(dram_heap, 1000);
			// indexable_heap_dump(pmem_heap, 1000);
		}

		while (true) {
			if (indexable_heap_size(dheap) < 512) {
				// Refill
				// pr_info("%s: ===== FINISHED: nothing to demotion =====",
				// 	__func__);
				break;
			}
			if (indexable_heap_size(pheap) < 512) {
				// We don't need to refill the promotion heap manually,
				// when we receive a sample, we will update the heap
				// pr_info("%s: ===== FINISHED: nothing to promotion =====",
				// 	__func__);
				break;
			}
			u64 dram_vpfn = *kv_ckey(indexable_heap_peek(dheap)),
			    pmem_vpfn = *kv_ckey(indexable_heap_peek(pheap));
			u64 dram_count = *kv_cvalue(indexable_heap_peek(dheap)),
			    pmem_count = *kv_cvalue(indexable_heap_peek(pheap));
			if (dram_count >= pmem_count) {
				// DRAM should contain the hottest data
				// pr_info("%s: ===== FINISHED: no misplaced =====",
				// __func__);
				break;
			}
			// struct folio *src __cleanup(resolve_folio_cleanup) =
			// 	uvirt_to_folio(mm, dram_vpfn << PAGE_SHIFT);
			struct folio *src =
				hagent_target_managed_folio(self, dram_vpfn);
			if (IS_ERR_OR_NULL(src) || folio_nid(src) != DRAM_NID) {
				// Remove invalid pfn from the heap to avoid
				// dead loop
				indexable_heap_pop(dheap);
				continue;
			}
			// struct folio *dst __cleanup(resolve_folio_cleanup) =
			// 	uvirt_to_folio(mm, pmem_vpfn << PAGE_SHIFT);
			struct folio *dst =
				hagent_target_managed_folio(self, pmem_vpfn);
			if (IS_ERR_OR_NULL(dst) || folio_nid(dst) == DRAM_NID) {
				// Remove invalid pfn from the heap to avoid
				// dead loop
				indexable_heap_pop(pheap);
				continue;
			}

			indexable_heap_pop(dheap);
			indexable_heap_pop(pheap);
			++found_pair;
			// pr_info("%s: pid=%d task=%p usage=%d", __func__,
			// 	self->task->tgid, self->task,
			// 	self->task->usage);
			// pr_info("%s: ===== EXCHANGE EXECUTING ====", __func__);
			// long err = folio_exchange(src, dst, MIGRATE_SYNC);

			// resolve folio has taken another reference, exceeding
			// the expected reference count during exchange
			long err =
				folio_exchange_isolated(src, dst, MIGRATE_SYNC);
			if (err) {
				++failed;
				// clang-format off
				pr_err("%s: exchange_folio: mode=%d err=%pe [src=%p vaddr=%p pfn=0x%lx] <-> [dst=%p vaddr=%p pfn=0x%lx]",
				       __func__, MIGRATE_SYNC, ERR_PTR(err),
				       src, (void *)(dram_vpfn << PAGE_SHIFT), folio_pfn(src),
				       dst, (void *)(pmem_vpfn << PAGE_SHIFT), folio_pfn(dst));
				// clang-format on
				// FIXME: should we put back the folio to the heap so that we can try at an another time?
			} else {
				// Althoug in theory the folio could only be
				// backed by DRAM or PMEM, in practive, the
				// kernel could have done migration in the
				// background that we are not aware of.
				if (indexable_heap_contains(dheap, pmem_vpfn)) {
					indexable_heap_update(dheap, pmem_vpfn,
							      dram_count);
				} else {
					indexable_heap_push(dheap, pmem_vpfn,
							    dram_count);
				}
				if (indexable_heap_contains(pheap, dram_vpfn)) {
					indexable_heap_update(pheap, dram_vpfn,
							      pmem_count);
				} else {
					indexable_heap_push(pheap, dram_vpfn,
							    pmem_count);
				}
				total_exchanges++;
				// FIXME: implement additional vmstat counters
				// count_vm_event(PAGE_PROMOTED);
				// count_vm_event(PAGE_DEMOTED);
				// count_vm_event(PAGE_EXCHANGED);
			}
			// pr_info("%s: ===== EXCHANGE RETURNED ====", __func__);

			if (found_pair >= migration_batch_size) {
				pr_info_ratelimited(
					"%s: found pair=%llu failed=%llu\n",
					__func__, found_pair, failed);
				break;
			}
			// pr_info("%s: next iteration\n", __func__);
		}
		self->total_exchanges += total_exchanges;
		if (self->total_exchanges > self->next_report) {
			self->next_report += 512 * 50;
			pr_info("%s: total exchanges=%llu\n", __func__,
				self->total_exchanges);
		}
	}
	// pr_info("%s: returned\n", __func__);
}

static void hagent_target_work_drop(struct hagent_target *self);
static void hagent_target_work_fn_stop(struct work_struct *work)
{
	struct hagent_target *self =
		container_of(work, typeof(*self), stop.work);
	hagnet_target_events_release(self);
	hagent_target_work_drop(self);
	complete(&self->stopped);
}

static void (*hagent_target_work_fn[THREAD_MAX])(struct work_struct *) = {
	[THREAD_POLICY] = hagent_target_work_fn_policy,
	[THREAD_MIGRATION] = hagent_target_work_fn_migration,
};
static char *hagent_target_work_name[THREAD_MAX] = {
	[THREAD_POLICY] = "hagent_target_work_policy",
	[THREAD_MIGRATION] = "hagent_target_work_migration",
};
static void hagent_target_work_drop(struct hagent_target *self)
{
	for (int i = 0; i < THREAD_MAX; ++i) {
		pr_info("%s: cancel_delayed_work_sync(%s)\n", __func__,
			hagent_target_work_name[i]);
		// Scynchrously stop the work and wait for exit
		cancel_delayed_work_sync(&self->works[i]);
	}
}
static int hagent_target_work_init(struct hagent_target *self)
{
	INIT_DELAYED_WORK(&self->stop, hagent_target_work_fn_stop);
	init_completion(&self->stopped);
	for (int i = 0; i < THREAD_MAX; ++i) {
		INIT_DELAYED_WORK(&self->works[i], hagent_target_work_fn[i]);
		pr_info("%s: INIT_DELAYED_WORK(%s)\n", __func__,
			hagent_target_work_name[i]);
	}
	return 0;
}

void hagent_target_drop(struct hagent_target *self)
{
	pr_info("%s: pid=%d", __func__, self->task->pid);
	queue_delayed_work(system_freezable_wq, &self->stop, 0);
	wait_for_completion(&self->stopped);
	for (int i = 0; i < DIRECTION_MAX; ++i)
		indexable_heap_drop(&self->heap[i]);
	sds_drop(&self->sds);
	// We have to destroy as a whole as we do not know the vpfn
	hagent_target_unmanage_all(self);
	HashMapU64Ptr_destroy(&self->map);
	if (self->chan)
		mpsc_drop(self->chan);
	if (self->task)
		put_task_struct(self->task);
	kfree(self);
}
struct hagent_target *hagent_target_new(pid_t pid)
{
	pr_info("%s: pid=%d", __func__, pid);
	struct hagent_target *self = kzalloc(sizeof(struct hagent_target),
					     GFP_KERNEL | __GFP_NOWARN);
	if (!self)
		return ERR_PTR(-ENOMEM);

	struct task_struct *task = find_get_task_by_vpid(pid);
	if (!task) {
		hagent_target_drop(self);
		return ERR_PTR(-ESRCH);
	}
	self->task = task;
	pr_info("%s: pid=%d task=%p usage=%d", __func__, pid, task,
		task->usage);

	mpsc_t chan = mpsc_new(sizeof(struct perf_sample) * CHANNEL_NELEMS);
	if (!chan) {
		hagent_target_drop(self);
		return ERR_PTR(-ENOMEM);
	}
	self->chan = chan;

	mutex_init(&self->lock);

	INIT_LIST_HEAD(&self->managed);
	self->map = HashMapU64Ptr_new(32);

	int err = sds_init_default(&self->sds);
	if (err) {
		hagent_target_drop(self);
		return ERR_PTR(err);
	}

	for (int i = 0; i < DIRECTION_MAX; ++i) {
		int err = indexable_heap_init(
			&self->heap[i], i == DIRECTION_DEMOTION,
			i == DIRECTION_DEMOTION ? "dram" : "pmem");
		if (err) {
			hagent_target_drop(self);
			return ERR_PTR(err);
		}
	}

	if (asynchronous_architecture) {
		static_branch_enable(&use_asynchronous_architecture);
		pr_info("%s: use asynchronous architecture\n", __func__);
		int err = hagent_target_work_init(self);
		if (err) {
			hagent_target_drop(self);
			return ERR_PTR(err);
		}
	} else {
		static_branch_disable(&use_asynchronous_architecture);
		pr_info("%s: use threaded architecture\n", __func__);
		pr_err("%s: threaded architecture is not implemented\n",
		       __func__);
		BUG();
	}

	err = hagnet_target_events_create(self, task);
	if (err) {
		hagent_target_drop(self);
		return ERR_PTR(err);
	}

	pr_info("%s: pid=%d", __func__, pid);
	return self;
}

pid_t hagent_target_pid(struct hagent_target *self)
{
	return self->task->pid;
}
