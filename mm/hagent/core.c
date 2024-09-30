// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021-2024 Junliang Hu
 *
 * Author: Junliang Hu <jlhu@cse.cuhk.edu.hk>
 *
 */

#include <linux/sched/clock.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <../internal.h>

#include "hagent.h"
#include "pebs.h"
#include "module.h"
#include "mpsc.h"
#include "sds.h"
#include "indexable_heap.h"

enum target_worker {
	WORKER_MAIN,
	WORKER_THROTTLE,
	WORKER_POLICY,
	WORKER_MIGRATION,
	MAX_WORKERS
};

enum target_chan {
	// Can only be consumed by WORKER_POLICY
	CHAN_SAMPLE,
	// Can only be consumed by WORKER_MIGRATION
	CHAN_EXCG_REQ,
	// Can only be consumed by WORKER_POLICY
	CHAN_EXCG_RSP,
	MAX_CHANS,
};

enum target_param {
	POLICY_MSET_BUCKET = 32,
	POLICY_TSET_BUCKET = 32,
	POLICY_BSET_BUCKET = 32,
	MPSC_RETRY = 2,
	MPSC_MAX_SIZE_BYTE = 1 << 20,
	MPSC_MAX_BATCH = 16384,
	IHEAP_MIN_SIZE = 512,
	// EVENT_CURVE_LEN = 100,
};

enum target_stat {
	STAT_T_OVERFLOW_HANDLER,
	STAT_T_MAIN,
	STAT_T_THROTTLE,
	STAT_T_POLICY,
	STAT_T_MIGRATION,
	// STAT_T_MPSC,
	// STAT_T_SDS,
	// STAT_T_INDEXABLE_HEAP,
	// STAT_T_EXCHANGE,
	STAT_T_PERF_PREPARE,
	MAX_STATS,
};
static char *const target_stat_name[] = {
	"overflow_handler",
	"main",
	"throttle",
	"policy",
	"migration",
	// "mpsc",
	// "sds",
	// "indexable_heap",
	// "exchange",
	"perf_prepare",
};

struct target {
	// Currently managed task
	struct task_struct *victim;
	// These channels are the only sharing states between the workers
	mpsc_t chans[MAX_CHANS];
	struct task_struct *workers[MAX_WORKERS];
	// Should only be used by the throttle and main thread
	struct perf_event_attr attrs[MAX_EVENTS];
	struct perf_event *events[MAX_EVENTS];

	atomic_long_t stats[MAX_STATS];
	// Should only used by the new() and drop()
	u64 start_time;
};

// External dependencies
extern int folio_exchange_isolated(struct folio *, struct folio *,
				   enum migrate_mode);

// Internal helpers
static struct folio *uvirt_to_folio(struct mm_struct *mm, u64 user_addr);

struct stat_stopwatch {
	struct target *target;
	u64 start;
	u64 item;
};
static struct stat_stopwatch stopwatch_new(struct target *target, u64 item)
{
	return (struct stat_stopwatch){
		.target = target,
		.item = item,
		.start = sched_clock(),
	};
}
static void stopwatch_drop(struct stat_stopwatch *t)
{
	atomic_long_add(sched_clock() - t->start, &t->target->stats[t->item]);
}
DEFINE_CLASS(stat_stopwatch, struct stat_stopwatch, stopwatch_drop(&_T),
	     stopwatch_new(s, item), struct target *s, enum target_stat item);

DEFINE_LOCK_GUARD_1(mmap_read_lock, struct mm_struct, mmap_read_lock(_T->lock),
		    mmap_read_unlock(_T->lock));
DEFINE_CLASS(task_mm, struct mm_struct *, IS_ERR_OR_NULL(_T) ?: mmput(_T),
	     get_task_mm(task), struct task_struct *task);
DEFINE_CLASS(uvirt_folio, struct folio *, IS_ERR_OR_NULL(_T) ?: folio_put(_T),
	     uvirt_to_folio(mm, user_addr), struct mm_struct *mm,
	     u64 user_addr);
DEFINE_CLASS(folio_get, struct folio *, folio_put(_T), ({
		     folio_get(folio);
		     folio;
	     }),
	     struct folio *folio);

static struct folio *uvirt_to_folio(struct mm_struct *mm, u64 user_addr)
{
	guard(mmap_read_lock)(mm);
	struct vm_area_struct *vma = vma_lookup(mm, user_addr);
	if (!vma)
		return ERR_PTR(-EFAULT);
	// We only want writable anon folios
	if (!vma_is_anonymous(vma) || !is_data_mapping(vma->vm_flags))
		return ERR_PTR(-ENOTSUPP);
	struct page *page = follow_page(vma, user_addr, FOLL_GET | FOLL_DUMP);
	return IS_ERR_OR_NULL(page) ? ERR_CAST(page) : page_folio(page);
}

noinline static void target_events_overflow(struct perf_event *event,
					    struct perf_sample_data *data,
					    struct pt_regs *regs)
{
	struct target *self = event->overflow_handler_context;
	mpsc_t ch = self->chans[CHAN_SAMPLE];
	guard(rcu)();
	guard(irqsave)();
	guard(stat_stopwatch)(self, STAT_T_OVERFLOW_HANDLER);
	{
		guard(stat_stopwatch)(self, STAT_T_PERF_PREPARE);
		perf_prepare_sample(data, event, regs);
	}
	struct perf_sample s = {
		.config = event->attr.config,
		.config1 = event->attr.config1,
		.pid = data->tid_entry.pid,
		.tid = data->tid_entry.tid,
		.time = data->time,
		.addr = data->addr,
		.weight = data->weight.full,
		.phys_addr = data->phys_addr,
	};
	if (mpsc_send(ch, &s, sizeof(s)) < 0) {
		// This should never happen as we created the mpsc using
		// overwritting mode.
		pr_err_ratelimited(
			"%s: discard sample due to ring buffer overflow\n",
			__func__);
	};
}
static void target_events_enable(struct target *self, bool enable)
{
	void intel_pmu_drain_pebs_buffer(void);
	for (int i = 0; i < MAX_EVENTS; i++) {
		if (self->events[i]) {
			if (enable)
				perf_event_enable(self->events[i]);
			else {
				intel_pmu_drain_pebs_buffer();
				perf_event_disable(self->events[i]);
			}
		}
	}
}
static void target_events_throttle(struct target *self, off_t step)
{
	// TODO: Change the period based on the predefined curves
	// static u64 period_curves[EVENT_CURVE_LEN ][MAX_EVENTS];
}
static u64 target_event_weight(struct perf_sample *s)
{
	switch (s->config) {
	case MEM_TRANS_RETIRED_LOAD_LATENCY:
		return 3;
	default:
		return 1;
	}
};

noinline static int target_worker_main(struct target *self)
{
	u64 period = msecs_to_jiffies(throttle_pulse_period_ms);
	while (!kthread_should_stop()) {
		schedule_timeout_uninterruptible(period);
		// guard(stat_stopwatch)(self, STAT_T_MAIN);
	}

	char comm[64] = {};
	get_kthread_comm(comm, sizeof(comm), current);
	pr_info("%s: stopped worker %s usage=%u\n", __func__, comm,
		refcount_read(&current->usage));
	return 0;
}

noinline static int target_worker_throttle(struct target *self)
{
	u64 period = msecs_to_jiffies(throttle_pulse_period_ms);
	u64 width = msecs_to_jiffies(throttle_pulse_width_ms);
	BUG_ON(period == 0 || width >= period);
	while (!kthread_should_stop()) {
		if (width) {
			{
				guard(stat_stopwatch)(self, STAT_T_THROTTLE);
				target_events_enable(self, true);
			}
			schedule_timeout_uninterruptible(width);
			{
				guard(stat_stopwatch)(self, STAT_T_THROTTLE);
				target_events_enable(self, false);
			}
			schedule_timeout_uninterruptible(period - width);
		} else
			schedule_timeout_uninterruptible(period);
	}

	char comm[64] = {};
	get_kthread_comm(comm, sizeof(comm), current);
	pr_info("%s: stopped worker %s usage=%u\n", __func__, comm,
		refcount_read(&current->usage));
	return 0;
}

noinline static void policy_release_managed(struct list_head *managed_folios)
{
	extern void folio_putback_lru(struct folio *);
	// release managed set
	struct folio *folio, *next;
	list_for_each_entry_safe(folio, next, managed_folios, lru) {
		list_del(&folio->lru);
		node_stat_mod_folio(folio,
				    NR_ISOLATED_ANON + folio_is_file_lru(folio),
				    -folio_nr_pages(folio));
		folio_putback_lru(folio);
		// folio_add_lru(folio);
	}
}
noinline static int policy_manage_folio(struct list_head *managed_folios,
					struct folio *folio)
{
	extern bool folio_isolate_lru(struct folio * folio);
	guard(folio_get)(folio);
	if (!folio_isolate_lru(folio))
		return -EAGAIN;
	list_add_tail(&folio->lru, managed_folios);
	node_stat_mod_folio(folio, NR_ISOLATED_ANON + folio_is_file_lru(folio),
			    folio_nr_pages(folio));
	return 0;
}

struct policy_worker {
	pid_t pid;
	// mset > fmem + smem + tset
	HashMapU64Ptr *mset;
	HashMapU64U64 *tset, *bset;
	struct list_head *managed_folios;
	struct sds *sds;
	struct indexable_heap *fmem, *smem;
	mpsc_t samples, excg_req, excg_rsp;
};
struct exch_req {
	u64 id;
	u64 vpfn0, vpfn1;
	struct folio *folio0, *folio1;
};
struct exch_rsp {
	u64 id;
	u64 vpfn0, vpfn1;
	struct folio *folio0, *folio1;
	int err;
};

noinline static int policy_handle_sample_one(struct policy_worker *data,
					     struct mm_struct *mm,
					     struct perf_sample *s)
{
	pid_t pid = data->pid;
	HashMapU64Ptr *mset = data->mset;
	HashMapU64U64 *tset = data->tset, *bset = data->bset;
	struct list_head *managed_folios = data->managed_folios;
	struct sds *sds = data->sds;
	struct indexable_heap *fmem = data->fmem, *smem = data->smem;

	u64 vpfn = s->addr >> PAGE_SHIFT;
	if (!vpfn)
		return -EINVAL;
	if (HashMapU64U64_contains(bset, &vpfn))
		return -EPERM;
	if (pid != s->pid)
		return -ESRCH;
	CLASS(uvirt_folio, folio)(mm, s->addr);
	if (IS_ERR_OR_NULL(folio))
		return -EFAULT;
	if (folio_ref_count(folio) < 2)
		return -ESTALE;
	// See uvirt_to_folio()
	BUG_ON(folio_mapping(folio));
	// Check if the page is in the managed set or under migration
	if (HashMapU64Ptr_contains(mset, &vpfn)) {
	} else if (folio_test_lru(folio)) {
		// Found a new lru folio that should be managed by us
		int err = policy_manage_folio(managed_folios, folio);
		if (err)
			return err;
		HashMapU64Ptr_Entry const entry = { vpfn, folio };
		HashMapU64Ptr_insert(mset, &entry);
	} else
		return -EPERM;
	// Update frequency info for folios managed by us
	bool in_fmem = folio_nid(folio) == FMEM_NID;
	struct indexable_heap *heap = in_fmem ? fmem : smem;

	u64 count = sds_push_multiple(sds, vpfn, target_event_weight(s));
	if (HashMapU64U64_contains(tset, &vpfn)) {
		// The folio is under migration record the frequency in the tset
		HashMapU64U64_Entry e = { vpfn, count };
		HashMapU64U64_update(tset, &e);
	} else if (indexable_heap_contains(heap, vpfn)) {
		// Update existing folio
		if (count)
			indexable_heap_update(heap, vpfn, count);
		else if (!in_fmem)
			indexable_heap_erase(heap, vpfn);
		// FMEM folios without access means they are cold and are great
		// candidates for demotion. But cold SMEM does not worth caring.
	} else {
		// Potential a decayed folio getting accessed again or just
		// plainly a new folio
		if (count)
			indexable_heap_push(heap, vpfn, count);
	}

	count_vm_event(in_fmem ? PEBS_NR_SAMPLED_FMEM : PEBS_NR_SAMPLED_SMEM);
	return 0;
}
noinline static int policy_handle_samples(struct policy_worker *data,
					  struct mm_struct *mm)
{
	mpsc_t samples = data->samples;
	int cpu, received = 0, discarded = 0;
	for_each_online_cpu(cpu)
		for (int fail = 0; fail < MPSC_RETRY;) {
			struct perf_sample s;
			ssize_t size =
				mpsc_recv_cpu(samples, cpu, &s, sizeof(s));
			if (size != sizeof(s)) {
				++fail;
				continue;
			}
			// TODO: check return value and account failed samples
			int err = policy_handle_sample_one(data, mm, &s);
			if (err < 0) {
				// TODO: error accounting
				// pr_err_ratelimited("%s: discard sample due to error %pe\n", __func__, ERR_PTR(err));
				++discarded;
			} else {
				++received;
			}
			if (received + discarded > MPSC_MAX_BATCH)
				goto out;
		}
out:
	count_vm_events(PEBS_NR_SAMPLED, received);
	count_vm_events(PEBS_NR_DISCARDED, discarded);
	return received;
}
noinline static int policy_send_exch_reqs(struct policy_worker *data)
{
	static atomic_long_t seq = {};
	struct indexable_heap *fmem = data->fmem, *smem = data->smem;
	HashMapU64Ptr *mset = data->mset;
	HashMapU64U64 *tset = data->tset;
	mpsc_t excg_req = data->excg_req;

	int sent = 0;
	while (indexable_heap_size(fmem) > IHEAP_MIN_SIZE &&
	       indexable_heap_size(smem) > IHEAP_MIN_SIZE) {
		u64 vpfn0 = *kv_ckey(indexable_heap_peek(fmem)),
		    count0 = *kv_cvalue(indexable_heap_peek(fmem)),
		    vpfn1 = *kv_ckey(indexable_heap_peek(smem)),
		    count1 = *kv_cvalue(indexable_heap_peek(smem));
		if (count0 >= count1 || sent > MPSC_MAX_BATCH)
			break;
		struct folio *folio0 = HashMapU64Ptr_get(mset, &vpfn0),
			     *folio1 = HashMapU64Ptr_get(mset, &vpfn1);
		indexable_heap_pop(fmem);
		if (IS_ERR_OR_NULL(folio0) || folio_nid(folio0) != FMEM_NID)
			continue;
		indexable_heap_pop(smem);
		if (IS_ERR_OR_NULL(folio1) || folio_nid(folio1) != SMEM_NID)
			continue;

		HashMapU64U64_Entry e0 = { vpfn0, count0 };
		HashMapU64U64_insert(tset, &e0);
		HashMapU64U64_Entry e1 = { vpfn1, count1 };
		HashMapU64U64_insert(tset, &e1);

		struct exch_req req = {
			.id = atomic_long_fetch_add(1, &seq),
			.vpfn0 = vpfn0,
			.vpfn1 = vpfn1,
			.folio0 = folio0,
			.folio1 = folio1,
		};
		if (mpsc_send(excg_req, &req, sizeof(req)) < 0) {
			pr_err("%s: discard exchange request due to ring buffer overflow\n",
			       __func__);
			BUG();
		} else {
			++sent;
		}
	}
	return sent;
}
noinline static int policy_handle_exch_rsp_one(struct policy_worker *data,
					       struct exch_rsp *rsp)
{
	struct indexable_heap *fmem = data->fmem, *smem = data->smem;
	HashMapU64U64 *tset = data->tset, *bset = data->bset;
	int error = rsp->err;
	u64 vpfn0 = rsp->vpfn0, vpfn1 = rsp->vpfn1;

	HashMapU64U64_Iter iter0 = HashMapU64U64_find(tset, &vpfn0),
			   iter1 = HashMapU64U64_find(tset, &vpfn1);
	HashMapU64U64_Entry *e0 = HashMapU64U64_Iter_get(&iter0),
			    *e1 = HashMapU64U64_Iter_get(&iter1);
	BUG_ON(IS_ERR_OR_NULL(e0) || IS_ERR_OR_NULL(e1));
	u64 count0 = e0->val, count1 = e1->val;
	HashMapU64U64_erase(tset, &vpfn0);
	HashMapU64U64_erase(tset, &vpfn1);

	switch (error) {
	case -ENOTSUPP:
		HashMapU64U64_Entry e0 = { vpfn0, count0 };
		HashMapU64U64_insert(bset, &e0);
		if (indexable_heap_contains(smem, vpfn1))
			indexable_heap_update(smem, vpfn1, count1);
		else
			indexable_heap_push(smem, vpfn1, count1);
		break;
	case -ENOTSUPP + 1:
		if (indexable_heap_contains(fmem, vpfn0))
			indexable_heap_update(fmem, vpfn0, count0);
		else
			indexable_heap_push(fmem, vpfn0, count0);
		HashMapU64U64_Entry e1 = { vpfn1, count1 };
		HashMapU64U64_insert(bset, &e1);
		error = -ENOTSUPP;
		break;
	case 0:
		swap(fmem, smem);
		fallthrough;
	default:
		if (indexable_heap_contains(fmem, vpfn0))
			indexable_heap_update(fmem, vpfn0, count0);
		else
			indexable_heap_push(fmem, vpfn0, count0);
		if (indexable_heap_contains(smem, vpfn1))
			indexable_heap_update(smem, vpfn1, count1);
		else
			indexable_heap_push(smem, vpfn1, count1);
		break;
	}
	return error;
}
noinline static int policy_handle_exch_rsps(struct policy_worker *data)
{
	mpsc_t excg_rsp = data->excg_rsp;
	int cpu, done = 0;
	for_each_online_cpu(cpu)
		for (int fail = 0; fail < MPSC_RETRY;) {
			struct exch_rsp rsp;
			ssize_t size =
				mpsc_recv_cpu(excg_rsp, cpu, &rsp, sizeof(rsp));
			if (size != sizeof(rsp)) {
				++fail;
				continue;
			}
			++done;
			policy_handle_exch_rsp_one(data, &rsp);
		}
	return done;
}
noinline static int target_worker_policy(struct target *self)
{
	// Shared data
	mpsc_t samples = self->chans[CHAN_SAMPLE];
	mpsc_t excg_req = self->chans[CHAN_EXCG_REQ];
	mpsc_t excg_rsp = self->chans[CHAN_EXCG_RSP];

	// Thread private data initialization
	// mangaed set
	HashMapU64Ptr __cleanup(HashMapU64Ptr_destroy)
		mset = HashMapU64Ptr_new(POLICY_MSET_BUCKET);
	struct list_head __cleanup(policy_release_managed)
		managed_folios = LIST_HEAD_INIT(managed_folios);
	// sds
	struct sds __cleanup(sds_drop) sds;
	BUG_ON(sds_init_default(&sds));
	// indexable_heap
	struct indexable_heap __cleanup(indexable_heap_drop) fmem;
	BUG_ON(indexable_heap_init(&fmem, true, "fmem"));
	struct indexable_heap __cleanup(indexable_heap_drop) smem;
	BUG_ON(indexable_heap_init(&smem, false, "smem"));
	// tset: temporay storage for folios under migration
	HashMapU64U64 __cleanup(HashMapU64U64_destroy)
		tset = HashMapU64U64_new(POLICY_TSET_BUCKET);
	// bset: blacklisted folios which canot be migrated
	HashMapU64U64 __cleanup(HashMapU64U64_destroy)
		bset = HashMapU64U64_new(POLICY_BSET_BUCKET);
	struct policy_worker data = {
		.pid = self->victim->tgid,
		.mset = &mset,
		.tset = &tset,
		.bset = &bset,
		.managed_folios = &managed_folios,
		.sds = &sds,
		.fmem = &fmem,
		.smem = &smem,
		.samples = samples,
		.excg_req = excg_req,
		.excg_rsp = excg_rsp,
	};

	// reporting is rate limited to every 500ms
	DEFINE_RATELIMIT_STATE(report_rs, msecs_to_jiffies(500), 1);

	u64 sample_count = 0, excg_req_count = 0, excg_rsp_count = 0,
	    report_period = 50000, next_report = report_period, backoff = 500;
	while (!kthread_should_stop()) {
		int which = mpsc_select(excg_rsp, samples);
		guard(stat_stopwatch)(self, STAT_T_POLICY);
		switch (which) {
		case -ERESTARTSYS:
			pr_warn_ratelimited("%s: interrupted\n", __func__);
			continue;
		case 0: {
			excg_rsp_count += policy_handle_exch_rsps(&data);
			break;
		}
		case 1: {
			CLASS(task_mm, mm)(self->victim);
			if (unlikely(IS_ERR_OR_NULL(mm))) {
				pr_err("%s: victim mm=%pe\n", __func__, mm);
				// exit early will cause kthread_stop to panic
				schedule_timeout_interruptible(
					msecs_to_jiffies(backoff *= 2));
				continue;
			}
			sample_count += policy_handle_samples(&data, mm);
			break;
		}
		default:
			pr_err("%s: unknown channel or error %pe\n", __func__,
			       ERR_PTR(which));

			BUG();
		}
		// Try sending migration requests
		excg_req_count += policy_send_exch_reqs(&data);

		u64 curr_report =
			max(sample_count, max(excg_req_count, excg_rsp_count));
		if (curr_report > next_report && __ratelimit(&report_rs)) {
			next_report = curr_report + report_period;
			pr_info("%s: samples=%llu excg_req=%llu excg_rsp=%llu\n",
				__func__, sample_count, excg_req_count,
				excg_rsp_count);
		}
	}

	char comm[64] = {};
	get_kthread_comm(comm, sizeof(comm), current);
	pr_info("%s: stopped worker %s usage=%u\n", __func__, comm,
		refcount_read(&current->usage));
	return 0;
}

noinline static int migration_handle_req(struct exch_req *req)
{
	struct folio *folio0 = req->folio0, *folio1 = req->folio1;
	u64 vpfn0 = req->vpfn0, vpfn1 = req->vpfn1;
	int err = folio_exchange_isolated(folio0, folio1, MIGRATE_SYNC);
	if (err) {
		// clang-format off
		pr_err_ratelimited("%s: folio_exchange_isolated: mode=%d err=%pe [src=%p vaddr=%p pfn=0x%lx] <-> [dst=%p vaddr=%p pfn=0x%lx]",
		       __func__, MIGRATE_SYNC, ERR_PTR(err),
		       folio0, (void *)(vpfn0 << PAGE_SHIFT), folio_pfn(folio0),
		       folio1, (void *)(vpfn1 << PAGE_SHIFT), folio_pfn(folio1));
		// clang-format on
	}
	return err;
}
noinline static int migration_send_ack(mpsc_t excg_rsp, struct exch_req *req,
				       int error)
{
	struct exch_rsp rsp = {
		.id = req->id,
		.vpfn0 = req->vpfn0,
		.vpfn1 = req->vpfn1,
		.folio0 = req->folio0,
		.folio1 = req->folio1,
		.err = error,
	};
	int err = mpsc_send(excg_rsp, &rsp, sizeof(rsp));
	if (err < 0) {
		pr_err("%s: failed to send exchange response due to ring buffer overflow\n",
		       __func__);
		BUG();
	}
	return err;
}
noinline static int migration_handle_requests(mpsc_t excg_req, mpsc_t excg_rsp)
{
	int cpu, received = 0;
	for_each_online_cpu(cpu)
		for (int fail = 0; fail < MPSC_RETRY;) {
			struct exch_req req;
			ssize_t size =
				mpsc_recv_cpu(excg_req, cpu, &req, sizeof(req));
			if (size != sizeof(req)) {
				++fail;
				continue;
			}
			++received;
			migration_send_ack(excg_rsp, &req,
					   migration_handle_req(&req));
		}
	return received;
}

noinline static int target_worker_migration(struct target *self)
{
	mpsc_t excg_req = self->chans[CHAN_EXCG_REQ],
	       excg_rsp = self->chans[CHAN_EXCG_RSP];

	u64 excg_count = 0, report_period = 500, next_report = report_period;
	// reporting is rate limited to every 1000ms
	DEFINE_RATELIMIT_STATE(report_rs, msecs_to_jiffies(1000), 1);

	while (!kthread_should_stop()) {
		int err = mpsc_wait(excg_req);
		guard(stat_stopwatch)(self, STAT_T_MIGRATION);
		switch (err) {
		case -ERESTARTSYS:
			pr_warn_ratelimited("%s: interrupted\n", __func__);
			continue;
		case 0:
			excg_count +=
				migration_handle_requests(excg_req, excg_rsp);
			break;
		default:
			pr_err("%s: unknown error %d\n", __func__, err);
			BUG();
		}
		if (excg_count > next_report && __ratelimit(&report_rs)) {
			next_report = excg_count + report_period;
			pr_info("%s: excg_count=%llu\n", __func__, excg_count);
		}
	}

	char comm[64] = {};
	get_kthread_comm(comm, sizeof(comm), current);
	pr_info("%s: stopped worker %s usage=%u\n", __func__, comm,
		refcount_read(&current->usage));
	return 0;
}

pid_t target_pid(struct target *self)
{
	return self->victim->tgid;
}
void target_drop(struct target *self)
{
	if (IS_ERR_OR_NULL(self))
		return;
	u64 total_elapsed = sched_clock() - self->start_time + 1;
	for (int i = 0; i < MAX_STATS; ++i) {
		long val = atomic_long_read(&self->stats[i]);
		pr_info("%s: %s=%ld permyriad=%llu\n", __func__,
			target_stat_name[i], val, val * 10000 / total_elapsed);
	}
	target_events_enable(self, false);
	for (int i = 0; i < MAX_WORKERS; i++) {
		struct task_struct *t = self->workers[i];
		if (IS_ERR_OR_NULL(t))
			continue;
		char comm[64] = {};
		get_kthread_comm(comm, sizeof(comm), t);
		pr_info("%s: stopping worker %s usage=%u\n", __func__, comm,
			refcount_read(&t->usage));
		// The worker must not exit before we stop it
		kthread_stop(t);
	}
	for (int i = 0; i < MAX_CHANS; i++) {
		mpsc_t ch = self->chans[i];
		!ch ?: mpsc_drop(ch);
	}
	struct task_struct *victim = self->victim;
	!victim ?: put_task_struct(victim);
	kfree(self);
}
struct target *target_new(pid_t pid)
{
	static int (*fns[])(void *) = {
		[WORKER_MAIN] = (void *)target_worker_main,
		[WORKER_THROTTLE] = (void *)target_worker_throttle,
		[WORKER_POLICY] = (void *)target_worker_policy,
		[WORKER_MIGRATION] = (void *)target_worker_migration,
	};
	static char *const names[] = {
		[WORKER_MAIN] = "main",
		[WORKER_THROTTLE] = "throttle",
		[WORKER_POLICY] = "policy",
		[WORKER_MIGRATION] = "migration",
	};

	struct target *self = kzalloc(sizeof(*self), GFP_KERNEL);
	if (!self)
		return ERR_PTR(-ENOMEM);
	self->victim = find_get_task_by_vpid(pid);
	if (!self->victim) {
		target_drop(self);
		return ERR_PTR(-ESRCH);
	}
	for (int i = 0; i < MAX_CHANS; i++) {
		mpsc_t ch = mpsc_new(MPSC_MAX_SIZE_BYTE);
		if (IS_ERR_OR_NULL(ch)) {
			target_drop(self);
			return ERR_PTR(-ENOMEM);
		}
		self->chans[i] = ch;
	}
	BUILD_BUG_ON(ARRAY_SIZE(fns) != MAX_WORKERS);
	BUILD_BUG_ON(ARRAY_SIZE(names) != MAX_WORKERS);
	for (int i = 0; i < MAX_WORKERS; i++) {
		struct task_struct *t =
			kthread_run(fns[i], self, "ht-%s/%d", names[i], pid);
		if (IS_ERR_OR_NULL(t)) {
			target_drop(self);
			return ERR_PTR(-ECHILD);
		}
		self->workers[i] = t;
	}
	BUILD_BUG_ON(ARRAY_SIZE(event_attrs) != MAX_EVENTS);
	for (int i = 0; i < MAX_EVENTS; i++) {
		struct perf_event *e = perf_event_create_kernel_counter(
			&event_attrs[i], -1, self->victim,
			target_events_overflow, self);
		if (IS_ERR_OR_NULL(e)) {
			target_drop(self);
			return ERR_CAST(e);
		}
		self->events[i] = e;
		pr_info("%s: created config=0x%llx sample_period=%lld\n",
			__func__, event_attrs[i].config,
			event_attrs[i].sample_period);
	}
	BUILD_BUG_ON(ARRAY_SIZE(target_stat_name) != MAX_STATS);
	self->start_time = sched_clock();
	return self;
}
