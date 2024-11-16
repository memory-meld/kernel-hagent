// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021-2024 Junliang Hu
 *
 * Author: Junliang Hu <jlhu@cse.cuhk.edu.hk>
 *
 */

#include <linux/sched/cputime.h>
#include <linux/sched/clock.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/sort.h>
#include <../internal.h>

#include "error.h"
#include "hagent.h"
#include "pebs.h"
#include "module.h"
#include "mpsc.h"
#include "indexable_heap.h"
#include "range_tree.h"

enum target_worker {
	// Main thread initiate the range splitting and merging by notifying the
	// policy via CHAN_SPLIT_REQ
	WORKER_MAIN,
	// Throttle thread periodically enable the perf events and disable them
	// in a PWM like fashion
	WORKER_THROTTLE,
	// Policy thread is responsible for the heavy lifting of process samples
	// and update range accounting/splitting/merging and initiate migration
	WORKER_POLICY,
	// Migration thread carries out the actual migration of folios
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
	// Can only be consumed by WORKER_POLICY
	CHAN_SPLT_REQ,
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
	RMT_GRANULARITY = 2ul << 20,
	RMT_MIN_SIZE = 3,
	RMT_MAX_SIZE = 256,
	RMT_SPLIT_FACTOR = 1,
	// Fit at most MIGRATION_WMARK% of the total capacity during migration
	MIGRATION_WMARK = 90,
	MIGRAION_MAX_BATCH = (64ul << 20) / PAGE_SIZE,
	MIGRATION_BSET_BUCKET = 32,
	MIGRATION_BSET_BACKOFF = 128,
	// EVENT_CURVE_LEN = 100,
};

enum target_stat {
	STAT_OVERFLOW_HANDLER,
	STAT_THROTTLE,
	STAT_POLICY,
	STAT_MIGRATION,
	STAT_PERF_PREPARE,
	STAT_SPLIT,
	MAX_STATS,
};
static char *const target_stat_name[] = {
	"overflow_handler", "throttle",	    "policy",
	"migration",	    "perf_prepare", "split",
};

struct target {
	// Currently managed task
	struct task_struct *victim;
	// These channels are the only sharing states between the workers
	mpsc_t chans[MAX_CHANS];
	struct task_struct *workers[MAX_WORKERS];
	// Should only be used by the throttle and main thread
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

static inline u64 task_clock(void)
{
	u64 utime, stime = 0;
	task_cputime_adjusted(current, &utime, &stime);
	return stime;
}
struct stat_stopwatch {
	struct target *target;
	u64 (*clock)(void);
	u64 start;
	u64 item;
};
static struct stat_stopwatch stopwatch_new(struct target *target,
					   u64 (*clock)(void), u64 item)
{
	return (struct stat_stopwatch){
		.target = target,
		.clock = clock,
		.item = item,
		.start = clock(),
	};
}
static void stopwatch_drop(struct stat_stopwatch *t)
{
	atomic_long_add(t->clock() - t->start, &t->target->stats[t->item]);
}
DEFINE_CLASS(stat, struct stat_stopwatch, stopwatch_drop(&_T),
	     stopwatch_new(s, clock, item), struct target *s,
	     u64 (*clock)(void), enum target_stat item);

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
	// Not in a kthread context, try using the scheduler local_clock()
	guard(stat)(self, local_clock, STAT_OVERFLOW_HANDLER);
	{
		guard(stat)(self, local_clock, STAT_PERF_PREPARE);
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
static void worker_farewell(struct task_struct *task)
{
	char comm[64] = {};
	get_kthread_comm(comm, sizeof(comm), task);
	pr_info("%s: worker %pSR stopped name=%s usage=%u\n", __func__,
		__builtin_return_address(0), comm, refcount_read(&task->usage));
}
struct splt_req {
	u64 id, data;
};
noinline static int worker_main(struct target *self)
{
	mpsc_t splt_req = self->chans[CHAN_SPLT_REQ];
	u64 period = msecs_to_jiffies(split_period_ms);
	u64 id = 0;
	while (!kthread_should_stop()) {
		schedule_timeout_uninterruptible(period);
		struct splt_req req = { .id = id++ };
		if (mpsc_send(splt_req, &req, sizeof(req)) < 0) {
			pr_err("%s: discard split request due to ring buffer overflow\n",
			       __func__);
			BUG();
		}
		// pr_info("%s: split request sent id=%llu\n", __func__, id - 1);
	}

	worker_farewell(current);
	return 0;
}

noinline static int worker_throttle(struct target *self)
{
	u64 period = msecs_to_jiffies(throttle_pulse_period_ms);
	u64 width = msecs_to_jiffies(throttle_pulse_width_ms);
	BUG_ON(period == 0 || width >= period);
	while (!kthread_should_stop()) {
		if (width) {
			{
				guard(stat)(self, task_clock, STAT_THROTTLE);
				target_events_enable(self, true);
			}
			schedule_timeout_uninterruptible(width);
			{
				guard(stat)(self, task_clock, STAT_THROTTLE);
				target_events_enable(self, false);
			}
			schedule_timeout_uninterruptible(period - width);
		} else
			schedule_timeout_uninterruptible(period);
	}

	worker_farewell(current);
	return 0;
}

noinline static int manage_folio(struct list_head *managed, struct folio *folio)
{
	extern bool folio_isolate_lru(struct folio * folio);
	guard(folio_get)(folio);
	if (!folio_isolate_lru(folio))
		return -EAGAIN;
	list_add_tail(&folio->lru, managed);
	node_stat_mod_folio(folio, NR_ISOLATED_ANON + folio_is_file_lru(folio),
			    folio_nr_pages(folio));
	return 0;
}
noinline static void unmanage_folio(struct list_head *managed)
{
	extern void folio_putback_lru(struct folio *);
	// release managed set
	struct folio *folio, *next;
	list_for_each_entry_safe(folio, next, managed, lru) {
		list_del(&folio->lru);
		node_stat_mod_folio(folio,
				    NR_ISOLATED_ANON + folio_is_file_lru(folio),
				    -folio_nr_pages(folio));
		folio_putback_lru(folio);
		// folio_add_lru(folio);
	}
}
struct policy_worker {
	pid_t pid;
	struct range_tree *rt;
	struct mrange **mrs; // mset > fmem + smem + tset
	mpsc_t samplech, excg_req, excg_rsp, splt_req;
	ulong (*node_avail_pages)(int);
};
struct exch_req {
	struct list_head *promotion, *demotion;
};
struct exch_rsp {
	struct list_head *promotion, *demotion;
};
noinline static int policy_handle_sample_one(struct policy_worker *data,
					     struct mm_struct *mm,
					     struct perf_sample *s)
{
	struct range_tree *rt = data->rt;
	// ulong *nr_access = data->nr_access;
	ulong vaddr = s->addr;
	if (vaddr < mm->start_brk || vaddr >= mm->mmap_base) {
		// pr_err_ratelimited(
		// 	"%s: vaddr=%#lx not in [start_brk=%#lx, mmap_base=%#lx)\n",
		// 	__func__, vaddr, mm->start_brk, mm->mmap_base);
		return -ECBADSAMPLE;
	}
	TRY(rt_count(rt, vaddr));
	return 0;
}
noinline static int policy_handle_samples(struct policy_worker *data,
					  struct mm_struct *mm)
{
	mpsc_t samplech = data->samplech;
	int received = 0, discarded = 0;
	struct perf_sample s = {};
	mpsc_for_each(samplech, s) {
		int err = policy_handle_sample_one(data, mm, &s);
		if (err < 0) {
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
noinline static int policy_send_exch_reqs(struct policy_worker *data,
					  struct mm_struct *mm)
{
	struct range_tree *rt = data->rt;
	struct mrange **mrs = data->mrs;
	ulong (*fn)(int) = data->node_avail_pages;
	mpsc_t excg_req = data->excg_req;
	if (rt->min_range > RTREE_EXCH_THRESH)
		return -EAGAIN;
	struct list_head *promo = TRY(
				 kmem_cache_alloc(list_head_cache, GFP_KERNEL)),
			 *demo = TRY(
				 kmem_cache_alloc(list_head_cache, GFP_KERNEL));
	INIT_LIST_HEAD(promo), INIT_LIST_HEAD(demo);
	guard(mmap_read_lock)(mm);
	ulong rlen = rt->len;
	TRY(rt_rank(rt, mm, mrs, &rlen));

	// ranges [0, s) should be placed in smem
	// ranges [f, olen) should be placed in fmem
	ulong s = 0, f = rlen;
	for (ulong i = 0, len = rlen, fmem = 0, smem = 0,
		   fmem_cap = fn(FMEM_NID), smem_cap = fn(SMEM_NID);
	     i < len; i++) {
		struct mrange *p = mrs[i], *q = mrs[len - 1 - i];
		if (smem_cap > (smem += p->in_smem + p->in_smem))
			s += 1;
		if (fmem_cap > (fmem += q->in_smem + q->in_smem))
			f -= 1;
	}

	pr_info("%s: rank ranges count=%lu smem=[0, %lu) fmem=[%lu, %lu) smem_cap=%luM fmem_cap=%luM\n",
		__func__, rt->len, s, f, rt->len,
		fn(SMEM_NID) << PAGE_SHIFT >> 20,
		fn(FMEM_NID) << PAGE_SHIFT >> 20);
	for (ulong i = 0; i < rt->len; i++) {
		mrange_show(mrs[i]);
	}

	// isolate folios based on the ranges above
	for (ulong i = 0; i <= s; i++) {
		struct mrange *r = mrs[i];
		ulong total = r->in_fmem;
		ulong got = rt_isolate(mm, r, FMEM_NID, manage_folio, demo);
		// TODO: count the isolated folios
	}
	for (ulong i = f; i < rlen; i++) {
		struct mrange *r = mrs[i];
		ulong total = r->in_smem;
		ulong got = rt_isolate(mm, r, SMEM_NID, manage_folio, promo);
	}

	// send exchange request
	struct exch_req req = {
		.promotion = promo,
		.demotion = demo,
	};
	if (mpsc_send(excg_req, &req, sizeof(req)) < 0) {
		pr_err("%s: discard exchange request due to ring buffer overflow\n",
		       __func__);
		BUG();
	}
	return 0;
}

noinline static int policy_handle_splt_reqs(struct policy_worker *data,
					    struct mm_struct *mm)
{
	mpsc_t splt_req = data->splt_req;
	struct range_tree *rt = data->rt;
	ulong done = 0;
	struct splt_req req = {};
	mpsc_for_each(splt_req, req) {
		ulong diff = ({
			ulong len = rt->len;
			rt_split(rt);
			rt->len - len;
		});
		if (!diff)
			continue;
		pr_info("%s: split request success id=%llu\n", __func__,
			req.id);
		rt_show(rt);
		long err = policy_send_exch_reqs(data, mm);
		if (err < 0)
			pr_err_ratelimited("%s: policy_send_exch_reqs()=%pe\n",
					   __func__, ERR_PTR(err));
		else
			done += 1;
	}
	return done;
}
noinline static int policy_handle_exch_rsps(struct policy_worker *data)
{
	mpsc_t excg_rsp = data->excg_rsp;
	int done = 0;
	struct exch_rsp rsp = {};
	mpsc_for_each(excg_rsp, rsp) {
		++done;
		unmanage_folio(rsp.promotion);
		unmanage_folio(rsp.demotion);
		kmem_cache_free(list_head_cache, rsp.demotion);
		kmem_cache_free(list_head_cache, rsp.promotion);
	}
	return done;
}

static void kmalloc_cleanup(const void *p)
{
	if (IS_ERR_OR_NULL(p))
		return;
	if (IS_ERR_OR_NULL(*(void **)p))
		return;
	kfree(*(void **)p);
}

ulong __node_present_pages(int nid)
{
	return node_present_pages(nid);
}
EXPORT_SYMBOL_GPL(__node_present_pages);

noinline static int worker_policy(struct target *self)
{
	// Shared data
	mpsc_t samplech = self->chans[CHAN_SAMPLE];
	mpsc_t excg_req = self->chans[CHAN_EXCG_REQ];
	mpsc_t excg_rsp = self->chans[CHAN_EXCG_RSP];
	mpsc_t splt_req = self->chans[CHAN_SPLT_REQ];

	// Thread private data initialization
	// rmt: the "range_tree" to record the managed ranges
	struct range_tree __cleanup(rt_drop) rt = {};
	{
		CLASS(task_mm, mm)(self->victim);
		BUG_ON(IS_ERR_OR_NULL(mm));
		BUG_ON(rt_init(&rt, mm->start_brk, mm->mmap_base));
		rt_show(&rt);
		pr_info("%s: mm_struct layout start_code=%#lx end_code=%#lx start_data=%#lx end_data=%#lx start_brk=%#lx brk=%#lx start_stack=%#lx arg_start=%#lx arg_end=%#lx env_start=%#lx env_end=%#lx mmap_base=%#lx mmap_legacy_base=%#lx\n",
			__func__, mm->start_code, mm->end_code, mm->start_data,
			mm->end_data, mm->start_brk, mm->brk, mm->start_stack,
			mm->arg_start, mm->arg_end, mm->env_start, mm->env_end,
			mm->mmap_base, mm->mmap_legacy_base);
	}
	__cleanup(kmalloc_cleanup) struct mrange **mrs =
		TRY(kcalloc(RTREE_MAX_SIZE, sizeof(*mrs), GFP_KERNEL));
	BUG_ON(!mrs);

	extern ulong __node_avail_pages(int nid);
	extern ulong node_avail_pages(int nid);
	ulong (*fn)(int) = symbol_get(__node_avail_pages)	?:
				   symbol_get(node_avail_pages) ?:
				   symbol_get(__node_present_pages);
	BUG_ON(!fn);

	struct policy_worker data = {
		.pid = self->victim->tgid,
		.rt = &rt,
		.mrs = mrs,
		.samplech = samplech,
		.excg_req = excg_req,
		.excg_rsp = excg_rsp,
		.splt_req = splt_req,
		.node_avail_pages = fn,
	};

	// reporting is rate limited to every 500ms
	DEFINE_RATELIMIT_STATE(report_rs, msecs_to_jiffies(500), 1);

	u64 sample_count = 0, excg_req_count = 0, excg_rsp_count = 0,
	    report_period = 50000, next_report = report_period,
	    initial_backoff = 500, backoff = initial_backoff;
	while (!kthread_should_stop()) {
		int which = mpsc_select3(excg_rsp, splt_req, samplech);
		guard(stat)(self, task_clock, STAT_POLICY);
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
			} else {
				backoff = initial_backoff;
			}
			guard(stat)(self, task_clock, STAT_SPLIT);
			excg_rsp_count += policy_handle_splt_reqs(&data, mm);
			break;
		}
		case 2: {
			CLASS(task_mm, mm)(self->victim);
			if (unlikely(IS_ERR_OR_NULL(mm))) {
				pr_err("%s: victim mm=%pe\n", __func__, mm);
				// exit early will cause kthread_stop to panic
				schedule_timeout_interruptible(
					msecs_to_jiffies(backoff *= 2));
				continue;
			} else {
				backoff = initial_backoff;
			}
			sample_count += policy_handle_samples(&data, mm);
			break;
		}
		default:
			pr_err("%s: unknown channel or error %pe\n", __func__,
			       ERR_PTR(which));
			BUG();
		}

		u64 curr_report =
			max(sample_count, max(excg_req_count, excg_rsp_count));
		if (curr_report > next_report && __ratelimit(&report_rs)) {
			next_report = curr_report + report_period;
			pr_info("%s: samples=%llu excg_req=%llu excg_rsp=%llu\n",
				__func__, sample_count, excg_req_count,
				excg_rsp_count);
		}
	}

	symbol_put_addr(fn);
	worker_farewell(current);
	return 0;
}

noinline static int migration_handle_req(struct exch_req *req,
					 HashMapU64U64 *bset)
{
	struct list_head *p = req->promotion, *d = req->demotion;
	LIST_HEAD(promotion_done);
	LIST_HEAD(demotion_done);
	ulong success = 0, failure = 0;
	while (!list_empty(p) && !list_empty(d)) {
		// fifo order
		struct folio *folio0 = list_entry(p->next, struct folio, lru),
			     *folio1 = list_entry(d->next, struct folio, lru);

		u64 pfn;
		pfn = folio_pfn(folio0);
		if (HashMapU64U64_contains(bset, &pfn)) {
			HashMapU64U64_Iter iter =
				HashMapU64U64_find(bset, &pfn);
			HashMapU64U64_Entry *e = HashMapU64U64_Iter_get(&iter);
			if (++e->val > MIGRATION_BSET_BACKOFF)
				HashMapU64U64_erase(bset, &pfn);
			list_move_tail(p->next, &promotion_done);
			continue;
		}
		if (!folio_test_anon(folio0)) {
			list_move_tail(p->next, &promotion_done);
			HashMapU64U64_Entry e = { folio_pfn(folio0), 0 };
			CHECK_INSERTED(HashMapU64U64_insert(bset, &e), true,
				       "cannot blacklist folio0 pfn=0x%lx",
				       folio_pfn(folio0));
			continue;
		}

		pfn = folio_pfn(folio1);
		if (HashMapU64U64_contains(bset, &pfn)) {
			HashMapU64U64_Iter iter =
				HashMapU64U64_find(bset, &pfn);
			HashMapU64U64_Entry *e = HashMapU64U64_Iter_get(&iter);
			if (++e->val > MIGRATION_BSET_BACKOFF)
				HashMapU64U64_erase(bset, &pfn);
			list_move_tail(d->next, &demotion_done);
			continue;
		}
		if (!folio_test_anon(folio1)) {
			list_move_tail(d->next, &demotion_done);
			HashMapU64U64_Entry e = { folio_pfn(folio1), 0 };
			CHECK_INSERTED(HashMapU64U64_insert(bset, &e), true,
				       "cannot blacklist folio1 pfn=0x%lx",
				       folio_pfn(folio1));
			continue;
		}

		int err = folio_exchange_isolated(folio0, folio1, MIGRATE_SYNC);
		if (err) {
			pr_err_ratelimited(
				"%s: folio_exchange_isolated: mode=%d err=%pe [src=%p pfn=0x%lx] <-> [dst=%p pfn=0x%lx]",
				__func__, MIGRATE_SYNC, ERR_PTR(err), folio0,
				folio_pfn(folio0), folio1, folio_pfn(folio1));
			++failure;
		}
		switch (err) {
		case -ENOTSUPP: {
			// folio0 failed, blacklist
			list_move_tail(p->next, &promotion_done);
			HashMapU64U64_Entry e = { folio_pfn(folio0), 0 };
			CHECK_INSERTED(HashMapU64U64_insert(bset, &e), true,
				       "cannot blacklist folio0 pfn=0x%lx",
				       folio_pfn(folio0));
			break;
		}
		case -ENOTSUPP + 1: {
			// folio1 failed, blacklist
			list_move_tail(d->next, &demotion_done);
			HashMapU64U64_Entry e = { folio_pfn(folio1), 0 };
			CHECK_INSERTED(HashMapU64U64_insert(bset, &e), true,
				       "cannot blacklist folio1 pfn=0x%lx",
				       folio_pfn(folio1));
			break;
		}
		case 0:
			// success
			++success;
			fallthrough;
		default:
			// ignore other error
			list_move_tail(p->next, &promotion_done);
			list_move_tail(d->next, &demotion_done);
			break;
		}
	}
	pr_info("%s: success=%lu failure=%lu\n", __func__, success, failure);

	// FIXME: handle the remaining folios via the old-fashioned
	// migrate_pages when the two lists are not balanced

	unmanage_folio(&promotion_done);
	unmanage_folio(&demotion_done);
	return 0;
}
noinline static int migration_send_ack(mpsc_t excg_rsp, struct exch_req *req,
				       int error)
{
	struct exch_rsp rsp = {
		.promotion = req->promotion,
		.demotion = req->demotion,
	};
	int err = mpsc_send(excg_rsp, &rsp, sizeof(rsp));
	if (err < 0) {
		pr_err("%s: failed to send exchange response due to ring buffer overflow\n",
		       __func__);
		BUG();
	}
	return err;
}
noinline static int migration_handle_requests(mpsc_t excg_req, mpsc_t excg_rsp,
					      HashMapU64U64 *bset)
{
	int received = 0;
	struct exch_req req = {};
	mpsc_for_each(excg_req, req) {
		++received;
		migration_send_ack(excg_rsp, &req,
				   migration_handle_req(&req, bset));
	}
	return received;
}

noinline static int worker_migration(struct target *self)
{
	mpsc_t excg_req = self->chans[CHAN_EXCG_REQ],
	       excg_rsp = self->chans[CHAN_EXCG_RSP];
	// bset: blacklisted folios which canot be migrated
	HashMapU64U64 __cleanup(HashMapU64U64_destroy)
		bset = HashMapU64U64_new(MIGRATION_BSET_BUCKET);
	extern ulong node_balloon_pages(int nid);

	u64 excg_count = 0, report_period = 500, next_report = report_period;
	// reporting is rate limited to every 1000ms
	DEFINE_RATELIMIT_STATE(report_rs, msecs_to_jiffies(1000), 1);

	while (!kthread_should_stop()) {
		int err = mpsc_wait(excg_req);
		guard(stat)(self, task_clock, STAT_MIGRATION);
		switch (err) {
		case -ERESTARTSYS:
			pr_warn_ratelimited("%s: interrupted\n", __func__);
			continue;
		case 0:
			// pr_info("%s: excg_req received\n", __func__);
			excg_count += migration_handle_requests(
				excg_req, excg_rsp, &bset);
			// ulong fmem_cap = FMEM_NODE->node_present_pages,
			//       smem_cap = SMEM_NODE->node_present_pages,
			//       fmem_bln = fn(FMEM_NID), smem_bln = fn(SMEM_NID);
			// pr_info("%s: fmem_cap=%luM smem_cap=%luM fmem_bln=%luM smem_bln=%luM\n",
			// 	__func__, fmem_cap << PAGE_SHIFT >> 20,
			// 	smem_cap << PAGE_SHIFT >> 20,
			// 	fmem_bln << PAGE_SHIFT >> 20,
			// 	smem_bln << PAGE_SHIFT >> 20);
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

	symbol_put(node_avail_pages);
	worker_farewell(current);
	return 0;
}

static int (*worker_fns[])(void *) = {
	[WORKER_MAIN] = (void *)worker_main,
	[WORKER_THROTTLE] = (void *)worker_throttle,
	[WORKER_POLICY] = (void *)worker_policy,
	[WORKER_MIGRATION] = (void *)worker_migration,
};
static char *const worker_names[] = {
	[WORKER_MAIN] = "main",
	[WORKER_THROTTLE] = "throttle",
	[WORKER_POLICY] = "policy",
	[WORKER_MIGRATION] = "migration",
};

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
		pr_info("%s: try to stop %s worker comm=%s usage=%u\n",
			__func__, worker_names[i], comm,
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
	BUILD_BUG_ON(ARRAY_SIZE(worker_fns) != MAX_WORKERS);
	BUILD_BUG_ON(ARRAY_SIZE(worker_names) != MAX_WORKERS);
	for (int i = 0; i < MAX_WORKERS; i++) {
		struct task_struct *t = kthread_run(
			worker_fns[i], self, "ht-%s/%d", worker_names[i], pid);
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
