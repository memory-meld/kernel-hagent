// SPDX-License-Identifier: GPL-2.0
/*
 * Folio exchange functionality - linux/mm/exchange.c
 *
 * Copyright (C) 2021-2024 Junliang Hu
 *
 * Folio exchange is developed for tiered memory management.
 *
 * Author: Junliang Hu <jlhu@cse.cuhk.edu.hk>
 *
 */

#include <linux/migrate.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/mm_inline.h>
#include <linux/nsproxy.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/writeback.h>
#include <linux/mempolicy.h>
#include <linux/vmalloc.h>
#include <linux/security.h>
#include <linux/backing-dev.h>
#include <linux/compaction.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/hugetlb.h>
#include <linux/hugetlb_cgroup.h>
#include <linux/gfp.h>
#include <linux/pfn_t.h>
#include <linux/memremap.h>
#include <linux/userfaultfd_k.h>
#include <linux/balloon_compaction.h>
#include <linux/page_idle.h>
#include <linux/page_owner.h>
#include <linux/sched/mm.h>
#include <linux/ptrace.h>
#include <linux/oom.h>
#include <linux/memory.h>
#include <linux/random.h>
#include <linux/sched/sysctl.h>
#include <linux/memory-tiers.h>

#include <asm/tlbflush.h>

#include <trace/events/migrate.h>

#include "internal.h"

DEFINE_CLASS(kmap, void *, kunmap(_T), kmap(page), struct page *page);
DEFINE_LOCK_GUARD_1(mmap_read_lock, struct mm_struct, mmap_read_lock(_T->lock),
		    mmap_read_unlock(_T->lock));
DEFINE_LOCK_GUARD_1(xas_lock, struct xa_state, xas_lock(_T->lock),
		    xas_unlock(_T->lock));
DEFINE_LOCK_GUARD_0(lru_cache, lru_cache_disable(), lru_cache_enable());

#define swapbits(a, b, mask)                               \
	do {                                               \
		typeof(a) __t1 = (a), __t2 = (b);          \
		typeof(b) __diff = (__t1 ^ __t2) & (mask); \
		(a) = __t1 ^ __diff;                       \
		(b) = __t2 ^ __diff;                       \
	} while (0)

// clang-format off
#define FOLIO_SWAP_FLAG(name, page)						\
static __always_inline void folio_swap_##name(struct folio *l, struct folio *r) \
{ swapbits(*folio_flags(l, page), *folio_flags(r, page), 1ul << PG_##name); }

#define DEFINE_COPY(name, var) \
	typeof(var) name = (var)

// FOLIO_SWAP_FLAG(locked, FOLIO_PF_NO_TAIL);
FOLIO_SWAP_FLAG(writeback, FOLIO_PF_NO_TAIL);
FOLIO_SWAP_FLAG(referenced, FOLIO_PF_HEAD);
FOLIO_SWAP_FLAG(uptodate, FOLIO_PF_NO_TAIL);
FOLIO_SWAP_FLAG(dirty, FOLIO_PF_HEAD);
// FOLIO_SWAP_FLAG(lru, FOLIO_PF_HEAD);
// FOLIO_SWAP_FLAG(head, FOLIO_PF_ANY);
// FOLIO_SWAP_FLAG(waiters, FOLIO_PF_HEAD);
FOLIO_SWAP_FLAG(active, FOLIO_PF_HEAD);
FOLIO_SWAP_FLAG(workingset, FOLIO_PF_HEAD);
FOLIO_SWAP_FLAG(error, FOLIO_PF_NO_TAIL);
// FOLIO_SWAP_FLAG(slab, FOLIO_PF_NO_TAIL);
// FOLIO_SWAP_FLAG(owner_priv_1, FOLIO_PF_ANY);
	FOLIO_SWAP_FLAG(swapcache, FOLIO_PF_NO_TAIL);
	FOLIO_SWAP_FLAG(checked, FOLIO_PF_NO_COMPOUND);
// FOLIO_SWAP_FLAG(arch_1, );
// FOLIO_SWAP_FLAG(reserved, FOLIO_PF_NO_COMPOUND);
FOLIO_SWAP_FLAG(private, FOLIO_PF_ANY);
// FOLIO_SWAP_FLAG(private_2, FOLIO_PF_ANY);
FOLIO_SWAP_FLAG(mappedtodisk, FOLIO_PF_NO_TAIL);
// FOLIO_SWAP_FLAG(reclaim, FOLIO_PF_NO_TAIL);
	// FOLIO_SWAP_FLAG(isolated, FOLIO_PF_ANY);
	FOLIO_SWAP_FLAG(readahead, FOLIO_PF_NO_TAIL);
FOLIO_SWAP_FLAG(swapbacked, FOLIO_PF_NO_TAIL);
FOLIO_SWAP_FLAG(unevictable, FOLIO_PF_HEAD);
// FOLIO_SWAP_FLAG(mlocked, FOLIO_PF_NO_TAIL);
// FOLIO_SWAP_FLAG(uncached, FOLIO_PF_NO_COMPOUND);
// FOLIO_SWAP_FLAG(hwpoison, FOLIO_PF_ANY);
#ifdef CONFIG_PAGE_IDLE_FLAG
FOLIO_SWAP_FLAG(young, FOLIO_PF_HEAD);
FOLIO_SWAP_FLAG(idle, FOLIO_PF_HEAD);
#endif
// clang-format on

static struct workqueue_struct *exchange_wq;

int writeout(struct address_space *mapping, struct folio *folio);
bool buffer_migrate_lock_buffers(struct buffer_head *head,
				 enum migrate_mode mode);
int folio_expected_refs(struct address_space *mapping, struct folio *folio);

void migrate_folio_done(struct folio *src, enum migrate_reason reason);

void buffer_migrate_unlock_buffers(struct buffer_head *head)
{
	struct buffer_head *bh = head;
	do {
		unlock_buffer(bh);
		bh = bh->b_this_page;
	} while (bh != head);
}

// We might hold the buffer locks, if failed, we should unlock them by calling
// folio_exchange_fs_finish().
int folio_exchange_fs_prepare(struct folio *folio, enum migrate_mode mode,
			      bool *lock_acquired)
{
	// pr_info("%s: folio=%p mode=%d", __func__, folio, mode);
	struct address_space *mapping = folio_mapping(folio);
	// anon folio does not need this step
	if (!mapping)
		return MIGRATEPAGE_SUCCESS;
	DEFINE_COPY(migrate_fn, mapping->a_ops->migrate_folio);
	if (!migrate_fn) { // fallback_migrate_folio()
		if (folio_test_dirty(folio)) {
			switch (mode) {
			case MIGRATE_SYNC:
			case MIGRATE_SYNC_NO_COPY:
				break;
			default:
				return -EBUSY;
			}
			return writeout(mapping, folio);
		}
		if (!filemap_release_folio(folio, GFP_KERNEL))
			return mode == MIGRATE_SYNC ? -EAGAIN : -EBUSY;
		return MIGRATEPAGE_SUCCESS;
	} else if (migrate_fn == migrate_folio) { // shmem
		return MIGRATEPAGE_SUCCESS;
	} else if (migrate_fn == buffer_migrate_folio) { // ext4
		struct buffer_head *head = folio_buffers(folio);
		if (!head)
			return MIGRATEPAGE_SUCCESS;
		if (folio_expected_refs(mapping, folio) !=
		    folio_ref_count(folio)) {
			pr_err("%s: folio=%p ref_count=%d expected_refs=%d",
			       __func__, folio, folio_ref_count(folio),
			       folio_expected_refs(mapping, folio));
			return -EAGAIN;
		}
		if (!buffer_migrate_lock_buffers(head, mode))
			return -EAGAIN;
		*lock_acquired = true;
	} else if (migrate_fn == filemap_migrate_folio) { // f2fs
		return MIGRATEPAGE_SUCCESS;
	} else {
		BUG();
	}
	return MIGRATEPAGE_SUCCESS;
}

// This should be called even folio_exchange_mapping fails.
void folio_exchange_fs_finish(struct folio *folio, enum migrate_mode mode,
			      bool lock_acquired)
{
	struct address_space *mapping = folio_mapping(folio);
	if (!mapping)
		return;
	DEFINE_COPY(migrate_fn, mapping->a_ops->migrate_folio);
	if (!migrate_fn) {
	} else if (migrate_fn == migrate_folio) {
	} else if (migrate_fn == buffer_migrate_folio) {
		if (lock_acquired)
			buffer_migrate_unlock_buffers(folio_buffers(folio));
	} else if (migrate_fn == filemap_migrate_folio) {
	} else {
		BUG();
	}
}

void folio_exchange_mapping_anon_anon(struct folio *old, struct folio *new)
{
	// pr_info("%s: old=%p new=%p", __func__, old, new);
	VM_BUG_ON_FOLIO(folio_mapping(old), old);
	VM_BUG_ON_FOLIO(folio_mapping(new), new);

	swap(old->index, new->index);
	swap(old->mapping, new->mapping);
	folio_swap_swapbacked(old, new);

	// pr_info("%s: old=%p new=%p  mapping=%p<->%p index=0x%lx<->0x%lx  success",
	// 	__func__, old, new, new->mapping, old->mapping, new->index,
	// 	old->index);
}

void folio_exchange_mapping_update_stats(struct folio *old, struct folio *new)
{
	long nr = folio_nr_pages(old);
	VM_BUG_ON_FOLIO(nr != folio_nr_pages(new), anon);

	struct zone *old_zone = folio_zone(old);
	struct zone *new_zone = folio_zone(new);
	if (old_zone == new_zone)
		return;

	struct lruvec *old_lruvec =
		mem_cgroup_lruvec(folio_memcg(old), old_zone->zone_pgdat);
	struct lruvec *new_lruvec =
		mem_cgroup_lruvec(folio_memcg(new), new_zone->zone_pgdat);

	// The total page count remains the same
	// __mod_lruvec_state(old_lruvec, NR_FILE_PAGES, -nr);
	// __mod_lruvec_state(new_lruvec, NR_FILE_PAGES, nr);

	// The new folio is a shmem folio, which means we moved a shmem folio
	// from old lruvec to the new lruvec.
	if (folio_test_swapbacked(new) && !folio_test_swapcache(new)) {
		__mod_lruvec_state(old_lruvec, NR_SHMEM, -nr);
		__mod_lruvec_state(new_lruvec, NR_SHMEM, nr);
		if (folio_test_pmd_mappable(new)) {
			__mod_lruvec_state(old_lruvec, NR_SHMEM_THPS, -nr);
			__mod_lruvec_state(new_lruvec, NR_SHMEM_THPS, nr);
		}
	}
#ifdef CONFIG_SWAP
	if (folio_test_swapcache(new)) {
		__mod_lruvec_state(old_lruvec, NR_SWAPCACHE, -nr);
		__mod_lruvec_state(new_lruvec, NR_SWAPCACHE, nr);
	}
#endif
	if (folio_test_dirty(new) &&
	    mapping_can_writeback(folio_mapping(new))) {
		__mod_lruvec_state(old_lruvec, NR_FILE_DIRTY, -nr);
		__mod_zone_page_state(old_zone, NR_ZONE_WRITE_PENDING, -nr);
		__mod_lruvec_state(new_lruvec, NR_FILE_DIRTY, nr);
		__mod_zone_page_state(new_zone, NR_ZONE_WRITE_PENDING, nr);
	}
}

// We moved the swapcache/private handling out of this function
void folio_exchange_mapping_file_anon(struct folio *file, struct folio *anon)
{
	// pr_info("%s: file=%p anon=%p", __func__, file, anon);
	VM_BUG_ON_FOLIO(folio_mapping(anon), anon);
	struct address_space *mapping = folio_mapping(file);
	VM_BUG_ON_FOLIO(!mapping, file);
	VM_BUG_ON_FOLIO(mapping_unmovable(mapping), file);
	int expected_refs = folio_expected_refs(mapping, file);
	long nr = folio_nr_pages(file);
	VM_BUG_ON_FOLIO(nr != folio_nr_pages(anon), anon);

	XA_STATE(xas, &mapping->i_pages, folio_index(file));
	guard(irqsave)();
	scoped_guard(xas_lock, &xas)
	{
		// We should always success because of we are seralized by the
		// folio lock
		VM_BUG_ON_FOLIO(!folio_ref_freeze(file, expected_refs), file);
		folio_ref_add(anon, nr);
		swap(file->index, anon->index);
		swap(file->mapping, anon->mapping);
		folio_swap_swapbacked(file, anon);
		folio_swap_dirty(file, anon);

		// Notice that we have changed the swapbacked bit
		long entries = folio_test_swapbacked(anon) ? nr : 1;
		for (long i = 0; i < entries; ++i) {
			xas_store(&xas, anon);
			xas_next(&xas);
		}

		folio_ref_unfreeze(file, expected_refs - nr);
	}

	// pr_info("%s: old=%p new=%p  mapping=%p<->%p index=0x%lx<->0x%lx  success",
	// 	__func__, file, anon, anon->mapping, file->mapping, anon->index,
	// 	file->index);

	folio_exchange_mapping_update_stats(file, anon);
}

void folio_exchange_mapping_file_file(struct folio *old, struct folio *new)
{
	// pr_info("%s: old=%p new=%p", __func__, old, new);
	struct address_space *old_mapping = folio_mapping(old);
	VM_BUG_ON_FOLIO(!old_mapping, old);
	VM_BUG_ON_FOLIO(mapping_unmovable(old_mapping), old);
	int old_expected_refs = folio_expected_refs(old_mapping, old);
	struct address_space *new_mapping = folio_mapping(new);
	VM_BUG_ON_FOLIO(!new_mapping, new);
	VM_BUG_ON_FOLIO(mapping_unmovable(new_mapping), new);
	int new_expected_refs = folio_expected_refs(new_mapping, new);
	long nr = folio_nr_pages(old);
	VM_BUG_ON_FOLIO(nr != folio_nr_pages(new), new);

	XA_STATE(old_xas, &old_mapping->i_pages, folio_index(old));
	XA_STATE(new_xas, &new_mapping->i_pages, folio_index(new));
	guard(irqsave)();
	scoped_guard(xas_lock, &old_xas) scoped_guard(xas_lock, &new_xas)
	{
		VM_BUG_ON_FOLIO(!folio_ref_freeze(old, old_expected_refs), old);
		VM_BUG_ON_FOLIO(!folio_ref_freeze(new, old_expected_refs), new);
		// The ref count should remain the same
		swap(old->index, new->index);
		swap(old->mapping, new->mapping);
		folio_swap_swapbacked(old, new);
		folio_swap_dirty(old, new);

		// Notice that we have changed the swapbacked bit
		long entries = folio_test_swapbacked(new) ? nr : 1;
		for (long i = 0; i < entries; ++i) {
			xas_store(&old_xas, new);
			xas_next(&old_xas);
		}
		entries = folio_test_swapbacked(old) ? nr : 1;
		for (long i = 0; i < entries; ++i) {
			xas_store(&new_xas, old);
			xas_next(&new_xas);
		}

		folio_ref_unfreeze(new, new_expected_refs);
		folio_ref_unfreeze(old, old_expected_refs);
	}

	// pr_info("%s: old=%p new=%p  mapping=%p<->%p index=0x%lx<->0x%lx  success",
	// 	__func__, old, new, new->mapping, old->mapping, new->index,
	// 	old->index);

	folio_exchange_mapping_update_stats(old, new);
	folio_exchange_mapping_update_stats(new, old);
}

void folio_exchange_mapping(struct folio *old, struct folio *new)
{
	struct address_space *old_mapping = folio_mapping(old);
	struct address_space *new_mapping = folio_mapping(new);
	if (old_mapping) {
		if (new_mapping)
			return folio_exchange_mapping_file_file(old, new);
		else
			return folio_exchange_mapping_file_anon(old, new);
	} else {
		if (new_mapping)
			return folio_exchange_mapping_file_anon(new, old);
		else
			return folio_exchange_mapping_anon_anon(old, new);
	}
}

void folio_exchange_fs_private(struct folio *old, struct folio *new,
			       enum migrate_mode mode)
{
	// The mapping has already been exchanged, so new folio has the old mapping
	struct address_space *old_mapping = folio_mapping(old);
	struct address_space *new_mapping = folio_mapping(new);
	// But the private bit and private field have not been exchanged
	void *old_private = folio_detach_private(old);
	void *new_private = folio_detach_private(new);
	// pr_info("%s: old=%p new=%p  mapping=%p<->%p private=%p<->%p", __func__,
	// 	old, new, new_mapping, old_mapping, old_private, new_private);
	if (old_private) {
		VM_BUG_ON_FOLIO(!new_mapping, new);
		folio_attach_private(new, old_private);
		DEFINE_COPY(fn, new_mapping->a_ops->migrate_folio);
		if (!fn) {
		} else if (fn == buffer_migrate_folio) {
			struct buffer_head *head = old_private, *bh = head;
			do {
				folio_set_bh(head, new, bh_offset(head));
				bh = bh->b_this_page;
			} while (bh != head);
		} else if (fn == filemap_migrate_folio) {
		} else {
			pr_err("%s: mapping not supported %p\n", __func__,
			       new_mapping);
			dump_page(folio_page(new, 0), NULL);
			BUG();
		}
	}
	if (new_private) {
		VM_BUG_ON_FOLIO(!old_mapping, old);
		folio_attach_private(old, new_private);
		DEFINE_COPY(fn, old_mapping->a_ops->migrate_folio);
		if (!fn) {
		} else if (fn == buffer_migrate_folio) {
			struct buffer_head *head = new_private, *bh = head;
			do {
				folio_set_bh(head, old, bh_offset(head));
				bh = bh->b_this_page;
			} while (bh != head);
		} else if (fn == filemap_migrate_folio) {
		} else {
			pr_err("%s: mapping not supported %p\n", __func__,
			       old_mapping);
			dump_page(folio_page(old, 0), NULL);
			BUG();
		}
	}
}

enum parallel_mode {
	PARALLEL_SINGLE,
	PARALLEL_2THREAD,
	PARALLEL_4THREAD,
	PARALLEL_8THREAD,
	// PARALLEL_DMA,
};
enum {
	NUM_WORKERS_MAX = 8,
};
struct exchange_data_parallel_work {
	struct work_struct work;
	// struct completion done;
	void *src, *dst;
	size_t size;
};
void exchange_data_parallel_work_fn(struct work_struct *work)
{
	struct exchange_data_parallel_work *w =
		container_of(work, struct exchange_data_parallel_work, work);
	unsigned long *src = w->src, *dst = w->dst;
	for (size_t i = 0, size = w->size / sizeof(unsigned long); i < size;
	     ++i) {
		swap(src[i], dst[i]);
	}
	// completion_done(&w->done);
}
void exchange_data_parallel_work_init(struct exchange_data_parallel_work *work,
				      void *src, void *dst, size_t size)
{
	INIT_WORK(&work->work, exchange_data_parallel_work_fn);
	// init_completion(&work->done);
	work->src = src;
	work->dst = dst;
	work->size = size;
}
void exchange_data_parallel(struct page *old, struct page *new, int nworkers)
{
	CLASS(kmap, vold)(old);
	CLASS(kmap, vnew)(new);
	struct exchange_data_parallel_work works[NUM_WORKERS_MAX] = {};
	for (size_t i = 0, chunk_size = PAGE_SIZE / nworkers; i < nworkers;
	     ++i) {
		exchange_data_parallel_work_init(&works[i],
						 vold + i * chunk_size,
						 vnew + i * chunk_size,
						 chunk_size);
		queue_work(exchange_wq, &works[i].work);
	}
	flush_workqueue(exchange_wq);
	// __flush_workqueue(system_highpri_wq);
	// for (size_t i = 0; i < PAGE_SIZE / NUM_WORKERS; i++) {
	// 	wait_for_completion(&works[i].done);
	// }
}

void exchange_data_single(struct page *old, struct page *new)
{
	CLASS(kmap, vold)(old);
	CLASS(kmap, vnew)(new);
	// TODO: choose a faster exchanging algorithm
	for (int i = 0; i < PAGE_SIZE / sizeof(unsigned long); i++) {
		swap(((unsigned long *)vold)[i], ((unsigned long *)vnew)[i]);
	}
}

void folio_exchange_data(struct folio *old, struct folio *new,
			 enum migrate_mode mode, enum parallel_mode par)
{
	VM_BUG_ON_FOLIO(folio_nr_pages(old) != folio_nr_pages(new), new);
	for (long i = 0, nr = folio_nr_pages(old); i < nr; ++i) {
		switch (par) {
		case PARALLEL_SINGLE:
			exchange_data_single(folio_page(old, i),
					     folio_page(new, i));
			break;
		case PARALLEL_2THREAD:
			exchange_data_parallel(folio_page(old, i),
					       folio_page(new, i), 2);
			break;
		case PARALLEL_4THREAD:
			exchange_data_parallel(folio_page(old, i),
					       folio_page(new, i), 4);
			break;
		case PARALLEL_8THREAD:
			exchange_data_parallel(folio_page(old, i),
					       folio_page(new, i), 8);
			break;
		default:
			BUG();
		}
		cond_resched();
	}
}

void folio_exchange_flags(struct folio *old, struct folio *new,
			  enum migrate_mode mode)
{
	// if (folio_test_waiters(old)) {
	// 	dump_page(folio_page(old, 0), "found waiters on folio");
	// }
	// if (folio_test_waiters(new)) {
	// 	dump_page(folio_page(new, 0), "found waiters on folio");
	// }
	folio_swap_error(old, new);
	folio_swap_referenced(old, new);
	folio_swap_uptodate(old, new);
	folio_swap_active(old, new);
	folio_swap_unevictable(old, new);
	folio_swap_workingset(old, new);
	folio_swap_checked(old, new);
	folio_swap_mappedtodisk(old, new);
	// already done in folio_exchange_mapping
	// folio_swap_dirty(old, new);

#ifdef CONFIG_PAGE_IDLE_FLAG
	folio_swap_young(old, new);
	folio_swap_idle(old, new);
#endif

	/*
	 * For memory tiering mode, when migrate between slow and fast
	 * memory node, reset cpupid, because that is used to record
	 * page access time in slow memory node.
	 */
	folio_xchg_last_cpupid(old, -1);
	folio_xchg_last_cpupid(new, -1);

	// will not supported for now: ksm is aleady excluded in folio_exchange_mapping
	// folio_exchange_ksm(old, new);

	// already done in folio_exchange_mapping
	// folio_swap_swapcache(old, new);
	// already done in folio_exchange_fs_private
	// folio_swap_private(old, new);

	folio_swap_writeback(old, new);
	// if (folio_test_writeback(old)) {
	// 	folio_end_writeback(old);
	// }
	// if (folio_test_writeback(new)) {
	// 	folio_end_writeback(new);
	// }
	folio_swap_readahead(old, new);

	// will not support for now
	// folio_exchange_owner(old, new);
	BUILD_BUG_ON(IS_ENABLED(CONFIG_PAGE_OWNER));

	// Make sure we wake up those blocked on the migration entry
	folio_set_waiters(old);
	folio_set_waiters(new);

	// mem_cgroup_exchange(old, new);
	swap(old->memcg_data, new->memcg_data);
	if (folio_test_large(old) && folio_test_large_rmappable(old))
		folio_undo_large_rmappable(old);
	if (folio_test_large(new) && folio_test_large_rmappable(new))
		folio_undo_large_rmappable(new);
}

struct folio *folio_exchange_lock(struct folio *folio, enum migrate_mode mode)
{
	// VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);

	if (!folio_trylock(folio)) {
		if (mode == MIGRATE_ASYNC)
			return ERR_PTR(-EAGAIN);
		if (current->flags & PF_MEMALLOC)
			return ERR_PTR(-EPERM);
		if (mode == MIGRATE_SYNC_LIGHT && !folio_test_uptodate(folio))
			return ERR_PTR(-EAGAIN);
		folio_lock(folio);
	}
	// pr_info("%s: folio locked folio=%p", __func__, folio);
	return folio;
}
DEFINE_CLASS(folio_exchange_lock, struct folio *, ({
		     if (IS_ERR_OR_NULL(_T))
			     return;
		     folio_unlock(_T);
	     }),
	     folio_exchange_lock(folio, mode), struct folio *folio,
	     enum migrate_mode mode);

bool folio_exchange_supported(struct folio *folio, enum migrate_mode mode)
{
	if (folio_ref_count(folio) == 1) {
		// /* Folio was freed from under us. So we are done. */
		// folio_clear_active(folio);
		// folio_clear_unevictable(folio);
		// /* free_pages_prepare() will clear PG_isolated. */
		// list_del(&folio->lru);
		// // migrate_folio_done(folio, MR_NUMA_MISPLACED);
		pr_warn("%s: folio=%p ref_count=1\n", __func__, folio);
		return false;
	}
	if (folio_test_writeback(folio)) {
		switch (mode) {
		case MIGRATE_SYNC:
		case MIGRATE_SYNC_NO_COPY:
			break;
		default:
			return false;
		}
		pr_info("%s: folio=%p waiting for writeback", __func__, folio);
		folio_wait_writeback(folio);
		pr_info("%s: folio=%p waiting for writeback done", __func__,
			folio);
	}
	/*
	 * Corner case handling:
	 * 1. ...
	 * 2. An orphaned page (see truncate_cleanup_page) might have
	 * fs-private metadata. The page can be picked up due to memory
	 * offlining.  Everywhere else except page reclaim, the page is
	 * invisible to the vm, so the page can not be migrated.  So try to
	 * free the metadata, so the page can be freed.
	 */
	if (!folio->mapping && folio_test_private(folio)) {
		try_to_free_buffers(folio);
		pr_info("%s: folio=%p orphaned page", __func__, folio);
		return false;
	}
	if (folio_test_mlocked(folio)) {
		pr_info("%s: folio=%p mlocked", __func__, folio);
		return false;
	}

	struct address_space *mapping = folio_mapping(folio);
	if (mapping && mapping_unmovable(mapping))
		return false;
	int expected_refs = folio_expected_refs(mapping, folio);
	int ref_count = folio_ref_count(folio);
	int mapcount = folio_mapcount(folio);
	if (expected_refs + mapcount != ref_count) {
		pr_info("%s: folio=%p wrong reference count ref_count=%d expected=%d mapcount=%d",
			__func__, folio, ref_count, expected_refs, mapcount);
		return false;
	}
	return true;
}
EXPORT_SYMBOL(folio_exchange_supported);

struct folio_isolated {
	struct folio *folio;
};
void folio_exchange_putback(struct folio_isolated *isolated)
{
	struct folio *folio = isolated->folio;
	if (!folio)
		return;
	node_stat_mod_folio(folio, NR_ISOLATED_ANON + folio_is_file_lru(folio),
			    -folio_nr_pages(folio));
	folio_add_lru(folio);
	// We use this because folio_add_lru() (lru, the new owner of this folio)
	// increased a reference count, we need another folio_put()
	// folio_putback_lru(folio);
}
struct folio_isolated folio_exchange_isolate(struct folio *folio,
					     enum migrate_mode mode)
{
	struct folio_isolated r = {};
	if (!folio_isolate_lru(folio)) {
		pr_err("%s: folio=%p failed to isolate", __func__, folio);
		return r;
	}
	r.folio = folio;
	node_stat_mod_folio(folio, NR_ISOLATED_ANON + folio_is_file_lru(folio),
			    folio_nr_pages(folio));
	/*
	 * Isolating the folio has taken another reference, so the
	 * caller's reference can be safely dropped without the folio
	 * disappearing underneath us during migration.
	 */
	folio_put(folio);
	return r;
}
DEFINE_CLASS(folio_exchange_isolate, struct folio_isolated,
	     folio_exchange_putback(&_T), folio_exchange_isolate(folio, mode),
	     struct folio *folio, enum migrate_mode mode)

struct folio_unmapped {
	struct folio *src;
	struct folio *dst;
	struct anon_vma *anon_vma;
};
void folio_exchange_remap(struct folio_unmapped *u)
{
	if (u->src)
		remove_migration_ptes(u->src, u->dst ?: u->src, false);
	if (u->anon_vma)
		put_anon_vma(u->anon_vma);
}
struct folio_unmapped folio_exchange_unmap(struct folio *folio,
					   enum migrate_mode mode)
{
	struct folio_unmapped u = {};

	/*
	 * By try_to_migrate(), src->mapcount goes down to 0 here. In this case,
	 * we cannot notice that anon_vma is freed while we migrate a page.
	 * This get_anon_vma() delays freeing anon_vma pointer until the end
	 * of migration. File cache pages are no problem because of page_lock()
	 * File Caches may use write_page() or lock_page() in migration, then,
	 * just care Anon page here.
	 *
	 * Only folio_get_anon_vma() understands the subtleties of
	 * getting a hold on an anon_vma from outside one of its mms.
	 * But if we cannot get anon_vma, then we won't need it anyway,
	 * because that implies that the anon page is no longer mapped
	 * (and cannot be remapped so long as we hold the page lock).
	 */
	if (folio_test_anon(folio) && !folio_test_ksm(folio))
		u.anon_vma = folio_get_anon_vma(folio);

	/*
	 * Corner case handling:
	 * 1. When a new swap-cache page is read into, it is added to the LRU
	 * and treated as swapcache but it has no rmap yet.
	 * Calling try_to_migrate() against a folio->mapping==NULL folio will
	 * trigger a BUG.  So handle it here.
	 * 2. ...
	 */
	if (folio->mapping && folio_mapped(folio)) {
		/* Establish migration ptes */
		VM_BUG_ON_FOLIO(folio_test_anon(folio) &&
					!folio_test_ksm(folio) && !u.anon_vma,
				folio);
		VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
		try_to_migrate(folio,
			       mode == MIGRATE_ASYNC ? TTU_BATCH_FLUSH : 0);
		u.src = folio;
		// pr_info("%s: migration entry installed folio=%p", __func__,
		// 	folio);
	}

	return u;
}
DEFINE_CLASS(folio_exchange_unmap, struct folio_unmapped,
	     folio_exchange_remap(&_T), folio_exchange_unmap(folio, mode),
	     struct folio *folio, enum migrate_mode mode);

int folio_exchange_move(struct folio *old, struct folio *new,
			enum migrate_mode mode, enum parallel_mode par)
{
	// pr_info("%s: old=%p new=%p mode=%d", __func__, old, new, mode);
	VM_BUG_ON_FOLIO(!folio_test_locked(old), old);
	VM_BUG_ON_FOLIO(!folio_test_locked(new), new);
	if (mode != MIGRATE_SYNC && mode != MIGRATE_ASYNC)
		return -EINVAL;
	bool old_buffer_locked = false, new_buffer_locked = false;

	int rc = 0;
	rc = folio_exchange_fs_prepare(old, mode, &old_buffer_locked);
	if (rc != MIGRATEPAGE_SUCCESS)
		goto out_old;
	rc = folio_exchange_fs_prepare(new, mode, &new_buffer_locked);
	if (rc != MIGRATEPAGE_SUCCESS)
		goto out;

	folio_exchange_mapping(old, new);
	folio_exchange_fs_private(old, new, mode);
	// Notice: here the lock on the fs private data should be swapped along
	// with the exchange of fs private data
	swap(old_buffer_locked, new_buffer_locked);
	folio_exchange_data(old, new, mode, par);
	folio_exchange_flags(old, new, mode);

out:
	folio_exchange_fs_finish(new, mode, new_buffer_locked);
out_old:
	folio_exchange_fs_finish(old, mode, old_buffer_locked);
	return rc;
}

int folio_exchange_parallel(struct folio *old, struct folio *new,
			    enum migrate_mode mode, enum parallel_mode par)
{
	bool old_lru = !__folio_test_movable(old);
	bool new_lru = !__folio_test_movable(new);
	VM_BUG_ON_FOLIO(!old_lru, old);
	VM_BUG_ON_FOLIO(!new_lru, new);

	// Reorganize the code logic:
	// 1. isolate folio
	// 2. lock folio
	// 3. check for support
	// 4. unmap folio

	CLASS(folio_exchange_isolate, old_isolated)(old, mode);
	if (IS_ERR_OR_NULL(old_isolated.folio)) {
		count_vm_event(FOLIO_EXCHANGE_FAILED_ISOLATE);
		return -ENOENT;
	}
	CLASS(folio_exchange_isolate, new_isolated)(new, mode);
	if (IS_ERR_OR_NULL(old_isolated.folio)) {
		count_vm_event(FOLIO_EXCHANGE_FAILED_ISOLATE);
		return -ENOENT;
	}

	CLASS(folio_exchange_lock, old_locked)(old, mode);
	if (IS_ERR(old_locked)) {
		count_vm_event(FOLIO_EXCHANGE_FAILED_LOCK);
		return PTR_ERR(old_locked);
	}
	CLASS(folio_exchange_lock, new_locked)(new, mode);
	if (IS_ERR(new_locked)) {
		count_vm_event(FOLIO_EXCHANGE_FAILED_LOCK);
		return PTR_ERR(old_locked);
	}
	if (!folio_exchange_supported(old, mode)) {
		count_vm_event(FOLIO_EXCHANGE_FAILED_SUPPORT);
		return PTR_ERR(old_locked);
	}

	if (!folio_exchange_supported(new, mode)) {
		count_vm_event(FOLIO_EXCHANGE_FAILED_SUPPORT);
		return PTR_ERR(old_locked);
	}

	CLASS(folio_exchange_unmap, old_unmapped)(old, mode);
	CLASS(folio_exchange_unmap, new_unmapped)(new, mode);

	// TODO: improve TLB flushing via batching
	try_to_unmap_flush();

	int err = folio_exchange_move(old, new, mode, par);
	if (err) {
		count_vm_event(FOLIO_EXCHANGE_FAILED_MOVE);
	}
	old_unmapped.dst = new;
	new_unmapped.dst = old;

	return err;
}
EXPORT_SYMBOL(folio_exchange_parallel);

int folio_exchange(struct folio *old, struct folio *new, enum migrate_mode mode)
{
	count_vm_event(FOLIO_EXCHANGE);
	int err = folio_exchange_parallel(old, new, mode, PARALLEL_SINGLE);
	count_vm_event(err ? FOLIO_EXCHANGE_FAILED : FOLIO_EXCHANGE_SUCCESS);
	return err;
}
EXPORT_SYMBOL(folio_exchange);

// ============================================================================
// ======== Below is the syscall implementation of exchange folios ============
// ============================================================================

struct mm_struct *find_mm_struct(pid_t pid, nodemask_t *mem_nodes);

// Resolves the given address to a struct folio. The reference count is not
// changed after calling this function.
struct folio *resolve_folio(struct mm_struct *mm, const void __user *p)
{
	guard(mmap_read_lock)(mm);

	unsigned long addr = (unsigned long)untagged_addr_remote(mm, p);

	struct vm_area_struct *vma = vma_lookup(mm, addr);
	if (!vma || !vma_migratable(vma))
		return ERR_PTR(-EFAULT);

	/* FOLL_DUMP to ignore special (like zero) pages */
	struct page *page = follow_page(vma, addr, FOLL_GET | FOLL_DUMP);
	if (IS_ERR(page))
		return (struct folio *)page;

	if (!page)
		return ERR_PTR(-ENOENT);

	struct folio *folio = page_folio(page);
	if (folio_is_zone_device(folio) || folio_test_hugetlb(folio)) {
		folio_put(folio);
		return ERR_PTR(-EINVAL);
	}
	// folio_put(folio);
	return folio;
}
void folio_dump_short(struct folio *folio, char const *caller)
{
	extern void dump_mapping(const struct address_space *mapping);
	struct address_space *mapping = folio_mapping(folio);
	pr_warn("%s: folio=%p refcount=%d mapcount=%d mapping=%p index=%#lx pfn=%#lx %s\n",
		caller, folio, folio_ref_count(folio), folio_mapcount(folio),
		mapping, folio_index(folio), folio_pfn(folio),
		folio_test_anon(folio) ? "anon" : "");
	if (mapping)
		dump_mapping(mapping);
}
EXPORT_SYMBOL(folio_dump_short);
void resolve_folio_cleanup(struct folio **foliop)
{
	struct folio *folio = *foliop;
	if (IS_ERR_OR_NULL(folio))
		return;
	// folio_dump_short(folio, __func__);
	folio_put(folio);
}
EXPORT_SYMBOL(resolve_folio_cleanup);

void folio_isolate_lru_cleanup(struct folio **foliop)
{
	struct folio *folio = *foliop;
	if (!folio || IS_ERR(folio))
		return;
	node_stat_mod_folio(folio, NR_ISOLATED_ANON + folio_is_file_lru(folio),
			    folio_nr_pages(folio));
}

static int kernel_exchange_folios(struct mm_struct *mm, unsigned long nr_pages,
				  const void __user *__user *src,
				  const void __user *__user *dst,
				  int __user *err)
{
	// Newly allocated folios might still be waiting in the fbatch, make
	// sure they are properly inserted to the LRU before the exchange.
	// These folios will ususally have an extra reference count and have the
	// PG_lru bit cleared.
	lru_add_drain_all();
	enum migrate_mode mode = MIGRATE_SYNC;
	DEFINE_XARRAY_ALLOC(xa);
	for (unsigned long i = 0; i < nr_pages; i++) {
		void const __user *src_addr, __user *dst_addr;
		get_user(src_addr, src + i);
		get_user(dst_addr, dst + i);

		// pr_info("%s: ===== EXCHANGE i=%ld FOLIO ====", __func__, i);
		// pr_info("%s: vaddr=%p<->%p ", __func__, src_addr, dst_addr);
		struct folio *src __cleanup(resolve_folio_cleanup) =
			resolve_folio(mm, src_addr);
		if (IS_ERR(src)) {
			xa_store(&xa, i, src, GFP_KERNEL);
			pr_err("%s: src_addr=%p resolve_folio()=%pe failed ",
			       __func__, src_addr, src);
			continue;
		}
		// pr_info("%s: ===== SRC FOLIO BEFORE EXCHANGE ====", __func__);
		// dump_page(folio_page(src, 0), NULL);
		// pr_info("%s: lruvec=%p", __func__, folio_lruvec(src));

		struct folio *dst __cleanup(resolve_folio_cleanup) =
			resolve_folio(mm, dst_addr);
		if (IS_ERR(dst)) {
			xa_store(&xa, i, dst, GFP_KERNEL);
			pr_err("%s: dst_addr=%p resolve_folio()=%pe failed ",
			       __func__, dst_addr, (void *)dst);
			continue;
		}
		// pr_info("%s: ===== DST FOLIO BEFORE EXCHANGE ====", __func__);
		// dump_page(folio_page(dst, 0), NULL);
		// pr_info("%s: lruvec=%p", __func__, folio_lruvec(src));

		// pr_info("%s: ===== EXCHANGE EXECUTING ====", __func__);
		for (long j = 0, err = -EAGAIN; j < 3 && err == -EAGAIN; ++j) {
			err = folio_exchange(src, dst, mode);
			xa_store(&xa, i, ERR_PTR(err), GFP_KERNEL);
			pr_err("%s: exchange_folio(src=%p, dst=%p, mode=%d)=%pe trial=%ld",
			       __func__, src, dst, mode, ERR_PTR(err), j);
		}
		// pr_info("%s: ===== EXCHANGE RETURNED ====", __func__);

		// pr_info("%s: ===== SRC FOLIO AFTER EXCHANGE ====", __func__);
		// dump_page(folio_page(src, 0), NULL);
		// pr_info("%s: lruvec=%p", __func__, folio_lruvec(src));
		// pr_info("%s: ===== DST FOLIO AFTER EXCHANGE ====", __func__);
		// dump_page(folio_page(dst, 0), NULL);
		// pr_info("%s: lruvec=%p", __func__, folio_lruvec(dst));
		// pr_info("%s: ===== EXCHANGE i=%ld FOLIO ====", __func__, i);
	}

	// lru_add_drain_all();
	return 0;
}

static int __init exchange_init(void)
{
	exchange_wq = alloc_workqueue("exchange_wq", WQ_HIGHPRI, 0);
	return 0;
}
late_initcall(exchange_init);

/*
 * Move a list of pages in the address space of the currently executing
 * process.
 */
SYSCALL_DEFINE5(exchange_folios, pid_t, pid, unsigned long, nr_pages,
		const void __user *__user *, src, const void __user *__user *,
		dst, int __user *, err)
{
	pr_info("%s: testing incomplete implementation pid=%d nr_pages=%lu",
		__func__, pid, nr_pages);
	nodemask_t task_nodes;
	struct mm_struct *mm = find_mm_struct(pid, &task_nodes);
	if (IS_ERR(mm))
		return PTR_ERR(mm);
	int ret = kernel_exchange_folios(mm, nr_pages, src, dst, err);
	mmput(mm);
	return ret;
}

int migrate_folio_to_node(struct folio *folio, int node, enum migrate_mode mode)
{
	LIST_HEAD(pagelist);
	struct migration_target_control mtc = {
		.nid = node,
		.gfp_mask = GFP_HIGHUSER_MOVABLE | __GFP_THISNODE,
	};

	if (!folio_isolate_lru(folio)) {
		return -EBUSY;
	}
	folio_put(folio);

	list_add_tail(&folio->lru, &pagelist);
	node_stat_mod_folio(folio, NR_ISOLATED_ANON + folio_is_file_lru(folio),
			    folio_nr_pages(folio));
	int err = migrate_pages(&pagelist, alloc_migration_target, NULL,
				(unsigned long)&mtc, mode, MR_SYSCALL, NULL);
	if (err > 0) {
		putback_movable_pages(&pagelist);
	}
	return err;
}
EXPORT_SYMBOL(migrate_folio_to_node);

int folio_bimigrate(struct folio *old, struct folio *new,
		    enum migrate_mode mode)
{
	int old_nid = folio_nid(old), new_nid = folio_nid(new);
	int err = migrate_folio_to_node(old, new_nid, mode);
	if (err)
		return err;
	err = migrate_folio_to_node(new, old_nid, mode);
	return err;
}
EXPORT_SYMBOL(folio_bimigrate);
