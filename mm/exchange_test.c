// SPDX-License-Identifier: GPL-2.0
/*
 * Folio exchange testcases - linux/mm/exchange_test.c
 *
 * Copyright (C) 2021-2024 Junliang Hu
 *
 * Author: Junliang Hu <jlhu@cse.cuhk.edu.hk>
 *
 */

#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mempolicy.h>
#include <linux/cleanup.h>
#include <linux/sched/clock.h>
#include <linux/umh.h>

#include <kunit/test.h>

#include <internal.h>

// #include <linux/xxhash.h>
// #define xxhash_ulong(value)                               \
// 	({                                                \
// 		ulong __tmp = (value);                    \
// 		xxh64(&__tmp, sizeof(__tmp), 0x6A09E667); \
// 	})

extern int folio_exchange(struct folio *old, struct folio *new,
			  enum migrate_mode mode);
extern bool folio_exchange_supported(struct folio *folio,
				     enum migrate_mode mode);

extern int folio_bimigrate(struct folio *old, struct folio *new,
			   enum migrate_mode mode);
extern int migrate_folio_to_node(struct folio *folio, int node,
				 enum migrate_mode mode);
extern void resolve_folio_cleanup(struct folio **foliop);

static void follow_page_cleanup(struct page **pagep)
{
	struct page *page = *pagep;
	if (!page || !IS_ERR(page))
		return;
	put_page(page);
}

#define DRAM_NODE first_node(node_states[N_MEMORY])
#define PMEM_NODE next_node(DRAM_NODE, node_states[N_MEMORY])

enum {
	PMEM_FILE_REGION,
	DRAM_FILE_REGION,
	PMEM_ANON_REGION,
	DRAM_ANON_REGION,
	EXPECTED_REGIONS = 4,

	REGION_SIZE = 1ul << 30,
};
struct usermode_helper {
	char dram_file[64], pmem_file[64];
	int dram_node, pmem_node;
	size_t size;
	// If the task is NULL, the helper is not valid
	struct task_struct *task;
};
static void usermode_helper_drop(struct usermode_helper *h)
{
	pr_info("%s", __func__);
	if (IS_ERR_OR_NULL(h) || IS_ERR_OR_NULL(h->task))
		return;
	pr_info("%s: task=%p pid=%d tgid=%d", __func__, h->task, h->task->pid,
		h->task->tgid);
	send_sig(SIGKILL, h->task, 0);
	// We called get_task_struct() in usermodehelper_save_task_struct()
	put_task_struct(h->task);
}
static int usermodehelper_save_task_struct(struct subprocess_info *info,
					   struct cred *new)
{
	// Make sure it does not go away during testing
	get_task_struct(current);
	*(struct task_struct **)info->data = current;
	return 0;
}
static struct usermode_helper usermode_helper_new(void)
{
	pr_info("%s", __func__);
	struct usermode_helper h = {
		.dram_node = DRAM_NODE,
		.pmem_node = PMEM_NODE,
		.size = REGION_SIZE,
	};
	char size[32] = {}, dram_node[32] = {}, pmem_node[32] = {};
	snprintf(size, sizeof(size), "%lu", h.size);
	snprintf(dram_node, sizeof(dram_node), "%d", h.dram_node);
	snprintf(pmem_node, sizeof(pmem_node), "%d", h.pmem_node);
	snprintf(h.dram_file, sizeof(h.dram_file), "/dram-%llu", local_clock());
	snprintf(h.pmem_file, sizeof(h.pmem_file), "/pmem-%llu", local_clock());
	// The newly created mmap region should be located at lower address
	// clang-format off
	char *argv[] = {
		"/data/mmap-helper", // Helper binary
		"anon", size, dram_node, // anonymous DRAM region
		"anon", size, pmem_node, // anonymous PMEM region
		h.dram_file, size, dram_node, // file PMEM region
		h.pmem_file, size, pmem_node, // file PMEM region
		NULL,
	};
	// clang-format on
	static char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
				NULL };

	// We need a custom init function to save the task_struct of the newly
	// launched helper, see: call_usermodehelper()
	struct subprocess_info *info = call_usermodehelper_setup(
		argv[0], argv, envp, GFP_KERNEL,
		usermodehelper_save_task_struct, NULL, &h.task);
	BUG_ON(IS_ERR_OR_NULL(info));
	long err = call_usermodehelper_exec(info, UMH_WAIT_EXEC);
	BUG_ON(IS_ERR_OR_NULL(h.task));
	pr_info("%s: call_usermodehelper_exec()=%pe task=%p pid=%d tgid=%d",
		__func__, (void *)err, h.task, h.task->pid, h.task->tgid);

	return h;
}
// Return the regions found in the vmas array, the size should be not less than
// EXPECTED_REGIONS, which is the number of regions we created.
// Also return the number of regions found via return value.
// The caller should hold the mmap read lock, because they need the returned vma
// to be valid.
static int usermode_helper_find_regions(struct usermode_helper *h,
					struct mm_struct *mm,
					struct vm_area_struct **vmas)
{
	mmap_assert_locked(mm);
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, 0);
	int found = 0;
	for_each_vma(vmi, vma) {
		// We created the regions with the given size and
		// MPOL_PREFERRED policy
		if (vma->vm_end - vma->vm_start != h->size ||
		    MPOL_PREFERRED != vma->vm_policy->mode)
			continue;
		vmas[found++] = vma;
		pr_info("%s: found vma=%p flags=%pGv start=0x%lx end=0x%lx size=0x%lx mpol=%u nodes=%*pbl ops=%pS",
			__func__, vma, &vma->vm_flags, vma->vm_start,
			vma->vm_end, vma->vm_end - vma->vm_start,
			vma->vm_policy->mode,
			nodemask_pr_args(&vma->vm_policy->nodes), vma->vm_ops);
	}

	return found;
};

DEFINE_CLASS(usermode_helper, struct usermode_helper, usermode_helper_drop(&_T),
	     usermode_helper_new(), void);

static void usermode_helper_start(struct kunit *test)
{
	CLASS(usermode_helper, h)();
	// This should always be true, because otherwise we would have bugged in
	// usermode_helper_new()
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, h.task);
	pr_info("%s: task=%p state=0x%x flags=0x%x mm=%p", __func__, h.task,
		h.task->__state, h.task->flags, h.task->mm);

	// call_usermodehelper() creates a user thread using a workqueue worker
	// as the parent, make sure the task is indeed a child
	KUNIT_EXPECT_NE(test, h.task->flags & PF_WQ_WORKER, PF_WQ_WORKER);

	// We should also not being a kernel thread
	KUNIT_EXPECT_NE(test, h.task->flags & PF_KTHREAD, PF_KTHREAD);
}

// clang-format off
DEFINE_LOCK_GUARD_1(mmap_read_lock, struct mm_struct, mmap_read_lock(_T->lock), mmap_read_unlock(_T->lock));
DEFINE_CLASS(mm_struct, struct mm_struct *, mmput(_T), get_task_mm(task), struct task_struct *task);
DEFINE_CLASS(folio_get, struct folio *, folio_put(_T), ({ folio_get(folio); folio; }), struct folio *folio);
DEFINE_CLASS(kmap, void *, kunmap(_T), kmap(page), struct page *page);
// clang-format on

static void usermode_helper_check_regions(struct kunit *test)
{
	CLASS(usermode_helper, h)();
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, h.task);
	pr_info("%s: task=%p state=0x%x flags=0x%x mm=%p", __func__, h.task,
		h.task->__state, h.task->flags, h.task->mm);

	CLASS(mm_struct, mm)(h.task);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, mm);

	struct vm_area_struct *vmas[EXPECTED_REGIONS];
	int found = 0;
	// The creation of file backed region needs IO, so this may take a while.
	for (int trial = 0; trial < 10; trial++,
		 schedule_timeout_uninterruptible(msecs_to_jiffies(1000))) {
		guard(mmap_read_lock)(mm);

		found = usermode_helper_find_regions(&h, mm, vmas);
		if (found == EXPECTED_REGIONS) {
			// On success, we should hold the lock so that vmas is
			// valid until we are done with them.
			// We have to manually handle the un/locking here.
			mmap_read_lock(mm);
			break;
		}
	}
	KUNIT_EXPECT_EQ(test, found, EXPECTED_REGIONS);

	{
		struct vm_area_struct *vma = vmas[DRAM_ANON_REGION];
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, vma);
		KUNIT_EXPECT_NULL(test, vma->vm_file);
		KUNIT_EXPECT_TRUE(test, vma_is_anonymous(vma));
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, vma->anon_vma);
	}

	{
		struct vm_area_struct *vma = vmas[PMEM_ANON_REGION];
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, vma);
		KUNIT_EXPECT_NULL(test, vma->vm_file);
		KUNIT_EXPECT_TRUE(test, vma_is_anonymous(vma));
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, vma->anon_vma);
	}

	{
		struct vm_area_struct *vma = vmas[DRAM_FILE_REGION];
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, vma);
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, vma->vm_file);
		KUNIT_EXPECT_NULL(test, vma->anon_vma);
		KUNIT_EXPECT_FALSE(test, vma_is_anonymous(vma));
		KUNIT_EXPECT_FALSE(test, vma_is_anon_shmem(vma));
	}

	{
		struct vm_area_struct *vma = vmas[PMEM_FILE_REGION];
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, vma);
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, vma->vm_file);
		KUNIT_EXPECT_NULL(test, vma->anon_vma);
		KUNIT_EXPECT_FALSE(test, vma_is_anonymous(vma));
		KUNIT_EXPECT_FALSE(test, vma_is_anon_shmem(vma));
	}

	if (found == EXPECTED_REGIONS)
		mmap_read_unlock(mm);
}

static void bench_follow_page(struct kunit *test)
{
	CLASS(usermode_helper, h)();
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, h.task);
	CLASS(mm_struct, mm)(h.task);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, mm);
	schedule_timeout_uninterruptible(msecs_to_jiffies(6000));
	guard(mmap_read_lock)(mm);
	struct vm_area_struct *vmas[EXPECTED_REGIONS];
	int found = usermode_helper_find_regions(&h, mm, vmas);
	KUNIT_EXPECT_EQ(test, found, EXPECTED_REGIONS);

	struct vm_area_struct *vma = vmas[DRAM_ANON_REGION];
	KUNIT_EXPECT_TRUE(test, vma_is_anonymous(vma));

	unsigned long begin = local_clock();
	for (unsigned long addr = vma->vm_start; addr < vma->vm_end;
	     addr += PAGE_SIZE) {
		struct page *page __cleanup(follow_page_cleanup) =
			follow_page(vma, addr, FOLL_GET | FOLL_DUMP);
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, page);
	}
	unsigned long elapsed = local_clock() - begin,
		      npages = (vma->vm_end - vma->vm_start) / PAGE_SIZE;
	pr_info("%s: follow_page() speed test: npages=%lu elapsed=%lu avgtime=%lu",
		__func__, npages, elapsed, elapsed / npages);
	// struct folio *folio = page_folio(
	// 	follow_page(vma, vma->vm_start, FOLL_GET | FOLL_DUMP));
}

static void exchange_test_folio_exchange(struct kunit *test, int src, int dst)
{
	CLASS(usermode_helper, h)();
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, h.task);
	CLASS(mm_struct, mm)(h.task);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, mm);
	schedule_timeout_uninterruptible(msecs_to_jiffies(6000));
	guard(mmap_read_lock)(mm);
	struct vm_area_struct *vmas[EXPECTED_REGIONS];
	int found = usermode_helper_find_regions(&h, mm, vmas);
	KUNIT_EXPECT_EQ(test, found, EXPECTED_REGIONS);

	struct vm_area_struct *src_vma = vmas[src];
	struct vm_area_struct *dst_vma = vmas[dst];

	struct folio *src_folio __cleanup(resolve_folio_cleanup) = page_folio(
		follow_page(src_vma, src_vma->vm_start, FOLL_GET | FOLL_DUMP));
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, src_folio);
	struct folio *dst_folio __cleanup(resolve_folio_cleanup) = page_folio(
		follow_page(dst_vma, dst_vma->vm_start, FOLL_GET | FOLL_DUMP));
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, dst_folio);

	CLASS(kmap, src_addr)(folio_page(src_folio, 0));
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, src_addr);
	memset(src_addr, 'a', PAGE_SIZE);

	CLASS(kmap, dst_addr)(folio_page(dst_folio, 0));
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, dst_addr);
	memset(dst_addr, 'b', PAGE_SIZE);

	// Try the exchange
	int ret = folio_exchange(src_folio, dst_folio, MIGRATE_SYNC);
	KUNIT_EXPECT_EQ(test, ret, 0);

	void *buf = kvzalloc(PAGE_SIZE, GFP_KERNEL);
	memset(buf, 'a', PAGE_SIZE);
	KUNIT_EXPECT_EQ(test, memcmp(dst_addr, buf, PAGE_SIZE), 0);

	memset(buf, 'b', PAGE_SIZE);
	KUNIT_EXPECT_EQ(test, memcmp(src_addr, buf, PAGE_SIZE), 0);

	kvfree(buf);
}

static void exchange_anon_anon(struct kunit *test)
{
	exchange_test_folio_exchange(test, DRAM_ANON_REGION, PMEM_ANON_REGION);
}
static void exchange_file_file(struct kunit *test)
{
	exchange_test_folio_exchange(test, DRAM_FILE_REGION, PMEM_FILE_REGION);
}
static void exchange_anon_file(struct kunit *test)
{
	exchange_test_folio_exchange(test, DRAM_ANON_REGION, PMEM_FILE_REGION);
}
static void exchange_file_anon(struct kunit *test)
{
	exchange_test_folio_exchange(test, DRAM_FILE_REGION, PMEM_ANON_REGION);
}

enum parallel_mode {
	PARALLEL_SINGLE,
	PARALLEL_2THREAD,
	PARALLEL_4THREAD,
	PARALLEL_8THREAD,
	// PARALLEL_DMA,
};
extern int folio_exchange_parallel(struct folio *old, struct folio *new,
				   enum migrate_mode mode,
				   enum parallel_mode par);
static void bench_folio_exchange_parallel(struct kunit *test,
					  enum parallel_mode par)
{
	CLASS(usermode_helper, h)();
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, h.task);
	CLASS(mm_struct, mm)(h.task);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, mm);
	schedule_timeout_uninterruptible(msecs_to_jiffies(6000));
	guard(mmap_read_lock)(mm);
	struct vm_area_struct *vmas[EXPECTED_REGIONS];
	int found = usermode_helper_find_regions(&h, mm, vmas);
	KUNIT_EXPECT_EQ(test, found, EXPECTED_REGIONS);

	struct vm_area_struct *src_vma = vmas[DRAM_ANON_REGION];
	struct vm_area_struct *dst_vma = vmas[PMEM_ANON_REGION];
	KUNIT_EXPECT_EQ(test, src_vma->vm_end - src_vma->vm_start, REGION_SIZE);
	KUNIT_EXPECT_EQ(test, src_vma->vm_end - src_vma->vm_start, REGION_SIZE);

	lru_add_drain_all();

	unsigned long begin = local_clock();
	for (unsigned long offset = 0; offset < REGION_SIZE;
	     offset += PAGE_SIZE) {
		struct folio *src_folio __cleanup(resolve_folio_cleanup) =
			page_folio(follow_page(src_vma,
					       src_vma->vm_start + offset,
					       FOLL_GET | FOLL_DUMP));
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, src_folio);
		struct folio *dst_folio __cleanup(resolve_folio_cleanup) =
			page_folio(follow_page(dst_vma,
					       dst_vma->vm_start + offset,
					       FOLL_GET | FOLL_DUMP));
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, dst_folio);

		int ret = folio_exchange_parallel(src_folio, dst_folio,
						  MIGRATE_SYNC, par);
		KUNIT_EXPECT_EQ(test, ret, 0);
	}
	unsigned long elapsed = local_clock() - begin;
	unsigned long npages = REGION_SIZE / PAGE_SIZE;
	pr_info("%s: folio_exchange() speed test: npages=%lu elapsed=%lu avgtime=%lu",
		__func__, npages, elapsed, elapsed / npages);
}
static void bench_folio_exchange_single(struct kunit *test)
{
	bench_folio_exchange_parallel(test, PARALLEL_SINGLE);
}
static void bench_folio_exchange_2thread(struct kunit *test)
{
	bench_folio_exchange_parallel(test, PARALLEL_2THREAD);
}
static void bench_folio_exchange_4thread(struct kunit *test)
{
	bench_folio_exchange_parallel(test, PARALLEL_4THREAD);
}
static void bench_folio_exchange_8thread(struct kunit *test)
{
	bench_folio_exchange_parallel(test, PARALLEL_8THREAD);
}

static void exchange_test_folio_migrate(struct kunit *test, int src, int dst)
{
	CLASS(usermode_helper, h)();
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, h.task);
	CLASS(mm_struct, mm)(h.task);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, mm);
	schedule_timeout_uninterruptible(msecs_to_jiffies(6000));
	guard(mmap_read_lock)(mm);
	struct vm_area_struct *vmas[EXPECTED_REGIONS];
	int found = usermode_helper_find_regions(&h, mm, vmas);
	KUNIT_EXPECT_EQ(test, found, EXPECTED_REGIONS);

	struct vm_area_struct *src_vma = vmas[src];
	struct vm_area_struct *dst_vma = vmas[dst];

	struct folio *src_folio __cleanup(resolve_folio_cleanup) = page_folio(
		follow_page(src_vma, src_vma->vm_start, FOLL_GET | FOLL_DUMP));
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, src_folio);
	struct folio *dst_folio __cleanup(resolve_folio_cleanup) = page_folio(
		follow_page(dst_vma, dst_vma->vm_start, FOLL_GET | FOLL_DUMP));
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, dst_folio);

	CLASS(kmap, src_addr)(folio_page(src_folio, 0));
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, src_addr);
	memset(src_addr, 'a', PAGE_SIZE);

	CLASS(kmap, dst_addr)(folio_page(dst_folio, 0));
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, dst_addr);
	memset(dst_addr, 'b', PAGE_SIZE);

	// Try the migrate
	int src_nid = folio_nid(src_folio), dst_nid = folio_nid(dst_folio);
	{
		// dump_page(folio_page(src_folio, 0), NULL);
		KUNIT_EXPECT_TRUE(test, folio_exchange_supported(src_folio,
								 MIGRATE_SYNC));
		int ret =
			migrate_folio_to_node(src_folio, dst_nid, MIGRATE_SYNC);
		KUNIT_EXPECT_EQ(test, ret, 0);
	}
	{
		// dump_page(folio_page(dst_folio, 0), NULL);
		KUNIT_EXPECT_TRUE(test, folio_exchange_supported(dst_folio,
								 MIGRATE_SYNC));
		int ret =
			migrate_folio_to_node(dst_folio, src_nid, MIGRATE_SYNC);
		KUNIT_EXPECT_EQ(test, ret, 0);
	}
}
static void bimigrate_anon_anon(struct kunit *test)
{
	exchange_test_folio_migrate(test, DRAM_ANON_REGION, PMEM_ANON_REGION);
}
static void bimigrate_file_file(struct kunit *test)
{
	exchange_test_folio_migrate(test, DRAM_FILE_REGION, PMEM_FILE_REGION);
}
static void bimigrate_anon_file(struct kunit *test)
{
	exchange_test_folio_migrate(test, DRAM_ANON_REGION, PMEM_FILE_REGION);
}
static void bimigrate_file_anon(struct kunit *test)
{
	exchange_test_folio_migrate(test, DRAM_FILE_REGION, PMEM_ANON_REGION);
}

static void bench_folio_bimigrate(struct kunit *test)
{
	CLASS(usermode_helper, h)();
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, h.task);
	CLASS(mm_struct, mm)(h.task);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, mm);
	schedule_timeout_uninterruptible(msecs_to_jiffies(6000));
	guard(mmap_read_lock)(mm);
	struct vm_area_struct *vmas[EXPECTED_REGIONS];
	int found = usermode_helper_find_regions(&h, mm, vmas);
	KUNIT_EXPECT_EQ(test, found, EXPECTED_REGIONS);

	struct vm_area_struct *src_vma = vmas[DRAM_ANON_REGION];
	struct vm_area_struct *dst_vma = vmas[PMEM_ANON_REGION];
	KUNIT_EXPECT_EQ(test, src_vma->vm_end - src_vma->vm_start, REGION_SIZE);
	KUNIT_EXPECT_EQ(test, src_vma->vm_end - src_vma->vm_start, REGION_SIZE);

	lru_add_drain_all();

	unsigned long begin = local_clock();
	for (unsigned long offset = 0; offset < REGION_SIZE;
	     offset += PAGE_SIZE) {
		struct folio *src_folio __cleanup(resolve_folio_cleanup) =
			page_folio(follow_page(src_vma,
					       src_vma->vm_start + offset,
					       FOLL_GET | FOLL_DUMP));
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, src_folio);
		struct folio *dst_folio __cleanup(resolve_folio_cleanup) =
			page_folio(follow_page(dst_vma,
					       dst_vma->vm_start + offset,
					       FOLL_GET | FOLL_DUMP));
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, dst_folio);

		int ret = folio_bimigrate(src_folio, dst_folio, MIGRATE_SYNC);
		KUNIT_EXPECT_EQ(test, ret, 0);
	}
	unsigned long elapsed = local_clock() - begin;
	unsigned long npages = REGION_SIZE / PAGE_SIZE;
	pr_info("%s: folio_bimigrate() speed test: npages=%lu elapsed=%lu avgtime=%lu",
		__func__, npages, elapsed, elapsed / npages);
}

static struct kunit_case exchange_test_cases[] = {
	KUNIT_CASE(usermode_helper_start),
	KUNIT_CASE_SLOW(usermode_helper_check_regions),
	KUNIT_CASE_SLOW(exchange_anon_anon),
	KUNIT_CASE_SLOW(exchange_file_file),
	KUNIT_CASE_SLOW(exchange_file_anon),
	KUNIT_CASE_SLOW(exchange_anon_file),
	KUNIT_CASE_SLOW(bimigrate_anon_anon),
	KUNIT_CASE_SLOW(bimigrate_file_file),
	KUNIT_CASE_SLOW(bimigrate_file_anon),
	KUNIT_CASE_SLOW(bimigrate_anon_file),
	{},
};

static struct kunit_case exchange_bench_cases[] = {
	KUNIT_CASE_SLOW(bench_follow_page),
	KUNIT_CASE_SLOW(bench_folio_bimigrate),
	KUNIT_CASE_SLOW(bench_folio_exchange_single),
	KUNIT_CASE_SLOW(bench_folio_exchange_2thread),
	KUNIT_CASE_SLOW(bench_folio_exchange_4thread),
	KUNIT_CASE_SLOW(bench_folio_exchange_8thread),
	{},
};

static struct kunit_suite exchange_test_suite = {
	.name = "exchange",
	.test_cases = exchange_test_cases,
};
// We have to build this as a module, otherwise we cannot access the
// usermodehelper at the default kunit run time, which is at system startup and
// is well before we have the root filesystem ready.
kunit_test_suite(exchange_test_suite);

static struct kunit_suite exchange_bench_suite = {
	.name = "exchange_bench",
	.test_cases = exchange_bench_cases,
};
kunit_test_suite(exchange_bench_suite);

// static int __init init(void) { return 0; }
// static void __exit exit(void) { }
// module_init(init);
// module_exit(exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Junliang Hu <jlhu@cse.cuhk.edu.hk>");
