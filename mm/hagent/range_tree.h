#ifndef HAGENT_PLACEMENT_RANGE_TREE_H
#define HAGENT_PLACEMENT_RANGE_TREE_H

#include <linux/mm.h>
#include <linux/maple_tree.h>
#include <linux/sort.h>

#include "module.h"
#include "error.h"
enum {
	RTREE_SPLIT_N = 2,
	RTREE_GRANULARITY = 2ul << 20,
	RTREE_SIGNIFICANCE_FACTOR = 2,
	// TODO: make this value configurable and adaptive
	RTREE_SPLIT_THRESH = 500,
	RTREE_EXCH_THRESH = RTREE_GRANULARITY,
	RTREE_MAX_SIZE = 2048,
	RTREE_COOL_AGE = 3,
};

struct mrange {
	ulong start, end;
	// We record the access count, but we rank them based on the frequency
	ulong age, nr_access;
	ulong in_fmem, in_smem;
};

noinline static inline struct mrange *mrange_new(ulong start, ulong end,
						 ulong age, ulong nr_access)
{
	struct mrange *r = kmalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return ERR_PTR(-ENOMEM);
	*r = (struct mrange){
		.start = start,
		.end = end,
		.age = age,
		.nr_access = nr_access,
	};
	return r;
}

noinline static inline void mrange_drop(struct mrange *r)
{
	kfree(r);
}

static inline ulong mrange_freq(struct mrange const *r)
{
	return r->nr_access * RTREE_GRANULARITY / (r->end - r->start + 1);
}

static inline void mrange_show(struct mrange const *r)
{
	static char const *units[] = {
		"B", "KiB", "MiB", "GiB", "TiB", //"PiB", "EiB",
	};
	ulong len = r->end - r->start, ui = ARRAY_SIZE(units), unit;
	while (len < (unit = 1ul << (--ui * 10))) {
	}

	pr_info("%s: managed range [%#lx, %#lx) len=%lu.%03lu%s freq=%lu age=%lu nr_access=%lu in_fmem=%lu in_smem=%lu\n",
		__func__, r->start, r->end, len / unit,
		(len % unit) * 1000 / unit, units[ui], mrange_freq(r), r->age,
		r->nr_access, r->in_fmem, r->in_smem);
}

// In theory the maximum range we need to cover is 128TiB under 48bit virtual
// address. But in practice we only need to cover [start_brk, mmap_base).
// An example is: [0x555558200000, 0x7f34ab400000) ~43TiB. We assume 64TiB, so
// total 2^25 segments. So for a perfect binary tree, the possible number of
// tree elements is 2^25 * 2. This is quite a large number, so we should use
// something else as the underlying storage than a simple array.
// CREDIT: https://codeforces.com/blog/entry/18051
struct range_tree {
	// Assume a full segment with sparse storage to simplify implementation
	// We index into the segment tree using the index off the start address
	// with a granularity of SEG_TREE_GRANULARITY
	ulong len, age, min_range;
	// Use the maple_tree as a sparse array
	struct maple_tree tree;
};

noinline static inline int rt_init(struct range_tree *self, ulong start,
				   ulong end)
{
	BUILD_BUG_ON(RTREE_GRANULARITY < PAGE_SIZE);
	start = round_down(start, RTREE_GRANULARITY);
	end = round_up(end, RTREE_GRANULARITY);
	self->len = 1;
	self->age = 0;
	self->min_range = end - start;
	mt_init(&self->tree);
	UNWRAP(mtree_insert_range(&self->tree, start, end - 1,
				  UNWRAP(mrange_new(start, end, self->age, 0)),
				  GFP_KERNEL));
	return 0;
}

noinline static inline void rt_drop(struct range_tree *self)
{
	struct mrange *r;
	ulong start = 0;
	mt_for_each(&self->tree, r, start, ULONG_MAX) {
		mrange_drop(r);
	}
}

noinline static inline void rt_show(struct range_tree *self)
{
	pr_info("%s: managed range count=%lu age=%lu\n", __func__, self->len,
		self->age);
	struct mrange *r;
	ulong start = 0;
	mt_for_each(&self->tree, r, start, ULONG_MAX) {
		mrange_show(r);
		// pr_info("%s: managed range [%#lx, %#lx) len=%luM age=%lu nr_access=%lu in_fmem=%lu in_smem=%lu\n",
		// 	__func__, r->start, r->end, (r->end - r->start) >> 20,
		// 	r->age, r->nr_access, r->in_fmem, r->in_smem);
	}
}

noinline static inline int rt_count(struct range_tree *self, ulong addr)
{
	ulong start = addr;
	struct mrange *r = mt_find(&self->tree, &start, ULONG_MAX);
	if (!r || r->start > addr) {
		pr_err_ratelimited("%s: address %#lx is not in any range\n",
				   __func__, addr);
		return -ECNOTCARE;
	}
	r->nr_access += 1;
	return 0;
}

// Split a managed range if its access count is sigificanitly higher than the
// neighboring ranges.
noinline static inline int rt_split(struct range_tree *self)
{
	ulong start = 0;
	for (struct mrange *curr = mt_find(&self->tree, &start, ULONG_MAX);
	     curr; curr = mt_find_after(&self->tree, &start, ULONG_MAX)) {
		curr->nr_access /= 2;
	}
	start = 0;
	for (struct mrange *
		     curr = mt_find(&self->tree, &start, ULONG_MAX),
		    *next = mt_find_after(&self->tree, &start, ULONG_MAX),
		    *prev = NULL;
	     curr && self->len < RTREE_MAX_SIZE; prev = curr, curr = next,
		    next = mt_find_after(&self->tree, &start, ULONG_MAX)) {
		if (curr->end - curr->start < RTREE_SPLIT_N * RTREE_GRANULARITY)
			continue;
		if (curr->nr_access < RTREE_SPLIT_THRESH)
			continue;
		// We should allow:
		// 1. the root node which has no neighbors
		// 2. curr->nr_access larger than at least one of its neighbors
		int score = !prev && !next;
		if (prev &&
		    prev->nr_access + RTREE_SPLIT_THRESH *
					      RTREE_SIGNIFICANCE_FACTOR <
			    curr->nr_access)
			score += 1;
		if (next &&
		    next->nr_access + RTREE_SPLIT_THRESH *
					      RTREE_SIGNIFICANCE_FACTOR <
			    curr->nr_access)
			score += 1;
		if (score < 1)
			continue;

		pr_info("%s: splitting range [%#lx, %#lx)\n", __func__,
			curr->start, curr->end);
		!prev ?: mrange_show(prev);
		mrange_show(curr);
		!next ?: mrange_show(prev);
		// rt_show(self);
		// Split the range
		BUG_ON(mtree_erase(&self->tree, curr->start) != curr);
		// ulong mid = round_down(curr->start / 2 + (curr->end + 1) / 2,
		// 		       RTREE_GRANULARITY);
		self->age += 1;
		ulong edges[RTREE_SPLIT_N + 1] = {
			[0] = curr->start, [RTREE_SPLIT_N] = curr->end
		};
		for (ulong i = 1,
			   step = (curr->end - curr->start) / RTREE_SPLIT_N;
		     i < RTREE_SPLIT_N; ++i) {
			edges[i] = round_down(curr->start + i * step,
					      RTREE_GRANULARITY);
			BUG_ON(edges[i] <= edges[i - 1]);
		}
		struct mrange *ins = NULL;
		ulong min_range = ULONG_MAX;
		for (ulong i = 0, nr_access = curr->nr_access / RTREE_SPLIT_N;
		     i < RTREE_SPLIT_N; ++i) {
			pr_info("%s: inserting range [%#lx, %#lx)\n", __func__,
				edges[i], edges[i + 1]);
			min_range = min(min_range, edges[i + 1] - edges[i]);
			UNWRAP(mtree_insert_range(
				&self->tree, edges[i], edges[i + 1] - 1,
				ins = UNWRAP(mrange_new(edges[i], edges[i + 1],
							self->age, nr_access)),
				GFP_KERNEL));
			mrange_show(ins);
		}
		mrange_drop(curr);
		self->min_range = min(self->min_range, min_range);
		// Prevent stuck at splitting the same range
		curr = ins;
		self->len += RTREE_SPLIT_N - 1;
	}
	// Newly created ranges can be observed by checking self->len
	return 0;
}

static inline bool rt_should_cool(struct range_tree const *self,
				  struct mrange const *r)
{
	return r->age + RTREE_COOL_AGE > self->age;
}

static inline int rt_rank_cmp(const void *a, const void *b, const void *pri)
{
	struct range_tree const *self = pri;
	struct mrange const *ra = *(struct mrange **)a,
			    *rb = *(struct mrange **)b;
	// Sort by the access frequency in descending order
	// return rt_should_cool(self, ra) - rt_should_cool(self, rb) ?:
	// 	       (mrange_freq(ra) - mrange_freq(rb) ?:
	// 			-((long)ra->in_fmem + ra->in_smem -
	// 			  rb->in_fmem - rb->in_smem));
	return rt_should_cool(self, ra) - rt_should_cool(self, rb) ?:
		       ra->nr_access - rb->nr_access		   ?:
		       // -((long)ra->end - ra->start + rb->end - rb->start) ?:
		       -((long)ra->in_fmem + ra->in_smem - rb->in_fmem -
			 rb->in_smem);
}

// See: for_each_vma_range
#define vma_for_each(__mm, __start, __end, __vma)      \
	for (VMA_ITERATOR((__vmi), (__mm), (__start)); \
	     ((__vma) = vma_find(&(__vmi), (__end))) != NULL;)
// Make sure the page reference is released
#define folio_for_each(__vma, __start, __end, __folio)                       \
	for (ulong __addr = max((__start), (__vma)->vm_start),               \
		   __e = min((__end), (__vma)->vm_end), __step;              \
	     __addr < __e; __addr += __step)                                 \
		for ((__folio) = ({                                          \
			     __step = PAGE_SIZE;                             \
			     struct page *__page = follow_page(              \
				     (__vma), __addr, FOLL_GET | FOLL_DUMP); \
			     IS_ERR_OR_NULL(__page) ? NULL :                 \
						      page_folio(__page);    \
		     });                                                     \
		     (__folio);                                              \
		     (__folio) = ({                                          \
			     __step = folio_nr_pages((__folio)) * PAGE_SIZE; \
			     folio_put((__folio));                           \
			     NULL;                                           \
		     }))

// TODO: calculate exchange candidates by walking every leaf's intersected vma,
// populating the in_fmem/in_smem fields and sort them based on access count
// r is assumed to be an output array to store self->len elements
// Output ranges are sorted by the access count in ascending order.
// If they are equal, then we sort by the number of folios in decending order.
// i.e. the range that is least accessed and has the most folios will be first.
noinline static inline int rt_rank(struct range_tree *self,
				   struct mm_struct *locked_mm,
				   struct mrange **out, ulong *len)
{
	ulong start = 0, i = 0;
	struct mrange *r;
	mt_for_each(&self->tree, r, start, ULONG_MAX) {
		out[i++] = r;
		struct vm_area_struct *vma;
		vma_for_each(locked_mm, r->start, r->end, vma) {
			struct folio *folio;
			folio_for_each(vma, r->start, r->end, folio) {
				// Only rank private anon folios for now
				int nid = folio_test_anon(folio) ?
						  folio_nid(folio) :
						  NUMA_NO_NODE;
				r->in_fmem += nid == FMEM_NID;
				r->in_smem += nid == SMEM_NID;
			}
		}
	}

	// ~~Comparison priority: rt_should_cool >> mrange_freq >> -(in_fmem + in_smem)~~
	// Comparison priority: rt_should_cool >> nr_access >> -(in_fmem + in_smem)
	// Sort order: ascending
	sort_r(out, self->len, sizeof(*out), rt_rank_cmp, NULL, self);

	for (ulong i = 0; i < self->len; ++i) {
		struct mrange *r = out[self->len - 1 - i];
		if (rt_should_cool(self, r))
			continue;
		*len = self->len - i;
		break;
	}

	return 0;
}

// isolate the folios that are on the given node using the provided function to
// the given list
noinline static inline int
rt_isolate(struct mm_struct *locked_mm, struct mrange *r, int nid,
	   int (*isolate)(struct list_head *list, struct folio *folio),
	   struct list_head *list)
{
	int success = 0;
	struct vm_area_struct *vma;
	vma_for_each(locked_mm, r->start, r->end, vma) {
		struct folio *folio;
		folio_for_each(vma, r->start, r->end, folio) {
			if (folio_nid(folio) != nid) {
				continue;
			}
			success += isolate(list, folio) == 0;
		}
	}
	return success;
}
#undef folio_for_each
#undef vma_for_each

#endif // HAGENT_PLACEMENT_RANGE_TREE_H
