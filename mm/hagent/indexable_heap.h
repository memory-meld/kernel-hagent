// SPDX-License-Identifier: GPL-2.0
/*
 * Indexable heap: a heap of KV pairs that can be queried via a key.
 *
 * Copyright (C) 2021-2024 Junliang Hu
 *
 * Author: Junliang Hu <jlhu@cse.cuhk.edu.hk>
 *
 */
#ifndef INDEXABLE_HEAP_H
#define INDEXABLE_HEAP_H
#include <linux/types.h>

#include "vector.h"
#include "cwisstable.h"

#define CHECK_INSERTED(ins, success, ...)                              \
	({                                                             \
		HashMapU64U64_Insert __insert = (ins);                 \
		HashMapU64U64_Entry *__entry =                         \
			HashMapU64U64_Iter_get(&__insert.iter);        \
		CWISS_CHECK(__insert.inserted == (success) && __entry, \
			    __VA_ARGS__);                              \
		__entry;                                               \
	})

// clang-format off
struct kv { u64 k, v; };
static inline u64 *kv_key(struct kv *kv)	{ return &kv->k; }
static inline u64 *kv_value(struct kv *kv)	{ return &kv->v; }
static inline u64 const *kv_ckey(struct kv const *kv)	{ return &kv->k; }
static inline u64 const *kv_cvalue(struct kv const *kv)	{ return &kv->v; }
// clang-format on

// auto elems_ht =
// 	indexable_heap<unsigned long, unsigned long,
// 		       std::unordered_map<unsigned long, std::size_t> >();
// template <typename Key, typename Val,
// 	  typename Map = std::unordered_map<Key, size_t> >
// class indexable_heap {
// 	using key_type = Key;
// 	using value_type = Val;
// 	using index_type = std::size_t;

// 	Map indices{};
// 	std::vector<std::pair<key_type, value_type> > values{};

// 	static inline index_type parent(index_type i)
// 	{
// 		return (i - 1) / 2;
// 	}
// 	static inline index_type left(index_type i)
// 	{
// 		return 2 * i + 1;
// 	}
// 	static inline index_type right(index_type i)
// 	{
// 		return 2 * i + 2;
// 	}
// 	inline void bubble_up(index_type i)
// 	{
// 		while (i > 0 && values[i].second < values[parent(i)].second) {
// 			std::swap(indices[values[i].first],
// 				  indices[values[parent(i)].first]);
// 			std::swap(values[i], values[parent(i)]);
// 			i = parent(i);
// 		}
// 	}
// 	inline void bubble_down(index_type i)
// 	{
// 		while (true) {
// 			auto l = left(i);
// 			auto r = right(i);
// 			auto smallest = i;
// 			if (l < values.size() && values[l] < values[smallest]) {
// 				smallest = l;
// 			}
// 			if (r < values.size() && values[r] < values[smallest]) {
// 				smallest = r;
// 			}
// 			if (smallest == i) {
// 				break;
// 			}
// 			std::swap(indices[values[i].first],
// 				  indices[values[smallest].first]);
// 			std::swap(values[i], values[smallest]);
// 			i = smallest;
// 		}
// 	}
// 	inline void make_heap()
// 	{
// 		for (auto i = 0; i < values.size(); i++) {
// 			indices[values[i].first] = i;
// 		}
// 		for (auto i = values.size() / 2; i > 0; i--) {
// 			bubble_down(i - 1);
// 		}
// 	}

//     public:
// 	indexable_heap() = default;
// 	indexable_heap(
// 		std::vector<std::pair<key_type, value_type> > const &values)
// 		: values(values)
// 	{
// 		make_heap();
// 	}
// 	indexable_heap(indexable_heap const &other) = default;
// 	indexable_heap(indexable_heap &&other) = default;
// 	indexable_heap &operator=(indexable_heap const &other) = default;
// 	indexable_heap &operator=(indexable_heap &&other) = default;

// 	inline void push_heap(key_type key, value_type value)
// 	{
// 		values.push_back(std::make_pair(key, value));
// 		indices[key] = values.size() - 1;
// 		bubble_up(values.size() - 1);
// 	}
// 	inline void pop_heap()
// 	{
// 		auto value = values[0];
// 		std::swap(indices[values[0].first],
// 			  indices[values.back().first]);
// 		std::swap(values[0], values.back());
// 		values.pop_back();
// 		bubble_down(0);
// 		indices.erase(value.first);
// 		// return value;
// 	}
// 	inline Map::value_type peek_top()
// 	{
// 		return values[0];
// 	}
// 	inline void update_heap(key_type key, value_type delta)
// 	{
// 		auto i = indices[key];
// 		values[i].second += delta;
// 		bubble_up(i);
// 		bubble_down(i);
// 	}
// };

// HashMapU64U64: A hash map from u64 to u64
CWISS_DECLARE_FLAT_HASHMAP(HashMapU64U64, u64, u64);
noinline static inline HashMapU64U64_Entry *
HashMapU64U64_update(HashMapU64U64 *self, HashMapU64U64_Entry const *e)
{
	HashMapU64U64_Entry *r = CHECK_INSERTED(
		HashMapU64U64_insert(self, e), false,
		"cannot update a non-existant entry key=%llx val=%llu", e->key,
		e->val);
	r->val = e->val;
	return r;
}

noinline static inline void HashMapU64U64_swap(HashMapU64U64 *self,
					       u64 const *keyx, u64 const *keyy)
{
	HashMapU64U64_Iter iterx = HashMapU64U64_find(self, keyx);
	HashMapU64U64_Entry *x = HashMapU64U64_Iter_get(&iterx);
	CWISS_CHECK(
		x != NULL,
		"getting a non-existant entry via keyx from the map keyx=0x%llx keyy=0x%llx",
		*keyx, *keyy);

	HashMapU64U64_Iter itery = HashMapU64U64_find(self, keyy);
	HashMapU64U64_Entry *y = HashMapU64U64_Iter_get(&itery);
	CWISS_CHECK(
		y != NULL,
		"getting a non-existant entry via keyy from the map keyx=0x%llx keyy=0x%llx",
		*keyx, *keyy);

	swap(x->val, y->val);
}
noinline static inline HashMapU64U64_Entry *
HashMapU64U64_get_or_insert(HashMapU64U64 *map, u64 key, u64 val)
{
	HashMapU64U64_Iter iter = HashMapU64U64_find(map, &key);
	HashMapU64U64_Entry *e = HashMapU64U64_Iter_get(&iter);
	if (e != NULL) {
		return e;
	}
	HashMapU64U64_Entry ne = { key, val };
	return CHECK_INSERTED(HashMapU64U64_insert(map, &ne), true,
			      "insertion failed key=%llx val=%llu", key, val);
}

// A heap with key-value pair elements which can be find by a key.
// Defaults to min-heap. Pass greater as the comparator to get a max-heap.
struct indexable_heap {
	char const *name;
	struct vector values;
	HashMapU64U64 indices;
	bool (*less)(u64, u64);
};
// clang-format off
static inline bool less(u64 a, u64 b)		{ return a < b; }
static inline bool greater(u64 a, u64 b)	{ return a > b; }
static inline size_t heap_parent(size_t i)	{ return (i - 1) / 2; }
static inline size_t heap_left(size_t i)	{ return 2 * i + 1; }
static inline size_t heap_right(size_t i)	{ return 2 * i + 2; }
// clang-format on

#define CHECK_KV(h, key, value)                                                        \
	({                                                                             \
		u64 __key = (key), __value = (value);                                  \
		HashMapU64U64_Iter __it =                                              \
			HashMapU64U64_find(&(h)->indices, &__key);                     \
		HashMapU64U64_Entry *__e = HashMapU64U64_Iter_get(&__it);              \
		CWISS_CHECK(                                                           \
			__e != NULL,                                                   \
			"getting a non-existant entry from the map key=%llx val=%llu", \
			__key, __value);                                               \
		CWISS_CHECK(                                                           \
			__e->val == __value,                                           \
			"value mismatch key=%llx expected val=%llu got=%llu",          \
			__key, __value, __e->val);                                     \
	})

noinline static inline void bubble_up(struct indexable_heap *h, size_t i)
{
	while (i > 0 &&
	       h->less(*kv_cvalue(vector_at(&h->values, i)),
		       *kv_cvalue(vector_at(&h->values, heap_parent(i))))) {
		// {
		// 	size_t p = heap_parent(i);
		// 	CHECK_KV(h, *kv_ckey(vector_at(&h->values, i)), i);
		// 	CHECK_KV(h, *kv_ckey(vector_at(&h->values, p)), p);
		// }
		HashMapU64U64_swap(
			&h->indices, kv_ckey(vector_at(&h->values, i)),
			kv_ckey(vector_at(&h->values, heap_parent(i))));

		// {
		// 	size_t p = heap_parent(i);
		// 	CHECK_KV(h, *kv_ckey(vector_at(&h->values, i)), p);
		// 	CHECK_KV(h, *kv_ckey(vector_at(&h->values, p)), i);
		// }
		vector_swap(&h->values, i, heap_parent(i));
		i = heap_parent(i);
	}
}
noinline static inline void bubble_down(struct indexable_heap *h, size_t i)
{
	while (true) {
		size_t l = heap_left(i);
		size_t r = heap_right(i);
		size_t smallest = i;
		if (l < vector_size(&h->values) &&
		    h->less(*kv_value(vector_at(&h->values, l)),
			    *kv_value(vector_at(&h->values, smallest)))) {
			smallest = l;
		}
		if (r < vector_size(&h->values) &&
		    h->less(*kv_value(vector_at(&h->values, r)),
			    *kv_value(vector_at(&h->values, smallest)))) {
			smallest = r;
		}
		if (smallest == i) {
			break;
		}

		// {
		// 	CHECK_KV(h, *kv_ckey(vector_at(&h->values, i)), i);
		// 	CHECK_KV(h, *kv_ckey(vector_at(&h->values, smallest)),
		// 		 smallest);
		// }
		HashMapU64U64_swap(&h->indices,
				   kv_ckey(vector_at(&h->values, i)),
				   kv_ckey(vector_at(&h->values, smallest)));
		// {
		// 	CHECK_KV(h, *kv_ckey(vector_at(&h->values, i)),
		// 		 smallest);
		// 	CHECK_KV(h, *kv_ckey(vector_at(&h->values, smallest)),
		// 		 i);
		// }
		vector_swap(&h->values, i, smallest);
		i = smallest;
	}
}

static inline int indexable_heap_init(struct indexable_heap *self,
				      bool min_heap, char const *name)
{
	if (vector_new(&self->values, sizeof(struct kv), 128)) {
		return -ENOMEM;
	}
	self->name = name;
	self->indices = HashMapU64U64_new(32);
	self->less = min_heap ? less : greater;
	return 0;
}

static inline size_t indexable_heap_size(struct indexable_heap *self)
{
	return vector_size(&self->values);
}

static inline bool indexable_heap_empty(struct indexable_heap *self)
{
	return indexable_heap_size(self) == 0;
}

static inline void indexable_heap_dump(struct indexable_heap *self, size_t n)
{
	n = min(n, vector_size(&self->values));
	pr_info("indexable_heap name=%s size=%zu dumping first n=%zu: \n",
		self->name, vector_size(&self->values), n);
	for (size_t i = 0; i < n; i++) {
		struct kv *kv = vector_at(&self->values, i);
		pr_cont(" (0x%llx, %llu)", kv->k, kv->v);
	}
}

static inline void indexable_heap_drop(struct indexable_heap *self)
{
	indexable_heap_dump(self, min(indexable_heap_size(self), 10000));
	HashMapU64U64_destroy(&self->indices);
	vector_drop(&self->values);
}

static inline void indexable_heap_make(struct indexable_heap *h)
{
	for (size_t i = 0; i < vector_size(&h->values); i++) {
		struct kv *kv = vector_at(&h->values, i);
		HashMapU64U64_Entry e = { kv->k, i };
		HashMapU64U64_insert(&h->indices, &e);
	}
	for (size_t i = vector_size(&h->values) / 2; i > 0; i--) {
		bubble_down(h, i - 1);
	}
}

noinline static inline void indexable_heap_push(struct indexable_heap *self,
						u64 key, u64 value)
{
	struct kv kv = { key, value };
	vector_push_back(&self->values, &kv);
	HashMapU64U64_Entry e = { key, vector_size(&self->values) - 1 };
	CWISS_CHECK(CHECK_INSERTED(HashMapU64U64_insert(&self->indices, &e),
				   true, "insertion failed key=%llx val=%llu",
				   e.key, e.val)
				    ->val == e.val,
		    "value mismatch key=%llx val=%llu", e.key, e.val);
	bubble_up(self, vector_size(&self->values) - 1);
}

noinline static inline void indexable_heap_pop(struct indexable_heap *self)
{
	CWISS_CHECK(vector_size(&self->values) > 0, "pop() on an empty heap");
	HashMapU64U64_Entry e = { *kv_ckey(vector_back(&self->values)), 0 };
	CWISS_CHECK(HashMapU64U64_update(&self->indices, &e)->val == e.val,
		    "value mismatch key=%llx val=%llu", e.key, e.val);
	CWISS_CHECK(HashMapU64U64_erase(&self->indices,
					kv_ckey(vector_front(&self->values))),
		    "erasing an non-existant entry from the map key=%llx",
		    *kv_ckey(vector_front(&self->values)));
	vector_swap(&self->values, 0, vector_size(&self->values) - 1);
	vector_pop_back(&self->values);
	bubble_down(self, 0);
}

noinline static inline struct kv const *
indexable_heap_peek(struct indexable_heap *self)
{
	return vector_front(&self->values);
}

noinline static inline bool indexable_heap_erase(struct indexable_heap *self,
						 u64 key)
{
	HashMapU64U64_Iter it = HashMapU64U64_find(&self->indices, &key);
	HashMapU64U64_Entry *e = HashMapU64U64_Iter_get(&it);
	CWISS_CHECK(e != NULL,
		    "erasing a non-existant entry from the map key=%llx", key);
	u64 index = e->val, last = vector_size(&self->values) - 1;
	CWISS_CHECK(index <= last, "index out of bounds index=%llu last=%llu",
		    index, last);
	// If not already the last element, swap with the last element
	// Manually swap instead of calling HashMapU64U64_swap to save one lookup
	if (index != last) {
		HashMapU64U64_Entry be = { *kv_ckey(vector_back(&self->values)),
					   index };
		CWISS_CHECK(HashMapU64U64_update(&self->indices, &be)->val,
			    "value mismatch key=%llx val=%llu", be.key, be.val);
		vector_swap(&self->values, index, last);
	}
	CWISS_CHECK(HashMapU64U64_erase(&self->indices, &key),
		    "erase failed key=%llx", key);
	vector_pop_back(&self->values);
	// bubble_down can handle index == last correctly
	bubble_down(self, index);
	return true;
}
noinline static inline u64 indexable_heap_inc(struct indexable_heap *self,
					      u64 key, s64 delta)
{
	HashMapU64U64_Iter it = HashMapU64U64_find(&self->indices, &key);
	HashMapU64U64_Entry *e = HashMapU64U64_Iter_get(&it);
	CWISS_CHECK(e != NULL, "getting a non-existant entry from the map");
	u64 index = e->val;
	u64 *p = kv_value(vector_at(&self->values, index));
	u64 old = *p;
	*p += delta;
	bubble_up(self, index);
	bubble_down(self, index);
	return old;
}

noinline static inline u64 indexable_heap_update(struct indexable_heap *self,
						 u64 key, u64 val)
{
	HashMapU64U64_Iter it = HashMapU64U64_find(&self->indices, &key);
	HashMapU64U64_Entry *e = HashMapU64U64_Iter_get(&it);
	CWISS_CHECK(e != NULL, "getting a non-existant entry from the map");
	u64 index = e->val;
	u64 *p = kv_value(vector_at(&self->values, index));
	u64 old = *p;
	*p = val;
	bubble_up(self, index);
	bubble_down(self, index);
	return old;
}

noinline static inline bool indexable_heap_contains(struct indexable_heap *self,
						    u64 key)
{
	HashMapU64U64_Iter it = HashMapU64U64_find(&self->indices, &key);
	return HashMapU64U64_Iter_get(&it) != NULL;
}

// void indexable_heap_make(struct indexable_heap *heap);
// void indexable_heap_push(struct indexable_heap *heap, u64 key, u64 value);
// void indexable_heap_pop(struct indexable_heap *heap);
// struct kv const *indexable_heap_peek(struct indexable_heap *heap);
// void indexable_heap_new(struct indexable_heap *heap, bool min_heap);

#endif
