// SPDX-License-Identifier: GPL-2.0
/*
 * A C++'s std::vector implementation in C.
 *
 * Copyright (C) 2021-2024 Junliang Hu
 *
 * Author: Junliang Hu <jlhu@cse.cuhk.edu.hk>
 *
 */

#ifndef VECTOR_H
#define VECTOR_H

#include <linux/types.h>
#include <linux/slab.h>

#define VECTOR_CHECK(cond_, ...)                                               \
	do {                                                                   \
		if (cond_)                                                     \
			break;                                                 \
		pr_err("VECTOR_CHECK failed at %s:%d caller %pSR\n", __FILE__, \
		       __LINE__, __builtin_return_address(0));                 \
		pr_err(__VA_ARGS__);                                           \
		dump_stack();                                                  \
		BUG();                                                         \
	} while (false)

struct vector {
	size_t elem_size;
	size_t len;
	size_t cap;
	void *data;
};

noinline int vector_new(struct vector *v, size_t elem_size, size_t cap);
noinline void vector_drop(struct vector *v);
noinline void *vector_at(struct vector *v, size_t i);
noinline void vector_grow(struct vector *v, size_t cap);
noinline void vector_resize(struct vector *v, void const *elem,
			    size_t new_size);
noinline void vector_push_back(struct vector *v, void const *elem);
noinline void vector_pop_back(struct vector *v);
noinline void vector_erase(struct vector *v, size_t i);
noinline void vector_clear(struct vector *v);
noinline void *vector_front(struct vector *v);
noinline void *vector_back(struct vector *v);

noinline void swap_data(void *a, void *b, void *tmp, size_t size);
enum { VECTOR_SWAP_STACK_SIZE = 256 };
noinline void vector_swap_stack(struct vector *v, size_t i, size_t j);
noinline void vector_swap(struct vector *v, size_t i, size_t j);
noinline size_t vector_size(struct vector *v);
noinline bool vector_empty(struct vector *v);

#endif /* VECTOR_H */
