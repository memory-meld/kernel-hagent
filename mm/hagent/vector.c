#include "vector.h"

int vector_new(struct vector *v, size_t elem_size, size_t cap)
{
	void *data = kvcalloc(cap, elem_size, GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	*v = (struct vector){
		.data = data, .len = 0, .cap = cap, .elem_size = elem_size
	};
	return 0;
};

void vector_drop(struct vector *v)
{
	if (v->data)
		kvfree(v->data);
}

void *vector_at(struct vector *v, size_t i)
{
	VECTOR_CHECK(i < v->len, "at() out of range i=%zu len=%zu\n", i,
		     v->len);
	// if (i >= v->len)
	// 	return NULL;
	return v->data + i * v->elem_size;
}

void vector_grow(struct vector *v, size_t cap)
{
	void *data = kvrealloc(v->data, v->cap * v->elem_size,
			       cap * v->elem_size, GFP_KERNEL);
	VECTOR_CHECK(data != NULL, "kvrealloc() returned null");
	v->data = data;
	v->cap = cap;
}

void vector_resize(struct vector *v, void const *elem, size_t new_size)
{
	if (new_size > v->cap) {
		vector_grow(v, new_size);
	}
	for (size_t i = v->len; i < new_size; i++) {
		memcpy(v->data + i * v->elem_size, elem, v->elem_size);
	}
	v->len = new_size;
}
void vector_push_back(struct vector *v, void const *elem)
{
	if (v->len == v->cap)
		vector_grow(v, 2 * v->cap);
	memcpy(v->data + v->len * v->elem_size, elem, v->elem_size);
	v->len++;
	// pr_info_ratelimited("%s: new_len=%zu elem=[0x%llx 0x%llx]", __func__, v->len,
	// 	*(u64 *)elem, *(u64 *)(elem + 8));
}

void vector_pop_back(struct vector *v)
{
	VECTOR_CHECK(v->len > 0, "pop_back() on empty vector");
	v->len--;
}

void vector_erase(struct vector *v, size_t i)
{
	VECTOR_CHECK(i < v->len, "erase() out of range");
	memmove(v->data + i * v->elem_size, v->data + (i + 1) * v->elem_size,
		(v->len - i - 1) * v->elem_size);
	v->len--;
}

void vector_clear(struct vector *v)
{
	v->len = 0;
}

void *vector_front(struct vector *v)
{
	VECTOR_CHECK(v->len > 0, "front() on empty vector");
	return v->data;
}
void *vector_back(struct vector *v)
{
	VECTOR_CHECK(v->len > 0, "back() on empty vector");
	return v->data + (v->len - 1) * v->elem_size;
}

void swap_data(void *a, void *b, void *tmp, size_t size)
{
	memcpy(tmp, a, size);
	memcpy(a, b, size);
	memcpy(b, tmp, size);
}
void vector_swap_stack(struct vector *v, size_t i, size_t j)
{
	char buf[VECTOR_SWAP_STACK_SIZE];
	swap_data(v->data + i * v->elem_size, v->data + j * v->elem_size, buf,
		  v->elem_size);
}
void vector_swap(struct vector *v, size_t i, size_t j)
{
	VECTOR_CHECK(i < v->len && j < v->len, "swap() out of range len=%zu i=%zu j=%zu\n",
		     v->len, i, j);
	switch (v->elem_size) {
	case 1:
		swap(*(u8 *)(v->data + i), *(u8 *)(v->data + j));
		break;
	case 2:
		swap(*(u16 *)(v->data + i * 2), *(u16 *)(v->data + j * 2));
		break;
	case 4:
		swap(*(u32 *)(v->data + i * 4), *(u32 *)(v->data + j * 4));
		break;
	case 8:
		swap(*(u64 *)(v->data + i * 8), *(u64 *)(v->data + j * 8));
		break;
	case 16:
		swap(*(u64 *)(v->data + i * 16), *(u64 *)(v->data + j * 16));
		swap(*(u64 *)(v->data + i * 16 + 8),
		     *(u64 *)(v->data + j * 16 + 8));
		break;
	default:
		if (v->elem_size <= VECTOR_SWAP_STACK_SIZE) {
			vector_swap_stack(v, i, j);
		} else {
			void *t = kvmalloc(v->elem_size, GFP_KERNEL);
			swap_data(v->data + i * v->elem_size,
				  v->data + j * v->elem_size, t, v->elem_size);
			kvfree(t);
		}
	}
}
size_t vector_size(struct vector *v)
{
	return v->len;
}
bool vector_empty(struct vector *v)
{
	return v->len == 0;
}
