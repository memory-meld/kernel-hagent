#ifndef HAGENT_MPSC_H
#define HAGENT_MPSC_H
#include <linux/ring_buffer.h>

typedef struct trace_buffer *mpsc_t;
noinline static inline mpsc_t mpsc_new(size_t bytes_per_cpu)
{
	return ring_buffer_alloc(bytes_per_cpu, RB_FL_OVERWRITE);
}
noinline static inline ssize_t mpsc_send(mpsc_t chan, void *src, size_t len)
{
	struct ring_buffer_event *e = ring_buffer_lock_reserve(chan, len);
	if (!e)
		return -EAGAIN;
	void *ptr = ring_buffer_event_data(e);
	memcpy(ptr, src, len);
	ring_buffer_unlock_commit(chan);
	return len;
}
noinline static inline ssize_t mpsc_recv_cpu(mpsc_t chan, int cpu, void *dst,
					     size_t len)
{
	struct ring_buffer_event *e =
		ring_buffer_consume(chan, cpu, NULL, NULL);
	if (!e)
		return -EAGAIN;
	void *ptr = ring_buffer_event_data(e);
	size_t size = min(len, ring_buffer_event_length(e));
	memcpy(dst, ptr, size);
	return size;
}
noinline static inline ssize_t mpsc_recv(mpsc_t chan, void *dst, size_t len)
{
	int cpu;
	for_each_online_cpu(cpu) {
		struct ring_buffer_event *e =
			ring_buffer_consume(chan, cpu, NULL, NULL);
		if (!e)
			continue;
		void *ptr = ring_buffer_event_data(e);
		size_t size = min(len, ring_buffer_event_length(e));
		memcpy(dst, ptr, size);
		return size;
	}
	return -EAGAIN;
}
noinline static inline void mpsc_drop(mpsc_t chan)
{
	ring_buffer_free(chan);
}
static inline bool mpsc_wait_always(void *p)
{
	return false;
}
noinline static inline int mpsc_wait(mpsc_t chan)
{
	return ring_buffer_wait(chan, RING_BUFFER_ALL_CPUS, 0, mpsc_wait_always,
				NULL);
}
extern int ring_buffer_select2(struct trace_buffer *b0, ring_buffer_cond_fn c0,
			       void *d0, struct trace_buffer *b1,
			       ring_buffer_cond_fn c1, void *d1);
extern int ring_buffer_select3(struct trace_buffer *b0, ring_buffer_cond_fn c0,
			       void *d0, struct trace_buffer *b1,
			       ring_buffer_cond_fn c1, void *d1,
			       struct trace_buffer *b2, ring_buffer_cond_fn c2,
			       void *d2);
noinline static inline int mpsc_select2(mpsc_t ch0, mpsc_t ch1)
{
	return ring_buffer_select2(ch0, mpsc_wait_always, NULL, ch1,
				   mpsc_wait_always, NULL);
}
noinline static inline int mpsc_select3(mpsc_t ch0, mpsc_t ch1, mpsc_t ch2)
{
	return ring_buffer_select3(ch0, mpsc_wait_always, NULL, ch1,
				   mpsc_wait_always, NULL, ch2,
				   mpsc_wait_always, NULL);
}

// CAREFUL: This macro does not support break
#define mpsc_for_each(ch, elem)                                        \
	for (int __cpu, __done = 0; !__done; __done = true)            \
		for_each_online_cpu(__cpu)                             \
			for (ssize_t __fail = 0; __fail < MPSC_RETRY;) \
				if (sizeof(elem) !=                    \
				    mpsc_recv_cpu(ch, __cpu, &elem,    \
						  sizeof(elem))) {     \
					++__fail;                      \
				} else

#endif // !HAGENT_MPSC_H
