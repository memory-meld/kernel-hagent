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
extern int ring_buffer_wait_select(struct trace_buffer *buffer0,
				   ring_buffer_cond_fn cond0, void *data0,
				   struct trace_buffer *buffer1,
				   ring_buffer_cond_fn cond1, void *data1);
noinline static inline int mpsc_select(mpsc_t ch0, mpsc_t ch1)
{
	return ring_buffer_wait_select(ch0, mpsc_wait_always, NULL, ch1,
				       mpsc_wait_always, NULL);
}

#endif // !HAGENT_MPSC_H
