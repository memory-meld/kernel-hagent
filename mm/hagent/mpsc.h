#ifndef HAGENT_MPSC_H
#define HAGENT_MPSC_H
#include <linux/ring_buffer.h>

typedef struct trace_buffer *mpsc_t;
static inline mpsc_t mpsc_new(size_t bytes_per_cpu)
{
	return ring_buffer_alloc(bytes_per_cpu, RB_FL_OVERWRITE);
}
static inline ssize_t mpsc_send(mpsc_t chan, void *src, size_t len)
{
	struct ring_buffer_event *e = ring_buffer_lock_reserve(chan, len);
	if (!e)
		return -EAGAIN;
	void *ptr = ring_buffer_event_data(e);
	memcpy(ptr, src, len);
	ring_buffer_unlock_commit(chan);
	return len;
}
static inline ssize_t mpsc_recv_cpu(mpsc_t chan, int cpu, void *dst, size_t len)
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
static inline ssize_t mpsc_recv(mpsc_t chan, void *dst, size_t len)
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
static inline void mpsc_drop(mpsc_t chan)
{
	ring_buffer_free(chan);
}

#endif // !HAGENT_MPSC_H
