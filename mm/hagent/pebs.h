#ifndef HAGENT_PLACEMENT_PEBS_H
#define HAGENT_PLACEMENT_PEBS_H

#include <linux/perf_event.h>
#include <../../kernel/events/internal.h>

struct perf_sample {
	u32 pid, tid;
	u64 time;
	u64 addr;
	u64 weight;
	u64 phys_addr;
};

#endif // !HAGENT_PLACEMENT_PEBS_H
