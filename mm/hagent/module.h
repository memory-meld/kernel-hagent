#ifndef HAGENT_PLACEMENT_MODULE_H
#define HAGENT_PLACEMENT_MODULE_H

#include <linux/perf_event.h>
#include <linux/prime_numbers.h>

#define FMEM_NID (first_node(node_states[N_MEMORY]))
#define SMEM_NID (last_node(node_states[N_MEMORY]))
#define FMEM_NODE (NODE_DATA(FMEM_NID))
#define SMEM_NODE (NODE_DATA(SMEM_NID))

enum module_param_defaults {
	LOAD_LATENCY_SAMPLE_PERIOD = 4093,
	LOAD_LATENCY_THRESHOLD = 60,
	RETIRED_STORES_SAMPLE_PERIOD = 65535,
	LOAD_L3_MISS_SAMPLE_PERIOD = 4093,
	SDS_WIDTH_AUTO = 8192,
	SDS_DEPTH = 4,
	ASYNCHRONOUS_ARCHITECTURE = true,
	DECAY_SKETCH = true,
	THROTTLE_PULSE_WIDTH_MS = 0,
	THROTTLE_PULSE_PERIOD_MS = 5000,
	SPLI_PERIOD_MS = 500,
};
enum rtree_param_defaults {
	RTREE_SPLIT_N = 2,
	RTREE_GRANULARITY = 2ul << 20,
	RTREE_SIGNIFICANCE_FACTOR = 2,
	// TODO: make this value configurable and adaptive
	RTREE_SPLIT_THRESH = 15,
	RTREE_EXCH_THRESH = RTREE_GRANULARITY,
	RTREE_MAX_SIZE = 2048,
	RTREE_COOL_AGE = 3,
};
enum event_config {
	MEM_TRANS_RETIRED_LOAD_LATENCY = 0x01cd,
	MEM_INST_RETIRED_ALL_STORES = 0x82d0,
	MEM_LOAD_L3_MISS_RETIRED_LOCAL_DRAM = 0x01d3,
};
enum target_event {
	EVENT_LOAD,
	EVENT_STORE,
	MAX_EVENTS,
};
extern struct perf_event_attr event_attrs[MAX_EVENTS];

extern ulong load_latency_sample_period;
extern ulong load_latency_threshold;
extern ulong retired_stores_sample_period;
extern ulong throttle_pulse_width_ms;
extern ulong throttle_pulse_period_ms;
extern ulong split_period_ms;
extern ulong rtree_split_thresh;
extern ulong rtree_exch_thresh;

extern struct kmem_cache *list_head_cache;

DECLARE_STATIC_KEY_TRUE(use_asynchronous_architecture);

#endif // !HAGENT_PLACEMENT_MODULE_H
