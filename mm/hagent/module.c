#include <linux/module.h>

#include "hagent.h"
#include "module.h"

ulong load_latency_sample_period = LOAD_LATENCY_SAMPLE_PERIOD;
module_param_named(load_latency_sample_period, load_latency_sample_period,
		   ulong, 0644);
MODULE_PARM_DESC(load_latency_sample_period,
		 "Sample period for ldlat event, defaults to 17");

ulong load_latency_threshold = LOAD_LATENCY_THRESHOLD;
module_param_named(load_latency_threshold, load_latency_threshold, ulong, 0644);
MODULE_PARM_DESC(load_latency_threshold,
		 "Load latency threshold for ldlat event, defaults to 64");

ulong retired_stores_sample_period = RETIRED_STORES_SAMPLE_PERIOD;
module_param_named(retired_stores_sample_period, retired_stores_sample_period,
		   ulong, 0644);
MODULE_PARM_DESC(retired_stores_sample_period,
		 "Sample period for retired stores event, defaults to 17");

ulong load_l3_miss_sample_period = LOAD_L3_MISS_SAMPLE_PERIOD;
module_param_named(load_l3_miss_sample_period, load_l3_miss_sample_period,
		   ulong, 0644);
MODULE_PARM_DESC(load_l3_miss_sample_period,
		 "Sample period for local DRAM L3 miss event, defaults to 17");

ulong streaming_decaying_sketch_width = SDS_WIDTH_AUTO;
module_param_named(streaming_decaying_sketch_width,
		   streaming_decaying_sketch_width, ulong, 0644);
MODULE_PARM_DESC(streaming_decaying_sketch_width,
		 "Width for streaming decaying sketch, defaults to 8192");

ulong streaming_decaying_sketch_depth = SDS_DEPTH;
module_param_named(streaming_decaying_sketch_depth,
		   streaming_decaying_sketch_depth, ulong, 0644);
MODULE_PARM_DESC(streaming_decaying_sketch_depth,
		 "Depth for streaming decaying sketch, defaults to 4");

ulong throttle_pulse_width_ms = THROTTLE_PULSE_WIDTH_MS;
module_param_named(throttle_pulse_width_ms, throttle_pulse_width_ms, ulong,
		   0644);
MODULE_PARM_DESC(throttle_pulse_width_ms,
		 "Throttle pulse width in ms, defaults to 1000");

ulong throttle_pulse_period_ms = THROTTLE_PULSE_PERIOD_MS;
module_param_named(throttle_pulse_period_ms, throttle_pulse_period_ms, ulong,
		   0644);
MODULE_PARM_DESC(throttle_pulse_period_ms,
		 "Throttle pulse period in ms, defaults to 5000");

ulong split_period_ms = SPLI_PERIOD_MS;
module_param_named(split_period_ms, split_period_ms, ulong, 0644);
MODULE_PARM_DESC(split_period_ms, "Split period in ms, defaults to 200");


DEFINE_STATIC_KEY_TRUE(should_decay_sketch);
struct kmem_cache *list_head_cache;

static void intel_pmu_print_debug_all(void)
{
	int cpu;
	for_each_online_cpu(cpu) {
		void perf_event_print_debug(void);
		smp_call_on_cpu(cpu, (int (*)(void *))perf_event_print_debug,
				NULL, false);
	}
}

struct perf_event_attr event_attrs[MAX_EVENTS] = {
	// [EVENT_LOAD] = {
	// 	.type = PERF_TYPE_RAW,
	// 	.config = MEM_TRANS_RETIRED_LOAD_LATENCY,
	// 	.config1 = LOAD_LATENCY_THRESHOLD,
	// 	.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR |
	// 		       PERF_SAMPLE_WEIGHT | PERF_SAMPLE_PHYS_ADDR,
	// 	.sample_period = SAMPLE_PERIOD,
	// 	.inherit = 1,
	// 	.precise_ip = 3,
	// 	// .disabled = 1,
	// 	.exclude_kernel = 1,
	// 	.exclude_hv = 1,
	// 	.exclude_callchain_kernel = 1,
	// },
	[EVENT_LOAD] = {
		.type = PERF_TYPE_RAW,
		.config = MEM_LOAD_L3_MISS_RETIRED_LOCAL_DRAM,
		.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR |
			       PERF_SAMPLE_WEIGHT | PERF_SAMPLE_PHYS_ADDR,
		.sample_period = LOAD_L3_MISS_SAMPLE_PERIOD,
		.inherit = 1,
		.precise_ip = 3,
		// .disabled = 1,
		.exclude_kernel = 1,
		.exclude_hv = 1,
		.exclude_callchain_kernel = 1,
	},
	[EVENT_STORE] = {
		.type = PERF_TYPE_RAW,
		.config = MEM_INST_RETIRED_ALL_STORES,
		.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR |
			       PERF_SAMPLE_WEIGHT | PERF_SAMPLE_PHYS_ADDR,
		.sample_period = RETIRED_STORES_SAMPLE_PERIOD ,
		.inherit = 1,
		.precise_ip = 3,
		// .disabled = 1,
		.exclude_kernel = 1,
		.exclude_hv = 1,
		.exclude_callchain_kernel = 1,
	},
};
static inline void event_attrs_update_param(void)
{
	// event_attrs[EVENT_LOAD].config1 = load_latency_threshold;
	// event_attrs[EVENT_LOAD].sample_period = load_latency_sample_period;
	// event_attrs[EVENT_LOAD].config1 = load_latency_threshold;
	event_attrs[EVENT_LOAD].sample_period = load_l3_miss_sample_period;
	event_attrs[EVENT_STORE].sample_period = retired_stores_sample_period;
	pr_info("%s: local_dram_miss_sample_period=%lu retired_stores_sample_period=%lu load_latency_sample_period=%lu load_latency_threshold=%lu\n",
		__func__, load_l3_miss_sample_period,
		retired_stores_sample_period, load_latency_sample_period,
		load_latency_threshold);
}

static u64 num_possible_pages(void)
{
	u64 spanned = 0;
	int nid;
	for_each_node_state(nid, N_MEMORY) {
		spanned += node_spanned_pages(nid);
	}
	return spanned;
}

static void sds_update_param(void)
{
	if (streaming_decaying_sketch_width != SDS_WIDTH_AUTO) {
		// Keep manually set values
		// leave depth unchanged
		return;
	}
	// The original implementation has 2000 < W < 12000.
	// When giving b = 1.08, N = 10^7, ε = 2^−16 or 2^−17,
	// the error rate is within (0.01, 0.05)
	// if we choose W = 7000, we have W = 7/10000 of N
	streaming_decaying_sketch_width =
		next_prime_number(num_possible_pages() / 2 * 7 / 10000 / 3);
	pr_info("%s: streaming_decaying_sketch_width=%lu\n", __func__,
		streaming_decaying_sketch_width);
}

static __init int init(void)
{
	list_head_cache = KMEM_CACHE(list_head, 0);
	if (!list_head_cache) {
		pr_err("Failed to create list_head cache\n");
		return -ENOMEM;
	}
	sds_update_param();
	event_attrs_update_param();
	return hagent_sysfs_init();
}

static __exit void exit(void)
{
	hagent_sysfs_exit();
	kmem_cache_destroy(list_head_cache);
}

module_init(init);
module_exit(exit);
MODULE_AUTHOR("Junliang Hu <jlhu@cse.cuhk.edu.hk>");
MODULE_DESCRIPTION("Memory placement optimization module");
MODULE_LICENSE("GPL");
