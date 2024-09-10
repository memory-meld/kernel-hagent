// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021-2024 Junliang Hu
 *
 * Author: Junliang Hu <jlhu@cse.cuhk.edu.hk>
 *
 */

#ifndef HAGENT_H
#define HAGENT_H

#include <linux/types.h>
#include <linux/init.h>
#include <linux/perf_event.h>

#include "sds.h"
#include "indexable_heap.h"
#include "mpsc.h"

extern void __exit hagent_sysfs_exit(void);
extern int __init hagent_sysfs_init(void);

enum {
	DIRECTION_DEMOTION,
	DIRECTION_PROMOTION,
	DIRECTION_MAX,
};

enum {
	// EVENT_LOAD,
	EVENT_STORE,
	EVENT_DRAM,
	EVENT_MAX,
};
extern struct perf_event_attr event_attrs[EVENT_MAX];

enum {
	THREAD_POLICY,
	THREAD_MIGRATION,
	THREAD_MAX,
};

CWISS_DECLARE_FLAT_HASHMAP(HashMapU64Ptr, u64, void *);

// Represent a hagent management target, i.e. a process.
struct hagent_target {
	struct task_struct *task;
	mpsc_t chan;
	union {
		struct task_struct *threads[THREAD_MAX];
		struct delayed_work works[THREAD_MAX];
	};
	struct delayed_work stop;
	struct completion stopped;
	struct perf_event *events[EVENT_MAX];
	struct mutex lock;
	// All managed struct folio *
	struct list_head managed;
	// vpfn -> struct folio *
	HashMapU64Ptr map;
	struct sds sds;
	struct indexable_heap heap[DIRECTION_MAX];
	// struct spsc decayed;
	u64 total_samples, dram_samples, pmem_samples, next_migration,
		next_dump, total_exchanges, next_report;
};

extern struct hagent_target *hagent_target_new(pid_t pid);
extern void hagent_target_drop(struct hagent_target *t);
extern pid_t hagent_target_pid(struct hagent_target *t);

#endif // !HAGENT_H
