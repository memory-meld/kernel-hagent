// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021-2024 Junliang Hu
 *
 * Author: Junliang Hu <jlhu@cse.cuhk.edu.hk>
 *
 */

#ifndef HAGENT_H
#define HAGENT_H

#include <linux/init.h>

extern void __exit hagent_sysfs_exit(void);
extern int __init hagent_sysfs_init(void);

struct target;
extern noinline struct target *target_new(pid_t pid);
extern noinline void target_drop(struct target *t);
extern pid_t target_pid(struct target *t);

#endif // !HAGENT_H
