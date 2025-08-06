// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021-2024 Junliang Hu
 *
 * Author: Junliang Hu <jlhu@cse.cuhk.edu.hk>
 *
 */

#ifndef DEMETER_H
#define DEMETER_H

#include <linux/init.h>

extern void __exit demeter_sysfs_exit(void);
extern int __init demeter_sysfs_init(void);

struct target;
extern noinline struct target *target_new(pid_t pid);
extern noinline void target_drop(struct target *t);
extern pid_t target_pid(struct target *t);

#endif // !DEMETER_H
