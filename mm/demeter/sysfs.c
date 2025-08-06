// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021-2024 Junliang Hu
 *
 * Author: Junliang Hu <jlhu@cse.cuhk.edu.hk>
 *
 */
#include <linux/mutex.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "demeter.h"

DEFINE_MUTEX(demeter_sysfs_lock);

struct demeter_sysfs_target {
	struct kobject kobj;
	struct target *target;
};

static struct demeter_sysfs_target *demeter_sysfs_target_alloc(void)
{
	return kzalloc(sizeof(struct demeter_sysfs_target),
		       GFP_KERNEL | __GFP_NOWARN);
}
static inline bool demeter_sysfs_target_running(struct demeter_sysfs_target *t)
{
	return t->target && target_pid(t->target);
}
static int demeter_sysfs_target_add_dirs(struct demeter_sysfs_target *t)
{
	return 0;
}
static void demeter_sysfs_target_rm_dirs(struct demeter_sysfs_target *t)
{
}

static void demeter_sysfs_target_release(struct kobject *kobj)
{
	struct demeter_sysfs_target *t =
		container_of(kobj, struct demeter_sysfs_target, kobj);
	if (t->target) {
		target_drop(t->target);
	}
	kfree(t);
}
static ssize_t pid_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	struct demeter_sysfs_target *t =
		container_of(kobj, struct demeter_sysfs_target, kobj);
	if (!t->target) {
		return sysfs_emit(buf, "%d\n", -1);
	}
	return sysfs_emit(buf, "%d\n", target_pid(t->target));
}
static ssize_t pid_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	struct demeter_sysfs_target *t =
		container_of(kobj, struct demeter_sysfs_target, kobj);
	int pid, err = kstrtoint(buf, 10, &pid);
	if (err || pid < -1) {
		return -EINVAL;
	}
	if (!mutex_trylock(&demeter_sysfs_lock)) {
		return -EBUSY;
	}
	if (t->target) {
		target_drop(t->target);
		t->target = NULL;
	}
	if (pid == -1) {
		mutex_unlock(&demeter_sysfs_lock);
		return count;
	}
	// Wait a while to avoid conflict with userspace initialization
	schedule_timeout_interruptible(msecs_to_jiffies(2000));
	struct target *target = target_new(pid);
	if (IS_ERR(target)) {
		mutex_unlock(&demeter_sysfs_lock);
		return PTR_ERR(target);
	}
	t->target = target;
	mutex_unlock(&demeter_sysfs_lock);
	return count;
}
static struct kobj_attribute demeter_sysfs_target_pid_attr =
	__ATTR_RW_MODE(pid, 0600);
static struct attribute *demeter_sysfs_target_attrs[] = {
	&demeter_sysfs_target_pid_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(demeter_sysfs_target);
static const struct kobj_type demeter_sysfs_target_ktype = {
	.release = demeter_sysfs_target_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = demeter_sysfs_target_groups,
};

struct demeter_sysfs_targets {
	struct kobject kobj;
	struct demeter_sysfs_target **targets;
	int nr;
};

static bool demeter_sysfs_targets_busy(struct demeter_sysfs_target **targets,
				      int nr_targets)
{
	for (int i = 0; i < nr_targets; ++i) {
		if (demeter_sysfs_target_running(targets[i])) {
			return true;
		}
	}
	return false;
}
static void demeter_sysfs_targets_rm_dirs(struct demeter_sysfs_targets *targets)
{
	for (int i = 0; i < targets->nr; ++i) {
		struct demeter_sysfs_target *t = targets->targets[i];
		demeter_sysfs_target_rm_dirs(t);
		kobject_put(&t->kobj);
	}
	targets->nr = 0;
	if (targets->targets)
		kfree(targets->targets);
	targets->targets = NULL;
}
static int demeter_sysfs_targets_add_dirs(struct demeter_sysfs_targets *targets,
					 int nr_targets)
{
	if (demeter_sysfs_targets_busy(targets->targets, targets->nr)) {
		return -EBUSY;
	}
	demeter_sysfs_targets_rm_dirs(targets);
	if (nr_targets == 0) {
		return 0;
	}
	struct demeter_sysfs_target **targets_arr =
		kcalloc(nr_targets, sizeof(struct demeter_sysfs_target *),
			GFP_KERNEL | __GFP_NOWARN);
	if (!targets_arr) {
		return -ENOMEM;
	}
	targets->targets = targets_arr;
	for (int i = 0; i < nr_targets; ++i) {
		struct demeter_sysfs_target *t = demeter_sysfs_target_alloc();
		if (!t) {
			demeter_sysfs_targets_rm_dirs(targets);
			return -ENOMEM;
		}
		int err = kobject_init_and_add(&t->kobj,
					       &demeter_sysfs_target_ktype,
					       &targets->kobj, "%d", i);
		if (err) {
			goto err;
		}
		err = demeter_sysfs_target_add_dirs(t);
		if (err) {
			goto err;
		}
		targets->targets[i] = t;
		targets->nr = i + 1;
		continue;
err:
		demeter_sysfs_targets_rm_dirs(targets);
		kobject_put(&t->kobj);
		return err;
	}
	return 0;
}
static ssize_t nr_targets_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct demeter_sysfs_targets *targets =
		container_of(kobj, struct demeter_sysfs_targets, kobj);
	return sysfs_emit(buf, "%d\n", targets->nr);
}
static ssize_t nr_targets_store(struct kobject *kobj,
				struct kobj_attribute *attr, const char *buf,
				size_t count)
{
	int nr, err = kstrtoint(buf, 10, &nr);
	if (err || nr < 0) {
		return -EINVAL;
	}
	struct demeter_sysfs_targets *targets =
		container_of(kobj, struct demeter_sysfs_targets, kobj);
	if (!mutex_trylock(&demeter_sysfs_lock))
		return -EBUSY;
	err = demeter_sysfs_targets_add_dirs(targets, nr);
	mutex_unlock(&demeter_sysfs_lock);
	if (err)
		return err;

	return count;
}
static struct demeter_sysfs_targets *demeter_sysfs_targets_alloc(void)
{
	return kzalloc(sizeof(struct demeter_sysfs_targets),
		       GFP_KERNEL | __GFP_NOWARN);
}
static void demeter_sysfs_targets_release(struct kobject *kobj)
{
	kfree(container_of(kobj, struct demeter_sysfs_targets, kobj));
}
static struct kobj_attribute demeter_sysfs_targets_nr_attr =
	__ATTR_RW_MODE(nr_targets, 0600);
static struct attribute *demeter_sysfs_targets_attrs[] = {
	&demeter_sysfs_targets_nr_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(demeter_sysfs_targets);
static const struct kobj_type demeter_sysfs_targets_ktype = {
	.release = demeter_sysfs_targets_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = demeter_sysfs_targets_groups,
};

static struct kobject *demeter_sysfs_root;
static struct demeter_sysfs_targets *demeter_sysfs_targets;
int __init demeter_sysfs_init(void)
{
	demeter_sysfs_root = kobject_create_and_add("demeter", mm_kobj);
	if (!demeter_sysfs_root) {
		return -ENOMEM;
	}

	demeter_sysfs_targets = demeter_sysfs_targets_alloc();
	int err = kobject_init_and_add(&demeter_sysfs_targets->kobj,
				       &demeter_sysfs_targets_ktype,
				       demeter_sysfs_root, "targets");
	if (err) {
		kobject_put(&demeter_sysfs_targets->kobj);
		kobject_put(demeter_sysfs_root);
		return err;
	}

	return 0;
}
void __exit demeter_sysfs_exit(void)
{
	if (!demeter_sysfs_root) {
		return;
	}
	if (!demeter_sysfs_targets) {
		kobject_put(demeter_sysfs_root);
		return;
	}
	demeter_sysfs_targets_rm_dirs(demeter_sysfs_targets);

	kobject_put(&demeter_sysfs_targets->kobj);
	kobject_put(demeter_sysfs_root);
}
// module_init(demeter_sysfs_init);
// module_exit(demeter_sysfs_exit);
