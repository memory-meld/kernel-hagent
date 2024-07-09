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

#include "hagent.h"

DEFINE_MUTEX(hagent_sysfs_lock);

struct hagent_sysfs_target {
	struct kobject kobj;
	struct hagent_target *target;
};

static struct hagent_sysfs_target *hagent_sysfs_target_alloc(void)
{
	return kzalloc(sizeof(struct hagent_sysfs_target),
		       GFP_KERNEL | __GFP_NOWARN);
}
static inline bool hagent_sysfs_target_running(struct hagent_sysfs_target *t)
{
	return t->target && hagent_target_pid(t->target);
}
static int hagent_sysfs_target_add_dirs(struct hagent_sysfs_target *t)
{
	return 0;
}
static void hagent_sysfs_target_rm_dirs(struct hagent_sysfs_target *t)
{
}

static void hagent_sysfs_target_release(struct kobject *kobj)
{
	struct hagent_sysfs_target *t =
		container_of(kobj, struct hagent_sysfs_target, kobj);
	if (t->target) {
		hagent_target_drop(t->target);
	}
	kfree(t);
}
static ssize_t pid_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	struct hagent_sysfs_target *t =
		container_of(kobj, struct hagent_sysfs_target, kobj);
	if (!t->target) {
		return sysfs_emit(buf, "%d\n", -1);
	}
	return sysfs_emit(buf, "%d\n", hagent_target_pid(t->target));
}
static ssize_t pid_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	struct hagent_sysfs_target *t =
		container_of(kobj, struct hagent_sysfs_target, kobj);
	int pid, err = kstrtoint(buf, 10, &pid);
	if (err || pid <= 0) {
		return -EINVAL;
	}
	if (!mutex_trylock(&hagent_sysfs_lock)) {
		return -EBUSY;
	}
	if (t->target) {
		hagent_target_drop(t->target);
	}
	struct hagent_target *target = hagent_target_new(pid);
	if (IS_ERR(target)) {
		mutex_unlock(&hagent_sysfs_lock);
		return PTR_ERR(target);
	}
	t->target = target;
	mutex_unlock(&hagent_sysfs_lock);
	return count;
}
static struct kobj_attribute hagent_sysfs_target_pid_attr =
	__ATTR_RW_MODE(pid, 0600);
static struct attribute *hagent_sysfs_target_attrs[] = {
	&hagent_sysfs_target_pid_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(hagent_sysfs_target);
static const struct kobj_type hagent_sysfs_target_ktype = {
	.release = hagent_sysfs_target_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = hagent_sysfs_target_groups,
};

struct hagent_sysfs_targets {
	struct kobject kobj;
	struct hagent_sysfs_target **targets;
	int nr;
};

static bool hagent_sysfs_targets_busy(struct hagent_sysfs_target **targets,
				      int nr_targets)
{
	for (int i = 0; i < nr_targets; ++i) {
		if (hagent_sysfs_target_running(targets[i])) {
			return true;
		}
	}
	return false;
}
static void hagent_sysfs_targets_rm_dirs(struct hagent_sysfs_targets *targets)
{
	for (int i = 0; i < targets->nr; ++i) {
		struct hagent_sysfs_target *t = targets->targets[i];
		hagent_sysfs_target_rm_dirs(t);
		kobject_put(&t->kobj);
	}
	targets->nr = 0;
	if (targets->targets)
		kfree(targets->targets);
	targets->targets = NULL;
}
static int hagent_sysfs_targets_add_dirs(struct hagent_sysfs_targets *targets,
					 int nr_targets)
{
	if (hagent_sysfs_targets_busy(targets->targets, targets->nr)) {
		return -EBUSY;
	}
	hagent_sysfs_targets_rm_dirs(targets);
	if (nr_targets == 0) {
		return 0;
	}
	struct hagent_sysfs_target **targets_arr =
		kcalloc(nr_targets, sizeof(struct hagent_sysfs_target *),
			GFP_KERNEL | __GFP_NOWARN);
	if (!targets_arr) {
		return -ENOMEM;
	}
	targets->targets = targets_arr;
	for (int i = 0; i < nr_targets; ++i) {
		struct hagent_sysfs_target *t = hagent_sysfs_target_alloc();
		if (!t) {
			hagent_sysfs_targets_rm_dirs(targets);
			return -ENOMEM;
		}
		int err = kobject_init_and_add(&t->kobj,
					       &hagent_sysfs_target_ktype,
					       &targets->kobj, "%d", i);
		if (err) {
			goto err;
		}
		err = hagent_sysfs_target_add_dirs(t);
		if (err) {
			goto err;
		}
		targets->targets[i] = t;
		targets->nr = i + 1;
		continue;
err:
		hagent_sysfs_targets_rm_dirs(targets);
		kobject_put(&t->kobj);
		return err;
	}
	return 0;
}
static ssize_t nr_targets_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct hagent_sysfs_targets *targets =
		container_of(kobj, struct hagent_sysfs_targets, kobj);
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
	struct hagent_sysfs_targets *targets =
		container_of(kobj, struct hagent_sysfs_targets, kobj);
	if (!mutex_trylock(&hagent_sysfs_lock))
		return -EBUSY;
	err = hagent_sysfs_targets_add_dirs(targets, nr);
	mutex_unlock(&hagent_sysfs_lock);
	if (err)
		return err;

	return count;
}
static struct hagent_sysfs_targets *hagent_sysfs_targets_alloc(void)
{
	return kzalloc(sizeof(struct hagent_sysfs_targets),
		       GFP_KERNEL | __GFP_NOWARN);
}
static void hagent_sysfs_targets_release(struct kobject *kobj)
{
	kfree(container_of(kobj, struct hagent_sysfs_targets, kobj));
}
static struct kobj_attribute hagent_sysfs_targets_nr_attr =
	__ATTR_RW_MODE(nr_targets, 0600);
static struct attribute *hagent_sysfs_targets_attrs[] = {
	&hagent_sysfs_targets_nr_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(hagent_sysfs_targets);
static const struct kobj_type hagent_sysfs_targets_ktype = {
	.release = hagent_sysfs_targets_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = hagent_sysfs_targets_groups,
};

static struct kobject *hagent_sysfs_root;
static struct hagent_sysfs_targets *hagent_sysfs_targets;
// void __exit hagent_sysfs_exit(void)
int __init hagent_sysfs_init(void)
{
	hagent_sysfs_root = kobject_create_and_add("hagent", mm_kobj);
	if (!hagent_sysfs_root) {
		return -ENOMEM;
	}

	hagent_sysfs_targets = hagent_sysfs_targets_alloc();
	int err = kobject_init_and_add(&hagent_sysfs_targets->kobj,
				       &hagent_sysfs_targets_ktype,
				       hagent_sysfs_root, "targets");
	if (err) {
		kobject_put(&hagent_sysfs_targets->kobj);
		kobject_put(hagent_sysfs_root);
		return err;
	}

	return 0;
}
void __exit hagent_sysfs_exit(void)
{
	if (!hagent_sysfs_root) {
		return;
	}
	if (!hagent_sysfs_targets) {
		kobject_put(hagent_sysfs_root);
		return;
	}
	hagent_sysfs_targets_rm_dirs(hagent_sysfs_targets);

	kobject_put(&hagent_sysfs_targets->kobj);
	kobject_put(hagent_sysfs_root);
}
// module_init(hagent_sysfs_init);
// module_exit(hagent_sysfs_exit);
