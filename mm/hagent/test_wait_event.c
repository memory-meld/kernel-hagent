#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mempolicy.h>
#include <linux/cleanup.h>
#include <linux/sched/clock.h>
#include <linux/umh.h>

#include <kunit/test.h>

struct wake_thread_data {
	struct wait_queue_head wqh;
	atomic_t woken;
	int id;
};
static int wake_thread(void *data)
{
	struct wake_thread_data *w = data;
	pr_info("%s: id=%d", __func__, w->id);
	while (!kthread_should_stop()) {
		schedule_timeout_uninterruptible(msecs_to_jiffies(1000));
		int wake = atomic_fetch_add(1, &w->woken);
		pr_info("%s: id=%d wake=%d->%d\n", __func__, w->id, wake,
			wake + 1);
		wake_up(&w->wqh);
	}
	return 0;
}
#define select_event(wqh0, cond0, wqh1, cond1)                   \
	({                                                       \
		__label__ out;                                   \
		long __ret = 0, __which = -1;                    \
		might_sleep();                                   \
		if (cond0) {                                     \
			__which = 0;                             \
			goto out;                                \
		}                                                \
		if (cond1) {                                     \
			__which = 1;                             \
			goto out;                                \
		}                                                \
		DEFINE_WAIT_FUNC(__wqe0, default_wake_function); \
		DEFINE_WAIT_FUNC(__wqe1, default_wake_function); \
		add_wait_queue(wqh0, &__wqe0);                   \
		add_wait_queue(wqh1, &__wqe1);                   \
		for (;;) {                                       \
			set_current_state(TASK_INTERRUPTIBLE);   \
			if (cond0) {                             \
				__which = 0;                     \
				break;                           \
			}                                        \
			if (cond1) {                             \
				__which = 1;                     \
				break;                           \
			}                                        \
			schedule();                              \
			if (signal_pending(current)) {           \
				__ret = -ERESTARTSYS;            \
				break;                           \
			}                                        \
		}                                                \
		remove_wait_queue(wqh1, &__wqe1);                \
		remove_wait_queue(wqh0, &__wqe0);                \
		__set_current_state(TASK_RUNNING);               \
out:                                                             \
		__ret < 0 ? __ret : __which;                     \
	})

static int wait_events(struct wake_thread_data *data,
		       struct wait_queue_entry *wait, s64 *wake, u64 len)
{
	int ret = 0;
	for (int i = 0; i < len; i++) {
		init_wait(&wait[i]);
		wait[i].func = default_wake_function;
	}
	// Add ourselves to all waitqueues.
	for (int i = 0; i < len; i++)
		add_wait_queue(&data[i].wqh, &wait[i]);
	for (bool should_stop = false; !should_stop;) {
		// NOTE: this should come **before** condition checking for avoid races.
		set_current_state(TASK_INTERRUPTIBLE);
		// Check condition(s) which we are waiting
		for (int i = 0; i < len; i++) {
			s64 w = atomic_read(&data[i].woken);
			if (w > wake[i]) {
				wake[i] = w;
				should_stop = true;
			}
		}
		if (should_stop)
			break;
		// Need to wait
		schedule();
		// Check if waiting has been interrupted by signal
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
	}
	// Remove ourselves from all waitqueues.
	for (int i = 0; i < len; i++)
		remove_wait_queue(&data[i].wqh, &wait[i]);
	__set_current_state(TASK_RUNNING);
	return ret;
}

static void test_wait_two_events(struct kunit *test)
{
	struct wake_thread_data data[] = { {}, {} };
	struct task_struct *t[ARRAY_SIZE(data)] = {};
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		data[i].id = i;
		init_waitqueue_head(&data[i].wqh);
	}
	for (int i = 0; i < ARRAY_SIZE(data); i++)
		t[i] = kthread_run(wake_thread, &data[i], "t%d", i);

	s64 wake[ARRAY_SIZE(data)] = {};
	while (true) {
		// clang-format off
		int err = select_event(
			&data[0].wqh, ({
				int w = atomic_read(&data[0].woken), ret = w > wake[0];
				wake[0] = w;
				ret;
			}),
			&data[1].wqh, ({
				int w = atomic_read(&data[1].woken), ret = w > wake[1];
				wake[1] = w;
				ret;
			}));
		// clang-format on
		pr_info("%s: select_event()=%pe", __func__, ERR_PTR(err));
		bool should_stop = true;
		for (int i = 0; i < ARRAY_SIZE(data); i++) {
			pr_cont(" wake[%d]=%lld", i, wake[i]);
			if (wake[i] < 10)
				should_stop = false;
		}
		pr_cont("\n");
		if (should_stop)
			break;
	}
	for (int i = 0; i < ARRAY_SIZE(data); i++)
		kthread_stop(t[i]);
}

static void test_wait_events(struct kunit *test)
{
	struct wake_thread_data data[] = { {}, {}, {}, {}, {} };
	struct task_struct *t[ARRAY_SIZE(data)] = {};
	for (int i = 0; i < ARRAY_SIZE(data); i++) {
		data[i].id = i;
		init_waitqueue_head(&data[i].wqh);
	}
	for (int i = 0; i < ARRAY_SIZE(data); i++)
		t[i] = kthread_run(wake_thread, &data[i], "t%d", i);

	struct wait_queue_entry wait[ARRAY_SIZE(data)] = {};
	s64 wake[ARRAY_SIZE(data)] = {};
	while (true) {
		int err = wait_events(data, wait, wake, ARRAY_SIZE(data));
		pr_info("%s: wait_events()=%pe", __func__, ERR_PTR(err));
		bool should_stop = true;
		for (int i = 0; i < ARRAY_SIZE(data); i++) {
			pr_cont(" wake[%d]=%lld", i, wake[i]);
			if (wake[i] < 10)
				should_stop = false;
		}
		pr_cont("\n");
		if (should_stop)
			break;
	}

	for (int i = 0; i < ARRAY_SIZE(data); i++)
		kthread_stop(t[i]);
}

static struct kunit_case hagent_test_cases[] = {
	KUNIT_CASE_SLOW(test_wait_two_events),
	KUNIT_CASE_SLOW(test_wait_events),
	{},
};

static struct kunit_suite hagent_test_suite = {
	.name = "hagent",
	.test_cases = hagent_test_cases,
};
kunit_test_suite(hagent_test_suite);

// static int __init init(void) { return 0; }
// static void __exit exit(void) { }
// module_init(init);
// module_exit(exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Junliang Hu <jlhu@cse.cuhk.edu.hk>");
