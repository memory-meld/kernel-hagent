#include <linux/virtio.h>
#include <linux/virtio_balloon.h>
#include <linux/swap.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/balloon_compaction.h>
#include <linux/oom.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/page_reporting.h>
#include <linux/sched/clock.h>

#define TRY(exp)                                                            \
	({                                                                  \
		__typeof__((exp)) __err = (exp);                            \
		if ((u64)(__err) >= (u64)(-MAX_ERRNO)) {                    \
			pr_err("%s:%d failed with error %lld:\n", __FILE__, \
			       __LINE__, (s64)__err);                       \
			dump_stack();                                       \
			return (s64)(__err);                                \
		}                                                           \
		__err;                                                      \
	})

struct virtio_balloon_config_extended {
	struct virtio_balloon_config base;
	/* Number of heterogeneous pages host wants Guest to give up. */
	__le32 num_hetero_pages;
	/* Number of pages we've actually got in balloon. */
	__le32 actual_hetero;
};

/*
 * Balloon device works in 4K page units.  So each page is pointed to by
 * multiple balloon pages.  All memory counters in this driver are in balloon
 * page units.
 */
#define VIRTIO_BALLOON_PAGES_PER_PAGE \
	(unsigned int)(PAGE_SIZE >> VIRTIO_BALLOON_PFN_SHIFT)
#define VIRTIO_BALLOON_ARRAY_PFNS_MAX 256
/* Maximum number of (4k) pages to deflate on OOM notifications. */
#define VIRTIO_BALLOON_OOM_NR_PAGES 256
#define VIRTIO_BALLOON_OOM_NOTIFY_PRIORITY 80

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_BALLOON, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

enum virtio_balloon_feature {
	F_TELL_HOST = VIRTIO_BALLOON_F_MUST_TELL_HOST,
	F_STATS = VIRTIO_BALLOON_F_STATS_VQ,
	F_OOM = VIRTIO_BALLOON_F_DEFLATE_ON_OOM,
	F_REPORT = VIRTIO_BALLOON_F_REPORTING,
#define VIRTIO_BALLOON_F_HETERO_MEM \
	6 /* Additional inflate/deflate queue for heterogeneous memory*/
	F_HETERO = VIRTIO_BALLOON_F_HETERO_MEM,
};

// clang-format off
static unsigned int features[] = {
	F_TELL_HOST,
	F_STATS,
	F_OOM,
	F_REPORT,
	F_HETERO,
};
// clang-format on

enum virtio_balloon_vq {
	Q_INFLATE,
	Q_DEFLATE,
	Q_STATS,
	// Q_FREE_PAGE,
	Q_REPORTING,
	Q_HETERO_INFLATE,
	Q_HETERO_DEFLATE,
	Q_MAX
};

enum virtio_balloon_inner_idx {
	I_NORMAL,
	I_HETERO,
	I_MAX,
};

enum virtio_balloon_stats_tag {
	T_SWAP_IN = VIRTIO_BALLOON_S_SWAP_IN,
	T_SWAP_OUT = VIRTIO_BALLOON_S_SWAP_OUT,
	T_MAJFLT = VIRTIO_BALLOON_S_MAJFLT,
	T_MINFLT = VIRTIO_BALLOON_S_MINFLT,
	T_MEMFREE = VIRTIO_BALLOON_S_MEMFREE,
	T_MEMTOT = VIRTIO_BALLOON_S_MEMTOT,
	T_AVAIL = VIRTIO_BALLOON_S_AVAIL,
	T_CACHES = VIRTIO_BALLOON_S_CACHES,
	T_HTLB_PGALLOC = VIRTIO_BALLOON_S_HTLB_PGALLOC,
	T_HTLB_PGFAIL = VIRTIO_BALLOON_S_HTLB_PGFAIL,
	T_NORMAL_ACCESS,
	T_NORMAL_FREE,
	T_NORMAL_TOTAL,
	T_HETERO_ACCESS,
	T_HETERO_FREE,
	T_HETERO_TOTAL,
	T_MAX,
};

typedef struct balloon_dev_info page_tracker_t;
static void (*page_tracker_track)(page_tracker_t *tracker,
				  struct page *page) = balloon_page_enqueue;
static struct page *(*page_tracker_untrack)(page_tracker_t *tracker) =
	balloon_page_dequeue;
static inline void page_tracker_init(page_tracker_t *tracker)
{
	balloon_devinfo_init(tracker);
}

struct virtio_balloon {
	struct virtio_device *vdev;
	struct virtqueue *vqs[Q_MAX];
	struct work_struct work[Q_MAX];
	struct virtio_balloon_tracepoints {
		u64 total_elapsed, work_elapsed;
	} tracepoints[Q_MAX];
	// make sure no new work are queued when stopping the device
	spinlock_t queue_work;
	atomic_t should_exit;
	struct notifier_block oom_notification;
	wait_queue_head_t ack;
	struct virtio_balloon_inner {
		struct mutex lock;
		// The actual size of pages in the balloon
		u32 len;
		// All the pages we have returned to the host
		page_tracker_t tracking;
		// Temporary storage for communicating with the host
		u32 pfns[VIRTIO_BALLOON_ARRAY_PFNS_MAX];
	} inner[I_MAX];
	struct virtio_balloon_stat_vec {
		u32 len;
		struct virtio_balloon_stat items[T_MAX];
	} stats;
};

static u32 vb_config_read_target(struct virtio_balloon *vb, u32 idx)
{
	u32 target = 0;
	switch (idx) {
	case I_NORMAL:
		virtio_cread_le(vb->vdev, struct virtio_balloon_config_extended,
				base.num_pages, &target);
		break;
	case I_HETERO:
		virtio_cread_le(vb->vdev, struct virtio_balloon_config_extended,
				num_hetero_pages, &target);
		break;
	default:
		dev_err(&vb->vdev->dev,
			"%s failure: requested sub-ballon does not exit\n",
			__func__);
		BUG();
	}
	return target;
}

static void vb_config_write_actual(struct virtio_balloon *vb, u32 idx,
				   u32 actual)
{
	switch (idx) {
	case I_NORMAL:
		virtio_cwrite_le(vb->vdev,
				 struct virtio_balloon_config_extended,
				 base.actual, &actual);
		break;
	case I_HETERO:
		virtio_cwrite_le(vb->vdev,
				 struct virtio_balloon_config_extended,
				 actual_hetero, &actual);
		break;
	default:
		dev_err(&vb->vdev->dev,
			"%s failure: requested sub-ballon does not exit\n",
			__func__);
		BUG();
	}
}

static void vb_callback_ack(struct virtqueue *vq)
{
	struct virtio_balloon *vb = vq->vdev->priv;
	wake_up(&vb->ack);
}

static void vb_callback_stats_request(struct virtqueue *vq)
{
	struct virtio_balloon *vb = vq->vdev->priv;

	scoped_guard(spinlock_irqsave, &vb->queue_work)
	{
		if (atomic_read(&vb->should_exit)) {
			return;
		}
		queue_work(system_freezable_wq, &vb->work[Q_STATS]);
	}
}

static bool vb_acked(struct virtio_balloon *vb, u32 feature)
{
	return virtio_has_feature(vb->vdev, feature);
}

static int vb_send_buf(struct virtio_balloon *vb, u32 qidx, void *buf, u32 len)
{
	struct virtqueue *vq = vb->vqs[qidx];
	struct scatterlist sg;
	sg_init_one(&sg, buf, len);
	TRY(virtqueue_add_outbuf(vq, &sg, 1, vb, GFP_KERNEL));
	virtqueue_kick(vq);
	return 0;
}

static void *vb_recv_buf(struct virtio_balloon *vb, u32 qidx, u32 *len)
{
	struct virtqueue *vq = vb->vqs[qidx];
	u32 _len;
	// no data should be associated with used buffer for all balloon vq
	return virtqueue_get_buf(vq, len ? len : &_len);
}

static s64 vb_inner_diff_from_target(struct virtio_balloon *vb, u32 idx)
{
	BUG_ON(idx != I_NORMAL && idx != I_HETERO);
	struct virtio_balloon_inner *inner = &vb->inner[idx];
	mutex_lock(&inner->lock);
	s64 target = vb_config_read_target(vb, idx);
	s64 diff = target - inner->len;
	mutex_unlock(&inner->lock);
	// dev_info(&vb->vdev->dev, "%s: idx=%u, target=%lld, has=%u, diff=%lld\n",
	// 	 __func__, idx, target, inner->len, diff);
	return diff;
}

static struct page *vb_inner_page_alloc(struct virtio_balloon *vb, u64 idx)
{
	int nid = NUMA_NO_NODE;
	switch (idx) {
	case I_NORMAL:
		nid = first_node(node_states[N_MEMORY]);
		break;
	case I_HETERO:
		nid = last_node(node_states[N_MEMORY]);
		break;
	default:
		dev_err(&vb->vdev->dev,
			"%s failure: requested sub-ballon does not exit\n",
			__func__);
		BUG();
	}
	return alloc_pages_node(nid,
				balloon_mapping_gfp_mask() | __GFP_NOMEMALLOC |
					__GFP_NORETRY | __GFP_NOWARN,
				0);
}

static u32 vb_inner_inflate(struct virtio_balloon *vb, u32 idx, u32 todo)
{
	BUG_ON(idx != I_NORMAL && idx != I_HETERO);
	u32 qidx = idx == I_NORMAL ? Q_INFLATE : Q_HETERO_INFLATE;

	struct virtio_balloon_inner *inner = &vb->inner[idx];
	todo = min(todo, (u32)ARRAY_SIZE(vb->inner[idx].pfns));

	// allocate pages without holding the lock
	struct list_head pages = LIST_HEAD_INIT(pages);
	while (todo-- > 0) {
		struct page *page = vb_inner_page_alloc(vb, idx);
		if (!page) {
			dev_info_ratelimited(
				&vb->vdev->dev,
				"%s failure: Out of puff! Can't get pages\n",
				__func__);
			msleep(200);
			break;
		}
		list_add(&page->lru, &pages);
	}

	mutex_lock(&inner->lock);

	u32 done = 0;
	struct page *page, *next;
	list_for_each_entry_safe(page, next, &pages, lru) {
		page_tracker_track(&inner->tracking, page);
		inner->pfns[done++] = page_to_pfn(page);
	}
	vb_send_buf(vb, qidx, inner->pfns, sizeof(*inner->pfns) * done);
	wait_event(vb->ack, vb_recv_buf(vb, qidx, NULL));
	inner->len += done;
	vb_config_write_actual(vb, idx, inner->len);

	mutex_unlock(&inner->lock);
	return done;
}

static u32 vb_inner_deflate(struct virtio_balloon *vb, u32 idx, u32 todo)
{
	BUG_ON(idx != I_NORMAL && idx != I_HETERO);
	u32 qidx = idx == I_NORMAL ? Q_DEFLATE : Q_HETERO_DEFLATE;
	struct virtio_balloon_inner *inner = &vb->inner[idx];
	todo = min(todo, inner->len);
	mutex_lock(&inner->lock);
	u32 done = 0;
	struct list_head pages = LIST_HEAD_INIT(pages);
	while (done < todo) {
		struct page *page = page_tracker_untrack(&inner->tracking);
		if (!page)
			break;
		inner->pfns[done++] = page_to_pfn(page);
		list_add(&page->lru, &pages);
	}
	vb_send_buf(vb, qidx, inner->pfns, sizeof(*inner->pfns) * done);
	wait_event(vb->ack, vb_recv_buf(vb, qidx, NULL));
	inner->len -= done;
	vb_config_write_actual(vb, idx, inner->len);

	struct page *page, *next;
	list_for_each_entry_safe(page, next, &pages, lru) {
		list_del(&page->lru);
		put_page(page);
	}

	mutex_unlock(&inner->lock);
	return done;
}

int vb_stat_push(struct virtio_balloon *vb, u16 tag, u64 val)
{
	struct virtio_balloon_stat_vec *vec = &vb->stats;
	if (vec->len >= ARRAY_SIZE(vec->items))
		return -EINVAL;
	vec->items[vec->len++] =
		(struct virtio_balloon_stat){ .tag = tag, .val = val };
	return 0;
}

void vb_stat_clear(struct virtio_balloon *vb)
{
	struct virtio_balloon_stat_vec *vec = &vb->stats;
	vec->len = 0;
}

static void vb_stats(struct virtio_balloon *vb)
{
	unsigned long events[NR_VM_EVENT_ITEMS] = {};
	all_vm_events(events);
	struct sysinfo global = {}, normal = {}, hetero = {};
	si_meminfo(&global);
	si_meminfo_node(&normal, first_node(node_states[N_MEMORY]));
	si_meminfo_node(&hetero, last_node(node_states[N_MEMORY]));

	// clang-format off
	u64 items[T_MAX] = {
		[T_SWAP_IN]       = events[PSWPIN],
		[T_SWAP_OUT]      = events[PSWPOUT],
		[T_MAJFLT]        = events[PGMAJFAULT],
		[T_MINFLT]        = events[PGFAULT],
		[T_MEMFREE]       = global.freeram * global.mem_unit,
		[T_MEMTOT]        = global.totalram * global.mem_unit,
		[T_AVAIL]         = si_mem_available() << PAGE_SHIFT,
		[T_CACHES]        = global_node_page_state(NR_FILE_PAGES) << PAGE_SHIFT,
		[T_HTLB_PGALLOC]  = events[HTLB_BUDDY_PGALLOC],
		[T_HTLB_PGFAIL]   = events[HTLB_BUDDY_PGALLOC_FAIL],
		// FIXME: DRAM access accounting
		// [T_NORMAL_ACCESS] = events[DRAM_ACCESS],
		[T_NORMAL_FREE]   = normal.freeram * normal.mem_unit,
		[T_NORMAL_TOTAL]  = normal.totalram * normal.mem_unit,
		// FIXME: PMEM access accounting
		// [T_HETERO_ACCESS] = events[PMEM_ACCESS],
		[T_HETERO_FREE]   = hetero.freeram * hetero.mem_unit,
		[T_HETERO_TOTAL]  = hetero.totalram * hetero.mem_unit,
	};
	// clang-format on

	vb_stat_clear(vb);
	for (u64 i = 0; i < ARRAY_SIZE(items); ++i) {
		vb_stat_push(vb, i, items[i]);
	}

	vb_send_buf(vb, Q_STATS, vb->stats.items,
		    sizeof(*vb->stats.items) * ARRAY_SIZE(vb->stats.items));
}

static void vb_stats_initial(struct virtio_balloon *vb)
{
	if (!vb_acked(vb, F_STATS))
		return;
	vb_stats(vb);
	dev_info(&vb->vdev->dev, "%s done\n", __func__);
}

static void vb_work_fn_inflate(struct work_struct *work)
{
	struct virtio_balloon *vb =
		container_of(work, struct virtio_balloon, work[Q_INFLATE]);
	struct virtio_balloon_tracepoints *t = &vb->tracepoints[Q_INFLATE];

	u64 chunk_begin = local_clock(),
	    *work_elapsed = &t->work_elapsed,
	    *total_elapsed = &t->total_elapsed;

	s64 todo = vb_inner_diff_from_target(vb, I_NORMAL);
	if (todo <= 0)
		return;
	u32 done = vb_inner_inflate(vb, I_NORMAL, todo);

	*work_elapsed += local_clock() - chunk_begin;

	if (done < todo) {
		queue_work(system_freezable_wq, &vb->work[Q_INFLATE]);
	} else {
		dev_info(&vb->vdev->dev, "%s: took %llu ms\n", __func__,
			 *work_elapsed / 1000 / 1000);
		*total_elapsed += *work_elapsed;
		*work_elapsed = 0;
	}
}

static void vb_work_fn_deflate(struct work_struct *work)
{
	struct virtio_balloon *vb =
		container_of(work, struct virtio_balloon, work[Q_DEFLATE]);
	struct virtio_balloon_tracepoints *t = &vb->tracepoints[Q_DEFLATE];

	u64 chunk_begin = local_clock(),
	    *work_elapsed = &t->work_elapsed,
	    *total_elapsed = &t->total_elapsed;

	s64 todo = -vb_inner_diff_from_target(vb, I_NORMAL);
	if (todo <= 0)
		return;
	u32 done = vb_inner_deflate(vb, I_NORMAL, todo);

	*work_elapsed += local_clock() - chunk_begin;

	if (done < todo) {
		queue_work(system_freezable_wq, &vb->work[Q_DEFLATE]);
	} else {
		dev_info(&vb->vdev->dev, "%s: took %llu ms\n", __func__,
			 *work_elapsed / 1000 / 1000);
		*total_elapsed += *work_elapsed;
		*work_elapsed = 0;
	}
}

static void vb_work_fn_stats(struct work_struct *work)
{
	struct virtio_balloon *vb =
		container_of(work, struct virtio_balloon, work[Q_STATS]);

	// We can only reach here by the user buffer notification callback.
	// So we first need to remove that buffer
	vb_recv_buf(vb, Q_STATS, NULL);
	vb_stats(vb);
}

static void vb_work_fn_reporting(struct work_struct *work)
{
	struct virtio_balloon *vb =
		container_of(work, struct virtio_balloon, work[Q_REPORTING]);

	// TODO
}

static void vb_work_fn_hetero_inflate(struct work_struct *work)
{
	struct virtio_balloon *vb = container_of(work, struct virtio_balloon,
						 work[Q_HETERO_INFLATE]);
	struct virtio_balloon_tracepoints *t =
		&vb->tracepoints[Q_HETERO_INFLATE];
	u64 chunk_begin = local_clock(),
	    *work_elapsed = &t->work_elapsed,
	    *total_elapsed = &t->total_elapsed;
	s64 todo = vb_inner_diff_from_target(vb, I_HETERO);
	if (todo <= 0)
		return;
	u32 done = vb_inner_inflate(vb, I_HETERO, todo);
	*work_elapsed += local_clock() - chunk_begin;
	if (done < todo) {
		queue_work(system_freezable_wq, &vb->work[Q_HETERO_INFLATE]);
	} else {
		dev_info(&vb->vdev->dev, "%s: took %llu ms\n", __func__,
			 *work_elapsed / 1000 / 1000);
		*total_elapsed += *work_elapsed;
		*work_elapsed = 0;
	}
}

static void vb_work_fn_hetero_deflate(struct work_struct *work)
{
	struct virtio_balloon *vb = container_of(work, struct virtio_balloon,
						 work[Q_HETERO_DEFLATE]);
	struct virtio_balloon_tracepoints *t =
		&vb->tracepoints[Q_HETERO_DEFLATE];
	u64 chunk_begin = local_clock(),
	    *work_elapsed = &t->work_elapsed,
	    *total_elapsed = &t->total_elapsed;
	s64 todo = -vb_inner_diff_from_target(vb, I_HETERO);
	if (todo <= 0)
		return;
	u32 done = vb_inner_deflate(vb, I_HETERO, todo);
	*work_elapsed += local_clock() - chunk_begin;
	if (done < todo) {
		queue_work(system_freezable_wq, &vb->work[Q_HETERO_DEFLATE]);
	} else {
		dev_info(&vb->vdev->dev, "%s: took %llu ms\n", __func__,
			 *work_elapsed / 1000 / 1000);
		*total_elapsed += *work_elapsed;
		*work_elapsed = 0;
	}
}

static void vb_work_queue(struct virtio_balloon *vb)
{
	// clang-format off
	struct work_struct *works[Q_MAX] = {
		[Q_INFLATE] = &vb->work[Q_INFLATE],
		[Q_DEFLATE] = &vb->work[Q_DEFLATE],
		// CAVEAT: driven by the host's used buffer notification
		// [Q_STATS] = vb_acked(vb, F_STATS) ? &vb->work[Q_STATS] : NULL,
		[Q_HETERO_INFLATE] = vb_acked(vb, F_HETERO) ? &vb->work[Q_HETERO_INFLATE] : NULL,
		[Q_HETERO_DEFLATE] = vb_acked(vb, F_HETERO) ? &vb->work[Q_HETERO_DEFLATE] : NULL,
	};
	// clang-format on
	scoped_guard(spinlock_irqsave, &vb->queue_work)
	{
		if (atomic_read(&vb->should_exit)) {
			return;
		}
		for (u64 i = 0; i < ARRAY_SIZE(works); ++i) {
			if (!works[i] || !works[i]->func) {
				continue;
			}
			queue_work(system_freezable_wq, works[i]);
		}
	}
	dev_info(&vb->vdev->dev, "%s done\n", __func__);
}

static void vb_work_stop(struct virtio_balloon *vb)
{
	scoped_guard(spinlock_irqsave, &vb->queue_work)
	{
		atomic_set(&vb->should_exit, 1);
		for (u64 i = 0; i < ARRAY_SIZE(vb->work); ++i) {
			struct work_struct *work = &vb->work[i];
			if (!work->func)
				continue;
			cancel_work_sync(work);
		}
	}
}

static int vb_work_init(struct virtio_balloon *vb)
{
	dev_info(&vb->vdev->dev, "%s started\n", __func__);

	// clang-format off
	struct work_struct *works[Q_MAX] = {
		[Q_INFLATE]   = &vb->work[Q_INFLATE],
		[Q_DEFLATE]   = &vb->work[Q_DEFLATE],
		[Q_STATS]     = vb_acked(vb, F_STATS) ? &vb->work[Q_STATS] : NULL,
		[Q_REPORTING] = vb_acked(vb, F_REPORT) ? &vb->work[Q_REPORTING] : NULL,
		[Q_HETERO_INFLATE] = vb_acked(vb, F_HETERO) ? &vb->work[Q_HETERO_INFLATE] : NULL,
		[Q_HETERO_DEFLATE] = vb_acked(vb, F_HETERO) ? &vb->work[Q_HETERO_DEFLATE] : NULL,
	};
	work_func_t fns[Q_MAX] = {
		[Q_INFLATE]   = vb_work_fn_inflate,
		[Q_DEFLATE]   = vb_work_fn_deflate,
		[Q_STATS]     = vb_acked(vb, F_STATS) ? vb_work_fn_stats : NULL,
		[Q_REPORTING] = vb_acked(vb, F_REPORT) ? vb_work_fn_reporting : NULL,
		[Q_HETERO_INFLATE] = vb_acked(vb, F_HETERO) ? vb_work_fn_hetero_inflate : NULL,
		[Q_HETERO_DEFLATE] = vb_acked(vb, F_HETERO) ? vb_work_fn_hetero_deflate : NULL,
	};
	// clang-format on
	for (u64 i = 0; i < ARRAY_SIZE(works); ++i) {
		if (!works[i] || !fns[i]) {
			continue;
		}
		INIT_WORK(works[i], fns[i]);
	}
	spin_lock_init(&vb->queue_work);
	dev_info(&vb->vdev->dev, "%s done\n", __func__);
	return 0;
}

static int vb_vqs_init(struct virtio_balloon *vb)
{
	dev_info(&vb->vdev->dev, "%s started\n", __func__);

	// clang-format off
	vq_callback_t *callbacks[Q_MAX] = {
		[Q_INFLATE]   = vb_callback_ack,
		[Q_DEFLATE]   = vb_callback_ack,
		[Q_STATS]     = vb_acked(vb, F_STATS) ? vb_callback_stats_request : NULL,
		[Q_REPORTING] = vb_acked(vb, F_REPORT) ? vb_callback_ack : NULL,
		[Q_HETERO_INFLATE] = vb_acked(vb, F_HETERO) ? vb_callback_ack : NULL,
		[Q_HETERO_DEFLATE] = vb_acked(vb, F_HETERO) ? vb_callback_ack : NULL,
	};
	char const *names[Q_MAX] = {
		[Q_INFLATE]   = "inflate",
		[Q_DEFLATE]   = "deflate",
		[Q_STATS]     = vb_acked(vb, F_STATS) ? "stats" : NULL,
		[Q_REPORTING] = vb_acked(vb, F_REPORT) ? "reporting" : NULL,
		[Q_HETERO_INFLATE] = vb_acked(vb, F_HETERO) ? "hetero-inflate" : NULL,
		[Q_HETERO_DEFLATE] = vb_acked(vb, F_HETERO) ? "hetero-deflate" : NULL,
	};
	// clang-format on

	TRY(virtio_find_vqs(vb->vdev, ARRAY_SIZE(vb->vqs), vb->vqs, callbacks,
			    names, NULL));

	dev_info(&vb->vdev->dev, "%s done\n", __func__);
	return 0;
}
static void vb_vqs_drop(struct virtio_balloon *vb)
{
	vb->vdev->config->del_vqs(vb->vdev);
}

static int vb_oom(struct notifier_block *nb, unsigned long _0, void *freed)
{
	struct virtio_balloon *vb =
		container_of(nb, struct virtio_balloon, oom_notification);

	u32 idx = vb_acked(vb, F_HETERO) ? I_HETERO : I_NORMAL;
	pr_warn_ratelimited("%s: deflate %d pages via %s vq\n", __func__,
			    VIRTIO_BALLOON_OOM_NR_PAGES,
			    idx == I_NORMAL ? "normal" : "hetero");
	vb_inner_deflate(vb, idx, VIRTIO_BALLOON_OOM_NR_PAGES);
	return NOTIFY_OK;
}

static int vb_init(struct virtio_balloon *vb, struct virtio_device *vdev)
{
	memset(vb, 0, sizeof(*vb));
	vb->vdev = vdev;
	vdev->priv = vb;
	dev_info(&vdev->dev, "%s started: vb=0x%px\n", __func__, vb);

	atomic_set(&vb->should_exit, 0);

	TRY(vb_vqs_init(vb));
	TRY(vb_work_init(vb));

	int err = 0;
	if (vb_acked(vb, F_OOM)) {
		vb->oom_notification.notifier_call = vb_oom;
		vb->oom_notification.priority =
			VIRTIO_BALLOON_OOM_NOTIFY_PRIORITY;
		err = register_oom_notifier(&vb->oom_notification);
		if (err)
			goto err_oom;
	}
	init_waitqueue_head(&vb->ack);
	for (u64 i = 0; i < ARRAY_SIZE(vb->inner); ++i) {
		struct virtio_balloon_inner *inner = &vb->inner[i];
		mutex_init(&inner->lock);
		page_tracker_init(&inner->tracking);
	}
	virtio_device_ready(vdev);
	dev_info(&vdev->dev, "virtio-balloon device registered\n");
	// stats queue require an initial stat item to kick-start
	vb_stats_initial(vb);
	// inflate/deflation starts as soon as balloon is ready
	vb_work_queue(vb);

	dev_info(&vb->vdev->dev, "%s done\n", __func__);
	return 0;

err_oom:
	if (vb_acked(vb, F_OOM))
		unregister_oom_notifier(&vb->oom_notification);
err_vqs_drop:
	vb_vqs_drop(vb);
	return err;
}

static void vb_stop(struct virtio_balloon *vb)
{
	if (vb_acked(vb, F_REPORT)) {
		// TODO: page_reporting_unregister()
	}
	if (vb_acked(vb, F_OOM)) {
		unregister_oom_notifier(&vb->oom_notification);
	}
	vb_work_stop(vb);
	for (u64 i = 0; i < ARRAY_SIZE(vb->inner); ++i) {
		struct virtio_balloon_inner *inner = &vb->inner[i];
		vb_inner_deflate(vb, i, inner->len);
	}
}

static void vb_reset(struct virtio_balloon *vb)
{
	virtio_reset_device(vb->vdev);
}

static void vb_drop(struct virtio_balloon *vb)
{
	vb_stop(vb);
	// TODO: mutex_destroy
	// for (u64 i = 0; i < ARRAY_SIZE(vb->inner); ++i) {
	// 	struct virtio_balloon_inner *inner = &vb->inner[i];
	// 	mutex_destroy(&inner->lock);
	// }
	vb_reset(vb);
	vb_vqs_drop(vb);
	return;
}

static int validate(struct virtio_device *vdev)
{
	BUILD_BUG_ON(PAGE_SHIFT != VIRTIO_BALLOON_PFN_SHIFT);

	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	if (virtio_has_feature(vdev, F_HETERO) &&
	    num_node_state(N_MEMORY) < 2) {
		dev_err(&vdev->dev,
			"%s failure: no heterogeneous memory presents\n",
			__func__);
		return -EINVAL;
	}

	__virtio_clear_bit(vdev, VIRTIO_F_ACCESS_PLATFORM);
	return 0;
}

static int probe(struct virtio_device *vdev)
{
	if (!vdev) {
		return -EINVAL;
	}
	struct virtio_balloon *vb = kvzalloc(sizeof(*vb), GFP_KERNEL);
	if (!vb) {
		return -ENOMEM;
	}

	TRY(vb_init(vb, vdev));
	return 0;
}

static void config_changed(struct virtio_device *vdev)
{
	struct virtio_balloon *vb = vdev->priv;
	vb_work_queue(vb);
}

static void remove(struct virtio_device *vdev)
{
	struct virtio_balloon *vb = vdev->priv;

	vb_drop(vb);
	kvfree(vb);
}

static int freeze(struct virtio_device *vdev)
{
	return -EINVAL;
}

static int restore(struct virtio_device *vdev)
{
	return -EINVAL;
}

static struct virtio_driver virtio_balloon_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.validate = validate,
	.probe = probe,
	.remove = remove,
	.config_changed = config_changed,
};

module_virtio_driver(virtio_balloon_driver);
MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_AUTHOR("Junliang Hu <jlhu@cse.cuhk.edu.hk>");
MODULE_DESCRIPTION("Enhanced Virtio balloon driver");
MODULE_LICENSE("GPL");
