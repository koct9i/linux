#include <linux/fsio_cgroup.h>

static inline struct fsio_cgroup *cgroup_fsio(struct cgroup *cgroup)
{
	return container_of(cgroup_subsys_state(cgroup, fsio_subsys_id),
			    struct fsio_cgroup, css);
}

static void fsio_free(struct fsio_cgroup *fsio)
{
	percpu_counter_destroy(&fsio->read_bytes);
	percpu_counter_destroy(&fsio->write_bytes);
	percpu_counter_destroy(&fsio->nr_dirty);
	percpu_counter_destroy(&fsio->nr_writeback);
	kfree(fsio);
}

static struct cgroup_subsys_state *fsio_css_alloc(struct cgroup *cgroup)
{
	struct fsio_cgroup *fsio;

	fsio = kzalloc(sizeof(struct fsio_cgroup), GFP_KERNEL);
	if (!fsio)
		return ERR_PTR(-ENOMEM);

	if (percpu_counter_init(&fsio->read_bytes, 0) ||
	    percpu_counter_init(&fsio->write_bytes, 0) ||
	    percpu_counter_init(&fsio->nr_dirty, 0) ||
	    percpu_counter_init(&fsio->nr_writeback, 0)) {
		fsio_free(fsio);
		return ERR_PTR(-ENOMEM);
	}

	return &fsio->css;
}

/*
 * Yep, ugly. As alternative we can switch fsio_writeback for all inodes in all
 * superblocks to the root cgroup and commit remaineded page counters into it.
 */
static void fsio_destroy(struct work_queue *work)
{
	struct fsio_cgroup *fsio = container_of(work,
			struct fsio_cgroup, destroy.work);

	if (percpu_counter_sum(&fsio->nr_dirty) ||
	    percpu_counter_sum(&fsio->nr_writeback))
		schedule_delayed_work(&fsio->destroy, HZ);
	else
		fsio_free(fsio);
}

static void fsio_css_free(struct cgroup *cgroup)
{
	struct fsio_cgroup *fsio = cgroup_fsio(cgroup);

	INIT_DEFERRABLE_WORK(&fsio->destroy, fsio_destroy);
	fsio_destroy(&fsio->destroy.work);
}

static u64 fsio_get_read_bytes(struct cgroup *cgroup, struct cftype *cft)
{
	struct fsio_cgroup *fsio = cgroup_fsio(cgroup);

	return percpu_counter_sum(&fsio->read_bytes);
}

static u64 fsio_get_write_bytes(struct cgroup *cgroup, struct cftype *cft)
{
	struct fsio_cgroup *fsio = cgroup_fsio(cgroup);

	return percpu_counter_sum(&fsio->write_bytes);
}

static u64 fsio_get_dirty_bytes(struct cgroup *cgroup, struct cftype *cft)
{
	struct fsio_cgroup *fsio = cgroup_fsio(cgroup);

	return percpu_counter_sum_positive(&fsio->nr_dirty) * PAGE_CACHE_SIZE;
}

static u64 fsio_get_writeback_bytes(struct cgroup *cgroup, struct cftype *cft)
{
	struct fsio_cgroup *fsio = cgroup_fsio(cgroup);

	return percpu_counter_sum_positive(&fsio->nr_writeback) *
		PAGE_CACHE_SIZE;
}

static struct cftype fsio_files[] = {
	{
		.name = "read_bytes",
		.read_u64 = fsio_get_read_bytes,
	},
	{
		.name = "write_bytes",
		.read_u64 = fsio_get_write_bytes,
	},
	{
		.name = "dirty_bytes",
		.read_u64 = fsio_get_dirty_bytes,
	},
	{
		.name = "writeback_bytes",
		.read_u64 = fsio_get_writeback_bytes,
	},
	{ }	/* terminate */
};

struct cgroup_subsys fsio_subsys = {
	.name = "fsio",
	.subsys_id = fsio_subsys_id,
	.css_alloc = fsio_css_alloc,
	.css_free = fsio_css_free,
	.base_cftypes = fsio_files,
};
