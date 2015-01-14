#include <linux/fsio_cgroup.h>
#include <linux/backing-dev.h>
#include <linux/slab.h>
#include "internal.h"

static void fsio_css_free(struct cgroup_subsys_state *css)
{
	struct fsio_cgroup *fsio = fsio_css_cgroup(css);

	percpu_counter_destroy(&fsio->read_bytes);
	percpu_counter_destroy(&fsio->write_bytes);
	percpu_counter_destroy(&fsio->nr_dirty);
	percpu_counter_destroy(&fsio->nr_writeback);
	percpu_ratelimit_destroy(&fsio->bandwidth);
	kfree(fsio);
}

static struct cgroup_subsys_state *
fsio_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct fsio_cgroup *fsio;

	fsio = kzalloc(sizeof(struct fsio_cgroup), GFP_KERNEL);
	if (!fsio)
		return ERR_PTR(-ENOMEM);

	if (percpu_counter_init(&fsio->read_bytes, 0, GFP_KERNEL) ||
	    percpu_counter_init(&fsio->write_bytes, 0, GFP_KERNEL) ||
	    percpu_counter_init(&fsio->nr_dirty, 0, GFP_KERNEL) ||
	    percpu_counter_init(&fsio->nr_writeback, 0, GFP_KERNEL) ||
	    percpu_ratelimit_init(&fsio->bandwidth, GFP_KERNEL)) {
		fsio_css_free(&fsio->css);
		return ERR_PTR(-ENOMEM);
	}

	fsio->thresh = ULONG_MAX;
	fsio->bg_thresh = ULONG_MAX;

	return &fsio->css;
}

static void fsio_switch_one_sb(struct super_block *sb, void *_fsio)
{
	struct fsio_cgroup *fsio = _fsio;
	struct fsio_cgroup *parent = fsio_parent_cgroup(fsio);
	struct address_space *mapping;
	struct inode *inode;

	spin_lock(&inode_sb_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		mapping = inode->i_mapping;
		if (likely(rcu_access_pointer(mapping->i_fsio) != fsio))
			continue;
		spin_lock_irq(&mapping->tree_lock);
		if (rcu_access_pointer(mapping->i_fsio) == fsio) {
			rcu_assign_pointer(mapping->i_fsio, parent);
			css_get(&parent->css);
			css_put(&fsio->css);
		}
		spin_unlock_irq(&mapping->tree_lock);
	}
	spin_unlock(&inode_sb_list_lock);
}

static int fsio_css_online(struct cgroup_subsys_state *css)
{
	struct fsio_cgroup *fsio = fsio_css_cgroup(css);
	struct fsio_cgroup *parent = fsio_parent_cgroup(fsio);

	if (parent && test_bit(FSIO_dirty_limited, &parent->state))
		set_bit(FSIO_dirty_limited, &fsio->state);

	if (parent && test_bit(FSIO_bandwidth_limited, &parent->state))
		set_bit(FSIO_bandwidth_limited, &fsio->state);

	return 0;
}

static void fsio_css_offline(struct cgroup_subsys_state *css)
{
	struct fsio_cgroup *fsio = fsio_css_cgroup(css);
	struct fsio_cgroup *parent = fsio_parent_cgroup(fsio);

	/* Switch all ->i_fsio references to the parent cgroup */
	iterate_supers(fsio_switch_one_sb, fsio);

	percpu_counter_add(&parent->read_bytes,
			percpu_counter_sum(&fsio->read_bytes));
	percpu_counter_add(&parent->write_bytes,
			percpu_counter_sum(&fsio->write_bytes));
}

static u64 fsio_get_read_bytes(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct cgroup_subsys_state *pos;
	u64 sum = 0;

	css_for_each_descendant_pre(pos, css)
		sum += percpu_counter_sum(&fsio_css_cgroup(pos)->read_bytes);

	return sum;
}

static u64 fsio_get_write_bytes(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct cgroup_subsys_state *pos;
	u64 sum = 0;

	css_for_each_descendant_pre(pos, css)
		sum += percpu_counter_sum(&fsio_css_cgroup(pos)->write_bytes);

	return sum;
}

static u64 fsio_get_dirty_bytes(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return percpu_counter_sum_positive(&fsio_css_cgroup(css)->
			nr_dirty) * PAGE_CACHE_SIZE;
}

static u64 fsio_get_writeback_bytes(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return percpu_counter_sum_positive(&fsio_css_cgroup(css)->
			nr_writeback) * PAGE_CACHE_SIZE;
}

static u64 fsio_get_dirty_limit(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct fsio_cgroup *fsio = fsio_css_cgroup(css);

	if (fsio->thresh == ULONG_MAX)
		return 0;

	return fsio->thresh * PAGE_CACHE_SIZE;
}

static int fsio_set_dirty_limit(struct cgroup_subsys_state *css,
				    struct cftype *cft, u64 val)
{
	struct fsio_cgroup *fsio = fsio_css_cgroup(css);
	struct cgroup_subsys_state *pos;

	if (val == 0) {
		fsio->thresh = ULONG_MAX;
		fsio->bg_thresh = ULONG_MAX;
	} else {
		fsio->thresh = val >> PAGE_CACHE_SHIFT;
		/* Small limits might be a problem for per-cpu counters */
		fsio->thresh = max(fsio->thresh, 2ul *
				percpu_counter_batch * num_online_cpus());
		fsio->bg_thresh = fsio->thresh / 2;
	}

	rcu_read_lock();
	css_for_each_descendant_pre(pos, css) {
		struct fsio_cgroup *fsio = fsio_css_cgroup(pos);
		struct fsio_cgroup *parent = fsio_parent_cgroup(fsio);

		if (!(pos->flags & CSS_ONLINE))
			continue;

		if (fsio->thresh != ULONG_MAX ||
		    (parent && test_bit(FSIO_dirty_limited, &parent->state)))
			set_bit(FSIO_dirty_limited, &fsio->state);
		else
			clear_bit(FSIO_dirty_limited, &fsio->state);
	}
	rcu_read_unlock();

	return 0;
}

static u64 fsio_get_bandwidth_bytes(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct fsio_cgroup *fsio = fsio_css_cgroup(css);

	return percpu_ratelimit_sum(&fsio->bandwidth);
}

static u64 fsio_get_bandwidth_limit(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct fsio_cgroup *fsio = fsio_css_cgroup(css);

	return percpu_ratelimit_quota(&fsio->bandwidth, NSEC_PER_SEC);
}

static int fsio_set_bandwidth_limit(struct cgroup_subsys_state *css,
				    struct cftype *cft, u64 val)
{
	struct fsio_cgroup *fsio = fsio_css_cgroup(css);
	struct cgroup_subsys_state *pos;

	percpu_ratelimit_setup(&fsio->bandwidth, val, NSEC_PER_SEC);

	rcu_read_lock();
	css_for_each_descendant_pre(pos, css) {
		struct fsio_cgroup *child = fsio_css_cgroup(pos);
		struct fsio_cgroup *parent = fsio_parent_cgroup(child);

		if (!(pos->flags & CSS_ONLINE))
			continue;

		if (child->bandwidth.quota != ULLONG_MAX ||
		    (parent && test_bit(FSIO_bandwidth_limited, &parent->state)))
			set_bit(FSIO_bandwidth_limited, &child->state);
		else
			clear_bit(FSIO_bandwidth_limited, &child->state);
	}
	rcu_read_unlock();

	return 0;
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
	{
		.name = "dirty_limit",
		.read_u64 = fsio_get_dirty_limit,
		.write_u64 = fsio_set_dirty_limit,
	},
	{
		.name = "bandwidth_bytes",
		.read_u64 = fsio_get_bandwidth_bytes,
	},
	{
		.name = "bandwidth_limit",
		.read_u64 = fsio_get_bandwidth_limit,
		.write_u64 = fsio_set_bandwidth_limit,
	},
	{ }	/* terminate */
};

struct cgroup_subsys fsio_cgrp_subsys = {
	.css_alloc = fsio_css_alloc,
	.css_online = fsio_css_online,
	.css_offline = fsio_css_offline,
	.css_free = fsio_css_free,
	.legacy_cftypes = fsio_files,
};

bool fsio_dirty_limits(struct address_space *mapping, unsigned long *pdirty,
		       unsigned long *pthresh, unsigned long *pbg_thresh)
{
	struct backing_dev_info *bdi = mapping->backing_dev_info;
	unsigned long dirty, thresh, bg_thresh;
	struct fsio_cgroup *fsio;

	rcu_read_lock();
	fsio = fsio_task_cgroup(current);
	for (; fsio; fsio = fsio_parent_cgroup(fsio)) {
		if (!test_bit(FSIO_dirty_limited, &fsio->state))
			break;
		dirty = percpu_counter_read_positive(&fsio->nr_dirty) +
			percpu_counter_read_positive(&fsio->nr_writeback);
		thresh = fsio->thresh;
		bg_thresh = fsio->bg_thresh;
		if (dirty > bg_thresh) {
			if (!test_bit(FSIO_dirty_exceeded, &fsio->state))
				set_bit(FSIO_dirty_exceeded, &fsio->state);
			if (percpu_ratelimit_blocked(&fsio->bandwidth))
				inject_delay(percpu_ratelimit_target(&fsio->bandwidth));
			rcu_read_unlock();
			if (dirty > (bg_thresh + thresh) / 2 &&
			    !test_and_set_bit(BDI_fsio_writeback_running, &bdi->state))
				bdi_start_writeback(bdi, dirty - bg_thresh,
						WB_REASON_FSIO_CGROUP);
			*pdirty = dirty;
			*pthresh = thresh;
			*pbg_thresh = bg_thresh;
			return true;
		}
	}
	rcu_read_unlock();

	return false;
}

bool fsio_dirty_exceeded(struct inode *inode)
{
	struct address_space *mapping = inode->i_mapping;
	struct fsio_cgroup *fsio;
	unsigned long dirty;

	if (mapping->backing_dev_info->dirty_exceeded)
		return true;

	rcu_read_lock();
	fsio = fsio_mapping_cgroup(mapping);
	for (; fsio; fsio = fsio_parent_cgroup(fsio)) {
		if (!test_bit(FSIO_dirty_limited, &fsio->state)) {
			fsio = NULL;
			break;
		}
		if (!test_bit(FSIO_dirty_exceeded, &fsio->state))
			continue;
		dirty = percpu_counter_read_positive(&fsio->nr_dirty) +
			percpu_counter_read_positive(&fsio->nr_writeback);
		if (dirty > fsio->bg_thresh)
			break;
		clear_bit(FSIO_dirty_exceeded, &fsio->state);
	}
	rcu_read_unlock();

	return fsio != NULL;
}
