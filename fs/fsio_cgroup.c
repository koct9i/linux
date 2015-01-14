#include <linux/fsio_cgroup.h>
#include <linux/slab.h>
#include "internal.h"

static void fsio_css_free(struct cgroup_subsys_state *css)
{
	struct fsio_cgroup *fsio = fsio_css_cgroup(css);

	percpu_counter_destroy(&fsio->read_bytes);
	percpu_counter_destroy(&fsio->write_bytes);
	percpu_counter_destroy(&fsio->nr_dirty);
	percpu_counter_destroy(&fsio->nr_writeback);
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
	    percpu_counter_init(&fsio->nr_writeback, 0, GFP_KERNEL)) {
		fsio_css_free(&fsio->css);
		return ERR_PTR(-ENOMEM);
	}

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

struct cgroup_subsys fsio_cgrp_subsys = {
	.css_alloc = fsio_css_alloc,
	.css_offline = fsio_css_offline,
	.css_free = fsio_css_free,
	.legacy_cftypes = fsio_files,
};
