#ifndef _LINUX_FSIO_CGGROUP_H
#define _LINUX_FSIO_CGGROUP_H

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/cgroup.h>
#include <linux/workqueue.h>
#include <linux/percpu_counter.h>

#ifdef CONFIG_FSIO_CGROUP

struct fsio_cgroup {
	struct cgroup_subsys_state css;
	struct percpu_counter read_bytes;
	struct percpu_counter write_bytes;
	struct percpu_counter nr_dirty;
	struct percpu_counter nr_writeback;
};

static inline struct fsio_cgroup *fsio_css_cgroup(struct cgroup_subsys_state *css)
{
	return container_of(css, struct fsio_cgroup, css);
}

static inline struct fsio_cgroup *fsio_parent_cgroup(struct fsio_cgroup *fsio)
{
	BUILD_BUG_ON(offsetof(struct fsio_cgroup, css));
	return fsio_css_cgroup(fsio->css.parent);
}

static inline struct fsio_cgroup *fsio_task_cgroup(struct task_struct *task)
{
	return fsio_css_cgroup(task_css(task, fsio_cgrp_id));
}

/*
 * This accounts all reads, both cached and direct-io
 */
static inline void fsio_account_read(unsigned long bytes)
{
	struct fsio_cgroup *fsio;

	rcu_read_lock();
	fsio = fsio_task_cgroup(current);
	__percpu_counter_add(&fsio->read_bytes, bytes,
			     PAGE_CACHE_SIZE * percpu_counter_batch);
	rcu_read_unlock();
}

/*
 * This is used for accounting direct-io writes
 */
static inline void fsio_account_write(unsigned long bytes)
{
	struct fsio_cgroup *fsio;

	rcu_read_lock();
	fsio = fsio_task_cgroup(current);
	__percpu_counter_add(&fsio->write_bytes, bytes,
			     PAGE_CACHE_SIZE * percpu_counter_batch);
	rcu_read_unlock();
}

/*
 * This called under mapping->tree_lock before setting radix-tree tag.
 */
static inline void fsio_account_page_dirtied(struct address_space *mapping)
{
	struct fsio_cgroup *fsio = mapping->i_fsio;

	lockdep_assert_held(&mapping->tree_lock);
	if (unlikely(!fsio || !(mapping_tags(mapping) &
	    (BIT(PAGECACHE_TAG_DIRTY) | BIT(PAGECACHE_TAG_WRITEBACK))))) {
		struct fsio_cgroup *task_fsio;

		rcu_read_lock();
		task_fsio = fsio_task_cgroup(current);
		if (task_fsio != fsio) {
			if (fsio)
				css_put(&fsio->css);
			css_get(&task_fsio->css);
			fsio = mapping->i_fsio = task_fsio;
		}
		rcu_read_unlock();
	}

	for (; fsio; fsio = fsio_parent_cgroup(fsio))
		percpu_counter_inc(&fsio->nr_dirty);
}

/*
 * This called after clearing dirty bit without mapping->tree_lock.
 */
static inline void fsio_clear_page_dirty(struct address_space *mapping)
{
	struct fsio_cgroup *fsio = mapping->i_fsio;

	for (; fsio; fsio = fsio_parent_cgroup(fsio))
		percpu_counter_dec(&fsio->nr_dirty);
}

/*
 * This called after clearing dirty bit before removing from page cache
 * without mapping->tree_lock.
 */
static inline void fsio_cancel_dirty_page(struct address_space *mapping)
{
	struct fsio_cgroup *fsio = mapping->i_fsio;

	for (; fsio; fsio = fsio_parent_cgroup(fsio))
		percpu_counter_dec(&fsio->nr_dirty);
}

/*
 * Called after setting writeback bit with mapping->tree_lock held.
 */
static inline void fsio_set_page_writeback(struct address_space *mapping)
{
	struct fsio_cgroup *fsio = mapping->i_fsio;

	if (WARN_ONCE(!fsio, "writeback called for clear page"))
		fsio = mapping->i_fsio = fsio_css_cgroup(
				init_css_set.subsys[fsio_cgrp_id]);

	for (; fsio; fsio = fsio_parent_cgroup(fsio))
		percpu_counter_inc(&fsio->nr_writeback);
}

/*
 * Called after clearing writeback bit with mapping->tree_lock held.
 */
static inline void fsio_clear_page_writeback(struct address_space *mapping)
{
	struct fsio_cgroup *fsio = mapping->i_fsio;

	__percpu_counter_add(&fsio->write_bytes, PAGE_CACHE_SIZE,
			     PAGE_CACHE_SIZE * percpu_counter_batch);
	for (; fsio; fsio = fsio_parent_cgroup(fsio))
		percpu_counter_dec(&fsio->nr_writeback);
}

/*
 * Called at evicting inode from cache after removing it from sb list.
 */
static inline void fsio_forget_inode(struct inode *inode)
{
	if (inode->i_mapping->i_fsio) {
		css_put(&inode->i_mapping->i_fsio->css);
		inode->i_mapping->i_fsio = NULL;
	}
}

#else /* CONFIG_FSIO_CGROUP */

static inline void fsio_account_read(unsigned long bytes) {}
static inline void fsio_account_write(unsigned long bytes) {}
static inline void fsio_account_page_dirtied(struct address_space *mapping) {}
static inline void fsio_clear_page_dirty(struct address_space *mapping) {}
static inline void fsio_cancel_dirty_page(struct address_space *mapping) {}
static inline void fsio_set_page_writeback(struct address_space *mapping) {}
static inline void fsio_clear_page_writeback(struct address_space *mapping) {}
static inline void fsio_forget_inode(struct inode *inode) {}

#endif /* CONFIG_FSIO_CGROUP */

#endif /* _LINUX_FSIO_CGGROUP_H */
