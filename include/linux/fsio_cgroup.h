#ifndef _LINUX_FSIO_CGGROUP_H
#define _LINUX_FSIO_CGGROUP_H

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/cgroup.h>
#include <linux/workqueue.h>
#include <linux/percpu_counter.h>
#include <linux/ratelimit.h>

struct fsio_cgroup {
	union {
		struct cgroup_subsys_state css;
		struct delayed_work destroy;
	};
	struct percpu_counter read_bytes;
	struct percpu_counter write_bytes;
	struct percpu_counter nr_dirty;
	struct percpu_counter nr_writeback;
	struct percpu_ratelimit bandwidth_bytes;
};

#ifdef CONFIG_FSIO_CGROUP

static inline struct fsio_cgroup *current_fsio_cgroup(void)
{
	return container_of(task_subsys_state(current, fsio_subsys_id),
			struct fsio_cgroup, css);
}

/*
 * This accounts all reads, both cached and direct-io.
 *
 * Unfortunately at this layer isn't so easy to get bdi or something similar
 * for implementing independent accounting for each pair (fsio-cgroup, bdi).
 */
static inline void fsio_account_read(unsigned long bytes)
{
	struct fsio_cgroup *fsio;

	rcu_read_lock();
	fsio = current_fsio_cgroup();
	__percpu_counter_add(&fsio->read_bytes, bytes,
			PAGE_CACHE_SIZE * percpu_counter_batch);
	percpu_ratelimit_charge(&fsio->bandwidth_bytes, bytes);
	rcu_read_unlock();
}

/*
 * This is used for accounting  direct-io writes.
 */
static inline void fsio_account_write(unsigned long bytes)
{
	struct fsio_cgroup *fsio;

	rcu_read_lock();
	fsio = current_fsio_cgroup();
	__percpu_counter_add(&fsio->write_bytes, bytes,
			PAGE_CACHE_SIZE * percpu_counter_batch);
	percpu_ratelimit_charge(&fsio->bandwidth_bytes, bytes);
	rcu_read_unlock();
}

static inline void fsio_account_read_syscall(void)
{
	struct fsio_cgroup *fsio;

	rcu_read_lock();
	fsio = current_fsio_cgroup();
	if (fsio->bandwidth_bytes.target_time.tv64 > ktime_get().tv64)
		delay_injection_target(fsio->bandwidth_bytes.target_time);
	rcu_read_unlock();
}

static inline void fsio_account_write_syscall(void)
{
	struct fsio_cgroup *fsio;

	rcu_read_lock();
	fsio = current_fsio_cgroup();
	if (fsio->bandwidth_bytes.target_time.tv64 > ktime_get().tv64)
		delay_injection_target(fsio->bandwidth_bytes.target_time);
	rcu_read_unlock();
}

/*
 * This called under mapping->tree_lock before setting radix-tree tag.
 * May be called for locked (write) or mapped (unmap) pages.
 */
static inline void fsio_account_page_dirtied(struct address_space *mapping)
{
	struct fsio_cgroup *fsio;

	if (mapping_tagged(mapping, PAGECACHE_TAG_DIRTY) ||
	    mapping_tagged(mapping, PAGECACHE_TAG_WRITEBACK)) {
		fsio = mapping->fsio_writeback;
		percpu_counter_inc(&fsio->nr_dirty);
	} else {
		/*
		 * This is first dirty page and there is no writeback. Here we
		 * store current cgroup. Following call radix_tree_tag_set()
		 * will pin this pointer till the end of last writeback.
		 */
		rcu_read_lock();
		fsio = current_fsio_cgroup();
		mapping->fsio_writeback = fsio;
		percpu_counter_inc(&fsio->nr_dirty);
		rcu_read_unlock();
	}
}

/*
 * This called after clearing dirty bit. Page here locked and unmapped,
 * thus dirtying process is complete and fsio_writeback already valid.
 * And it's stable because at this point page still in mapping and tagged.
 */
static inline void fsio_cancel_dirty_page(struct address_space *mapping)
{
	struct fsio_cgroup *fsio = mapping->fsio_writeback;

	percpu_counter_dec(&fsio->nr_dirty);
}

/*
 * This called after redirtying page, thus nr_dirty will not fall to zero.
 */
static inline void fsio_account_page_redirty(struct address_space *mapping)
{
	struct fsio_cgroup *fsio = mapping->fsio_writeback;

	percpu_counter_dec(&fsio->nr_dirty);
}

/*
 * This switches page accounging from dirty to writeback,
 * after that nr_writeback will keep this cgroup alive.
 */
static inline void fsio_set_page_writeback(struct address_space *mapping)
{
	struct fsio_cgroup *fsio = mapping->fsio_writeback;

	percpu_counter_inc(&fsio->nr_writeback);
	/* FIXME do we need some sort of barrier instruction here? */
	percpu_counter_dec(&fsio->nr_dirty);
}

/*
 * Writeback is done, fsio_writeback pointer becomes invalid after that.
 * Cgroup can be destroied if both nr_dirty and nr_writeback are zero.
 */
static inline void fsio_clear_page_writeback(struct address_space *mapping)
{
	struct fsio_cgroup *fsio = mapping->fsio_writeback;

	__percpu_counter_add(&fsio->write_bytes, PAGE_CACHE_SIZE,
			PAGE_CACHE_SIZE * percpu_counter_batch);
	percpu_counter_dec(&fsio->nr_writeback);
}

#else /* CONFIG_FSIO_CGROUP */

static inline void fsio_account_read(unsigned long bytes) {}
static inline void fsio_account_write(unsigned long bytes) {}
static inline void fsio_account_read_syscall(void) {}
static inline void fsio_account_write_syscall(void) {}
static inline void fsio_account_page_dirtied(struct address_space *mapping) {}
static inline void fsio_cancel_dirty_page(struct address_space *mapping) {}
static inline void fsio_account_page_redirty(struct address_space *mapping) {}
static inline void fsio_set_page_writeback(struct address_space *mapping) {}
static inline void fsio_clear_page_writeback(struct address_space *mapping) {}

#endif /* CONFIG_FSIO_CGROUP */

#endif /* _LINUX_FSIO_CGGROUP_H */
