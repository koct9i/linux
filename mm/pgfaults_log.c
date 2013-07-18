#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/slab.h>

#include "internal.h"

/* 0 means that logging is disabled */
unsigned int pagefaults_log_nr = 0;

#define PATH_BUF_SIZE 128

struct log_entry {
	struct list_head list;
	unsigned long timestamp;
	pid_t pid;
	pgoff_t offset;
	size_t path_offset;
	char path[PATH_BUF_SIZE];
};

static DEFINE_SPINLOCK(lock);
static unsigned int nr_entries;
static LIST_HEAD(log);

static inline struct log_entry* __pop_entry(void)
{
	struct log_entry *ret = NULL;

	if (!list_empty(&log)) {
		ret = list_first_entry(&log, struct log_entry, list);
		list_del(&ret->list);
		nr_entries--;
	}

	return ret;
}

static inline struct log_entry* pop_entry(void)
{
	struct log_entry *ret;

	spin_lock_irq(&lock);
	ret = __pop_entry();
	spin_unlock_irq(&lock);

	return ret;
}

static inline void push_entry(struct log_entry *entry)
{
	struct log_entry *tmp;
	LIST_HEAD(to_free);

	spin_lock_irq(&lock);

	nr_entries++;
	while (nr_entries > pagefaults_log_nr) {
		tmp = __pop_entry();
		if (entry)
			list_add_tail(&tmp->list, &to_free);
	}

	list_add_tail(&entry->list, &log);

	spin_unlock_irq(&lock);

	while (!list_empty(&to_free)) {
		tmp = list_first_entry(&to_free, struct log_entry, list);
		list_del(&tmp->list);
		kfree(tmp);
	}
}

void log_pagefault(struct file *file, pgoff_t offset)
{
	struct log_entry *log_entry;
	char *p;

	if (!pagefaults_log_nr)
		return;

	log_entry = kmalloc(sizeof(struct log_entry), GFP_KERNEL);
	if (!log_entry)
		return;

	log_entry->timestamp = jiffies;
	log_entry->pid = current->pid;
	log_entry->offset = offset;

	path_get(&file->f_path);
	p = d_path(&file->f_path, log_entry->path, PATH_BUF_SIZE);
	path_put(&file->f_path);

	if (p) {
		log_entry->path_offset = p - &log_entry->path[0];
		log_entry->path[PATH_BUF_SIZE - 1] = 0;
		if (log_entry->path_offset > PATH_BUF_SIZE - 1)
			log_entry->path_offset = PATH_BUF_SIZE - 1;
	} else {
		log_entry->path_offset = 0;
		log_entry->path[0] = 0;
	}

	push_entry(log_entry);
}

void* pagefaults_seq_start(struct seq_file *m, loff_t *pos)
{
	return (void*)pop_entry();
}

void pagefaults_seq_stop(struct seq_file *m, void *v)
{
}

void* pagefaults_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	return (void*)pop_entry();
}

int pagefaults_seq_show(struct seq_file *m, void *v)
{
	struct log_entry *entry = (struct log_entry *)v;

	if (entry) {
		seq_printf(m, "%lu:%d:%s:%lu\n",
			   entry->timestamp,
			   entry->pid,
			   entry->path + entry->path_offset,
			   entry->offset);
		kfree(entry);
	}

	return 0;
}

const struct seq_operations pagefaults_seq_ops = {
	.start = pagefaults_seq_start,
	.stop = pagefaults_seq_stop,
	.next = pagefaults_seq_next,
	.show = pagefaults_seq_show,
};

static int pagefaults_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &pagefaults_seq_ops);
}

static const struct file_operations pagefaults_proc_fops = {
	.open		= pagefaults_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

int pagefaults_log_nr_handler(struct ctl_table *table, int write,
			      void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	struct log_entry *entry;
	LIST_HEAD(to_free);

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (write && !ret) {
		spin_lock_irq(&lock);
		while (nr_entries > pagefaults_log_nr) {
			entry = __pop_entry();
			if (entry)
				list_add_tail(&entry->list, &to_free);
		}
		spin_unlock_irq(&lock);
	}

	while (!list_empty(&to_free)) {
		entry = list_first_entry(&to_free, struct log_entry, list);
		list_del(&entry->list);
		kfree(entry);
	}

	return ret;
}

static int __init proc_pagefaults_init(void)
{
	proc_create("pagefaults", 0, NULL, &pagefaults_proc_fops);
	return 0;
}
module_init(proc_pagefaults_init);
