#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/ratelimit.h>
#include <linux/spinlock.h>
#include <linux/cpumask.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <linux/kernel_stat.h>
#include <linux/err.h>

#include "sched.h"

/*
 * CPU accounting code for task groups.
 *
 * Based on the work by Paul Menage (menage@google.com) and Balbir Singh
 * (balbir@in.ibm.com).
 */

/* Time spent by the tasks of the cpu accounting group executing in ... */
enum cpuacct_stat_index {
	CPUACCT_STAT_USER,	/* ... user mode */
	CPUACCT_STAT_SYSTEM,	/* ... kernel mode */

	CPUACCT_STAT_NSTATS,
};

struct cpuacct_percpu {
	u64 cpuusage;
	unsigned long nr_delays;
	unsigned long cpu_balance;
	struct ratelimit_batch cpulimit_batch;
};

/* track cpu usage of a group of tasks and its child groups */
struct cpuacct {
	struct cgroup_subsys_state css;
	struct cpuacct_percpu __percpu *percpu;
	struct kernel_cpustat __percpu *cpustat;
	struct ratelimit cpulimit;
};

/* return cpu accounting group corresponding to this container */
static inline struct cpuacct *cgroup_ca(struct cgroup *cgrp)
{
	return container_of(cgroup_subsys_state(cgrp, cpuacct_subsys_id),
			    struct cpuacct, css);
}

/* return cpu accounting group to which this task belongs */
static inline struct cpuacct *task_ca(struct task_struct *tsk)
{
	return container_of(task_subsys_state(tsk, cpuacct_subsys_id),
			    struct cpuacct, css);
}

static inline struct cpuacct *__parent_ca(struct cpuacct *ca)
{
	return cgroup_ca(ca->css.cgroup->parent);
}

static inline struct cpuacct *parent_ca(struct cpuacct *ca)
{
	if (!ca->css.cgroup->parent)
		return NULL;
	return cgroup_ca(ca->css.cgroup->parent);
}

static DEFINE_PER_CPU(struct cpuacct_percpu, root_cpuacct_percpu);
static struct cpuacct root_cpuacct = {
	.cpustat	= &kernel_cpustat,
	.percpu		= &root_cpuacct_percpu,
};

/* create a new cpu accounting group */
static struct cgroup_subsys_state *cpuacct_css_alloc(struct cgroup *cgrp)
{
	struct cpuacct *ca;

	if (!cgrp->parent) {
		ca = &root_cpuacct;
		goto do_init;
	}

	ca = kzalloc(sizeof(*ca), GFP_KERNEL);
	if (!ca)
		goto out;

	ca->percpu = alloc_percpu(struct cpuacct_percpu);
	if (!ca->percpu)
		goto out_free_ca;

	ca->cpustat = alloc_percpu(struct kernel_cpustat);
	if (!ca->cpustat)
		goto out_free_percpu;
do_init:
	ratelimit_init(&ca->cpulimit);

	return &ca->css;

out_free_percpu:
	free_percpu(ca->percpu);
out_free_ca:
	kfree(ca);
out:
	return ERR_PTR(-ENOMEM);
}

/* destroy an existing cpu accounting group */
static void cpuacct_css_free(struct cgroup *cgrp)
{
	struct cpuacct *ca = cgroup_ca(cgrp);

	ratelimit_destroy(&ca->cpulimit);
	free_percpu(ca->cpustat);
	free_percpu(ca->percpu);
	kfree(ca);
}

static u64 cpuacct_cpuusage_read(struct cpuacct *ca, int cpu)
{
	u64 *cpuusage = per_cpu_ptr(&ca->percpu->cpuusage, cpu);
	u64 data;

#ifndef CONFIG_64BIT
	/*
	 * Take rq->lock to make 64-bit read safe on 32-bit platforms.
	 */
	raw_spin_lock_irq(&cpu_rq(cpu)->lock);
	data = *cpuusage;
	raw_spin_unlock_irq(&cpu_rq(cpu)->lock);
#else
	data = *cpuusage;
#endif

	return data;
}

static void cpuacct_cpuusage_write(struct cpuacct *ca, int cpu, u64 val)
{
	u64 *cpuusage = per_cpu_ptr(&ca->percpu->cpuusage, cpu);

#ifndef CONFIG_64BIT
	/*
	 * Take rq->lock to make 64-bit write safe on 32-bit platforms.
	 */
	raw_spin_lock_irq(&cpu_rq(cpu)->lock);
	*cpuusage = val;
	raw_spin_unlock_irq(&cpu_rq(cpu)->lock);
#else
	*cpuusage = val;
#endif
}

/* return total cpu usage (in nanoseconds) of a group */
static u64 cpuusage_read(struct cgroup *cgrp, struct cftype *cft)
{
	struct cpuacct *ca = cgroup_ca(cgrp);
	u64 totalcpuusage = 0;
	int i;

	for_each_present_cpu(i)
		totalcpuusage += cpuacct_cpuusage_read(ca, i);

	return totalcpuusage;
}

static int cpuusage_write(struct cgroup *cgrp, struct cftype *cftype,
								u64 reset)
{
	struct cpuacct *ca = cgroup_ca(cgrp);
	int err = 0;
	int i;

	if (reset) {
		err = -EINVAL;
		goto out;
	}

	for_each_present_cpu(i)
		cpuacct_cpuusage_write(ca, i, 0);

out:
	return err;
}

static u64 cpulimit_read(struct cgroup *cgrp, struct cftype *cft)
{
	struct cpuacct *ca = cgroup_ca(cgrp);

	return ratelimit_quota(&ca->cpulimit, NSEC_PER_SEC);
}

static int cpulimit_write(struct cgroup *cgrp, struct cftype *cft, u64 val)
{
	struct cpuacct *ca = cgroup_ca(cgrp);

	do_div(val, 10);
	ratelimit_setup(&ca->cpulimit, NSEC_PER_SEC / 10, val);
	return 0;
}

static u64 cpulimit_delays(struct cgroup *cgrp, struct cftype *cft)
{
	struct cpuacct *ca = cgroup_ca(cgrp);
	u64 sum = 0;
	int i;

	for_each_present_cpu(i)
		sum += per_cpu(ca->percpu->nr_delays, i);
	return sum;
}

static int cpuacct_percpu_seq_read(struct cgroup *cgroup, struct cftype *cft,
				   struct seq_file *m)
{
	struct cpuacct *ca = cgroup_ca(cgroup);
	u64 percpu;
	int i;

	for_each_present_cpu(i) {
		percpu = cpuacct_cpuusage_read(ca, i);
		seq_printf(m, "%llu ", (unsigned long long) percpu);
	}
	seq_printf(m, "\n");
	return 0;
}

static const char * const cpuacct_stat_desc[] = {
	[CPUACCT_STAT_USER] = "user",
	[CPUACCT_STAT_SYSTEM] = "system",
};

static int cpuacct_stats_show(struct cgroup *cgrp, struct cftype *cft,
			      struct cgroup_map_cb *cb)
{
	struct cpuacct *ca = cgroup_ca(cgrp);
	int cpu;
	s64 val = 0;

	for_each_online_cpu(cpu) {
		struct kernel_cpustat *kcpustat = per_cpu_ptr(ca->cpustat, cpu);
		val += kcpustat->cpustat[CPUTIME_USER];
		val += kcpustat->cpustat[CPUTIME_NICE];
	}
	val = cputime64_to_clock_t(val);
	cb->fill(cb, cpuacct_stat_desc[CPUACCT_STAT_USER], val);

	val = 0;
	for_each_online_cpu(cpu) {
		struct kernel_cpustat *kcpustat = per_cpu_ptr(ca->cpustat, cpu);
		val += kcpustat->cpustat[CPUTIME_SYSTEM];
		val += kcpustat->cpustat[CPUTIME_IRQ];
		val += kcpustat->cpustat[CPUTIME_SOFTIRQ];
	}

	val = cputime64_to_clock_t(val);
	cb->fill(cb, cpuacct_stat_desc[CPUACCT_STAT_SYSTEM], val);

	return 0;
}

static struct cftype files[] = {
	{
		.name = "usage",
		.read_u64 = cpuusage_read,
		.write_u64 = cpuusage_write,
	},
	{
		.name = "usage_percpu",
		.read_seq_string = cpuacct_percpu_seq_read,
	},
	{
		.name = "stat",
		.read_map = cpuacct_stats_show,
	},
	{
		.name = "limit",
		.read_u64 = cpulimit_read,
		.write_u64 = cpulimit_write,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "delays",
		.read_u64 = cpulimit_delays,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{ }	/* terminate */
};

/*
 * charge this task's execution time to its accounting group.
 *
 * called with rq->lock held.
 */
void cpuacct_charge(struct task_struct *tsk, u64 cputime)
{
	struct cpuacct *ca, *parent;
	int cpu;

	cpu = task_cpu(tsk);

	rcu_read_lock();

	ca = task_ca(tsk);

	if (ratelimit_charge_batch(&ca->cpulimit,
				&tsk->cpulimit_batch, cputime)) {
		this_cpu_inc(ca->percpu->nr_delays);
		delay_injection_target(tsk, ca->cpulimit.target_time);
	}

	while (true) {
		u64 *cpuusage = per_cpu_ptr(&ca->percpu->cpuusage, cpu);
		*cpuusage += cputime;

		parent = parent_ca(ca);
		if (!parent)
			break;

		if (ratelimit_charge_percpu(&parent->cpulimit,
					&ca->percpu->cpulimit_batch, cputime)) {
			this_cpu_inc(parent->percpu->nr_delays);
			delay_injection_target(tsk, parent->cpulimit.target_time);
		}

		ca = parent;
	}

	rcu_read_unlock();
}

/*
 * Add user/system time to cpuacct.
 *
 * Note: it's the caller that updates the account of the root cgroup.
 */
void cpuacct_account_field(struct task_struct *p, int index, u64 val)
{
	struct kernel_cpustat *kcpustat;
	struct cpuacct *ca;

	rcu_read_lock();
	ca = task_ca(p);
	while (ca != &root_cpuacct) {
		kcpustat = this_cpu_ptr(ca->cpustat);
		kcpustat->cpustat[index] += val;
		ca = __parent_ca(ca);
	}
	rcu_read_unlock();
}

static void cpuacct_fork(struct task_struct *task)
{
	struct task_struct *parent = current;

	task->cpulimit_batch.balance = parent->cpulimit_batch.balance / 2;
	parent->cpulimit_batch.balance -= task->cpulimit_batch.balance;
}

static void cpuacct_attach(struct cgroup *cgrp, struct cgroup_taskset *tset)
{
	struct task_struct *task;
	struct cpuacct *ca;

	cgroup_taskset_for_each(task, cgrp, tset) {
		rcu_read_lock();
		ca = task_ca(task);
		ratelimit_flush_batch(&ca->cpulimit, &task->cpulimit_batch);
		rcu_read_unlock();
	}
}

struct cgroup_subsys cpuacct_subsys = {
	.name		= "cpuacct",
	.css_alloc	= cpuacct_css_alloc,
	.css_free	= cpuacct_css_free,
	.fork		= cpuacct_fork,
	.attach		= cpuacct_attach,
	.subsys_id	= cpuacct_subsys_id,
	.base_cftypes	= files,
	.early_init	= 1,
};
