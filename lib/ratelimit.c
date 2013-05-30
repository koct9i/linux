/*
 * ratelimit.c - Do something with rate limit.
 *
 * Isolated from kernel/printk.c by Dave Young <hidave.darkstar@gmail.com>
 *
 * 2008-05-01 rewrite the function and use a ratelimit_state data struct as
 * parameter. Now every user can use their own standalone ratelimit_state.
 *
 * This file is released under the GPLv2.
 */

#include <linux/ratelimit.h>
#include <linux/jiffies.h>
#include <linux/export.h>
#include <linux/hrtimer.h>

/*
 * __ratelimit - rate limiting
 * @rs: ratelimit_state data
 * @func: name of calling function
 *
 * This enforces a rate limit: not more than @rs->burst callbacks
 * in every @rs->interval
 *
 * RETURNS:
 * 0 means callbacks will be suppressed.
 * 1 means go ahead and do it.
 */
int ___ratelimit(struct ratelimit_state *rs, const char *func)
{
	unsigned long flags;
	int ret;

	if (!rs->interval)
		return 1;

	/*
	 * If we contend on this state's lock then almost
	 * by definition we are too busy to print a message,
	 * in addition to the one that will be printed by
	 * the entity that is holding the lock already:
	 */
	if (!raw_spin_trylock_irqsave(&rs->lock, flags))
		return 0;

	if (!rs->begin)
		rs->begin = jiffies;

	if (time_is_before_jiffies(rs->begin + rs->interval)) {
		if (rs->missed)
			printk(KERN_WARNING "%s: %d callbacks suppressed\n",
				func, rs->missed);
		rs->begin   = 0;
		rs->printed = 0;
		rs->missed  = 0;
	}
	if (rs->burst && rs->burst > rs->printed) {
		rs->printed++;
		ret = 1;
	} else {
		rs->missed++;
		ret = 0;
	}
	raw_spin_unlock_irqrestore(&rs->lock, flags);

	return ret;
}
EXPORT_SYMBOL(___ratelimit);

static void __percpu_ratelimit_setup(struct percpu_ratelimit *rl, u64 speed)
{
	rl->interval = ns_to_ktime(NSEC_PER_SEC / 10);
	if (do_div(speed, 10))
		speed++;
	rl->quota = speed;
	rl->deadline = ns_to_ktime(NSEC_PER_SEC);
	rl->cur_balance = rl->quota;
	if (do_div(speed, num_possible_cpus()))
		speed++;
	rl->cpu_precharge = min_t(u64, UINT_MAX, speed);
	rl->target_time = ktime_get();
}

int percpu_ratelimit_init(struct percpu_ratelimit *rl, u64 events_per_second)
{
	memset(rl, 0, sizeof(*rl));
	rl->cpu_balance = alloc_percpu(typeof(*rl->cpu_balance));
	if (!rl->cpu_balance)
		return -ENOMEM;
	raw_spin_lock_init(&rl->lock);
	__percpu_ratelimit_setup(rl, events_per_second);
	return 0;
}

void percpu_ratelimit_destroy(struct percpu_ratelimit *rl)
{
	free_percpu(rl->cpu_balance);
}

static void percpu_ratelimit_drain(void *info)
{
	struct percpu_ratelimit *rl = info;

	__this_cpu_write(*rl->cpu_balance, 0);
}

void percpu_ratelimit_setup(struct percpu_ratelimit *rl, u64 events_per_second)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&rl->lock, flags);
	__percpu_ratelimit_setup(rl, events_per_second);
	raw_spin_unlock_irqrestore(&rl->lock, flags);
	on_each_cpu(percpu_ratelimit_drain, rl, 1);
}

void percpu_ratelimit_charge(struct percpu_ratelimit *rl, u64 events)
{
	unsigned long flags;
	u64 balance, delta;
	ktime_t now, deadline;

	preempt_disable();
	balance = __this_cpu_read(*rl->cpu_balance);
	if (likely(balance >= events)) {
		__this_cpu_sub(*rl->cpu_balance, events);
	} else {
		now = ktime_get();
		raw_spin_lock_irqsave(&rl->lock, flags);
		deadline = ktime_sub(now, rl->deadline);
		if (ktime_compare(rl->target_time, deadline) < 0)
			rl->target_time = deadline;
		balance += rl->cur_balance;
		if (balance >= events + rl->cpu_precharge) {
			balance -= events;
		} else {
			delta = events + rl->cpu_precharge - balance;
			if (do_div(delta, rl->quota))
				delta++;
			balance += rl->quota * delta - events;
			rl->target_time = ktime_add_ns(rl->target_time,
					ktime_to_ns(rl->interval) * delta);
		}
		rl->cur_balance = balance - rl->cpu_precharge;
		__this_cpu_write(*rl->cpu_balance, rl->cpu_precharge);
		raw_spin_unlock_irqrestore(&rl->lock, flags);
	}
	preempt_enable();
}

bool percpu_ratelimit_try_charge(struct percpu_ratelimit *rl, u64 events)
{
	unsigned long flags;
	u64 balance, delta;
	ktime_t now, deadline;
	bool ret = false;

	preempt_disable();
	balance = __this_cpu_read(*rl->cpu_balance);
	if (likely(balance >= events)) {
		__this_cpu_sub(*rl->cpu_balance, events);
		ret = true;
		goto out;
	}
	now = ktime_get();
	if (ktime_compare(now, rl->target_time) >= 0) {
		raw_spin_lock_irqsave(&rl->lock, flags);
		deadline = ktime_sub(now, rl->deadline);
		if (ktime_compare(rl->target_time, deadline) < 0)
			rl->target_time = deadline;
		balance += rl->cur_balance;
		if (balance >= events + rl->cpu_precharge) {
			balance -= events;
		} else {
			delta = events + rl->cpu_precharge - balance;
			if (do_div(delta, rl->quota))
				delta++;
			balance += rl->quota * delta - events;
			rl->target_time = ktime_add_ns(rl->target_time,
					ktime_to_ns(rl->interval) * delta);
		}
		if (ktime_compare(now, rl->target_time) >= 0) {
			rl->cur_balance = balance - rl->cpu_precharge;
			__this_cpu_write(*rl->cpu_balance, rl->cpu_precharge);
			ret = true;
		} else {
			rl->cur_balance = balance + events;
			__this_cpu_write(*rl->cpu_balance, 0);
		}
		raw_spin_unlock_irqrestore(&rl->lock, flags);
	}
out:
	preempt_enable();
	return ret;
}

int percpu_ratelimit_timeout(struct percpu_ratelimit *rl)
{
	ktime_t target = rl->target_time;
	unsigned long slack = ktime_to_ns(rl->interval);

	return schedule_hrtimeout_range(&target, slack, HRTIMER_MODE_ABS);
}
