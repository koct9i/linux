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

static void __ratelimit_setup(struct ratelimit *rl, u64 period, u64 quota)
{
#if BITS_PER_LONG < 64
	/* divisor must be less than 2^32 */
	while (quota >> 32) {
		quota = (quota >> 1) | (quota & 1);
		period >>= 1;
	}
#endif
	if (!period || !quota) {
		rl->period = 0;
		rl->quota = ULONG_MAX;
		rl->batch = ULONG_MAX;
	} else {
		rl->period = min(period, (u64)ULONG_MAX);
		rl->quota = quota;
		if (do_div(quota, num_possible_cpus()))
			quota++;
		rl->batch = quota;
	}
	rl->balance = 0;
	rl->target_time = ktime_set(0, 0);
	rl->deadline = ktime_set(3, 0);
}

static enum hrtimer_restart ratelimit_unblock(struct hrtimer *timer)
{
	struct ratelimit *rl = container_of(timer,
			struct ratelimit, unblock_timer);
	enum hrtimer_restart ret = HRTIMER_NORESTART;
	ktime_t now = timer->base->get_time();

	raw_spin_lock(&rl->lock);
	if (ktime_compare(rl->target_time, now) > 0) {
		hrtimer_set_expires_range_ns(timer,
				rl->target_time, rl->period);
		ret = HRTIMER_RESTART;
	}
	raw_spin_unlock(&rl->lock);

	return ret;
}

void ratelimit_init(struct ratelimit *rl)
{
	raw_spin_lock_init(&rl->lock);
	hrtimer_init(&rl->unblock_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	rl->unblock_timer.function = ratelimit_unblock;
	__ratelimit_setup(rl, 0, 0);
}
EXPORT_SYMBOL(ratelimit_init);

void ratelimit_destroy(struct ratelimit *rl)
{
	hrtimer_cancel(&rl->unblock_timer);
}
EXPORT_SYMBOL(ratelimit_destroy);

void ratelimit_setup(struct ratelimit *rl, u64 period, u64 quota)
{
	unsigned long flags, old_period, old_quota;
	bool drain;

	raw_spin_lock_irqsave(&rl->lock, flags);
	old_period = rl->period;
	old_quota = rl->quota;
	__ratelimit_setup(rl, period, quota);
	drain = rl->period > old_period || rl->quota < old_quota;
	raw_spin_unlock_irqrestore(&rl->lock, flags);
	hrtimer_try_to_cancel(&rl->unblock_timer);
}
EXPORT_SYMBOL(ratelimit_setup);

u64 ratelimit_quota(struct ratelimit *rl, u64 inteval)
{
	unsigned long flags, period, quota;

	raw_spin_lock_irqsave(&rl->lock, flags);
	period = rl->period;
	quota = rl->quota;
	raw_spin_unlock_irqrestore(&rl->lock, flags);
#if BITS_PER_LONG < 64
	/* divisor must be less than 2^32 */
	while (period >> 32) {
		quota = (quota >> 1) | (quota & 1);
		period >>= 1;
	}
#endif
	if (!period)
		return ULLONG_MAX;
	if (do_div(inteval, period))
		inteval++;
	return inteval * quota; /* FIXME how to handle overflow here? */
}
EXPORT_SYMBOL(ratelimit_quota);

static bool __ratelimit_charge(struct ratelimit *rl,
		struct ratelimit_batch *batch, u64 count, bool try_charge)
{
	ktime_t now, deadline;
	unsigned long flags;
	bool blocked;
	u64 delta, charge;

	now = ktime_get();

	raw_spin_lock_irqsave(&rl->lock, flags);

	deadline = ktime_sub(now, rl->deadline);
	if (ktime_compare(rl->target_time, deadline) < 0)
		rl->target_time = deadline;

	charge = count;

	if (batch) {
		charge += rl->batch - batch->balance;
		batch->balance = rl->batch;
	}

	if (rl->balance >= charge) {
		rl->balance -= charge;
	} else {
		charge -= rl->balance;
		delta = charge;
		if (do_div(delta, rl->quota))
			delta++;
		rl->balance = delta * rl->quota - charge;
		delta *= rl->period;
		rl->target_time = ktime_add_ns(rl->target_time, delta);
	}

	blocked = ratelimit_blocked(rl);
	if (!blocked && ktime_compare(rl->target_time, now) > 0) {
		blocked = true;
		hrtimer_start_range_ns(&rl->unblock_timer,
				rl->target_time, rl->period, HRTIMER_MODE_ABS);
	}

	if (try_charge && blocked)
		rl->balance += count;

	raw_spin_unlock_irqrestore(&rl->lock, flags);

	return blocked;
}

bool ratelimit_charge(struct ratelimit *rl, u64 count)
{
	return __ratelimit_charge(rl, NULL, count, false);
}
EXPORT_SYMBOL(ratelimit_charge);

bool ratelimit_try_charge(struct ratelimit *rl, u64 count)
{
	return ratelimit_blocked(rl) ||
	       __ratelimit_charge(rl, NULL, count, true);
}
EXPORT_SYMBOL(ratelimit_try_charge);

bool ratelimit_charge_sync(struct ratelimit *rl, u64 count)
{
	bool blocked;

	might_sleep();
	blocked = ratelimit_charge(rl, count);
	if (blocked)
		ratelimit_wait(rl);
	return blocked;
}
EXPORT_SYMBOL(ratelimit_charge_sync);

bool ratelimit_charge_batch(struct ratelimit *rl,
		struct ratelimit_batch *batch, u64 count)
{
	if (likely(batch->balance >= count)) {
		batch->balance -= count;
		return ratelimit_blocked(rl);
	}

	return __ratelimit_charge(rl, batch, count, false);
}
EXPORT_SYMBOL(ratelimit_charge_batch);

bool ratelimit_try_charge_batch(struct ratelimit *rl,
		struct ratelimit_batch *batch, u64 count)
{
	bool blocked;

	blocked = ratelimit_blocked(rl);
	if (likely(!blocked)) {
		if (likely(batch->balance >= count))
			batch->balance -= count;
		else
			blocked = __ratelimit_charge(rl, batch, count, true);
	}
	return blocked;
}
EXPORT_SYMBOL(ratelimit_try_charge_batch);

bool ratelimit_charge_percpu(struct ratelimit *rl,
		struct ratelimit_batch __percpu *batch, u64 count)
{
	bool blocked;

	preempt_disable();
	if (likely(__this_cpu_read(batch->balance) >= count)) {
		__this_cpu_sub(batch->balance, count);
		blocked = ratelimit_blocked(rl);
	} else
		blocked = __ratelimit_charge(rl, __this_cpu_ptr(batch),
					     count, false);
	preempt_enable();

	return blocked;
}
EXPORT_SYMBOL(ratelimit_charge_percpu);

bool ratelimit_try_charge_percpu(struct ratelimit *rl,
		struct ratelimit_batch __percpu *batch, u64 count)
{
	bool blocked;

	blocked = ratelimit_blocked(rl);
	if (likely(!blocked)) {
		preempt_disable();
		if (likely(__this_cpu_read(batch->balance) >= count))
			__this_cpu_sub(batch->balance, (unsigned long)count);
		else
			blocked = __ratelimit_charge(rl, __this_cpu_ptr(batch),
						     count, true);
		preempt_enable();
	}
	return blocked;
}
EXPORT_SYMBOL(ratelimit_try_charge_percpu);
