#include <linux/percpu_ratelimit.h>

static void __percpu_ratelimit_setup(struct percpu_ratelimit *rl,
				     u64 period, u64 quota)
{
	rl->period = ns_to_ktime(period);
	rl->quota = quota;
	rl->total += quota - rl->budget;
	rl->budget = quota;
	if (do_div(quota, num_possible_cpus() * 2))
		quota++;
	rl->cpu_batch = min_t(u64, UINT_MAX, quota);
	rl->target = ktime_get();
}

static enum hrtimer_restart ratelimit_unblock(struct hrtimer *t)
{
	struct percpu_ratelimit *rl = container_of(t, struct percpu_ratelimit, timer);
	enum hrtimer_restart ret = HRTIMER_NORESTART;
	ktime_t now = t->base->get_time();

	raw_spin_lock(&rl->lock);
	if (ktime_after(rl->target, now)) {
		hrtimer_set_expires_range(t, rl->target, rl->period);
		ret = HRTIMER_RESTART;
	}
	raw_spin_unlock(&rl->lock);

	return ret;
}

int percpu_ratelimit_init(struct percpu_ratelimit *rl, gfp_t gfp)
{
	memset(rl, 0, sizeof(*rl));
	rl->cpu_budget = alloc_percpu_gfp(typeof(*rl->cpu_budget), gfp);
	if (!rl->cpu_budget)
		return -ENOMEM;
	raw_spin_lock_init(&rl->lock);
	hrtimer_init(&rl->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	rl->timer.function = ratelimit_unblock;
	rl->deadline = ns_to_ktime(NSEC_PER_SEC);
	__percpu_ratelimit_setup(rl, NSEC_PER_SEC, ULLONG_MAX);
	return 0;
}
EXPORT_SYMBOL_GPL(percpu_ratelimit_init);

void percpu_ratelimit_destroy(struct percpu_ratelimit *rl)
{
	free_percpu(rl->cpu_budget);
	hrtimer_cancel(&rl->timer);
}
EXPORT_SYMBOL_GPL(percpu_ratelimit_destroy);

static void percpu_ratelimit_drain(void *info)
{
	struct percpu_ratelimit *rl = info;

	__this_cpu_write(*rl->cpu_budget, 0);
}

void percpu_ratelimit_setup(struct percpu_ratelimit *rl, u64 period, u64 quota)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&rl->lock, flags);
	__percpu_ratelimit_setup(rl, period, quota);
	raw_spin_unlock_irqrestore(&rl->lock, flags);
	on_each_cpu(percpu_ratelimit_drain, rl, 1);
	hrtimer_cancel(&rl->timer);
}
EXPORT_SYMBOL_GPL(percpu_ratelimit_setup);

bool percpu_ratelimit_charge(struct percpu_ratelimit *rl, u64 events)
{
	unsigned long flags;
	u64 budget, delta;
	ktime_t now, deadline;

	preempt_disable();
	budget = __this_cpu_read(*rl->cpu_budget);
	if (likely(budget >= events)) {
		__this_cpu_sub(*rl->cpu_budget, events);
	} else {
		now = ktime_get();
		raw_spin_lock_irqsave(&rl->lock, flags);
		deadline = ktime_sub(now, rl->deadline);
		if (ktime_after(deadline, rl->target))
			rl->target = deadline;
		budget += rl->budget;
		if (budget >= events + rl->cpu_batch) {
			budget -= events;
		} else {
			delta = events + rl->cpu_batch - budget;
			if (do_div(delta, rl->quota))
				delta++;
			rl->target = ktime_add_ns(rl->target,
					ktime_to_ns(rl->period) * delta);
			delta *= rl->quota;
			rl->total += delta;
			budget += delta - events;
		}
		rl->budget = budget - rl->cpu_batch;
		__this_cpu_write(*rl->cpu_budget, rl->cpu_batch);
		if (!hrtimer_active(&rl->timer) && ktime_after(rl->target, now))
			hrtimer_start_range_ns(&rl->timer, rl->target,
					ktime_to_ns(rl->period),
					HRTIMER_MODE_ABS);
		raw_spin_unlock_irqrestore(&rl->lock, flags);
	}
	preempt_enable();

	return percpu_ratelimit_blocked(rl);
}
EXPORT_SYMBOL_GPL(percpu_ratelimit_charge);

u64 percpu_ratelimit_sum(struct percpu_ratelimit *rl)
{
	unsigned long flags;
	int cpu;
	s64 ret;

	raw_spin_lock_irqsave(&rl->lock, flags);
	ret = rl->total - rl->budget;
	for_each_online_cpu(cpu)
		ret -= per_cpu(*rl->cpu_budget, cpu);
	raw_spin_unlock_irqrestore(&rl->lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(percpu_ratelimit_sum);
