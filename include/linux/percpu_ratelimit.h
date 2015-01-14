#ifndef _LINUX_PERCPU_RATELIMIT_H
#define _LINUX_PERCPU_RATELIMIT_H

#include <linux/hrtimer.h>

struct percpu_ratelimit {
	struct hrtimer  timer;
	ktime_t		target;		/* time of next refill */
	ktime_t		deadline;	/* interval to utilize past budget */
	ktime_t		latency;	/* maximum injected delay */
	ktime_t		period;		/* interval between refills */
	u64		quota;		/* events refill per period */
	u64		budget;		/* amount of available events */
	u64		total;		/* consumed and pre-charged events */
	raw_spinlock_t	lock;		/* protect the state */
	u32		cpu_batch;	/* events in per-cpu precharge */
	u32 __percpu	*cpu_budget;	/* per-cpu precharge */
};

static inline bool percpu_ratelimit_blocked(struct percpu_ratelimit *rl)
{
       return hrtimer_active(&rl->timer);
}

static inline ktime_t percpu_ratelimit_target(struct percpu_ratelimit *rl)
{
	return rl->target;
}

static inline int percpu_ratelimit_wait(struct percpu_ratelimit *rl)
{
	ktime_t target = rl->target;

	return schedule_hrtimeout_range(&target, ktime_to_ns(rl->period),
					HRTIMER_MODE_ABS);
}

int percpu_ratelimit_init(struct percpu_ratelimit *rl, gfp_t gfp);
void percpu_ratelimit_destroy(struct percpu_ratelimit *rl);
void percpu_ratelimit_setup(struct percpu_ratelimit *rl, u64 quota, u64 period);
u64 percpu_ratelimit_quota(struct percpu_ratelimit *rl, u64 period);
bool percpu_ratelimit_charge(struct percpu_ratelimit *rl, u64 events);
u64 percpu_ratelimit_sum(struct percpu_ratelimit *rl);

#endif /* _LINUX_PERCPU_RATELIMIT_H */
