#ifndef _LINUX_RATELIMIT_H
#define _LINUX_RATELIMIT_H

#include <linux/param.h>
#include <linux/spinlock.h>
#include <linux/hrtimer.h>

#define DEFAULT_RATELIMIT_INTERVAL	(5 * HZ)
#define DEFAULT_RATELIMIT_BURST		10

struct ratelimit_state {
	raw_spinlock_t	lock;		/* protect the state */

	int		interval;
	int		burst;
	int		printed;
	int		missed;
	unsigned long	begin;
};

#define DEFINE_RATELIMIT_STATE(name, interval_init, burst_init)		\
									\
	struct ratelimit_state name = {					\
		.lock		= __RAW_SPIN_LOCK_UNLOCKED(name.lock),	\
		.interval	= interval_init,			\
		.burst		= burst_init,				\
	}

static inline void ratelimit_state_init(struct ratelimit_state *rs,
					int interval, int burst)
{
	raw_spin_lock_init(&rs->lock);
	rs->interval = interval;
	rs->burst = burst;
	rs->printed = 0;
	rs->missed = 0;
	rs->begin = 0;
}

extern struct ratelimit_state printk_ratelimit_state;

extern int ___ratelimit(struct ratelimit_state *rs, const char *func);
#define __ratelimit(state) ___ratelimit(state, __func__)

#ifdef CONFIG_PRINTK

#define WARN_ON_RATELIMIT(condition, state)			\
		WARN_ON((condition) && __ratelimit(state))

#define WARN_RATELIMIT(condition, format, ...)			\
({								\
	static DEFINE_RATELIMIT_STATE(_rs,			\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);	\
	int rtn = !!(condition);				\
								\
	if (unlikely(rtn && __ratelimit(&_rs)))			\
		WARN(rtn, format, ##__VA_ARGS__);		\
								\
	rtn;							\
})

#else

#define WARN_ON_RATELIMIT(condition, state)			\
	WARN_ON(condition)

#define WARN_RATELIMIT(condition, format, ...)			\
({								\
	int rtn = WARN(condition, format, ##__VA_ARGS__);	\
	rtn;							\
})

#endif

struct ratelimit {
	unsigned long	period;		/* nsecs between quota assignations */
	unsigned long	quota;		/* of units per period */
	unsigned long	batch;		/* size of precharges */
	u64		balance;	/* currently available units */
	ktime_t		target_time;	/* time of next nonblocked charge */
	struct hrtimer	unblock_timer;	/* armed if target_time in future */
	ktime_t		deadline;	/* time to utilize past quota */
	raw_spinlock_t	lock;		/* protects the state, irq-safe */
};

struct ratelimit_batch {
	unsigned long	balance;
};

void ratelimit_init(struct ratelimit *rl);
void ratelimit_destroy(struct ratelimit *rl);
void ratelimit_setup(struct ratelimit *rl, u64 period, u64 quota);
u64 ratelimit_quota(struct ratelimit *rl, u64 interval);

static inline bool ratelimit_blocked(struct ratelimit *rl)
{
	return hrtimer_active(&rl->unblock_timer);
}

static inline int ratelimit_wait(struct ratelimit *rl)
{
	ktime_t time = rl->target_time;

	return schedule_hrtimeout_range(&time, rl->period, HRTIMER_MODE_ABS);
}

static inline void ratelimit_init_batch(struct ratelimit_batch *batch)
{
	batch->balance = 0;
}

static inline void
ratelimit_flush_batch(struct ratelimit *rl, struct ratelimit_batch *batch)
{
	if (batch->balance) {
		raw_spin_lock_irq(&rl->lock);
		rl->balance += batch->balance;
		batch->balance = 0;
		raw_spin_unlock_irq(&rl->lock);
	}
}

bool ratelimit_charge(struct ratelimit *rl, u64 count);
bool ratelimit_try_charge(struct ratelimit *rl, u64 count);
bool ratelimit_charge_sync(struct ratelimit *rl, u64 count);

bool ratelimit_charge_batch(struct ratelimit *rl,
		struct ratelimit_batch *batch, u64 count);
bool ratelimit_try_charge_batch(struct ratelimit *rl,
		struct ratelimit_batch *batch, u64 count);

bool ratelimit_charge_percpu(struct ratelimit *rl,
		struct ratelimit_batch __percpu *batch, u64 count);
bool ratelimit_try_charge_percpu(struct ratelimit *rl,
		struct ratelimit_batch __percpu *batch, u64 count);

#endif /* _LINUX_RATELIMIT_H */
