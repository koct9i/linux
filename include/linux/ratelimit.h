#ifndef _LINUX_RATELIMIT_H
#define _LINUX_RATELIMIT_H

#include <linux/param.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>

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

struct percpu_ratelimit {
	ktime_t		target_time;	/* time of nearest possible event */
	ktime_t		deadline;	/* inteval to utilize past quota */
	unsigned long	interval;	/* time between quota assignations */
	u64		quota;		/* amount of events per interval */
	u64		cur_balance;	/* amount of available events */
	raw_spinlock_t	lock;		/* protect the state */
	u32		cpu_precharge;	/* events in per-cpu precharge */
	u32 __percpu	*cpu_balance;	/* per-cpu precharge */
};

int percpu_ratelimit_init(struct percpu_ratelimit *rl, u64 events_per_sec);
void percpu_ratelimit_destroy(struct percpu_ratelimit *rl);
void percpu_ratelimit_setup(struct percpu_ratelimit *rl, u64 events_per_sec);
void percpu_ratelimit_charge(struct percpu_ratelimit *rl, u64 events);
bool percpu_ratelimit_try_charge(struct percpu_ratelimit *rl, u64 events);
int percpu_ratelimit_timeout(struct percpu_ratelimit *rl);

#endif /* _LINUX_RATELIMIT_H */
