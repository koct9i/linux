#include <linux/module.h>

/* validate @native and @pcp counter values match @expected */
#define CHECK(native, pcp, expected)                                    \
	do {                                                            \
		WARN((native) != (expected),                            \
		     "raw %ld (0x%lx) != expected %lld (0x%llx)",	\
		     (native), (native),				\
		     (long long)(expected), (long long)(expected));	\
		WARN(__this_cpu_read(pcp) != (expected),                \
		     "pcp %ld (0x%lx) != expected %lld (0x%llx)",	\
		     __this_cpu_read(pcp), __this_cpu_read(pcp),	\
		     (long long)(expected), (long long)(expected));	\
	} while (0)

#define TEST_MINMAX_(stem, bit, val, op, c_op, arg, lim, ret)		\
do {									\
	stem##write(bit##_counter, val);				\
	bit##_var = (typeof(bit))(ret ? ((val) c_op (arg)) : val);	\
	WARN(stem##op(bit##_counter, arg, lim) != ret,			\
		"unexpected %s", ret ? "fail" : "success");		\
	WARN(stem##read(bit##_counter) != bit##_var,			\
		"%s %lld %lld %lld pcp %lld != expected %lld",		\
		#stem #op, (long long)(val), (long long)(arg),		\
		(long long)(lim),					\
		(long long)stem##read(bit##_counter),			\
		(long long)bit##_var);					\
} while (0)

#define TEST_MINMAX(bit, val, op, c_op, arg, lim, ret)			\
do {									\
	TEST_MINMAX_(raw_cpu_, bit, val, op, c_op, arg, lim, ret);	\
	TEST_MINMAX_(__this_cpu_, bit, val, op, c_op, arg, lim, ret);	\
	TEST_MINMAX_(this_cpu_, bit, val, op, c_op, arg, lim, ret);	\
} while (0)

#define MINMAX_RANGE_TEST(bit, lo, hi)				\
do {								\
	TEST_MINMAX(bit, hi, add_max, +, 0, hi, true);		\
	TEST_MINMAX(bit, hi-1, add_max, +, 1, hi, true);	\
	TEST_MINMAX(bit, hi, add_max, +, 1, hi, false);		\
	TEST_MINMAX(bit, lo, add_max, +, 1, hi, true);		\
	TEST_MINMAX(bit, lo, add_max, +, hi - lo, hi, true);	\
	TEST_MINMAX(bit, lo, add_max, +, hi - lo, hi-1, false);	\
	TEST_MINMAX(bit, lo+1, add_max, +, hi - lo, hi, false);	\
								\
	TEST_MINMAX(bit, lo, sub_min, -, 0, lo, true);		\
	TEST_MINMAX(bit, lo+1, sub_min, -, 1, lo, true);	\
	TEST_MINMAX(bit, lo, sub_min, -, 1, lo, false);		\
	TEST_MINMAX(bit, hi, sub_min, -, 1, lo, true);		\
	TEST_MINMAX(bit, hi, sub_min, -, hi - lo, lo, true);	\
	TEST_MINMAX(bit, hi, sub_min, -, hi - lo, lo+1, false);	\
	TEST_MINMAX(bit, hi-1, sub_min, -, hi - lo, lo, false);	\
} while (0)

#define MINMAX_FAMILY_TEST(bit, min, max, ubit, umax)	\
do {							\
	MINMAX_RANGE_TEST(bit, 0, max);			\
	MINMAX_RANGE_TEST(bit, (min + 1), 0);		\
	MINMAX_RANGE_TEST(bit, min, -1);		\
	MINMAX_RANGE_TEST(bit, -1, 1);			\
	MINMAX_RANGE_TEST(bit, -100, 100);		\
	MINMAX_RANGE_TEST(ubit, 0, umax);		\
	MINMAX_RANGE_TEST(ubit, 100, 200);		\
} while (0)

static s8 s8_var;
static DEFINE_PER_CPU(s8, s8_counter);

static u8 u8_var;
static DEFINE_PER_CPU(u8, u8_counter);

static s16 s16_var;
static DEFINE_PER_CPU(s16, s16_counter);

static u16 u16_var;
static DEFINE_PER_CPU(u16, u16_counter);

static s32 s32_var;
static DEFINE_PER_CPU(s32, s32_counter);

static u32 u32_var;
static DEFINE_PER_CPU(u32, u32_counter);

static long long_var;
static DEFINE_PER_CPU(long, long_counter);

static unsigned long ulong_var;
static DEFINE_PER_CPU(unsigned long, ulong_counter);

static s64 s64_var;
static DEFINE_PER_CPU(s64, s64_counter);

static u64 u64_var;
static DEFINE_PER_CPU(u64, u64_counter);

static int __init percpu_test_init(void)
{
	/*
	 * volatile prevents compiler from optimizing it uses, otherwise the
	 * +ul_one/-ul_one below would replace with inc/dec instructions.
	 */
	volatile unsigned int ui_one = 1;
	long l = 0;
	unsigned long ul = 0;

	pr_info("percpu test start\n");

	preempt_disable();

	l += -1;
	__this_cpu_add(long_counter, -1);
	CHECK(l, long_counter, -1);

	l += 1;
	__this_cpu_add(long_counter, 1);
	CHECK(l, long_counter, 0);

	ul = 0;
	__this_cpu_write(ulong_counter, 0);

	ul += 1UL;
	__this_cpu_add(ulong_counter, 1UL);
	CHECK(ul, ulong_counter, 1);

	ul += -1UL;
	__this_cpu_add(ulong_counter, -1UL);
	CHECK(ul, ulong_counter, 0);

	ul += -(unsigned long)1;
	__this_cpu_add(ulong_counter, -(unsigned long)1);
	CHECK(ul, ulong_counter, -1);

	ul = 0;
	__this_cpu_write(ulong_counter, 0);

	ul -= 1;
	__this_cpu_dec(ulong_counter);
	CHECK(ul, ulong_counter, -1);
	CHECK(ul, ulong_counter, ULONG_MAX);

	l += -ui_one;
	__this_cpu_add(long_counter, -ui_one);
	CHECK(l, long_counter, 0xffffffff);

	l += ui_one;
	__this_cpu_add(long_counter, ui_one);
	CHECK(l, long_counter, (long)0x100000000LL);


	l = 0;
	__this_cpu_write(long_counter, 0);

	l -= ui_one;
	__this_cpu_sub(long_counter, ui_one);
	CHECK(l, long_counter, -1);

	l = 0;
	__this_cpu_write(long_counter, 0);

	l += ui_one;
	__this_cpu_add(long_counter, ui_one);
	CHECK(l, long_counter, 1);

	l += -ui_one;
	__this_cpu_add(long_counter, -ui_one);
	CHECK(l, long_counter, (long)0x100000000LL);

	l = 0;
	__this_cpu_write(long_counter, 0);

	l -= ui_one;
	this_cpu_sub(long_counter, ui_one);
	CHECK(l, long_counter, -1);
	CHECK(l, long_counter, ULONG_MAX);

	ul = 0;
	__this_cpu_write(ulong_counter, 0);

	ul += ui_one;
	__this_cpu_add(ulong_counter, ui_one);
	CHECK(ul, ulong_counter, 1);

	ul = 0;
	__this_cpu_write(ulong_counter, 0);

	ul -= ui_one;
	__this_cpu_sub(ulong_counter, ui_one);
	CHECK(ul, ulong_counter, -1);
	CHECK(ul, ulong_counter, ULONG_MAX);

	ul = 3;
	__this_cpu_write(ulong_counter, 3);

	ul = this_cpu_sub_return(ulong_counter, ui_one);
	CHECK(ul, ulong_counter, 2);

	ul = __this_cpu_sub_return(ulong_counter, ui_one);
	CHECK(ul, ulong_counter, 1);

	MINMAX_FAMILY_TEST(s8, S8_MIN, S8_MAX, u8, U8_MAX);
	MINMAX_FAMILY_TEST(s16, S16_MIN, S16_MAX, u16, U16_MAX);
	MINMAX_FAMILY_TEST(s32, S32_MIN, S32_MAX, u32, U32_MAX);
	MINMAX_FAMILY_TEST(long, LONG_MIN, LONG_MAX, ulong, ULONG_MAX);
	MINMAX_FAMILY_TEST(s64, S64_MIN, S64_MAX, u64, U64_MAX);

	preempt_enable();

	pr_info("percpu test done\n");
	return -EAGAIN;  /* Fail will directly unload the module */
}

static void __exit percpu_test_exit(void)
{
}

module_init(percpu_test_init)
module_exit(percpu_test_exit)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Greg Thelen");
MODULE_DESCRIPTION("percpu operations test");
