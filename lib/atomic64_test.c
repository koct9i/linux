/*
 * Testsuite for atomic64_t functions
 *
 * Copyright © 2010  Luca Barbieri
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/atomic.h>

#ifdef CONFIG_X86
#include <asm/processor.h>	/* for boot_cpu_has below */
#endif

#define TEST(bit, op, c_op, val)				\
do {								\
	atomic##bit##_set(&v, v0);				\
	r = v0;							\
	atomic##bit##_##op(val, &v);				\
	r c_op val;						\
	WARN(atomic##bit##_read(&v) != r, "%Lx != %Lx\n",	\
		(unsigned long long)atomic##bit##_read(&v),	\
		(unsigned long long)r);				\
} while (0)

/*
 * Test for a atomic operation family,
 * @test should be a macro accepting parameters (bit, op, ...)
 */

#define FAMILY_TEST(test, bit, op, args...)	\
do {						\
	test(bit, op, ##args);		\
	test(bit, op##_acquire, ##args);	\
	test(bit, op##_release, ##args);	\
	test(bit, op##_relaxed, ##args);	\
} while (0)

#define TEST_RETURN(bit, op, c_op, val)				\
do {								\
	atomic##bit##_set(&v, v0);				\
	r = v0;							\
	r c_op val;						\
	BUG_ON(atomic##bit##_##op(val, &v) != r);		\
	BUG_ON(atomic##bit##_read(&v) != r);			\
} while (0)

#define RETURN_FAMILY_TEST(bit, op, c_op, val)			\
do {								\
	FAMILY_TEST(TEST_RETURN, bit, op, c_op, val);		\
} while (0)

#define TEST_ARGS(bit, op, init, ret, expect, args...)		\
do {								\
	atomic##bit##_set(&v, init);				\
	BUG_ON(atomic##bit##_##op(&v, ##args) != ret);		\
	BUG_ON(atomic##bit##_read(&v) != expect);		\
} while (0)

#define XCHG_FAMILY_TEST(bit, init, new)				\
do {									\
	FAMILY_TEST(TEST_ARGS, bit, xchg, init, init, new, new);	\
} while (0)

#define CMPXCHG_FAMILY_TEST(bit, init, new, wrong)			\
do {									\
	FAMILY_TEST(TEST_ARGS, bit, cmpxchg, 				\
			init, init, new, init, new);			\
	FAMILY_TEST(TEST_ARGS, bit, cmpxchg,				\
			init, init, init, wrong, new);			\
} while (0)

#define INC_RETURN_FAMILY_TEST(bit, i)			\
do {							\
	FAMILY_TEST(TEST_ARGS, bit, inc_return,		\
			i, (i) + one, (i) + one);	\
} while (0)

#define DEC_RETURN_FAMILY_TEST(bit, i)			\
do {							\
	FAMILY_TEST(TEST_ARGS, bit, dec_return,		\
			i, (i) - one, (i) - one);	\
} while (0)

#define TEST_MINMAX(bit, val, op, c_op, arg, lim, ret)		\
do {								\
	atomic##bit##_set(&v, val);				\
	r = (typeof(r))(ret ? ((val) c_op (arg)) : (val));	\
	BUG_ON(atomic##bit##_##op(&v, arg, lim) != ret);	\
	BUG_ON(atomic##bit##_read(&v) != r);			\
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

#define MINMAX_FAMILY_TEST(bit, min, max)	\
do {						\
	MINMAX_RANGE_TEST(bit, 0, max);		\
	MINMAX_RANGE_TEST(bit, (min + 1), 0);	\
	MINMAX_RANGE_TEST(bit, min, -1);	\
	MINMAX_RANGE_TEST(bit, -1, 1);		\
	MINMAX_RANGE_TEST(bit, -273, 451);	\
} while (0)

static __init void test_atomic(void)
{
	int v0 = 0xaaa31337;
	int v1 = 0xdeadbeef;
	int onestwos = 0x11112222;
	int one = 1;

	atomic_t v;
	int r;

	TEST(, add, +=, onestwos);
	TEST(, add, +=, -one);
	TEST(, sub, -=, onestwos);
	TEST(, sub, -=, -one);
	TEST(, or, |=, v1);
	TEST(, and, &=, v1);
	TEST(, xor, ^=, v1);
	TEST(, andnot, &= ~, v1);

	RETURN_FAMILY_TEST(, add_return, +=, onestwos);
	RETURN_FAMILY_TEST(, add_return, +=, -one);
	RETURN_FAMILY_TEST(, sub_return, -=, onestwos);
	RETURN_FAMILY_TEST(, sub_return, -=, -one);

	INC_RETURN_FAMILY_TEST(, v0);
	DEC_RETURN_FAMILY_TEST(, v0);

	XCHG_FAMILY_TEST(, v0, v1);
	CMPXCHG_FAMILY_TEST(, v0, v1, onestwos);

	MINMAX_FAMILY_TEST(, INT_MIN, INT_MAX);

#define atomic_u32_set(var, val)	atomic_set(var, val)
#define atomic_u32_read(var)		atomic_read(var)
	MINMAX_RANGE_TEST(_u32, 0, UINT_MAX);
	MINMAX_RANGE_TEST(_u32, 100, 500);
}

#define INIT(c) do { atomic64_set(&v, c); r = c; } while (0)
static __init void test_atomic64(void)
{
	long long v0 = 0xaaa31337c001d00dLL;
	long long v1 = 0xdeadbeefdeafcafeLL;
	long long v2 = 0xfaceabadf00df001LL;
	long long onestwos = 0x1111111122222222LL;
	long long one = 1LL;

	atomic64_t v = ATOMIC64_INIT(v0);
	long long r = v0;
	BUG_ON(v.counter != r);

	atomic64_set(&v, v1);
	r = v1;
	BUG_ON(v.counter != r);
	BUG_ON(atomic64_read(&v) != r);

	TEST(64, add, +=, onestwos);
	TEST(64, add, +=, -one);
	TEST(64, sub, -=, onestwos);
	TEST(64, sub, -=, -one);
	TEST(64, or, |=, v1);
	TEST(64, and, &=, v1);
	TEST(64, xor, ^=, v1);
	TEST(64, andnot, &= ~, v1);

	RETURN_FAMILY_TEST(64, add_return, +=, onestwos);
	RETURN_FAMILY_TEST(64, add_return, +=, -one);
	RETURN_FAMILY_TEST(64, sub_return, -=, onestwos);
	RETURN_FAMILY_TEST(64, sub_return, -=, -one);

	INIT(v0);
	atomic64_inc(&v);
	r += one;
	BUG_ON(v.counter != r);

	INIT(v0);
	atomic64_dec(&v);
	r -= one;
	BUG_ON(v.counter != r);

	INC_RETURN_FAMILY_TEST(64, v0);
	DEC_RETURN_FAMILY_TEST(64, v0);

	XCHG_FAMILY_TEST(64, v0, v1);
	CMPXCHG_FAMILY_TEST(64, v0, v1, v2);

	MINMAX_FAMILY_TEST(64, LLONG_MIN, LLONG_MAX);

#define atomic_u64_set(var, val)	atomic64_set(var, val)
#define atomic_u64_read(var)		atomic64_read(var)
	MINMAX_RANGE_TEST(_u64, 0, ULLONG_MAX);
	MINMAX_RANGE_TEST(_u64, 100, 500);

	INIT(v0);
	BUG_ON(atomic64_add_unless(&v, one, v0));
	BUG_ON(v.counter != r);

	INIT(v0);
	BUG_ON(!atomic64_add_unless(&v, one, v1));
	r += one;
	BUG_ON(v.counter != r);

#ifdef CONFIG_ARCH_HAS_ATOMIC64_DEC_IF_POSITIVE
	INIT(onestwos);
	BUG_ON(atomic64_dec_if_positive(&v) != (onestwos - 1));
	r -= one;
	BUG_ON(v.counter != r);

	INIT(0);
	BUG_ON(atomic64_dec_if_positive(&v) != -one);
	BUG_ON(v.counter != r);

	INIT(-one);
	BUG_ON(atomic64_dec_if_positive(&v) != (-one - one));
	BUG_ON(v.counter != r);
#else
#warning Please implement atomic64_dec_if_positive for your architecture and select the above Kconfig symbol
#endif

	INIT(onestwos);
	BUG_ON(!atomic64_inc_not_zero(&v));
	r += one;
	BUG_ON(v.counter != r);

	INIT(0);
	BUG_ON(atomic64_inc_not_zero(&v));
	BUG_ON(v.counter != r);

	INIT(-one);
	BUG_ON(!atomic64_inc_not_zero(&v));
	r += one;
	BUG_ON(v.counter != r);
}

static __init int test_atomics(void)
{
	test_atomic();
	test_atomic64();

#ifdef CONFIG_X86
	pr_info("passed for %s platform %s CX8 and %s SSE\n",
#ifdef CONFIG_X86_64
		"x86-64",
#elif defined(CONFIG_X86_CMPXCHG64)
		"i586+",
#else
		"i386+",
#endif
	       boot_cpu_has(X86_FEATURE_CX8) ? "with" : "without",
	       boot_cpu_has(X86_FEATURE_XMM) ? "with" : "without");
#else
	pr_info("passed\n");
#endif

	return 0;
}

core_initcall(test_atomics);
