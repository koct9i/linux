#ifndef __ASM_ARM_COMPILER_H
#define __ASM_ARM_COMPILER_H

/*
 * This is used to ensure the compiler did actually allocate the register we
 * asked it for some inline assembly sequences.  Apparently we can't trust
 * the compiler from one version to another so a bit of paranoia won't hurt.
 * This string is meant to be concatenated with the inline asm string and
 * will cause compilation to stop on mismatch.
 * (for details, see gcc PR 15089)
 */
#define __asmeq(x, y)  ".ifnc " x "," y " ; .err ; .endif\n\t"

/*
 * This is used for calling exported symbols from inline assembly code.
 */
#if defined(MODULE) && defined(CONFIG_MODULES_USE_LONG_CALLS)
#define __asmbl(cond, reg, target) \
	"movw	" reg ", #:lower16:" target "\n\t" \
	"movt	" reg ", #:upper16:" target "\n\t" \
	"blx" cond "	" reg "\n\t"
#define __asmbl_clobber(reg)	,reg
#else
#define __asmbl(cond, reg, target) "bl" cond "	" target"\n\t"
#define __asmbl_clobber(reg)
#endif

#endif /* __ASM_ARM_COMPILER_H */
