#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>

#include "asm/page.h"
#include "asm/bitops.h"
#include "asm/int.h"

#include "bug.h"
#include "images/core.pb-c.h"

#define SIGMAX			64
#define SIGMAX_OLD		31

#define MAJOR(dev)		((dev)>>8)
#define MINOR(dev)		((dev) & 0xff)

typedef void rt_signalfn_t(int, siginfo_t *, void *);
typedef rt_signalfn_t *rt_sighandler_t;

typedef void rt_restorefn_t(void);
typedef rt_restorefn_t *rt_sigrestore_t;

#define _KNSIG           64
# define _NSIG_BPW      64

#define _KNSIG_WORDS     (_KNSIG / _NSIG_BPW)

typedef struct {
	u64 sig[_KNSIG_WORDS];
} k_rtsigset_t;

static inline void ksigfillset(k_rtsigset_t *set)
{
	int i;
	for (i = 0; i < _KNSIG_WORDS; i++)
		set->sig[i] = (unsigned long)-1;
}

#define SA_RESTORER	0x04000000

typedef struct {
	rt_sighandler_t	rt_sa_handler;
	unsigned long	rt_sa_flags;
	rt_sigrestore_t	rt_sa_restorer;
	k_rtsigset_t	rt_sa_mask;
} rt_sigaction_t;

typedef struct {
	unsigned int	entry_number;
	unsigned int	base_addr;
	unsigned int	limit;
	unsigned int	seg_32bit:1;
	unsigned int	contents:2;
	unsigned int	read_exec_only:1;
	unsigned int	limit_in_pages:1;
	unsigned int	seg_not_present:1;
	unsigned int	useable:1;
	unsigned int	lm:1;
} user_desc_t;

typedef struct {
	uint64_t	r15;
	uint64_t	r14;
	uint64_t	r13;
	uint64_t	r12;
	uint64_t	bp;
	uint64_t	bx;
	uint64_t	r11;
	uint64_t	r10;
	uint64_t	r9;
	uint64_t	r8;
	uint64_t	ax;
	uint64_t	cx;
	uint64_t	dx;
	uint64_t	si;
	uint64_t	di;
	uint64_t	orig_ax;
	uint64_t	ip;
	uint64_t	cs;
	uint64_t	flags;
	uint64_t	sp;
	uint64_t	ss;
	uint64_t	fs_base;
	uint64_t	gs_base;
	uint64_t	ds;
	uint64_t	es;
	uint64_t	fs;
	uint64_t	gs;
} user_regs_struct64;

typedef struct {
	uint32_t	bx;
	uint32_t	cx;
	uint32_t	dx;
	uint32_t	si;
	uint32_t	di;
	uint32_t	bp;
	uint32_t	ax;
	uint32_t	ds;
	uint32_t	es;
	uint32_t	fs;
	uint32_t	gs;
	uint32_t	orig_ax;
	uint32_t	ip;
	uint32_t	cs;
	uint32_t	flags;
	uint32_t	sp;
	uint32_t	ss;
} user_regs_struct32;

#ifdef CONFIG_X86_64
/*
 * To be sure that we rely on inited reg->__is_native, this member
 * is (short int) instead of initial (bool). The right way to
 * check if regs are native or compat is to use user_regs_native() macro.
 * This should cost nothing, as *usually* sizeof(bool) == sizeof(short)
 */
typedef struct {
	union {
		user_regs_struct64 native;
		user_regs_struct32 compat;
	};
	short __is_native; /* use user_regs_native macro to check it */
} user_regs_struct_t;

#define NATIVE_MAGIC	0x0A
#define COMPAT_MAGIC	0x0C
static inline bool user_regs_native(user_regs_struct_t *pregs)
{
	BUG_ON(pregs->__is_native != NATIVE_MAGIC &&
		pregs->__is_native != COMPAT_MAGIC);
	return pregs->__is_native == NATIVE_MAGIC;
}

#define get_user_reg(pregs, name) ((user_regs_native(pregs)) ?		\
		((pregs)->native.name) : ((pregs)->compat.name))
#define set_user_reg(pregs, name, val) ((user_regs_native(pregs)) ?	\
		((pregs)->native.name = (val)) : ((pregs)->compat.name = (val)))
static inline int core_is_compat(CoreEntry *c)
{
	switch (c->thread_info->gpregs->gpregs_case)
	{
		case USER_X86_REGS_CASE_T__NATIVE:
			return 0;
		case USER_X86_REGS_CASE_T__COMPAT:
			return 1;
		default:
			return -1;
	}
}
#else /* !CONFIG_X86_64 */
typedef struct {
	union {
		user_regs_struct32 native;
	};
} user_regs_struct_t;
#define user_regs_native(pregs)		true
#define get_user_reg(pregs, name)	((pregs)->native.name)
#define set_user_reg(pregs, name, val)	((pregs)->native.name = val)
static inline int core_is_compat(CoreEntry *c) { return 0; }
#endif /* !CONFIG_X86_64 */

typedef struct {
	unsigned short	cwd;
	unsigned short	swd;
	unsigned short	twd;	/* Note this is not the same as
				   the 32bit/x87/FSAVE twd */
	unsigned short	fop;
	u64		rip;
	u64		rdp;
	u32		mxcsr;
	u32		mxcsr_mask;
	u32		st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
	u32		xmm_space[64];	/* 16*16 bytes for each XMM-reg = 256 bytes */
	u32		padding[24];
} user_fpregs_struct_t;

#ifdef CONFIG_X86_64
# define TASK_SIZE	((1UL << 47) - PAGE_SIZE)
#else
/*
 * Task size may be limited to 3G but we need a
 * higher limit, because it's backward compatible.
 */
# define TASK_SIZE	(0xffffe000)
#endif

static inline unsigned long task_size() { return TASK_SIZE; }

typedef u64 auxv_t;
typedef u32 tls_t;

#define REG_RES(regs)		get_user_reg(&regs, ax)
#define REG_IP(regs)		get_user_reg(&regs, ip)
#define REG_SYSCALL_NR(regs)	get_user_reg(&regs, orig_ax)

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__X86_64

#define AT_VECTOR_SIZE 44

#define CORE_THREAD_ARCH_INFO(core) core->thread_info

typedef UserX86RegsEntry UserRegsEntry;

static inline u64 encode_pointer(void *p) { return (u64)(long)p; }
static inline void *decode_pointer(u64 v) { return (void*)(long)v; }

#endif /* __CR_ASM_TYPES_H__ */
