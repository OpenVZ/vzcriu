#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include "asm/types.h"
#include "asm/fpu.h"
#include "images/core.pb-c.h"
#include "syscall-codes.h"

struct rt_sigcontext {
	unsigned long			r8;
	unsigned long			r9;
	unsigned long			r10;
	unsigned long			r11;
	unsigned long			r12;
	unsigned long			r13;
	unsigned long			r14;
	unsigned long			r15;
	unsigned long			rdi;
	unsigned long			rsi;
	unsigned long			rbp;
	unsigned long			rbx;
	unsigned long			rdx;
	unsigned long			rax;
	unsigned long			rcx;
	unsigned long			rsp;
	unsigned long			rip;
	unsigned long			eflags;
	unsigned short			cs;
	unsigned short			gs;
	unsigned short			fs;
	unsigned short			ss;
	unsigned long			err;
	unsigned long			trapno;
	unsigned long			oldmask;
	unsigned long			cr2;
	void				*fpstate;
	unsigned long			reserved1[8];
};

struct rt_sigcontext_32 {
	u32				gs;
	u32				fs;
	u32				es;
	u32				ds;
	u32				di;
	u32				si;
	u32				bp;
	u32				sp;
	u32				bx;
	u32				dx;
	u32				cx;
	u32				ax;
	u32				trapno;
	u32				err;
	u32				ip;
	u32				cs;
	u32				flags;
	u32				sp_at_signal;
	u32				ss;

	u32				fpstate;
	u32				oldmask;
	u32				cr2;
};

#define SIGFRAME_MAX_OFFSET 8

#include "sigframe.h"

/*
 * XXX: move declarations to generic sigframe.h or sigframe-compat.h
 *      when (if) other architectures will support compatible C/R
 */

typedef u32			compat_uptr_t;
typedef u32			compat_size_t;
typedef u32			compat_sigset_word;

#define _COMPAT_NSIG		64
#define _COMPAT_NSIG_BPW	32
#define _COMPAT_NSIG_WORDS	(_COMPAT_NSIG / _COMPAT_NSIG_BPW)

typedef struct {
	compat_sigset_word	sig[_COMPAT_NSIG_WORDS];
} compat_sigset_t;

#ifdef CONFIG_X86_64
typedef struct compat_siginfo {
	int	si_signo;
	int	si_errno;
	int	si_code;
	int	_pad[128/sizeof(int) - 3];
} compat_siginfo_t;

static inline void __always_unused __check_compat_sigset_t(void)
{
	BUILD_BUG_ON(sizeof(compat_sigset_t) != sizeof(k_rtsigset_t));
}

#define CONFIG_COMPAT
extern void *alloc_compat_syscall_stack(void);
extern void free_compat_syscall_stack(void *mem);
extern unsigned long call32_from_64(void *stack, void *func);

extern int arch_compat_rt_sigaction(void *stack32, int sig,
		rt_sigaction_t_compat *act);
#else
#define rt_sigframe_ia32		rt_sigframe
static inline void *alloc_compat_syscall_stack(void) { return NULL; }
static inline void free_compat_syscall_stack(void *stack32) { }
static inline int
arch_compat_rt_sigaction(void *stack, int sig, void *act) { return -1; }
#endif

typedef struct compat_sigaltstack {
	compat_uptr_t		ss_sp;
	int			ss_flags;
	compat_size_t		ss_size;
} compat_stack_t;

struct ucontext_ia32 {
	unsigned int		uc_flags;
	unsigned int		uc_link;
	compat_stack_t		uc_stack;
	struct rt_sigcontext_32	uc_mcontext;
	k_rtsigset_t		uc_sigmask; /* mask last for extensibility */
};

struct rt_sigframe_ia32 {
	u32			pretcode;
	s32			sig;
	u32			pinfo;
	u32			puc;
#ifdef CONFIG_X86_64
	compat_siginfo_t	info;
#else
	struct rt_siginfo	info;
#endif
	struct ucontext_ia32	uc;
	char			retcode[8];

	/* fp state follows here */
	fpu_state_t		fpu_state;
};

#ifdef CONFIG_X86_64
struct rt_sigframe_64 {
	char			*pretcode;
	struct rt_ucontext	uc;
	struct rt_siginfo	info;

	/* fp state follows here */
	fpu_state_t		fpu_state;
};

struct rt_sigframe {
	union {
		struct rt_sigframe_ia32	compat;
		struct rt_sigframe_64	native;
	};
	bool is_native;
};

#define RT_SIGFRAME_UC_SIGMASK(rt_sigframe) ((rt_sigframe->is_native) ?	\
	(&rt_sigframe->native.uc.uc_sigmask) :				\
	(&rt_sigframe->compat.uc.uc_sigmask))

#define RT_SIGFRAME_REGIP(rt_sigframe) ((rt_sigframe->is_native) ?	\
	(rt_sigframe)->native.uc.uc_mcontext.rip :			\
	(rt_sigframe)->compat.uc.uc_mcontext.ip)

#define RT_SIGFRAME_FPU(rt_sigframe)	((rt_sigframe->is_native) ?	\
	(&(rt_sigframe)->native.fpu_state) : (&(rt_sigframe)->compat.fpu_state))
#define RT_SIGFRAME_HAS_FPU(rt_sigframe) (RT_SIGFRAME_FPU(rt_sigframe)->has_fpu)

/*
 * Sigframe offset is different for native/compat tasks.
 * Offsets calculations one may see at kernel:
 * - compatible is in sys32_rt_sigreturn at arch/x86/ia32/ia32_signal.c
 * - native is in sys_rt_sigreturn at arch/x86/kernel/signal.c
 */
#define RT_SIGFRAME_OFFSET(rt_sigframe)	((rt_sigframe->is_native) ? 8 : 4 )

#define USER32_CS		0x23

#define ARCH_RT_SIGRETURN_NATIVE(new_sp)				\
	asm volatile(							\
		     "movq %0, %%rax				    \n"	\
		     "movq %%rax, %%rsp				    \n"	\
		     "movl $"__stringify(__NR_rt_sigreturn)", %%eax \n" \
		     "syscall					    \n"	\
		     :							\
		     : "r"(new_sp)					\
		     : "rax","rsp","memory")

#define ARCH_RT_SIGRETURN_COMPAT(new_sp)				\
	asm volatile(							\
		"pushq $"__stringify(USER32_CS)"		\n"	\
		"pushq $1f					\n"	\
		"lretq						\n"	\
		"1:						\n"	\
		".code32					\n"	\
		"movl %%edi, %%esp				\n"	\
		"movl $"__stringify(__NR32_rt_sigreturn)",%%eax	\n"	\
		"int $0x80					\n"	\
		".code64					\n"	\
		:							\
		: "rdi"(new_sp)						\
		: "eax","esp","memory")

#define ARCH_RT_SIGRETURN(new_sp, rt_sigframe)				\
do {									\
	if ((rt_sigframe)->is_native)					\
		ARCH_RT_SIGRETURN_NATIVE(new_sp);			\
	else								\
		ARCH_RT_SIGRETURN_COMPAT(new_sp);			\
} while (0)

#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,      \
			     thread_args, clone_restore_fn)             \
	asm volatile(							\
		     "clone_emul:				\n"	\
		     "movq %2, %%rsi				\n"	\
		     "subq $16, %%rsi			        \n"	\
		     "movq %6, %%rdi				\n"	\
		     "movq %%rdi, 8(%%rsi)			\n"	\
		     "movq %5, %%rdi				\n"	\
		     "movq %%rdi, 0(%%rsi)			\n"	\
		     "movq %1, %%rdi				\n"	\
		     "movq %3, %%rdx				\n"	\
		     "movq %4, %%r10				\n"	\
		     "movl $"__stringify(__NR_clone)", %%eax	\n"	\
		     "syscall				        \n"	\
									\
		     "testq %%rax,%%rax			        \n"	\
		     "jz thread_run				\n"	\
									\
		     "movq %%rax, %0				\n"	\
		     "jmp clone_end				\n"	\
									\
		     "thread_run:				\n"	\
		     "xorq %%rbp, %%rbp			        \n"	\
		     "popq %%rax				\n"	\
		     "popq %%rdi				\n"	\
		     "callq *%%rax				\n"	\
									\
		     "clone_end:				\n"	\
		     : "=r"(ret)					\
		     : "g"(clone_flags),				\
		       "g"(new_sp),					\
		       "g"(&parent_tid),				\
		       "g"(&thread_args[i].pid),			\
		       "g"(clone_restore_fn),				\
		       "g"(&thread_args[i])				\
		     : "rax", "rcx", "rdi", "rsi", "rdx", "r10", "r11", "memory")

#define ARCH_FAIL_CORE_RESTORE					\
	asm volatile(						\
		     "movq %0, %%rsp			    \n"	\
		     "movq 0, %%rax			    \n"	\
		     "jmp *%%rax			    \n"	\
		     :						\
		     : "r"(ret)					\
		     : "memory")

#ifndef ARCH_MAP_VDSO_32
# define ARCH_MAP_VDSO_32		0x2002
#endif

extern int kdat_compat_sigreturn_test(void);
#else /* !CONFIG_X86_64 */

#define ARCH_RT_SIGRETURN(new_sp, rt_sigframe)				\
	asm volatile(							\
		     "movl %0, %%eax				    \n"	\
		     "movl %%eax, %%esp				    \n"	\
		     "movl $"__stringify(__NR_rt_sigreturn)", %%eax \n" \
		     "int $0x80					    \n"	\
		     :							\
		     : "r"(new_sp)					\
		     : "eax","esp","memory")

#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,      \
			     thread_args, clone_restore_fn)             \
	(void)ret;							\
	(void)clone_flags;						\
	(void)new_sp;							\
	(void)parent_tid;						\
	(void)thread_args;						\
	(void)clone_restore_fn;						\
	;
#define ARCH_FAIL_CORE_RESTORE					\
	asm volatile(						\
		     "movl %0, %%esp			    \n"	\
		     "xorl %%eax, %%eax			    \n"	\
		     "jmp *%%eax			    \n"	\
		     :						\
		     : "r"(ret)					\
		     : "memory")

#define RT_SIGFRAME_UC(rt_sigframe) (&rt_sigframe->uc)
#define RT_SIGFRAME_OFFSET(rt_sigframe)	4
#define RT_SIGFRAME_REGIP(rt_sigframe)					\
	(unsigned long)(rt_sigframe)->uc.uc_mcontext.ip
#define RT_SIGFRAME_FPU(rt_sigframe) (&(rt_sigframe)->fpu_state)
#define RT_SIGFRAME_HAS_FPU(rt_sigframe) (RT_SIGFRAME_FPU(rt_sigframe)->has_fpu)
#define kdat_compat_sigreturn_test()			0
#endif /* !CONFIG_X86_64 */

static inline void
__setup_sas_compat(struct ucontext_ia32* uc, ThreadSasEntry *sas)
{
	uc->uc_stack.ss_sp	= (compat_uptr_t)(sas)->ss_sp;
	uc->uc_stack.ss_flags	= (int)(sas)->ss_flags;
	uc->uc_stack.ss_size	= (compat_size_t)(sas)->ss_size;
}

static inline void
__setup_sas(struct rt_sigframe* sigframe, ThreadSasEntry *sas)
{
#ifdef CONFIG_X86_64
	if (sigframe->is_native) {
		struct rt_ucontext *uc	= &sigframe->native.uc;

		uc->uc_stack.ss_sp	= (void *)decode_pointer((sas)->ss_sp);
		uc->uc_stack.ss_flags	= (int)(sas)->ss_flags;
		uc->uc_stack.ss_size	= (size_t)(sas)->ss_size;
	} else {
		__setup_sas_compat(&sigframe->compat.uc, sas);
	}
#else
	__setup_sas_compat(&sigframe->uc, sas);
#endif
}

static inline void _setup_sas(struct rt_sigframe* sigframe, ThreadSasEntry *sas)
{
	if (sas)
		__setup_sas(sigframe, sas);
}
#define setup_sas _setup_sas

int restore_gpregs(struct rt_sigframe *f, UserX86RegsEntry *r);
int restore_nonsigframe_gpregs(UserX86RegsEntry *r);

int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe,
		struct rt_sigframe *rsigframe);

void restore_tls(tls_t *ptls);

int ptrace_set_breakpoint(pid_t pid, void *addr);
int ptrace_flush_breakpoints(pid_t pid);


#endif
