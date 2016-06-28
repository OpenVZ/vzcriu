#ifndef __CR_PARASITE_COMPAT_H__
#define __CR_PARASITE_COMPAT_H__

/* XXX: define _compat types per-arch */

#ifndef __ASSEMBLY__

#include "images/core.pb-c.h"

typedef struct {
	u32	rt_sa_handler;
	u32	rt_sa_flags;
	u32	rt_sa_restorer;
	k_rtsigset_t	rt_sa_mask;
} rt_sigaction_t_compat;

struct parasite_dump_sa_args_compat {
	rt_sigaction_t_compat sas[SIGMAX];
};

struct parasite_timeval_compat {
	u32	tv_sec;
	u32	tv_usec;
};

struct parasite_itimerval_compat {
	struct parasite_timeval_compat it_interval;
	struct parasite_timeval_compat it_value;
};

struct parasite_dump_itimers_args_compat {
	struct parasite_itimerval_compat real;
	struct parasite_itimerval_compat virt;
	struct parasite_itimerval_compat prof;
};

struct parasite_timespec_compat {
	u32	tv_sec;
	u32	tv_nsec;
};

struct parasite_itimerspec_compat {
	struct parasite_timespec_compat it_interval;
	struct parasite_timespec_compat it_value;
};

struct posix_timer_compat {
	s32 it_id;
	struct parasite_itimerspec_compat val;
	s32 overrun;
};

struct parasite_dump_posix_timers_args_compat {
	s32 timer_n;
	struct posix_timer_compat timer[0];
};

static inline int posix_timers_compat_dump_size(int timer_n)
{
	return sizeof(s32) + sizeof(struct posix_timer_compat) * timer_n;
}

typedef struct {
	u32	ss_sp;
	s32	ss_flags;
	u32	ss_size;
} stack_t_compat;

struct parasite_dump_thread_compat {
	u32				tid_addr;
	s32				tid;
	tls_t				tls;
	stack_t_compat			sas;
	s32				pdeath_sig;
	struct parasite_dump_creds	creds[0];
};

static inline void copy_sas_compat(ThreadSasEntry *dst,
		const stack_t_compat *src)
{
	dst->ss_sp = encode_pointer((void*)(uintptr_t)src->ss_sp);
	dst->ss_size = (u64)src->ss_size;
	dst->ss_flags = src->ss_flags;
}


#endif /* !__ASSEMBLY__ */

#endif /* __CR_PARASITE_COMPAT_H__ */
