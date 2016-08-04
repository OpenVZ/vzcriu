#ifndef __CR_PARASITE_H__
#define __CR_PARASITE_H__

#define PARASITE_STACK_SIZE	(16 << 10)
#define PARASITE_ARG_SIZE_MIN	( 1 << 12)

#define PARASITE_MAX_SIZE	(64 << 10)

#ifndef __ASSEMBLY__

#include <sys/un.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#include "image.h"
#include "util-pie.h"
#include "lock.h"

#include "images/vma.pb-c.h"
#include "images/tty.pb-c.h"

#define __head __used __section(.head.text)

/*
 * NOTE: each command's args should be arch-independed sized.
 * If you want to use one of the standard types, declare
 * alternative type for compatible tasks in parasite-compat.h
 */
enum {
	PARASITE_CMD_IDLE		= 0,
	PARASITE_CMD_ACK,

	PARASITE_CMD_INIT_DAEMON,
	PARASITE_CMD_DUMP_THREAD,
	PARASITE_CMD_UNMAP,

	/*
	 * This must be greater than INITs.
	 */
	PARASITE_CMD_FINI,

	PARASITE_CMD_MPROTECT_VMAS,
	PARASITE_CMD_DUMPPAGES,

	PARASITE_CMD_DUMP_SIGACTS,
	PARASITE_CMD_DUMP_ITIMERS,
	PARASITE_CMD_DUMP_POSIX_TIMERS,
	PARASITE_CMD_DUMP_MISC,
	PARASITE_CMD_DRAIN_FDS,
	PARASITE_CMD_GET_PROC_FD,
	PARASITE_CMD_DUMP_TTY,
	PARASITE_CMD_CHECK_VDSO_MARK,
	PARASITE_CMD_CHECK_AIOS,
	PARASITE_CMD_DUMP_CGROUP,

	PARASITE_CMD_MAX,
};

struct ctl_msg {
	u32	cmd;			/* command itself */
	u32	ack;			/* ack on command */
	s32	err;			/* error code on reply */
};

#define ctl_msg_cmd(_cmd)		\
	(struct ctl_msg){.cmd = _cmd, }

#define ctl_msg_ack(_cmd, _err)	\
	(struct ctl_msg){.cmd = _cmd, .ack = _cmd, .err = _err, }

struct parasite_init_args {
	s32			h_addr_len;
	struct sockaddr_un	h_addr;

	s32			log_level;

	u64			sigreturn_addr;

	u64			sigframe; /* pointer to sigframe */

	futex_t			daemon_connected;
};

struct parasite_unmap_args {
	u64		parasite_start;
	u64		parasite_len;
};

struct parasite_vma_entry
{
	u64		start;
	u64		len;
	s32		prot;
};

struct parasite_vdso_vma_entry {
	u64	start;
	u64	len;
	u64	proxy_vdso_addr;
	u64	proxy_vvar_addr;
	s32		is_marked;
	u8		try_fill_symtable;
	u8		is_vdso;
};

struct parasite_dump_pages_args {
	u32	nr_vmas;
	u32	add_prot;
	u32	off;
	u32	nr_segs;
	u32	nr_pages;
};

static inline struct parasite_vma_entry *pargs_vmas(struct parasite_dump_pages_args *a)
{
	return (struct parasite_vma_entry *)(a + 1);
}

static inline struct iovec *pargs_iovs(struct parasite_dump_pages_args *a)
{
	return (struct iovec *)(pargs_vmas(a) + a->nr_vmas);
}

struct parasite_dump_sa_args {
	rt_sigaction_t sas[SIGMAX];
};

struct parasite_dump_itimers_args {
	struct itimerval real;
	struct itimerval virt;
	struct itimerval prof;
};

struct posix_timer {
	int it_id;
	struct itimerspec val;
	int overrun;
};

struct parasite_dump_posix_timers_args {
	int timer_n;
	struct posix_timer timer[0];
};

struct parasite_aio {
	u64 ctx;
	u64 size;
};

struct parasite_check_aios_args {
	u32 nr_rings;
	struct parasite_aio ring[0];
};

static inline int posix_timers_dump_size(int timer_n)
{
	return sizeof(int) + sizeof(struct posix_timer) * timer_n;
}

/*
 * Misc sfuff, that is too small for separate file, but cannot
 * be read w/o using parasite
 */

struct parasite_dump_misc {
	u64 brk;

	u32 pid;
	u32 sid;
	u32 pgid;
	u32 umask;

	s32 dumpable;
};

/*
 * Calculate how long we can make the groups array in parasite_dump_creds
 * and still fit the struct in one page
 */
#define PARASITE_MAX_GROUPS							\
	((PAGE_SIZE - sizeof(struct parasite_dump_thread) -			\
	 offsetof(struct parasite_dump_creds, groups)) / sizeof(unsigned int)) /* groups */

struct parasite_dump_creds {
	u32			cap_last_cap;

	u32			cap_inh[CR_CAP_SIZE];
	u32			cap_prm[CR_CAP_SIZE];
	u32			cap_eff[CR_CAP_SIZE];
	u32			cap_bnd[CR_CAP_SIZE];

	s32			uids[4];
	s32			gids[4];
	u32			secbits;
	u32			ngroups;
	/*
	 * FIXME -- this structure is passed to parasite code
	 * through parasite args area so in parasite_dump_creds()
	 * call we check for size of this data fits the size of
	 * the area. Unfortunatelly, we _actually_ use more bytes
	 * than the sizeof() -- we put PARASITE_MAX_GROUPS int-s
	 * in there, so the size check is not correct.
	 *
	 * However, all this works simply because we make sure
	 * the PARASITE_MAX_GROUPS is so, that the total amount
	 * of memory in use doesn't exceed the PAGE_SIZE and the
	 * args area is at least one page (PARASITE_ARG_SIZE_MIN).
	 */
	u32			groups[0];
};

struct parasite_dump_thread {
	unsigned int			*tid_addr;
	pid_t				tid;
	tls_t				tls;
	stack_t				sas;
	int				pdeath_sig;
	struct parasite_dump_creds	creds[0];
};

static inline void copy_sas(ThreadSasEntry *dst, const stack_t *src)
{
	dst->ss_sp = encode_pointer(src->ss_sp);
	dst->ss_size = (u64)src->ss_size;
	dst->ss_flags = src->ss_flags;
}

/*
 * How many descriptors can be transferred from parasite:
 *
 * 1) struct parasite_drain_fd + all descriptors should fit into one page
 * 2) The value should be a multiple of CR_SCM_MAX_FD, because descriptors
 *    are transferred with help of send_fds and recv_fds.
 * 3) criu should work with a defaul value of the file limit (1024)
 */
#define PARASITE_MAX_FDS	CR_SCM_MAX_FD * 3

struct parasite_drain_fd {
	s32	nr_fds;
	s32	fds[0];
};

static inline int drain_fds_size(struct parasite_drain_fd *dfds)
{
	int nr_fds = min((int)PARASITE_MAX_FDS, dfds->nr_fds);

	BUILD_BUG_ON(sizeof(*dfds) + PARASITE_MAX_FDS * sizeof(dfds->fds[0]) > PAGE_SIZE);

	return sizeof(dfds) + nr_fds * sizeof(dfds->fds[0]);
}

struct parasite_tty_args {
	s32	fd;
	s32	type;

	s32	sid;
	s32	pgrp;

	s32	st_pckt;
	s32	st_lock;
	s32	st_excl;

	u8	hangup;
};

struct parasite_dump_cgroup_args {
	/*
	 * 4K should be enough for most cases.
	 *
	 * The string is null terminated.
	 */
	char contents[PARASITE_ARG_SIZE_MIN];
};

/* the parasite prefix is added by gen_offsets.sh */
#define __pblob_offset(ptype, symbol)					\
	parasite_ ## ptype ## _blob_offset__ ## symbol
#define parasite_sym(pblob, ptype, symbol)				\
	((void *)(pblob) + __pblob_offset(ptype, symbol))

#endif /* !__ASSEMBLY__ */

#include "parasite-compat.h"

#endif /* __CR_PARASITE_H__ */
