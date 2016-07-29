#ifndef __CR_PROC_PARSE_H__
#define __CR_PROC_PARSE_H__

#include <sys/types.h>
#include "asm/types.h"
#include "list.h"

#include "images/eventfd.pb-c.h"
#include "images/eventpoll.pb-c.h"
#include "images/signalfd.pb-c.h"
#include "images/fsnotify.pb-c.h"
#include "images/timerfd.pb-c.h"
#include "images/seccomp.pb-c.h"

#define PROC_TASK_COMM_LEN	32
#define PROC_TASK_COMM_LEN_FMT	"(%31s"

struct proc_pid_stat {
	int			pid;
	char			comm[PROC_TASK_COMM_LEN];
	char			state;
	int			ppid;
	int			pgid;
	int			sid;
	int			tty_nr;
	int			tty_pgrp;
	unsigned int		flags;
	unsigned long		min_flt;
	unsigned long		cmin_flt;
	unsigned long		maj_flt;
	unsigned long		cmaj_flt;
	unsigned long		utime;
	unsigned long		stime;
	long			cutime;
	long			cstime;
	long			priority;
	long			nice;
	int			num_threads;
	int			zero0;
	unsigned long long	start_time;
	unsigned long		vsize;
	long			mm_rss;
	unsigned long		rsslim;
	unsigned long		start_code;
	unsigned long		end_code;
	unsigned long		start_stack;
	unsigned long		esp;
	unsigned long		eip;
	unsigned long		sig_pending;
	unsigned long		sig_blocked;
	unsigned long		sig_ignored;
	unsigned long		sig_handled;
	unsigned long		wchan;
	unsigned long		zero1;
	unsigned long		zero2;
	int			exit_signal;
	int			task_cpu;
	unsigned int		rt_priority;
	unsigned int		policy;
	unsigned long long	delayacct_blkio_ticks;
	unsigned long		gtime;
	long			cgtime;
	unsigned long		start_data;
	unsigned long		end_data;
	unsigned long		start_brk;
	unsigned long		arg_start;
	unsigned long		arg_end;
	unsigned long		env_start;
	unsigned long		env_end;
	int			exit_code;
};

struct seccomp_info {
	SeccompFilter filter;
	int id;
	struct seccomp_info *prev;
};

#define PROC_CAP_SIZE	2

struct proc_status_creds {
	unsigned int uids[4];
	unsigned int gids[4];

	char			state;
	int			ppid;
	unsigned long long	sigpnd;
	unsigned long long	shdpnd;

	int			seccomp_mode;
	u32			last_filter;

	/*
	 * Keep them at the end of structure
	 * for fast comparision reason.
	 */
	u32			cap_inh[PROC_CAP_SIZE];
	u32			cap_prm[PROC_CAP_SIZE];
	u32			cap_eff[PROC_CAP_SIZE];
	u32			cap_bnd[PROC_CAP_SIZE];
};

bool proc_status_creds_dumpable(struct proc_status_creds *parent,
				struct proc_status_creds *child);

struct mount_info;
typedef int (*mount_fn_t)(struct mount_info *mi, const char *src, const
			  char *fstype, unsigned long mountflags);

struct fstype {
	char *name;
	int code;
	int (*dump)(struct mount_info *pm);
	int (*restore)(struct mount_info *pm);
	int (*parse)(struct mount_info *pm);
	mount_fn_t mount;
};

struct vm_area_list;

#define INVALID_UID ((uid_t)-1)

extern bool add_skip_mount(const char *mountpoint);
struct ns_id;
extern struct mount_info *parse_mountinfo(pid_t pid, struct ns_id *nsid, bool for_dump);
extern int parse_pid_stat(pid_t pid, struct proc_pid_stat *s);
extern unsigned int parse_pid_loginuid(pid_t pid, int *err, bool ignore_noent);
extern int parse_pid_oom_score_adj(pid_t pid, int *err);
extern int prepare_loginuid(unsigned int value, unsigned int loglevel);
struct vma_area;
typedef int (*dump_filemap_t)(struct vma_area *vma_area, int fd);
extern int parse_smaps(pid_t pid, struct vm_area_list *vma_area_list, dump_filemap_t cb);
extern int parse_self_maps_lite(struct vm_area_list *vms);
extern int parse_pid_status(pid_t pid, struct proc_status_creds *);

struct inotify_wd_entry {
	InotifyWdEntry e;
	FhEntry f_handle;
	struct list_head node;
};

struct fanotify_mark_entry {
	FanotifyMarkEntry e;
	FhEntry f_handle;
	struct list_head node;
	union {
		FanotifyInodeMarkEntry ie;
		FanotifyMountMarkEntry me;
	};
};

struct eventpoll_tfd_entry {
	EventpollTfdEntry e;
	struct list_head node;
};

union fdinfo_entries {
	EventfdFileEntry efd;
	SignalfdEntry sfd;
	struct inotify_wd_entry ify;
	struct fanotify_mark_entry ffy;
	struct eventpoll_tfd_entry epl;
	TimerfdEntry tfy;
};

extern void free_inotify_wd_entry(union fdinfo_entries *e);
extern void free_fanotify_mark_entry(union fdinfo_entries *e);
extern void free_event_poll_entry(union fdinfo_entries *e);

struct fdinfo_common {
	off64_t pos;
	int flags;
	int mnt_id;
	int owner;
};

extern int parse_fdinfo(int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg);
extern int parse_fdinfo_pid(int pid, int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg);
extern int parse_file_locks(void);
extern int get_fd_mntid(int fd, int *mnt_id);

struct pid;
extern int parse_threads(int pid, struct pid **_t, int *_n);

extern int check_mnt_id(void);

/*
 * This struct describes a group controlled by one controller.
 * The @name is the controller name or 'name=...' for named cgroups.
 * The @path is the path from the hierarchy root.
 */

struct cg_ctl {
	struct list_head l;
	char *name;
	char *path;
	u32 cgns_prefix;
};

/*
 * Returns the list of cg_ctl-s sorted by name
 */
struct list_head;
struct parasite_dump_cgroup_args;
extern int parse_task_cgroup(int pid, struct parasite_dump_cgroup_args *args, struct list_head *l, unsigned int *n);
extern void put_ctls(struct list_head *);

int collect_controllers(struct list_head *cgroups, unsigned int *n_cgroups);

/* callback for AUFS support */
extern int aufs_parse(struct mount_info *mi);

/* callback for OverlayFS support */
extern int overlayfs_parse(struct mount_info *mi);

int parse_children(pid_t pid, pid_t **_c, int *_n);

#endif /* __CR_PROC_PARSE_H__ */
