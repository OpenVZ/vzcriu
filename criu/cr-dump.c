#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/time.h>
#include <sys/wait.h>


#include <sched.h>
#include <sys/resource.h>

#include <sys/time.h>
#include <sys/resource.h>

#include "types.h"
#include "protobuf.h"
#include "images/fdinfo.pb-c.h"
#include "images/fs.pb-c.h"
#include "images/mm.pb-c.h"
#include "images/creds.pb-c.h"
#include "images/core.pb-c.h"
#include "images/file-lock.pb-c.h"
#include "images/rlimit.pb-c.h"
#include "images/siginfo.pb-c.h"

#include "common/list.h"
#include "imgset.h"
#include "file-ids.h"
#include "kcmp-ids.h"
#include "common/compiler.h"
#include "crtools.h"
#include "cr_options.h"
#include "servicefd.h"
#include "string.h"
#include "ptrace-compat.h"
#include "util.h"
#include "namespaces.h"
#include "image.h"
#include "proc_parse.h"
#include "parasite.h"
#include "parasite-syscall.h"
#include "files.h"
#include "files-reg.h"
#include "shmem.h"
#include "sk-inet.h"
#include "pstree.h"
#include "mount.h"
#include "tty.h"
#include "net.h"
#include "sk-packet.h"
#include "sk-queue.h"
#include "cpu.h"
#include "elf.h"
#include "cgroup.h"
#include "cgroup-props.h"
#include "file-lock.h"
#include "page-xfer.h"
#include "kerndat.h"
#include "stats.h"
#include "mem.h"
#include "page-pipe.h"
#include "posix-timer.h"
#include "vdso.h"
#include "vma.h"
#include "cr-service.h"
#include "plugin.h"
#include "irmap.h"
#include "sysfs_parse.h"
#include "action-scripts.h"
#include "aio.h"
#include "lsm.h"
#include "seccomp.h"
#include "seize.h"
#include "fault-injection.h"
#include "dump.h"
#include "eventpoll.h"
#include "memfd.h"
#include "timens.h"
#include "img-streamer.h"
#include "pipes.h"
#include "devices.h"

struct rlim_ctl {
	struct rlimit		old_rlimit;
	struct rlimit		new_rlimit;
	bool			unlimited;
};

static int rlimit_unlimit_nofile_pid(pid_t pid, struct rlim_ctl *ctl)
{
	ctl->new_rlimit.rlim_cur = kdat.sysctl_nr_open;
	ctl->new_rlimit.rlim_max = kdat.sysctl_nr_open;

	if (prlimit(pid, RLIMIT_NOFILE, &ctl->new_rlimit, &ctl->old_rlimit)) {
		pr_perror("rlimir: Can't setup RLIMIT_NOFILE for %d", pid);
		return -1;
	} else
		pr_debug("rlimit: RLIMIT_NOFILE unlimited for %d\n", pid);

	ctl->unlimited = true;
	return 0;
}

static int rlimit_limit_nofile_pid(pid_t pid, struct rlim_ctl *ctl)
{
	if (!ctl->unlimited)
		return 0;

	if (prlimit(pid, RLIMIT_NOFILE, &ctl->old_rlimit, NULL)) {
		pr_perror("rlimir: Can't restore RLIMIT_NOFILE for %d", pid);
		return -1;
	} else
		pr_debug("rlimit: RLIMIT_NOFILE restored for %d\n", pid);

	ctl->unlimited = false;
	return 0;
}

typedef struct {
	const char	*name;
	const char	fmt_barrier[64];
	const char	fmt_limit[64];
	unsigned long	barrier;
	unsigned long	limit;
} bc_val_t;

#define declare_ub(_u, _b, _l)							\
	{									\
		.name		= __stringify_1(_u),				\
		.fmt_barrier	= "beancounter." __stringify_1(_u) ".barrier",	\
		.fmt_limit	= "beancounter." __stringify_1(_u) ".limit",	\
		.barrier	= _b,						\
		.limit		= _l,						\
	}

#define declare_ub_unlimited(_u)						\
	declare_ub(_u, LONG_MAX, LONG_MAX)

static bc_val_t bc_vals[] = {
	declare_ub_unlimited(lockedpages),
	declare_ub_unlimited(privvmpages),
	declare_ub_unlimited(shmpages),
	declare_ub_unlimited(numproc),
	declare_ub_unlimited(vmguarpages),
	declare_ub_unlimited(numflock),
	declare_ub_unlimited(numpty),
	declare_ub_unlimited(numsiginfo),
	declare_ub_unlimited(numfile),
	declare_ub_unlimited(numiptent),
};

typedef struct {
	const char	*name;
	unsigned long	value;
} memcg_val_t;

static memcg_val_t memcg_vals[] = {
	{
		.name		= "memory.memsw.limit_in_bytes",
		.value		= LONG_MAX,
	}, {
		.name		= "memory.limit_in_bytes",
		.value		= LONG_MAX,
	},
};

#define VE_BC_STATUS_UNDEF	0
#define VE_BC_STATUS_READ	1
#define VE_BC_STATUS_UNLIMITED	2

typedef struct {
	char		veid[512];
	unsigned int	status;

	int		bc_dirfd;
	bc_val_t	*bc_vals;
	size_t		nr_bc_vals;

	int		memcg_dirfd;
	memcg_val_t	*memcg_vals;
	size_t		nr_memcg_vals;
} bc_set_t;

static bc_set_t bc_set = {
	.bc_vals	= bc_vals,
	.nr_bc_vals	= ARRAY_SIZE(bc_vals),
	.memcg_vals	= memcg_vals,
	.nr_memcg_vals	= ARRAY_SIZE(memcg_vals),
	.bc_dirfd	= -1,
	.memcg_dirfd	= -1,
};

extern char *get_dumpee_veid(pid_t pid_real);

static int __maybe_unused ve_read_cg(int dirfd, const char *path, unsigned long *value)
{
	int fd, ret = -1;
	char buf[256];

	fd = openat(dirfd, path, O_RDONLY);
	if (fd < 0) {
		pr_perror("ubc: Can't open %s", path);
		goto out;
	}

	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret <= 0) {
		ret = -1;
		pr_perror("ubc: Can't read %s", path);
		goto out;
	}
	*value = atol(buf);
	ret = 0;
out:
	return ret;
}

static int __maybe_unused ve_write_cg(int dirfd, const char *path, unsigned long value)
{
	int fd, ret = -1;
	char buf[256];

	fd = openat(dirfd, path, O_RDWR);
	if (fd < 0) {
		pr_perror("ubc: Can't open %s", path);
		goto out;
	}

	snprintf(buf, sizeof(buf), "%lu", value);
	ret = write(fd, buf, strlen(buf));
	close(fd);
	if (ret <= 0) {
		ret = -1;
		pr_perror("ubc: Can't write %s", path);
		goto out;
	}
	ret = 0;
out:
	return ret;
}

static void __maybe_unused ve_bc_read(pid_t pid, bc_set_t *bc_set)
{
	char *veid = get_dumpee_veid(pid);
	char path[PATH_MAX];
	int i;

	if (!kdat.has_beancounters)
		return;

	if (!opts.ve)
		return;

	if (IS_ERR_OR_NULL(veid)) {
		pr_err("ubc: Can't fetch VEID of a dumpee %d\n", pid);
		return;
	}
	strlcpy(bc_set->veid, veid, sizeof(bc_set->veid));

	pr_debug("ubc: reading %s\n", bc_set->veid);

	snprintf(path, sizeof(path), "/sys/fs/cgroup/beancounter/%s", veid);
	bc_set->bc_dirfd = open(path, O_DIRECTORY | O_PATH);
	if (bc_set->bc_dirfd < 0) {
		pr_perror("ubc: Can't open %s", path);
		return;
	}

	snprintf(path, sizeof(path), "/sys/fs/cgroup/memory/machine.slice/%s", veid);
	bc_set->memcg_dirfd = open(path, O_DIRECTORY | O_PATH);
	if (bc_set->memcg_dirfd < 0) {
		pr_perror("ubc: Can't open %s", path);
		return;
	}

	for (i = 0; i < bc_set->nr_bc_vals; i++) {
		if (ve_read_cg(bc_set->bc_dirfd,
			       bc_set->bc_vals[i].fmt_barrier,
			       &bc_set->bc_vals[i].barrier) ||
		    ve_read_cg(bc_set->bc_dirfd,
			       bc_set->bc_vals[i].fmt_limit,
			       &bc_set->bc_vals[i].limit))
			return;

		pr_debug("ubc: %s: %s: barrier %lu limit %lu\n",
			 veid, bc_set->bc_vals[i].name,
			 bc_set->bc_vals[i].barrier,
			 bc_set->bc_vals[i].limit);
	}

	for (i = 0; i < bc_set->nr_memcg_vals; i++) {
		if (ve_read_cg(bc_set->memcg_dirfd,
			       bc_set->memcg_vals[i].name,
			       &bc_set->memcg_vals[i].value))
			return;

		pr_debug("ubc: %s: %s: %lu\n",
			 veid, bc_set->memcg_vals[i].name,
			 bc_set->memcg_vals[i].value);
	}


	pr_debug("ubc: read %s\n", bc_set->veid);
	bc_set->status |= VE_BC_STATUS_READ;
}

static void __maybe_unused ve_bc_unlimit(bc_set_t *bc_set)
{
	int i, j;

	if (!kdat.has_beancounters)
		return;

	if (!(bc_set->status & VE_BC_STATUS_READ))
		return;

	pr_debug("ubc: unlimiting %s\n", bc_set->veid);

	for (i = 0; i < bc_set->nr_bc_vals; i++) {
		if (ve_write_cg(bc_set->bc_dirfd,
				bc_set->bc_vals[i].fmt_barrier,
				LONG_MAX) ||
		    ve_write_cg(bc_set->bc_dirfd,
				bc_set->bc_vals[i].fmt_limit,
				LONG_MAX)) {
			pr_err("ubc: Can't unlimit %s/%s for %s\n",
			       bc_set->bc_vals[i].fmt_barrier,
			       bc_set->bc_vals[i].fmt_limit,
			       bc_set->veid);
			for (j = i; j >= 0; j--) {
				ve_write_cg(bc_set->bc_dirfd,
					    bc_set->bc_vals[j].fmt_barrier,
					    bc_set->bc_vals[j].barrier);
				ve_write_cg(bc_set->bc_dirfd,
					    bc_set->bc_vals[j].fmt_limit,
					    bc_set->bc_vals[j].limit);
			}
			return;
		}
	}

	for (i = 0; i < bc_set->nr_memcg_vals; i++) {
		if (ve_write_cg(bc_set->memcg_dirfd,
				bc_set->memcg_vals[i].name,
				LONG_MAX)) {
			pr_err("ubc: Can't unlimit %s for %s\n",
			       bc_set->memcg_vals[i].name,
			       bc_set->veid);
			for (j = i; j >= 0; j--) {
				ve_write_cg(bc_set->memcg_dirfd,
				bc_set->memcg_vals[i].name,
				bc_set->memcg_vals[i].value);
			}
			return;
		}
	}

	pr_debug("ubc: unlimited %s\n", bc_set->veid);
	bc_set->status |= VE_BC_STATUS_UNLIMITED;
}

static void __maybe_unused ve_bc_finish(bc_set_t *bc_set)
{
	int i;

	if (!kdat.has_beancounters)
		return;

	pr_debug("ubc: restore limits %s\n", bc_set->veid);

	if (!(bc_set->status & VE_BC_STATUS_UNLIMITED))
		return;

	for (i = 0; i < bc_set->nr_bc_vals; i++) {
		ve_write_cg(bc_set->bc_dirfd,
			    bc_set->bc_vals[i].fmt_barrier,
			    bc_set->bc_vals[i].barrier);
		ve_write_cg(bc_set->bc_dirfd,
			    bc_set->bc_vals[i].fmt_limit,
			    bc_set->bc_vals[i].limit);
	}

	for (i = bc_set->nr_memcg_vals - 1; i >= 0; i--) {
		ve_write_cg(bc_set->memcg_dirfd,
			    bc_set->memcg_vals[i].name,
			    bc_set->memcg_vals[i].value);
	}

	pr_debug("ubc: restored %s\n", bc_set->veid);
}


/*
 * Architectures can overwrite this function to restore register sets that
 * are not covered by ptrace_set/get_regs().
 *
 * with_threads = false: Only the register sets of the tasks are restored
 * with_threads = true : The register sets of the tasks with all their threads
 *			 are restored
 */
int __attribute__((weak)) arch_set_thread_regs(struct pstree_item *item,
					       bool with_threads)
{
	return 0;
}

#define PERSONALITY_LENGTH	9
static char loc_buf[PERSONALITY_LENGTH];

void free_mappings(struct vm_area_list *vma_area_list)
{
	struct vma_area *vma_area, *p;

	list_for_each_entry_safe(vma_area, p, &vma_area_list->h, list) {
		if (!vma_area->file_borrowed)
			free(vma_area->vmst);
		free(vma_area);
	}

	vm_area_list_init(vma_area_list);
}

int collect_mappings(pid_t pid, struct vm_area_list *vma_area_list,
						dump_filemap_t dump_file)
{
	int ret = -1;

	pr_info("\n");
	pr_info("Collecting mappings (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = parse_smaps(pid, vma_area_list, dump_file);
	if (ret < 0)
		goto err;

	pr_info("Collected, longest area occupies %lu pages\n",
		vma_area_list->nr_priv_pages_longest);
	pr_info_vma_list(&vma_area_list->h);

	pr_info("----------------------------------------\n");
err:
	return ret;
}

static int dump_sched_info(int pid, ThreadCoreEntry *tc)
{
	int ret;
	struct sched_param sp;

	BUILD_BUG_ON(SCHED_OTHER != 0); /* default in proto message */

	/*
	 * In musl-libc sched_getscheduler and sched_getparam don't call
	 * syscalls and instead the always return -ENOSYS
	 */
	ret = syscall(__NR_sched_getscheduler, pid);
	if (ret < 0) {
		pr_perror("Can't get sched policy for %d", pid);
		return -1;
	}

	pr_info("%d has %d sched policy\n", pid, ret);
	tc->has_sched_policy = true;
	tc->sched_policy = ret;

	if ((ret == SCHED_RR) || (ret == SCHED_FIFO)) {
		ret = syscall(__NR_sched_getparam, pid, &sp);
		if (ret < 0) {
			pr_perror("Can't get sched param for %d", pid);
			return -1;
		}

		pr_info("\tdumping %d prio for %d\n", sp.sched_priority, pid);
		tc->has_sched_prio = true;
		tc->sched_prio = sp.sched_priority;
	}

	/*
	 * The nice is ignored for RT sched policies, but is stored
	 * in kernel. Thus we have to take it with us in the image.
	 */

	errno = 0;
	ret = getpriority(PRIO_PROCESS, pid);
	if (ret == -1 && errno) {
		pr_perror("Can't get nice for %d ret %d", pid, ret);
		return -1;
	}

	pr_info("\tdumping %d nice for %d\n", ret, pid);
	tc->has_sched_nice = true;
	tc->sched_nice = ret;

	return 0;
}

struct cr_imgset *glob_imgset;

static int collect_fds(pid_t pid, struct parasite_drain_fd **dfds)
{
	struct dirent *de;
	DIR *fd_dir;
	int size = 0;
	int n;

	pr_info("\n");
	pr_info("Collecting fds (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	fd_dir = opendir_proc(pid, "fd");
	if (!fd_dir)
		return -1;

	n = 0;
	while ((de = readdir(fd_dir))) {
		if (dir_dots(de))
			continue;

		if (sizeof(struct parasite_drain_fd) + sizeof(int) * (n + 1) > size) {
			struct parasite_drain_fd *t;

			size += PAGE_SIZE;
			t = xrealloc(*dfds, size);
			if (!t) {
				closedir(fd_dir);
				return -1;
			}
			*dfds = t;
		}

		(*dfds)->fds[n++] = atoi(de->d_name);
	}

	(*dfds)->nr_fds = n;
	pr_info("Found %d file descriptors\n", n);
	pr_info("----------------------------------------\n");

	closedir(fd_dir);

	return 0;
}

static int fill_fd_params_special(int fd, struct fd_parms *p)
{
	*p = FD_PARMS_INIT;

	if (fstat(fd, &p->stat) < 0) {
		pr_perror("Can't fstat exe link");
		return -1;
	}

	if (get_fd_mntid(fd, &p->mnt_id))
		return -1;

	return 0;
}

static long get_fs_type(int lfd)
{
	struct statfs fst;

	if (fstatfs(lfd, &fst)) {
		pr_perror("Unable to statfs fd %d", lfd);
		return -1;
	}
	return fst.f_type;
}

static int dump_one_reg_file_cond(int lfd, u32 *id, struct fd_parms *parms)
{
	if (fd_id_generate_special(parms, id)) {
		parms->fs_type = get_fs_type(lfd);
		if (parms->fs_type < 0)
			return -1;
		return dump_one_reg_file(lfd, *id, parms);
	}
	return 0;
}

static int dump_task_exe_link(pid_t pid, MmEntry *mm)
{
	struct fd_parms params;
	int fd, ret = 0;

	fd = open_proc_path(pid, "exe");
	if (fd < 0)
		return -1;

	if (fill_fd_params_special(fd, &params))
		return -1;

	ret = dump_one_reg_file_cond(fd, &mm->exe_file_id, &params);

	close(fd);
	return ret;
}

static int dump_task_fs(pid_t pid, struct parasite_dump_misc *misc, struct cr_imgset *imgset)
{
	struct fd_parms p;
	FsEntry fe = FS_ENTRY__INIT;
	int fd, ret;

	fe.has_umask = true;
	fe.umask = misc->umask;

	fd = open_proc_path(pid, "cwd");
	if (fd < 0)
		return -1;

	if (fill_fd_params_special(fd, &p))
		return -1;

	ret = dump_one_reg_file_cond(fd, &fe.cwd_id, &p);
	if (ret < 0)
		return ret;

	close(fd);

	fd = open_proc_path(pid, "root");
	if (fd < 0)
		return -1;

	if (fill_fd_params_special(fd, &p))
		return -1;

	ret = dump_one_reg_file_cond(fd, &fe.root_id, &p);
	if (ret < 0)
		return ret;

	close(fd);

	pr_info("Dumping task cwd id %#x root id %#x\n",
			fe.cwd_id, fe.root_id);

	return pb_write_one(img_from_set(imgset, CR_FD_FS), &fe, PB_FS);
}

static inline rlim_t encode_rlim(rlim_t val)
{
	return val == RLIM_INFINITY ? -1 : val;
}

static int dump_task_rlimits(int pid, TaskRlimitsEntry *rls)
{
	int res;

	for (res = 0; res <rls->n_rlimits ; res++) {
		struct rlimit64 lim;

		if (syscall(__NR_prlimit64, pid, res, NULL, &lim)) {
			pr_perror("Can't get rlimit %d", res);
			return -1;
		}

		rls->rlimits[res]->cur = encode_rlim(lim.rlim_cur);
		rls->rlimits[res]->max = encode_rlim(lim.rlim_max);
	}

	return 0;
}

static int dump_pid_misc(pid_t pid, TaskCoreEntry *tc)
{
	int ret;

	if (kdat.luid != LUID_NONE) {
		pr_info("dumping /proc/%d/loginuid\n", pid);

		tc->has_loginuid = true;
		tc->loginuid = parse_pid_loginuid(pid, &ret, false);
		tc->loginuid = userns_uid(tc->loginuid);
		/*
		 * loginuid dumping is critical, as if not correctly
		 * restored, you may loss ability to login via SSH to CT
		 */
		if (ret < 0)
			return ret;
	} else {
		tc->has_loginuid = false;
	}

	pr_info("dumping /proc/%d/oom_score_adj\n", pid);

	tc->oom_score_adj = parse_pid_oom_score_adj(pid, &ret);
	/*
	 * oom_score_adj dumping is not very critical, as it will affect
	 * on victim in OOM situation and one will find dumping error in log
	 */
	if (ret < 0)
		tc->has_oom_score_adj = false;
	else
		tc->has_oom_score_adj = true;

	return 0;
}

static int dump_filemap(struct vma_area *vma_area, int fd)
{
	struct fd_parms p = FD_PARMS_INIT;
	VmaEntry *vma = vma_area->e;
	int ret = 0;
	struct statfs fst;
	u32 id;

	BUG_ON(!vma_area->vmst);
	p.stat = *vma_area->vmst;
	p.mnt_id = vma_area->mnt_id;

	if (fstatfs(fd, &fst)) {
		pr_perror("Unable to statfs fd %d", fd);
		return -1;
	}

	p.fs_type = fst.f_type;

	/*
	 * AUFS support to compensate for the kernel bug
	 * exposing branch pathnames in map_files.
	 *
	 * If the link found in vma_get_mapfile() pointed
	 * inside a branch, we should use the pathname
	 * from root that was saved in vma_area->aufs_rpath.
	 */
	if (vma_area->aufs_rpath) {
		struct fd_link aufs_link;

		strlcpy(aufs_link.name, vma_area->aufs_rpath,
				sizeof(aufs_link.name));
		aufs_link.len = strlen(aufs_link.name);
		p.link = &aufs_link;
	}

	/* Flags will be set during restore in open_filmap() */

	if (vma->status & VMA_AREA_MEMFD)
		ret = dump_one_memfd_cond(fd, &id, &p);
	else
		ret = dump_one_reg_file_cond(fd, &id, &p);

	vma->shmid = id;
	return ret;
}

static int check_sysvipc_map_dump(pid_t pid, VmaEntry *vma)
{
	if (root_ns_mask & CLONE_NEWIPC)
		return 0;

	pr_err("Task %d with SysVIPC shmem map @%"PRIx64" doesn't live in IPC ns\n",
			pid, vma->start);
	return -1;
}

static int get_task_auxv(pid_t pid, MmEntry *mm)
{
	auxv_t mm_saved_auxv[AT_VECTOR_SIZE];
	int fd, i, ret;

	pr_info("Obtaining task auvx ...\n");

	fd = open_proc(pid, "auxv");
	if (fd < 0)
		return -1;

	ret = read(fd, mm_saved_auxv, sizeof(mm_saved_auxv));
	if (ret < 0) {
		ret = -1;
		pr_perror("Error reading %d's auxv", pid);
		goto err;
	} else {
		mm->n_mm_saved_auxv = ret / sizeof(auxv_t);
		for (i = 0; i < mm->n_mm_saved_auxv; i++)
			mm->mm_saved_auxv[i] = (u64)mm_saved_auxv[i];
	}

	ret = 0;
err:
	close_safe(&fd);
	return ret;
}

static int dump_task_mm(pid_t pid, const struct proc_pid_stat *stat,
		const struct parasite_dump_misc *misc,
		const struct vm_area_list *vma_area_list,
		const struct cr_imgset *imgset)
{
	MmEntry mme = MM_ENTRY__INIT;
	struct vma_area *vma_area;
	int ret = -1, i = 0;

	pr_info("\n");
	pr_info("Dumping mm (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	mme.n_vmas = vma_area_list->nr;
	mme.vmas = xmalloc(mme.n_vmas * sizeof(VmaEntry *));
	if (!mme.vmas)
		return -1;

	list_for_each_entry(vma_area, &vma_area_list->h, list) {
		VmaEntry *vma = vma_area->e;

		pr_info_vma(vma_area);

		if (!vma_entry_is(vma, VMA_AREA_REGULAR))
			ret = 0;
		else if (vma_entry_is(vma, VMA_AREA_SYSVIPC))
			ret = check_sysvipc_map_dump(pid, vma);
		else if (vma_entry_is(vma, VMA_AREA_SOCKET))
			ret = dump_socket_map(vma_area);
		else
			ret = 0;
		if (ret)
			goto err;

		mme.vmas[i++] = vma;

		if (vma_entry_is(vma, VMA_AREA_AIORING)) {
			ret = dump_aio_ring(&mme, vma_area);
			if (ret)
				goto err;
		}
	}

	mme.mm_start_code = stat->start_code;
	mme.mm_end_code = stat->end_code;
	mme.mm_start_data = stat->start_data;
	mme.mm_end_data = stat->end_data;
	mme.mm_start_stack = stat->start_stack;
	mme.mm_start_brk = stat->start_brk;

	mme.mm_arg_start = stat->arg_start;
	mme.mm_arg_end = stat->arg_end;
	mme.mm_env_start = stat->env_start;
	mme.mm_env_end = stat->env_end;

	mme.mm_brk = misc->brk;

	mme.dumpable = misc->dumpable;
	mme.has_dumpable = true;

	mme.thp_disabled = misc->thp_disabled;
	mme.has_thp_disabled = true;

	mme.n_mm_saved_auxv = AT_VECTOR_SIZE;
	mme.mm_saved_auxv = xmalloc(pb_repeated_size(&mme, mm_saved_auxv));
	if (!mme.mm_saved_auxv)
		goto err;

	if (get_task_auxv(pid, &mme))
		goto err;

	if (dump_task_exe_link(pid, &mme))
		goto err;

	ret = pb_write_one(img_from_set(imgset, CR_FD_MM), &mme, PB_MM);
	xfree(mme.mm_saved_auxv);
	free_aios(&mme);
err:
	xfree(mme.vmas);
	return ret;
}

static int get_task_futex_robust_list(pid_t pid, ThreadCoreEntry *info)
{
	struct robust_list_head *head = NULL;
	size_t len = 0;
	int ret;

	ret = syscall(SYS_get_robust_list, pid, &head, &len);
	if (ret < 0 && errno == ENOSYS) {
		/*
		 * If the kernel says get_robust_list is not implemented, then
		 * check whether set_robust_list is also not implemented, in
		 * that case we can assume it is empty, since set_robust_list
		 * is the only way to populate it. This case is possible when
		 * "futex_cmpxchg_enabled" is unset in the kernel.
		 *
		 * The following system call should always fail, even if it is
		 * implemented, in which case it will return -EINVAL because
		 * len should be greater than zero.
		 */
		ret = syscall(SYS_set_robust_list, NULL, 0);
		if (ret == 0 || (ret < 0 && errno != ENOSYS))
			goto err;

		head = NULL;
		len = 0;
	} else if (ret) {
		goto err;
	}

	info->futex_rla		= encode_pointer(head);
	info->futex_rla_len	= (u32)len;

	return 0;

err:
	pr_err("Failed obtaining futex robust list on %d\n", pid);
	return -1;
}

static int get_task_personality(pid_t pid, u32 *personality)
{
	int fd, ret = -1;

	pr_info("Obtaining personality ... \n");

	fd = open_proc(pid, "personality");
	if (fd < 0)
		goto err;

	ret = read(fd, loc_buf, sizeof(loc_buf) - 1);
	close(fd);

	if (ret >= 0) {
		loc_buf[ret] = '\0';
		*personality = atoi(loc_buf);
	}
err:
	return ret;
}

static DECLARE_KCMP_TREE(vm_tree, KCMP_VM);
static DECLARE_KCMP_TREE(fs_tree, KCMP_FS);
static DECLARE_KCMP_TREE(files_tree, KCMP_FILES);
static DECLARE_KCMP_TREE(sighand_tree, KCMP_SIGHAND);

static int dump_task_kobj_ids(struct pstree_item *item)
{
	int new;
	struct kid_elem elem;
	int pid = item->pid->real;
	TaskKobjIdsEntry *ids = item->ids;

	elem.pid = pid;
	elem.idx = 0; /* really 0 for all */
	elem.genid = 0; /* FIXME optimize */

	new = 0;
	ids->vm_id = kid_generate_gen(&vm_tree, &elem, &new);
	if (!ids->vm_id || !new) {
		pr_err("Can't make VM id for %d\n", pid);
		return -1;
	}

	new = 0;
	ids->fs_id = kid_generate_gen(&fs_tree, &elem, &new);
	if (!ids->fs_id || !new) {
		pr_err("Can't make FS id for %d\n", pid);
		return -1;
	}

	new = 0;
	ids->files_id = kid_generate_gen(&files_tree, &elem, &new);
	if (!ids->files_id || (!new && !shared_fdtable(item))) {
		pr_err("Can't make FILES id for %d\n", pid);
		return -1;
	}

	new = 0;
	ids->sighand_id = kid_generate_gen(&sighand_tree, &elem, &new);
	if (!ids->sighand_id || !new) {
		pr_err("Can't make IO id for %d\n", pid);
		return -1;
	}

	return 0;
}

int get_task_ids(struct pstree_item *item)
{
	int ret;

	item->ids = xmalloc(sizeof(*item->ids));
	if (!item->ids)
		goto err;

	task_kobj_ids_entry__init(item->ids);

	if (item->pid->state != TASK_DEAD) {
		ret = dump_task_kobj_ids(item);
		if (ret)
			goto err_free;
	}

	ret = dump_task_ns_ids(item);
	if (ret)
		goto err_free;

	return 0;

err_free:
	xfree(item->ids);
	item->ids = NULL;
err:
	return -1;
}

static int get_thread_ids(struct pstree_item *item, int id)
{
	CoreEntry *core = item->core[id];
	core->ids = xmalloc(sizeof(*core->ids));
	if (!core->ids)
		return -1;

	task_kobj_ids_entry__init(core->ids);

	return dump_thread_ids(item->threads[id]->real, core->ids);
}

static int do_dump_task_ids(const struct pstree_item *item, struct cr_img *img)
{
	return pb_write_one(img, item->ids, PB_IDS);
}

static int dump_task_ids(struct pstree_item *item, const struct cr_imgset *cr_imgset)
{
	return do_dump_task_ids(item, img_from_set(cr_imgset, CR_FD_IDS));
}

struct get_internal_start_time_rq {
	int pid;
	unsigned long long result;
};

static int child_get_internal_start_time(void *arg)
{
	struct proc_pid_stat p;
	struct get_internal_start_time_rq *r =
		(struct get_internal_start_time_rq *)arg;

	/* We need to join ve to access container relative
	 * value of task's start_time, otherwize we will see
	 * start_time visible to host.
	 */
	if (join_veX(r->pid)) {
		pr_err("Failed to join ve, owning process %d\n", r->pid);
		return -1;
	}

	if (parse_pid_stat(r->pid, &p)) {
		pr_err("Failed to parse /proc/[pid]/stat for process: %d\n", r->pid);
		return -1;
	}

	r->result = p.start_time;
	return 0;
}

static int dump_thread_ve_start_time(int pid, ThreadCoreEntry *thread_core)
{
	int ret;
	struct get_internal_start_time_rq r = {
		.pid = pid,
		.result = 0
	};

	ret = call_in_child_process(child_get_internal_start_time, &r);
	if (ret) {
		pr_err("Failed to get internal start_time of a process from ve\n");
		return ret;
	}

	thread_core->has_vz_start_time = true;
	thread_core->vz_start_time = r.result;

	pr_info("Dumped start_time for task %d is %lu\n",
		pid, thread_core->vz_start_time);
	return 0;
}

int dump_thread_core(int pid, CoreEntry *core, const struct parasite_dump_thread *ti)
{
	int ret;
	ThreadCoreEntry *tc = core->thread_core;

	if (dump_thread_ve_start_time(pid, tc))
		return -1;

	ret = collect_lsm_profile(pid, tc->creds);
	if (!ret) {
		/*
		 * XXX: It's possible to set two: 32-bit and 64-bit
		 * futex list's heads. That makes about no sense, but
		 * it's possible. Until we meet such application, dump
		 * only one: native or compat futex's list pointer.
		 */
		if (!core_is_compat(core))
			ret = get_task_futex_robust_list(pid, tc);
		else
			ret = get_task_futex_robust_list_compat(pid, tc);
	}
	if (!ret)
		ret = dump_sched_info(pid, tc);
	if (!ret) {
		core_put_tls(core, ti->tls);
		CORE_THREAD_ARCH_INFO(core)->clear_tid_addr =
			encode_pointer(ti->tid_addr);
		BUG_ON(!tc->sas);
		copy_sas(tc->sas, &ti->sas);
		if (ti->pdeath_sig) {
			tc->has_pdeath_sig = true;
			tc->pdeath_sig = ti->pdeath_sig;
		}
		tc->comm = xstrdup(ti->comm);
		if (tc->comm == NULL)
			return -1;
	}
	if (!ret)
		ret = seccomp_dump_thread(pid, tc);

	return ret;
}

static int dump_task_core_all(struct parasite_ctl *ctl,
			      struct pstree_item *item,
			      const struct proc_pid_stat *stat,
			      const struct cr_imgset *cr_imgset,
			      const struct parasite_dump_misc *misc)
{
	struct cr_img *img;
	CoreEntry *core = item->core[0];
	pid_t pid = item->pid->real;
	int ret = -1;
	struct parasite_dump_cgroup_args cgroup_args, *info = NULL;

	BUILD_BUG_ON(sizeof(cgroup_args) < PARASITE_ARG_SIZE_MIN);

	pr_info("\n");
	pr_info("Dumping core (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	core->tc->child_subreaper = misc->child_subreaper;
	core->tc->has_child_subreaper = true;

	ret = get_task_personality(pid, &core->tc->personality);
	if (ret < 0)
		goto err;

	strlcpy((char *)core->tc->comm, stat->comm, TASK_COMM_LEN);
	core->tc->flags = stat->flags;
	core->tc->task_state = item->pid->state;
	core->tc->exit_code = 0;

	if (stat->tty_nr) {
		struct pstree_item *p = item;

		core->tc->has_tty_nr = true;
		core->tc->tty_nr = stat->tty_nr;

		/*
		 * It is a linear search for simplicity,
		 * if it become a problem we should switch
		 * to rbtree or hashing. Because this facility
		 * is out of vanilla criu I don't wanna bloat
		 * code until really needed.
		 */
		for (p = item; p; p = p->parent) {
			if (p->pid->real_pgid != p->pid->real)
				continue;
			if (p->pid->real_pgid != stat->tty_pgrp)
				continue;
			pr_debug("tty: Inherit tty_pgrp real %u virt %u\n",
				 stat->tty_pgrp, vpid(p));
			core->tc->has_tty_pgrp = true;
			core->tc->tty_pgrp = vpid(p);
			break;
		}
	}

	ret = parasite_dump_thread_leader_seized(ctl, item, pid, core);
	if (ret)
		goto err;

	ret = dump_pid_misc(pid, core->tc);
	if (ret)
		goto err;

	ret = dump_task_rlimits(pid, core->tc->rlimits);
	if (ret)
		goto err;

	/* For now, we only need to dump the root task's cgroup ns, because we
	 * know all the tasks are in the same cgroup namespace because we don't
	 * allow nesting.
	 */
	if (item->ids->has_cgroup_ns_id && !item->parent) {
		info = &cgroup_args;
		ret = parasite_dump_cgroup(ctl, &cgroup_args);
		if (ret)
			goto err;
	}

	core->tc->has_cg_set = true;
	ret = dump_task_cgroup(item, &core->tc->cg_set, info);
	if (ret)
		goto err;

	img = img_from_set(cr_imgset, CR_FD_CORE);
	ret = pb_write_one(img, core, PB_CORE);

err:
	pr_info("----------------------------------------\n");

	return ret;
}

static int predump_criu_ns_ids(void)
{
	struct pid pid;
	struct {
		struct pstree_item i;
		struct dmp_info d;
	} crt = { .i.pid = &pid, };

	/*
	 * This thing is normally done inside
	 * write_img_inventory().
	 */

	crt.i.pid->state = TASK_ALIVE;
	crt.i.pid->real = getpid();

	return predump_task_ns_ids(&crt.i);
}

static int set_top_pid_ns(void)
{
	struct ns_id *ns;

	for (ns = ns_ids; ns != NULL; ns = ns->next) {
		if (ns->nd != &pid_ns_desc)
			continue;
		if (ns->type == NS_ROOT) {
			top_pid_ns = ns;
			break;
		}
		if (ns->type == NS_CRIU)
			top_pid_ns = ns;
	}

	if (!top_pid_ns) {
		pr_err("Can't set top_pid_ns\n");
		return -1;
	}

	return 0;
}

static int collect_pstree_ids_predump(void)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		if (item->pid->state == TASK_DEAD)
			continue;

		if (predump_task_ns_ids(item))
			return -1;
	}

	return set_top_pid_ns();
}

int collect_pstree_ids(void)
{
	struct pstree_item *item;
	int i;

	for_each_pstree_item(item) {
		if (get_task_ids(item))
			return -1;
		for (i = 0; i < item->nr_threads; i++) {
			if (item->threads[i]->real == item->pid->real)
				continue;
			if (get_thread_ids(item, i))
				return -1;
		}
	}

	return set_top_pid_ns();
}

static int collect_file_locks(void)
{
	return parse_file_locks();
}

static int dump_task_thread(struct parasite_ctl *parasite_ctl,
				const struct pstree_item *item, int id)
{
	struct parasite_thread_ctl *tctl = dmpi(item)->thread_ctls[id];
	struct pid *tid = item->threads[id];
	CoreEntry *core = item->core[id];
	pid_t pid = tid->real, parasite_tid;
	int ret = -1;
	struct cr_img *img;

	pr_info("\n");
	pr_info("Dumping core for thread (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = parasite_dump_thread_seized(tctl, parasite_ctl, item, id, tid, &parasite_tid, core);
	if (ret) {
		pr_err("Can't dump thread for pid %d\n", pid);
		goto err;
	}

	if (tid->ns[0].virt == -1)
		tid->ns[0].virt = parasite_tid;
	else {
		/* It was collected in parse_pid_status() */
		if (last_level_pid(tid) != parasite_tid) {
			pr_err("Parasite and /proc/[pid]/status gave different tids\n");
			goto err;
		}
	}

	pstree_insert_pid(tid, item->ids->pid_ns_id);

	img = open_image(CR_FD_CORE, O_DUMP, tid->ns[0].virt);
	if (!img)
		goto err;

	ret = pb_write_one(img, core, PB_CORE);

	close_image(img);
err:
	pr_info("----------------------------------------\n");
	return ret;
}

static int dump_one_zombie(const struct pstree_item *item,
			   const struct proc_pid_stat *pps)
{
	CoreEntry *core;
	int ret = -1;
	struct cr_img *img;

	core = core_entry_alloc(1, 1);
	if (!core)
		return -1;

	strlcpy((char *)core->tc->comm, pps->comm, TASK_COMM_LEN);

	if (dump_thread_ve_start_time(vpid(item), core->thread_core))
		return -1;

	core->tc->task_state = TASK_DEAD;
	core->tc->exit_code = pps->exit_code;

	pstree_insert_pid(item->pid, item->ids->pid_ns_id);

	img = open_image(CR_FD_CORE, O_DUMP, vpid(item));
	if (!img)
		goto err;

	ret = pb_write_one(img, core, PB_CORE);
	close_image(img);
	if (ret)
		goto err;

	img = open_image(CR_FD_IDS, O_DUMP, vpid(item));
	if (!img)
		goto err;
	ret = do_dump_task_ids(item, img);
	close_image(img);
err:
	core_entry_free(core);
	return ret;
}

#define SI_BATCH	32

static int dump_signal_queue(pid_t tid, SignalQueueEntry **sqe, bool group)
{
	struct ptrace_peeksiginfo_args arg;
	int ret;
	SignalQueueEntry *queue = NULL;

	pr_debug("Dump %s signals of %d\n", group ? "shared" : "private", tid);

	arg.nr = SI_BATCH;
	arg.flags = 0;
	if (group)
		arg.flags |= PTRACE_PEEKSIGINFO_SHARED;
	arg.off = 0;

	queue = xmalloc(sizeof(*queue));
	if (!queue)
		return -1;

	signal_queue_entry__init(queue);

	while (1) {
		int nr, si_pos;
		siginfo_t *si;

		si = xmalloc(SI_BATCH * sizeof(*si));
		if (!si) {
			ret = -1;
			break;
		}

		nr = ret = ptrace(PTRACE_PEEKSIGINFO, tid, &arg, si);
		if (ret == 0)
			break; /* Finished */

		if (ret < 0) {
			if (errno == EIO) {
				pr_warn("ptrace doesn't support PTRACE_PEEKSIGINFO\n");
				ret = 0;
			} else
				pr_perror("ptrace");

			break;
		}

		queue->n_signals += nr;
		queue->signals = xrealloc(queue->signals, sizeof(*queue->signals) * queue->n_signals);
		if (!queue->signals) {
			ret = -1;
			break;
		}

		for (si_pos = queue->n_signals - nr;
				si_pos < queue->n_signals; si_pos++) {
			SiginfoEntry *se;

			se = xmalloc(sizeof(*se));
			if (!se) {
				ret = -1;
				break;
			}

			siginfo_entry__init(se);
			se->siginfo.len = sizeof(siginfo_t);
			se->siginfo.data = (void *)si++; /* XXX we don't free cores, but when
							  * we will, this would cause problems
							  */
			queue->signals[si_pos] = se;
		}

		if (ret < 0)
			break;

		arg.off += nr;
	}

	*sqe = queue;
	return ret;
}

static int dump_task_signals(pid_t pid, struct pstree_item *item)
{
	int i, ret;

	/* Dump private signals for each thread */
	for (i = 0; i < item->nr_threads; i++) {
		ret = dump_signal_queue(item->threads[i]->real, &item->core[i]->thread_core->signals_p, false);
		if (ret) {
			pr_err("Can't dump private signals for thread %d\n", item->threads[i]->real);
			return -1;
		}
	}

	/* Dump shared signals */
	ret = dump_signal_queue(pid, &item->core[0]->tc->signals_s, true);
	if (ret) {
		pr_err("Can't dump shared signals (pid: %d)\n", pid);
		return -1;
	}

	return 0;
}

static struct proc_pid_stat pps_buf;

static int dump_task_threads(struct parasite_ctl *parasite_ctl,
			     const struct pstree_item *item)
{
	int i;

	for (i = 0; i < item->nr_threads; i++) {
		/* Leader is already dumped */
		if (item->pid->real == item->threads[i]->real) {
			vtid(item, i) = vpid(item);
			continue;
		}
		if (dump_task_thread(parasite_ctl, item, i))
			return -1;
	}

	return 0;
}

/*
 * What this routine does is just reads pid-s of dead
 * tasks in item's children list from item's ns proc.
 *
 * It does *not* find wihch real pid corresponds to
 * which virtual one, but it's not required -- all we
 * need to dump for zombie can be found in the same
 * ns proc.
 */

static int fill_zombies_pids(struct pstree_item *item)
{
	struct pstree_item *child;
	int i, nr;
	pid_t *ch;

	/*
	 * Pids read here are virtual -- caller has set up
	 * the proc of target pid namespace.
	 */
	if (parse_children(vpid(item), &ch, &nr) < 0)
		return -1;

	/*
	 * Step 1 -- filter our ch's pid of alive tasks
	 */
	list_for_each_entry(child, &item->children, sibling) {
		if (vpid(child) < 0)
			continue;
		for (i = 0; i < nr; i++) {
			if (ch[i] == vpid(child)) {
				ch[i] = -1;
				break;
			}
		}
	}

	/*
	 * Step 2 -- assign remaining pids from ch on
	 * children's items in arbitrary order. The caller
	 * will then re-read everything needed to dump
	 * zombies using newly obtained virtual pids.
	 */
	i = 0;
	list_for_each_entry(child, &item->children, sibling) {
		if (vpid(child) > 0)
			continue;
		for (; i < nr; i++) {
			if (ch[i] < 0)
				continue;
			vpid(child) = ch[i];
			ch[i] = -1;
			break;
		}
		BUG_ON(i == nr);
	}

	xfree(ch);

	return 0;
}

static int dump_zombies(void)
{
	struct pstree_item *item;
	int ret = -1;
	int pidns = root_ns_mask & CLONE_NEWPID;

	if (pidns && set_proc_fd(get_service_fd(CR_PROC_FD_OFF)))
		return -1;

	/*
	 * We dump zombies separately because for pid-ns case
	 * we'd have to resolve their pids w/o parasite via
	 * target ns' proc.
	 */

	for_each_pstree_item(item) {
		if (item->pid->state != TASK_DEAD)
			continue;

		if (vpid(item) < 0) {
			BUG_ON(kdat.has_nspid);
			if (!pidns)
				vpid(item) = item->pid->real;
			else if (root_item == item) {
				pr_err("A root task is dead\n");
				goto err;
			} else if (fill_zombies_pids(item->parent))
				goto err;
		}

		pr_info("Obtaining zombie stat ... \n");
		if (parse_pid_stat(vpid(item), &pps_buf) < 0)
			goto err;

		if (!kdat.has_nspid) {
			vsid(item) = pps_buf.sid;
			vpgid(item) = pps_buf.pgid;
		}

		BUG_ON(!list_empty(&item->children));
		if (dump_one_zombie(item, &pps_buf) < 0)
			goto err;
	}

	ret = 0;
err:
	if (pidns)
		close_proc();

	return ret;
}

static int pre_dump_one_task(struct pstree_item *item, InventoryEntry *parent_ie)
{
	pid_t pid = item->pid->real;
	struct vm_area_list vmas;
	struct parasite_ctl *parasite_ctl;
	int ret = -1;
	struct parasite_dump_misc misc;
	struct mem_dump_ctl mdc;

	struct rlim_ctl rlim_ctl = { };

	vm_area_list_init(&vmas);

	pr_info("========================================\n");
	pr_info("Pre-dumping task (pid: %d comm: %s)\n", pid, __task_comm_info(pid));
	pr_info("========================================\n");

	if (item->pid->state == TASK_STOPPED) {
		pr_warn("Stopped tasks are not supported\n");
		return 0;
	}

	if (item->pid->state == TASK_DEAD)
		return 0;

	ret = collect_mappings(pid, &vmas, NULL);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	rlimit_unlimit_nofile_pid(pid, &rlim_ctl);

	ret = -1;
	parasite_ctl = parasite_infect_seized(pid, item, &vmas);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with parasite\n", pid);
		goto err_free;
	}

	ret = parasite_fixup_vdso(parasite_ctl, pid, &vmas);
	if (ret) {
		pr_err("Can't fixup vdso VMAs (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = parasite_dump_misc_seized(parasite_ctl, &misc);
	if (ret) {
		pr_err("Can't dump misc (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = predump_task_files(pid);
	if (ret) {
		pr_err("Pre-dumping files failed (pid: %d)\n", pid);
		goto err_cure;
	}

	if (vpid(item) == -1) {
		vpid(item) = misc.pid;
		vsid(item) = misc.sid;
		vpgid(item) = misc.pgid;
	} else {
		/* They were collected in parse_pid_status() */
		if (last_level_pid(item->pid) != misc.pid ||
		    last_level_pid(item->sid) != misc.sid ||
		    last_level_pid(item->pgid) != misc.pgid) {
			pr_err("Parasite and /proc/[pid]/status gave different pids\n");
			goto err;
		}
	}

	mdc.pre_dump = true;
	mdc.lazy = false;
	mdc.stat = NULL;
	mdc.parent_ie = parent_ie;

	ret = parasite_dump_pages_seized(item, &vmas, &mdc, parasite_ctl);
	if (ret)
		goto err_cure;

	if (compel_cure_remote(parasite_ctl))
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
err_free:
	free_mappings(&vmas);
err:
	rlimit_limit_nofile_pid(pid, &rlim_ctl);
	return ret;

err_cure:
	if (compel_cure(parasite_ctl))
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
	goto err_free;
}

static int dump_one_task(struct pstree_item *item, InventoryEntry *parent_ie)
{
	pid_t pid = item->pid->real;
	struct vm_area_list vmas;
	struct parasite_ctl *parasite_ctl;
	int ret, exit_code = -1;
	struct parasite_dump_misc misc;
	struct cr_imgset *cr_imgset = NULL;
	struct parasite_drain_fd *dfds = NULL;
	struct proc_posix_timers_stat proc_args;
	struct mem_dump_ctl mdc;

	struct rlim_ctl rlim_ctl = { };

	vm_area_list_init(&vmas);

	pr_info("========================================\n");
	pr_info("Dumping task (pid: %d comm: %s)\n", pid, __task_comm_info(pid));
	pr_info("========================================\n");

	if (item->pid->state == TASK_DEAD)
		/*
		 * zombies are dumped separately in dump_zombies()
		 */
		return 0;

	pr_info("Obtaining task stat ... \n");
	ret = parse_pid_stat(pid, &pps_buf);
	if (ret < 0)
		goto err;

	item->pid->real_ppid = pps_buf.ppid;
	item->pid->real_pgid = pps_buf.pgid;
	item->pid->real_sid = pps_buf.sid;

	ret = collect_mappings(pid, &vmas, dump_filemap);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	if (!shared_fdtable(item)) {
		dfds = xmalloc(sizeof(*dfds));
		if (!dfds)
			goto err;

		ret = collect_fds(pid, &dfds);
		if (ret) {
			pr_err("Collect fds (pid: %d) failed with %d\n", pid, ret);
			goto err;
		}

		parasite_ensure_args_size(drain_fds_size(dfds));
	}

	ret = parse_posix_timers(pid, &proc_args);
	if (ret < 0) {
		pr_err("Can't read posix timers file (pid: %d)\n", pid);
		goto err;
	}

	parasite_ensure_args_size(posix_timers_dump_size(proc_args.timer_n));

	ret = dump_task_signals(pid, item);
	if (ret) {
		pr_err("Dump %d signals failed %d\n", pid, ret);
		goto err;
	}

	rlimit_unlimit_nofile_pid(pid, &rlim_ctl);

	parasite_ctl = parasite_infect_seized(pid, item, &vmas);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with parasite\n", pid);
		goto err;
	}

	if (fault_injected(FI_DUMP_EARLY)) {
		pr_info("fault: CRIU sudden detach\n");
		kill(getpid(), SIGKILL);
	}

	if (root_ns_mask & CLONE_NEWPID && root_item == item) {
		int pfd;

		pfd = parasite_get_proc_fd_seized(parasite_ctl);
		if (pfd < 0) {
			pr_err("Can't get proc fd (pid: %d)\n", pid);
			goto err_cure_imgset;
		}

		if (install_service_fd(CR_PROC_FD_OFF, pfd) < 0)
			goto err_cure_imgset;
	}

	ret = parasite_fixup_vdso(parasite_ctl, pid, &vmas);
	if (ret) {
		pr_err("Can't fixup vdso VMAs (pid: %d)\n", pid);
		goto err_cure_imgset;
	}

	ret = parasite_collect_aios(parasite_ctl, &vmas); /* FIXME -- merge with above */
	if (ret) {
		pr_err("Failed to check aio rings (pid: %d)\n", pid);
		goto err_cure_imgset;
	}

	ret = parasite_dump_misc_seized(parasite_ctl, &misc);
	if (ret) {
		pr_err("Can't dump misc (pid: %d)\n", pid);
		goto err_cure_imgset;
	}

	if (vpid(item) == -1) {
		vpid(item) = misc.pid;
		vsid(item) = misc.sid;
		vpgid(item) = misc.pgid;
	} else {
		/* They were collected in parse_pid_status() */
		if (last_level_pid(item->pid) != misc.pid ||
		    last_level_pid(item->sid) != misc.sid ||
		    last_level_pid(item->pgid) != misc.pgid) {
			pr_err("Parasite and /proc/[pid]/status gave different pids\n");
			goto err;
		}
	}
	item->child_subreaper = misc.child_subreaper;

	pstree_insert_pid(item->pid, item->ids->pid_ns_id);

	pr_info("sid=%d pgid=%d pid=%d\n", vsid(item), vpgid(item), vpid(item));

	if (vsid(item) == 0) {
		pr_err("A session leader of %d(%d) is outside of its pid namespace\n",
			item->pid->real, vpid(item));
		goto err_cure;
	}

	cr_imgset = cr_task_imgset_open(vpid(item), O_DUMP);
	if (!cr_imgset)
		goto err_cure;

	ret = dump_task_ids(item, cr_imgset);
	if (ret) {
		pr_err("Dump ids (pid: %d) failed with %d\n", pid, ret);
		goto err_cure;
	}

	if (dfds) {
		ret = dump_task_files_seized(parasite_ctl, item, dfds);
		if (ret) {
			pr_err("Dump files (pid: %d) failed with %d\n", pid, ret);
			goto err_cure;
		}
	}

	mdc.pre_dump = false;
	mdc.lazy = opts.lazy_pages;
	mdc.stat = &pps_buf;
	mdc.parent_ie = parent_ie;

	ret = parasite_dump_pages_seized(item, &vmas, &mdc, parasite_ctl);
	if (ret)
		goto err_cure;

	ret = parasite_dump_sigacts_seized(parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump sigactions (pid: %d) with parasite\n", pid);
		goto err_cure;
	}

	ret = parasite_dump_itimers_seized(parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump itimers (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = parasite_dump_posix_timers_seized(&proc_args, parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump posix timers (pid: %d)\n", pid);
		goto err_cure;
	}

	rlimit_limit_nofile_pid(pid, &rlim_ctl);

	ret = dump_task_core_all(parasite_ctl, item, &pps_buf, cr_imgset, &misc);
	if (ret) {
		pr_err("Dump core (pid: %d) failed with %d\n", pid, ret);
		goto err_cure;
	}

	ret = compel_stop_daemon(parasite_ctl);
	if (ret) {
		pr_err("Can't stop daemon in parasite (pid: %d)\n", pid);
		goto err_cure;
	}

	ret = dump_task_threads(parasite_ctl, item);
	if (ret) {
		pr_err("Can't dump threads\n");
		goto err_cure;
	}

	/*
	 * On failure local map will be cured in cr_dump_finish()
	 * for lazy pages.
	 */
	if (opts.lazy_pages)
		ret = compel_cure_remote(parasite_ctl);
	else
		ret = compel_cure(parasite_ctl);
	if (ret) {
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
		goto err;
	}

	ret = dump_task_mm(pid, &pps_buf, &misc, &vmas, cr_imgset);
	if (ret) {
		pr_err("Dump mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = dump_task_fs(pid, &misc, cr_imgset);
	if (ret) {
		pr_err("Dump fs (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	close_cr_imgset(&cr_imgset);
	exit_code = 0;
err:
	close_pid_proc();
	free_mappings(&vmas);
	xfree(dfds);
	rlimit_limit_nofile_pid(pid, &rlim_ctl);
	return exit_code;

err_cure:
	close_cr_imgset(&cr_imgset);
err_cure_imgset:
	ret = compel_cure(parasite_ctl);
	if (ret)
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
	goto err;
}

static int alarm_attempts = 0;

bool alarm_timeouted(void) {
	return alarm_attempts > 0;
}

static void alarm_handler(int signo)
{

	pr_err("Timeout reached. Try to interrupt: %d\n", alarm_attempts);
	if (alarm_attempts++ < 5) {
		alarm(1);
		/* A curren syscall will be exited with EINTR */
		return;
	}
	pr_err("FATAL: Unable to interrupt the current operation\n");
	BUG();
}

static int setup_alarm_handler(void)
{
	struct sigaction sa = {
		.sa_handler	= alarm_handler,
		.sa_flags	= 0, /* Don't restart syscalls */
	};

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGALRM);
	if (sigaction(SIGALRM, &sa, NULL)) {
		pr_perror("Unable to setup SIGALRM handler");
		return -1;
	}

	return 0;
}

static int cr_pre_dump_finish(int status)
{
	InventoryEntry he = INVENTORY_ENTRY__INIT;
	struct pstree_item *item;
	int ret;

	ve_bc_finish(&bc_set);

	/*
	 * Restore registers for tasks only. The threads have not been
	 * infected. Therefore, the thread register sets have not been changed.
	 */
	ret = arch_set_thread_regs(root_item, false);
	if (ret)
		goto err;

	ret = inventory_save_uptime(&he);
	if (ret)
		goto err;

	he.has_pre_dump_mode = true;
	he.pre_dump_mode = opts.pre_dump_mode;

	pstree_switch_state(root_item, TASK_ALIVE);

	timing_stop(TIME_FROZEN);

	if (status < 0) {
		ret = status;
		goto err;
	}

	pr_info("Pre-dumping tasks' memory\n");
	for_each_pstree_item(item) {
		struct parasite_ctl *ctl = dmpi(item)->parasite_ctl;
		struct page_pipe *mem_pp;
		struct page_xfer xfer;

		if (!ctl)
			continue;

		pr_info("\tPre-dumping %d\n", vpid(item));
		timing_start(TIME_MEMWRITE);
		ret = open_page_xfer(&xfer, CR_FD_PAGEMAP, vpid(item));
		if (ret < 0)
			goto err;

		mem_pp = dmpi(item)->mem_pp;

		if (opts.pre_dump_mode == PRE_DUMP_READ) {
			timing_stop(TIME_MEMWRITE);
			ret = page_xfer_predump_pages(item->pid->real,
							&xfer, mem_pp);
		} else {
			ret = page_xfer_dump_pages(&xfer, mem_pp);
		}

		xfer.close(&xfer);

		if (ret)
			goto err;

		timing_stop(TIME_MEMWRITE);

		destroy_page_pipe(mem_pp);
		if (compel_cure_local(ctl))
			pr_err("Can't cure local: something happened with mapping?\n");
	}

	free_freezer_real_states();
	free_pstree(root_item);
	seccomp_free_entries();

	if (irmap_predump_run()) {
		ret = -1;
		goto err;
	}

err:
	if (disconnect_from_page_server())
		ret = -1;

	if (bfd_flush_images())
		ret = -1;

	if (write_img_inventory(&he))
		ret = -1;

	pipe_dump_fini();

	if (ret)
		pr_err("Pre-dumping FAILED.\n");
	else {
		write_stats(DUMP_STATS);
		pr_info("Pre-dumping finished successfully\n");
	}
	return ret;
}

int cr_pre_dump_tasks(pid_t pid)
{
	InventoryEntry *parent_ie = NULL;
	struct pstree_item *item;
	int ret = -1;

	vz_ensure_ve0();
	ve_bc_read(pid, &bc_set);

	/*
	 * We might need a lot of pipes to fetch huge number of pages to dump.
	 */
	rlimit_unlimit_nofile();

	if (images_init(false))
		goto err;

	root_item = alloc_pstree_item();
	if (!root_item)
		goto err;
	root_item->pid->real = pid;

	if (!opts.track_mem) {
		pr_info("Enforcing memory tracking for pre-dump.\n");
		opts.track_mem = true;
	}

	if (opts.final_state == TASK_DEAD) {
		pr_info("Enforcing tasks run after pre-dump.\n");
		opts.final_state = TASK_ALIVE;
	}

	if (init_stats(DUMP_STATS))
		goto err;

	if (cr_plugin_init(CR_PLUGIN_STAGE__PRE_DUMP))
		goto err;

	if (lsm_check_opts())
		goto err;

	if (irmap_load_cache())
		goto err;

	if (cpu_init())
		goto err;

	if (pipe_dump_init())
		goto err;

	if (vdso_init_dump())
		goto err;

	if (connect_to_page_server_to_send() < 0)
		goto err;

	if (setup_alarm_handler())
		goto err;

	/*
	 * Pre-dump criu's and root_item's ns ids, as they are need
	 * to discover root_item's pid_ns nesting.
	 */
	if (predump_criu_ns_ids() || predump_task_ns_ids(root_item))
		goto err;

	if (collect_pstree())
		goto err;

	/* Pre-dump other tasks ns ids */
	if (collect_pstree_ids_predump())
		goto err;

	if (collect_namespaces(false) < 0)
		goto err;

	ve_bc_unlimit(&bc_set);

	/* Errors handled later in detect_pid_reuse */
	parent_ie = get_parent_inventory();

	for_each_pstree_item(item)
		if (pre_dump_one_task(item, parent_ie))
			goto err;

	if (parent_ie) {
		inventory_entry__free_unpacked(parent_ie, NULL);
		parent_ie = NULL;
	}

	ret = cr_dump_shmem();
	if (ret)
		goto err;

	if (irmap_predump_prep())
		goto err;

	ret = 0;
err:
	if (parent_ie)
		inventory_entry__free_unpacked(parent_ie, NULL);

	return cr_pre_dump_finish(ret);
}

static int cr_lazy_mem_dump(void)
{
	struct pstree_item *item;
	int ret = 0;

	pr_info("Starting lazy pages server\n");
	ret = cr_page_server(false, true, -1);

	for_each_pstree_item(item) {
		if (item->pid->state != TASK_DEAD) {
			destroy_page_pipe(dmpi(item)->mem_pp);
			if (compel_cure_local(dmpi(item)->parasite_ctl))
				pr_err("Can't cure local: something happened with mapping?\n");
		}
	}

	if (ret)
		pr_err("Lazy pages transfer FAILED.\n");
	else
		pr_info("Lazy pages transfer finished successfully\n");

	return ret;
}

static int cr_dump_finish(int ret)
{
	int post_dump_ret = 0, dump_alive_ret = 0;
	int state;

	ve_bc_finish(&bc_set);

	if (disconnect_from_page_server())
		ret = -1;

	close_cr_imgset(&glob_imgset);

	if (bfd_flush_images())
		ret = -1;

	cr_plugin_fini(CR_PLUGIN_STAGE__DUMP, ret);
	cgp_fini();

	if (!ret) {
		/*
		 * It might be a migration case, where we're asked
		 * to dump everything, then some script transfer
		 * image on a new node and we're supposed to kill
		 * dumpee because it continue running somewhere
		 * else.
		 *
		 * Thus ask user via script if we're to break
		 * checkpoint.
		 */
		post_dump_ret = run_scripts(ACT_POST_DUMP);
		if (post_dump_ret)
			pr_err("Post dump script passed with %d\n", post_dump_ret);
	}

	/*
	 * Dump is complete at this stage. To choose what
	 * to do next we need to consider the following
	 * scenarios
	 *
	 *  - error happened during checkpoint: just clean up
	 *    everything and continue execution of the dumpee;
	 *
	 *  - dump succeeded but post-dump script returned
	 *    some ret code: same as in previous scenario --
	 *    just clean up everything and continue execution,
	 *    we will return script ret code back to criu caller
	 *    and it's up to a caller what to do with running instance
	 *    of the dumpee -- either kill it, or continue running;
	 *
	 *  - dump succeeded but -R option passed, pointing that
	 *    we're asked to continue execution of the dumpee. It's
	 *    assumed that a user will use post-dump script to keep
	 *    consistency of the FS and other resources, we simply
	 *    start rollback procedure and cleanup everything.
	 */
	state = (ret || post_dump_ret) ? TASK_ALIVE : opts.final_state;
	if (state == TASK_ALIVE) {
		network_unlock();
		delete_link_remaps();
		clean_cr_time_mounts();
	}

	if (!ret && opts.lazy_pages)
		ret = cr_lazy_mem_dump();

	if (arch_set_thread_regs(root_item, true) < 0)
		return -1;
	pstree_switch_state(root_item, state);

	if (stats_initialized())
		timing_stop(TIME_FROZEN);

	if (state == TASK_ALIVE) {
		dump_alive_ret |= run_scripts(ACT_DUMP_ALIVE);
		if (dump_alive_ret)
			pr_err("Dump alive script exited with %d\n", dump_alive_ret);
	}

	free_freezer_real_states();
	free_pstree(root_item);
	seccomp_free_entries();
	free_file_locks();
	free_link_remaps();
	free_aufs_branches();
	free_userns_maps();
	free_ttys();
	pipe_dump_fini();

	close_service_fd(CR_PROC_FD_OFF);
	close_image_dir();

	if (ret || post_dump_ret || dump_alive_ret) {
		pr_err("Dumping FAILED.\n");
	} else {
		write_stats(DUMP_STATS);
		pr_info("Dumping finished successfully\n");
	}
	return post_dump_ret | dump_alive_ret ? : (ret != 0);
}

int cr_dump_tasks(pid_t pid)
{
	InventoryEntry he = INVENTORY_ENTRY__INIT;
	InventoryEntry *parent_ie = NULL;
	struct pstree_item *item;
	int pre_dump_ret = 0;
	int ret = -1;

	vz_ensure_ve0();
	ve_bc_read(pid, &bc_set);

	pr_info("========================================\n");
	pr_info("Dumping processes (pid: %d comm: %s)\n", pid, __task_comm_info(pid));
	pr_info("========================================\n");

	/*
	 *  We will fetch all file descriptors for each task, their number can
	 *  be bigger than a default file limit, so we need to raise it to the
	 *  maximum.
	 */
	rlimit_unlimit_nofile();

	if (images_init(false))
		goto err;

	root_item = alloc_pstree_item();
	if (!root_item)
		goto err;
	root_item->pid->real = pid;

	pre_dump_ret = run_scripts(ACT_PRE_DUMP);
	if (pre_dump_ret != 0) {
		pr_err("Pre dump script failed with %d!\n", pre_dump_ret);
		goto err;
	}
	if (init_stats(DUMP_STATS))
		goto err;

	if (cr_plugin_init(CR_PLUGIN_STAGE__DUMP))
		goto err;

	if (lsm_check_opts())
		goto err;

	if (irmap_load_cache())
		goto err;

	if (cpu_init())
		goto err;

	if (pipe_dump_init())
		goto err;

	if (vdso_init_dump())
		goto err;

	if (cgp_init(opts.cgroup_props,
		     opts.cgroup_props ?
		     strlen(opts.cgroup_props) : 0,
		     opts.cgroup_props_file))
		goto err;

	if (parse_cg_info())
		goto err;

	if (prepare_inventory(&he))
		goto err;

	if (opts.cpu_cap & CPU_CAP_IMAGE) {
		if (cpu_dump_cpuinfo())
			goto err;
	}

	if (connect_to_page_server_to_send() < 0)
		goto err;

	if (setup_alarm_handler())
		goto err;

	if (predump_task_ns_ids(root_item))
		goto err;
	/*
	 * The collect_pstree will also stop (PTRACE_SEIZE) the tasks
	 * thus ensuring that they don't modify anything we collect
	 * afterwards.
	 */

	if (collect_pstree())
		goto err;

	if (collect_pstree_ids())
		goto err;

	if (network_lock())
		goto err;

	if (collect_file_locks())
		goto err;

	if (collect_namespaces(true) < 0)
		goto err;

	if (collect_unix_bindmounts() < 0)
		goto err;

	glob_imgset = cr_glob_imgset_open(O_DUMP);
	if (!glob_imgset)
		goto err;

	if (seccomp_collect_dump_filters() < 0)
		goto err;

	ve_bc_unlimit(&bc_set);

	/* Errors handled later in detect_pid_reuse */
	parent_ie = get_parent_inventory();

	for_each_pstree_item(item) {
		if (dump_one_task(item, parent_ie))
			goto err;
	}

	if (parent_ie) {
		inventory_entry__free_unpacked(parent_ie, NULL);
		parent_ie = NULL;
	}

	if (flush_eventpoll_dinfo_queue())
		goto err;

	/*
	 * It may happen that a process has completed but its files in
	 * /proc/PID/ are still open by another process. If the PID has been
	 * given to some newer thread since then, we may be unable to dump
	 * all this.
	 */
	if (dead_pid_conflict())
		goto err;

	if (dump_devices())
		goto err;

	/* MNT namespaces are dumped after files to save remapped links */
	if (dump_mnt_namespaces() < 0)
		goto err;

	if (dump_file_locks())
		goto err;

	if (dump_verify_tty_sids())
		goto err;

	if (dump_zombies())
		goto err;

	if (dump_pstree(root_item))
		goto err;

	if (handle_pstree_sessions())
		goto err;

	/*
	 * TODO: cr_dump_shmem has to be called before dump_namespaces(),
	 * because page_ids is a global variable and it is used to dump
	 * ipc shared memory, but an ipc namespace is dumped in a child
	 * process.
	 */
	ret = cr_dump_shmem();
	if (ret)
		goto err;

	if (root_ns_mask) {
		ret = dump_namespaces(root_item, root_ns_mask);
		if (ret)
			goto err;
	}

	if ((root_ns_mask & CLONE_NEWTIME) == 0) {
		ret = dump_time_ns(0);
		if (ret)
			goto err;
	}

	ret = dump_cgroups();
	if (ret)
		goto err;

	ret = fix_external_unix_sockets();
	if (ret)
		goto err;

	ret = tty_post_actions();
	if (ret)
		goto err;

	ret = sk_queue_post_actions();
	if (ret)
		goto err;

	ret = inventory_save_uptime(&he);
	if (ret)
		goto err;

	he.has_pre_dump_mode = false;

	ret = write_img_inventory(&he);
	if (ret)
		goto err;
err:
	if (parent_ie)
		inventory_entry__free_unpacked(parent_ie, NULL);

	return cr_dump_finish(ret);
}
