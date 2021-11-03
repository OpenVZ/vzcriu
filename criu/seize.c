#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>

#include "int.h"
#include "common/compiler.h"
#include "cr_options.h"
#include "cr-errno.h"
#include "pstree.h"
#include "criu-log.h"
#include <compel/ptrace.h>
#include "proc_parse.h"
#include "seccomp.h"
#include "seize.h"
#include "stats.h"
#include "string.h"
#include "xmalloc.h"
#include "util.h"
#include "ftw.h"

char *task_comm_info(pid_t pid, char *comm, size_t size)
{
	bool is_read = false;

	if (!pr_quelled(LOG_INFO)) {
		int saved_errno = errno;
		char path[32];
		int fd;

		snprintf(path, sizeof(path), "/proc/%d/comm", pid);
		fd = open(path, O_RDONLY);
		if (fd >= 0) {
			ssize_t n = read(fd, comm, size);
			if (n > 0) {
				is_read = true;
				/* Replace '\n' printed by kernel with '\0' */
				comm[n - 1] = '\0';
			} else {
				pr_warn("Failed to read %s: %s\n", path, strerror(errno));
			}
			close(fd);
		} else {
			pr_warn("Failed to open %s: %s\n", path, strerror(errno));
		}
		errno = saved_errno;
	}

	if (!is_read)
		comm[0] = '\0';

	return comm;
}

/*
 * NOTE: Don't run simultaneously, it uses local static buffer!
 */
char *__task_comm_info(pid_t pid)
{
	static char comm[32];

	return task_comm_info(pid, comm, sizeof(comm));
}

#define NR_ATTEMPTS 5

static const char frozen[] = "FROZEN";
static const char freezing[] = "FREEZING";
static const char thawed[] = "THAWED";

enum freezer_state { FREEZER_ERROR = -1, THAWED, FROZEN, FREEZING };

/*
 * The @path is the full path to the freezer
 */
struct freezer_struct {
	char *path;
	enum freezer_state state;
	struct list_head l;
};

static LIST_HEAD(freezer_real_states);

/* Track if we are running on cgroup v2 system. */
static bool cgroup_v2 = false;

static enum freezer_state get_freezer_v1_state(int fd)
{
	char state[32];
	int ret;

	BUILD_BUG_ON((sizeof(state) < sizeof(frozen)) || (sizeof(state) < sizeof(freezing)) ||
		     (sizeof(state) < sizeof(thawed)));

	lseek(fd, 0, SEEK_SET);
	ret = read(fd, state, sizeof(state) - 1);
	if (ret <= 0) {
		pr_perror("Unable to get a current state");
		goto err;
	}
	if (state[ret - 1] == '\n')
		state[ret - 1] = 0;
	else
		state[ret] = 0;

	pr_debug("freezer.state=%s\n", state);
	if (strcmp(state, frozen) == 0)
		return FROZEN;
	else if (strcmp(state, freezing) == 0)
		return FREEZING;
	else if (strcmp(state, thawed) == 0)
		return THAWED;

	pr_err("Unknown freezer state: %s\n", state);
err:
	return FREEZER_ERROR;
}

static enum freezer_state get_freezer_v2_state(int fd)
{
	int exit_code = FREEZER_ERROR;
	char path[PATH_MAX];
	FILE *event;
	char state;
	int ret;

	/*
	 * cgroupv2 freezer uses cgroup.freeze to control the state. The file
	 * can return 0 or 1. 1 means the cgroup is frozen; 0 means it is not
	 * frozen. Writing 1 to an unfrozen cgroup can freeze it. Freezing can
	 * take some time and if the cgroup has finished freezing can be
	 * seen in cgroup.events: frozen 0|1.
	 */

	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0) {
		pr_perror("Unable to seek freezer FD");
		goto out;
	}
	ret = read(fd, &state, 1);
	if (ret <= 0) {
		pr_perror("Unable to read from freezer FD");
		goto out;
	}
	pr_debug("cgroup.freeze=%c\n", state);
	if (state == '0') {
		exit_code = THAWED;
		goto out;
	}

	snprintf(path, sizeof(path), "%s/cgroup.events", opts.freeze_cgroup);
	event = fopen(path, "r");
	if (event == NULL) {
		pr_perror("Unable to open %s", path);
		goto out;
	}
	while (fgets(path, sizeof(path), event)) {
		if (strncmp(path, "frozen", 6) != 0) {
			continue;
		} else if (strncmp(path, "frozen 0", 8) == 0) {
			exit_code = FREEZING;
			goto close;
		} else if (strncmp(path, "frozen 1", 8) == 0) {
			exit_code = FROZEN;
			goto close;
		}
	}

	pr_err("Unknown freezer state: %c\n", state);
close:
	fclose(event);
out:
	return exit_code;
}

static enum freezer_state get_freezer_state(int fd)
{
	if (cgroup_v2)
		return get_freezer_v2_state(fd);
	return get_freezer_v1_state(fd);
}

static enum freezer_state get_self_freezer_state(const char *dir)
{
	char path[PATH_MAX];
	char self_freezing;
	int ret;
	int fd;

	ret = snprintf(path, sizeof(path), "%s/%s", dir, "freezer.self_freezing");
	if (ret >= sizeof(path)) {
		pr_perror("Directory path [%s] is too long", dir);
		goto err;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Unable to open %s", path);
		goto err;
	}

	if (read(fd, &self_freezing, 1) <= 0) {
		pr_perror("Unable to get a current self_freezing state from %s", path);
		close(fd);
		goto err;
	}
	close(fd);

	pr_debug("%s/freezer.self_freezing=%c\n", dir, self_freezing);
	if (self_freezing == '1')
		return FROZEN;
	else
		return THAWED;

err:
	return FREEZER_ERROR;
}

static enum freezer_state origin_freezer_state = FREEZER_ERROR;

const char *get_real_freezer_state(char *path)
{
	struct freezer_struct *it;

	list_for_each_entry(it, &freezer_real_states, l) {
		/*
		 * compare path and it->path using get_relative_path()
		 * we just need to check that return value is empty
		 * string
		 */
		char *rel = get_relative_path(path, it->path);
		if (rel && !rel[0])
			return it->state == THAWED ? thawed : frozen;
	}

	pr_perror("Failed to find freezer state by path [%s]", path);

	return NULL;
}

static int freezer_write_state(int fd, enum freezer_state new_state)
{
	char state[32] = { 0 };
	int ret;

	if (new_state == THAWED) {
		if (cgroup_v2)
			state[0] = '0';
		else if (__strlcpy(state, thawed, sizeof(state)) >= sizeof(state))
			return -1;
	} else if (new_state == FROZEN) {
		if (cgroup_v2)
			state[0] = '1';
		else if (__strlcpy(state, frozen, sizeof(state)) >= sizeof(state))
			return -1;
	} else {
		return -1;
	}

	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0) {
		pr_perror("Unable to seek freezer FD");
		return -1;
	}
	if (write(fd, state, sizeof(state)) != sizeof(state)) {
		pr_perror("Unable to %s tasks", (new_state == THAWED) ? "thaw" : "freeze");
		return -1;
	}

	return 0;
}

static int __freezer_open(char *base)
{
	const char freezer_v1[] = "freezer.state";
	const char freezer_v2[] = "cgroup.freeze";
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", base, cgroup_v2 ? freezer_v2 : freezer_v1);
	fd = open(path, O_RDWR);
	if (fd < 0) {
		pr_perror("Unable to open %s", path);
		return -1;
	}

	return fd;
}

static int freezer_open(void)
{
	return __freezer_open(opts.freeze_cgroup);
}

static int log_unfrozen_stacks(char *root);

static int __wait_freezer_state_change(int fd, enum freezer_state new_state, bool alarm,
				       unsigned long *i,
				       unsigned long nr_attempts,
				       const struct timespec *req)
{
	enum freezer_state state = FREEZER_ERROR;

	for (; *i < nr_attempts; (*i)++) {
		if (*i != 0)
			nanosleep(req, NULL);
		state = get_freezer_state(fd);
		if (state == FREEZER_ERROR)
			return -1;
		if (state == new_state)
			break;
		if (alarm && alarm_timeouted())
			return -1;
	}

	if (*i >= nr_attempts) {
		pr_err("Timeout waiting freezer.state change from %s to %s\n",
		       state == FREEZER_ERROR ? "none" : THAWED ? "thaw" : "freeze",
		       new_state == THAWED ? "thaw" : "freeze");
		if (new_state == FROZEN && !pr_quelled(LOG_DEBUG))
			log_unfrozen_stacks(opts.freeze_cgroup);
		return -1;
	}

	return 0;
}

static int wait_freezer_state_change(int fd, enum freezer_state new_state)
{
	/* 0.1 sec interval looks solid enough */
	static const unsigned long step_ms = 100;
	unsigned long i = 0, nr_attempts = (opts.timeout * MSEC_PER_SEC) / step_ms;
	const struct timespec req = {
		.tv_nsec = step_ms * NSEC_PER_MSEC,
		.tv_sec = 0,
	};

	if (unlikely(!nr_attempts)) {
		/*
		 * If timeout is turned off, lets
		 * wait for at least 10 seconds.
		 */
		nr_attempts = (DEFAULT_TIMEOUT * MSEC_PER_SEC) / step_ms;
	}

	if (__wait_freezer_state_change(fd, new_state, false, &i, nr_attempts, &req))
		return -1;

	pr_debug("Waiting for %s freeser.state in %lu attempts\n",
		 new_state == THAWED ? "thaw" : "freeze", i);
	return 0;
}

static int freezer_restore_state(void)
{
	struct freezer_struct *it;

	if (!opts.freeze_cgroup)
		return 0;

	list_for_each_entry(it, &freezer_real_states, l) {
		int fd;

		pr_info("Restoring freezer state [%s] to [%s]\n",
				it->state == FROZEN ? frozen : thawed, it->path);

		fd = __freezer_open(it->path);
		if (fd < 0)
			return -1;

		if (freezer_write_state(fd, it->state) &&
			wait_freezer_state_change(fd, it->state)) {
			close(fd);
			return -1;
		}

		close(fd);
	}

	return 0;
}

static FILE *freezer_open_thread_list(char *root_path)
{
	char path[PATH_MAX];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", root_path, cgroup_v2 ? "cgroup.threads" : "tasks");
	f = fopen(path, "r");
	if (f == NULL) {
		pr_perror("Unable to open %s", path);
		return NULL;
	}

	return f;
}

/* A number of tasks in a freezer cgroup which are not going to be dumped */
static int processes_to_wait;
static pid_t *processes_to_wait_pids;

static bool is_traced(pid_t pid)
{
	char path[PATH_MAX];
	char comm[64];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "r");
	if (!f) {
		pr_perror("Unable to open %s", path);
		return false;
	}

	while (fgets(path, sizeof(path), f)) {
		ssize_t ret;
		pid_t tpid;
		int fd;

		if (strncmp("TracerPid:\t", path, 11))
			continue;

		fclose(f);

		tpid = atol(&path[11]);

		snprintf(path, sizeof(path), "/proc/%d/comm", tpid);
		fd = open(path, O_RDONLY);
		if (fd >= 0) {
			ret = read(fd, comm, sizeof(comm) - 1);
			if (ret <= 0) {
				strncpy(comm, "can't read", sizeof(comm));
				comm[sizeof(comm) - 1] = '\0';
			} else {
				comm[ret - 1] = '\0';
			}
		} else {
			strncpy(comm, "can't open", sizeof(comm));
			comm[sizeof(comm) - 1] = '\0';
		}

		pr_debug("pid %d is traced by %d (%s)\n", pid, tpid, comm);
		return tpid ? true : false;
	}
	fclose(f);
	return false;
}

static int seize_cgroup_tree(char *root_path, enum freezer_state state)
{
	DIR *dir;
	struct dirent *de;
	char path[PATH_MAX];
	FILE *f;

	/*
	 * New tasks can appear while a freezer state isn't
	 * frozen, so we need to catch all new tasks.
	 */
	f = freezer_open_thread_list(root_path);
	if (f == NULL)
		return -1;

	while (fgets(path, sizeof(path), f)) {
		pid_t pid;
		int ret;

		pid = atoi(path);

		/* Here we are going to skip tasks which are already traced. */
		ret = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
		if (ret == 0)
			continue;
		if (errno != ESRCH) {
			pr_perror("Unexpected error for pid %d (comm %s)", pid, __task_comm_info(pid));
			fclose(f);
			return -1;
		}

		if (!compel_interrupt_task(pid)) {
			pr_debug("SEIZE %d (comm %s): success\n", pid, __task_comm_info(pid));
			processes_to_wait++;
		} else if (state == FROZEN) {
			char buf[] = "/proc/XXXXXXXXXX/exe";
			struct stat st;

			/* skip kernel threads */
			snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
			if (stat(buf, &st) == -1 && errno == ENOENT)
				continue;

			if (is_traced(pid)) {
				fclose(f);
				return -EAGAIN;
			}

			/*
			 * fails when meets a zombie, or exiting process:
			 * there is a small race in a kernel -- the process
			 * may start exiting and we are trying to freeze it
			 * before it compete exit procedure. The caller simply
			 * should wait a bit and try freezing again.
			 */
			pr_err("zombie %d (comm %s) found while seizing\n", pid, __task_comm_info(pid));
			if (!pr_quelled(LOG_DEBUG)) {
				/*
				 * FIXME: Debug printing in a sake of
				 * https://jira.sw.ru/browse/PSBM-53929
				 * Drop before the release.
				 */
				char __path[64], __buf[2048];
				static char ps_cmd[] = "ps";
				int fd, ret;

				cr_system(-1, -1, -1, ps_cmd, (char *[]){ ps_cmd, "aufx", NULL }, 0);

				snprintf(__path, sizeof(__path), "/proc/%d/stack", pid);
				fd = open(__path, O_RDONLY);
				if (fd >= 0) {
					ret = read(fd, __buf, sizeof(__buf) - 1);
					if (ret > 0) {
						__buf[ret] = '\0';
						pr_debug("/proc/%d/stack:\n%s\n", pid, __buf);
					}
					close(fd);
				}

				snprintf(__path, sizeof(__path), "/proc/%d/stat", pid);
				fd = open(__path, O_RDONLY);
				if (fd >= 0) {
					ret = read(fd, __buf, sizeof(__buf) - 1);
					if (ret > 0) {
						__buf[ret] = '\0';
						pr_debug("/proc/%d/stat:\n%s\n", pid, __buf);
					}
					close(fd);
				}

				snprintf(__path, sizeof(__path), "/proc/%d/status", pid);
				fd = open(__path, O_RDONLY);
				if (fd >= 0) {
					ret = read(fd, __buf, sizeof(__buf) - 1);
					if (ret > 0) {
						__buf[ret] = '\0';
						pr_debug("/proc/%d/status:\n%s\n",
							 pid, __buf);
					}
					close(fd);
				}
			}
			fclose(f);
			return -EAGAIN;
		}
	}
	fclose(f);

	dir = opendir(root_path);
	if (!dir) {
		pr_perror("Unable to open %s", root_path);
		return -1;
	}

	while ((de = readdir(dir))) {
		struct stat st;
		int ret;

		if (dir_dots(de))
			continue;

		sprintf(path, "%s/%s", root_path, de->d_name);

		if (fstatat(dirfd(dir), de->d_name, &st, 0) < 0) {
			pr_perror("stat of %s failed", path);
			closedir(dir);
			return -1;
		}

		if (!S_ISDIR(st.st_mode))
			continue;
		ret = seize_cgroup_tree(path, state);
		if (ret < 0) {
			closedir(dir);
			return ret;
		}
	}
	closedir(dir);

	return 0;
}

/*
 * A freezer cgroup can contain tasks which will not be dumped
 * and we need to wait them, because the are interrupted them by ptrace.
 */
static int freezer_wait_processes(void)
{
	int i;

	processes_to_wait_pids = xmalloc(sizeof(pid_t) * processes_to_wait);
	if (processes_to_wait_pids == NULL)
		return -1;

	for (i = 0; i < processes_to_wait; i++) {
		int status;
		pid_t pid;

		/*
		 * Here we are going to skip tasks which are already traced.
		 * Ptraced tasks looks like children for us, so if
		 * a task isn't ptraced yet, waitpid() will return a error.
		 */
		pid = waitpid(-1, &status, 0);
		if (pid < 0) {
			pr_perror("Unable to wait processes");
			xfree(processes_to_wait_pids);
			processes_to_wait_pids = NULL;
			return -1;
		}
		pr_warn("Unexpected process %d in the freezer cgroup (status 0x%x)\n", pid, status);

		processes_to_wait_pids[i] = pid;
	}

	return 0;
}

static int freezer_detach(void)
{
	int i;

	if (!opts.freeze_cgroup)
		return 0;

	for (i = 0; i < processes_to_wait && processes_to_wait_pids; i++) {
		pid_t pid = processes_to_wait_pids[i];
		int status, save_errno;

		if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == 0) {
			pr_debug("Detached from %d\n", pid);
			continue;
		}

		save_errno = errno;

		/* A process may be killed by SIGKILL */
		if (wait4(pid, &status, __WALL, NULL) == pid) {
			pr_warn("The %d process returned 0x %x\n", pid, status);
			continue;
		}
		errno = save_errno;
		pr_perror("Unable to detach from %d", pid);
	}

	return 0;
}

static int log_unfrozen_stacks(char *root)
{
	DIR *dir;
	struct dirent *de;
	char path[PATH_MAX];
	FILE *f;

	f = freezer_open_thread_list(root);
	if (f == NULL)
		return -1;

	while (fgets(path, sizeof(path), f)) {
		pid_t pid;
		int ret, stack;
		char stackbuf[2048];

		pid = atoi(path);

		stack = open_proc(pid, "stack");
		if (stack < 0) {
			pr_err("`- couldn't log %d's stack\n", pid);
			fclose(f);
			return -1;
		}

		ret = read(stack, stackbuf, sizeof(stackbuf) - 1);
		close(stack);
		if (ret < 0) {
			pr_perror("couldn't read %d's stack", pid);
			fclose(f);
			return -1;
		}
		stackbuf[ret] = '\0';

		pr_debug("Task %d has stack:\n%s", pid, stackbuf);
	}
	fclose(f);

	dir = opendir(root);
	if (!dir) {
		pr_perror("Unable to open %s", root);
		return -1;
	}

	while ((de = readdir(dir))) {
		struct stat st;

		if (dir_dots(de))
			continue;

		sprintf(path, "%s/%s", root, de->d_name);

		if (fstatat(dirfd(dir), de->d_name, &st, 0) < 0) {
			pr_perror("stat of %s failed", path);
			closedir(dir);
			return -1;
		}

		if (!S_ISDIR(st.st_mode))
			continue;

		if (log_unfrozen_stacks(path) < 0) {
			closedir(dir);
			return -1;
		}
	}
	closedir(dir);

	return 0;
}

static int freezer_save_state(const char *fpath, const struct stat *sb,
			   int tflag, struct FTW *ftwbuf)
{
	struct freezer_struct *real_state;
	enum freezer_state state;

	/* Skip root freezer state (ftwbuf->level == 0) */
	if (tflag == FTW_D && ftwbuf->level != 0) {
		state = get_self_freezer_state(fpath);
		if (state == FREEZER_ERROR)
			return -1;

		real_state = xmalloc(sizeof(*real_state));
		if (!real_state)
			return -1;

		real_state->path = xstrdup(fpath);
		real_state->state = state;
		list_add(&real_state->l, &freezer_real_states);

		pr_info("Saving freezer [%s] state [%s]\n",
			real_state->path, real_state->state == THAWED ? thawed : frozen);
	}

	return 0;
}

#define NFTW_FD_MAX 64
static int save_freezer_states(char *root)
{
	return nftw(root, freezer_save_state, NFTW_FD_MAX, FTW_PHYS);
}

void free_freezer_real_states(void)
{
	struct freezer_struct *it, *temp;

	list_for_each_entry_safe(it, temp, &freezer_real_states, l) {
		list_del(&it->l);
		xfree(it->path);
		xfree(it);
	}
}

static int freezer_write_state_recurse(char *root, enum freezer_state state)
{
	DIR *dir;
	struct dirent *de;
	char path[PATH_MAX];
	int fd;

	fd = __freezer_open(root);
	if (fd < 0)
		return -1;

	if (freezer_write_state(fd, state)) {
		close(fd);
		return -1;
	}
	close(fd);

	dir = opendir(root);
	if (!dir) {
		pr_perror("Unable to open %s", root);
		return -1;
	}

	while ((de = readdir(dir))) {
		struct stat st;

		if (dir_dots(de))
			continue;

		sprintf(path, "%s/%s", root, de->d_name);

		if (fstatat(dirfd(dir), de->d_name, &st, 0) < 0) {
			pr_perror("stat of %s failed", path);
			closedir(dir);
			return -1;
		}

		if (!S_ISDIR(st.st_mode))
			continue;

		if (freezer_write_state_recurse(path, state) < 0) {
			closedir(dir);
			return -1;
		}
	}
	closedir(dir);

	return 0;
}

static int freeze_processes(void)
{
	int fd, exit_code = -1;
	enum freezer_state state;

	/* 0.1 sec interval looks solid enough */
	static const unsigned long step_ms = 100;
	unsigned long nr_attempts = (opts.timeout * MSEC_PER_SEC) / step_ms;
	unsigned long i = 0;

	const struct timespec req = {
		.tv_nsec = step_ms * NSEC_PER_MSEC,
		.tv_sec = 0,
	};

	if (unlikely(!nr_attempts)) {
		/*
		 * If timeout is turned off, lets
		 * wait for at least 10 seconds.
		 */
		nr_attempts = (DEFAULT_TIMEOUT * MSEC_PER_SEC) / step_ms;
	}

	pr_debug("freezing processes: %lu attempts with %lu ms steps\n", nr_attempts, step_ms);

	fd = freezer_open();
	if (fd < 0)
		return -1;

	state = get_freezer_state(fd);
	if (state == FREEZER_ERROR) {
		close(fd);
		return -1;
	}

	origin_freezer_state = state == FREEZING ? FROZEN : state;

again:
	if (state == THAWED) {
		if (freezer_write_state(fd, FROZEN)) {
			close(fd);
			return -1;
		}

		/*
		 * Wait the freezer to complete before
		 * processing tasks. They might be exiting
		 * before freezing complete so we should
		 * not read @tasks pids while freezer in
		 * transition stage.
		 */
		if (__wait_freezer_state_change(fd, FROZEN, true, &i, nr_attempts, &req))
			goto err;

		pr_debug("freezing processes: %lu attempts done\n", i);
	}

	/*
	 * Pay attention on @i variable -- it's continuation.
	 */
	for (; i < nr_attempts; i++) {
		exit_code = seize_cgroup_tree(opts.freeze_cgroup, state);
		if (exit_code == -EAGAIN) {
			if (alarm_timeouted())
				goto err;
			if (origin_freezer_state == THAWED) {
				if (freezer_write_state(fd, THAWED)) {
					exit_code = -1;
					goto err;
				}
				nanosleep(&req, NULL);
				goto again;
			}
			nanosleep(&req, NULL);
		} else
			break;
	}

	if (!opts.skip_freezer_state && save_freezer_states(opts.freeze_cgroup) < 0) {
		pr_err("Unable to save freezer states\n");
		exit_code = -1;
	}

err:
	if (exit_code == 0) {
		/*
		 * When CRIU gets tasks frozen in freezer cgroup
		 * this freezer cgroups can be nested, so, if
		 * one of nested freezer cgroup was frozen separately
		 * and then we thaw parent cgroup their child will not
		 * be thawed! See kernel/cgroup/legacy_freezer.c
		 * and difference between CGROUP_FREEZING_SELF and
		 * CGROUP_FREEZING_PARENT.
		 * So, there we want to release all nested freezers
		 * because tasks need to be seized by ptrace.
		 * But ptrace can't caught task that under refrigerator
		 * because in this case task sit in D-state.
		 */
		if (freezer_write_state_recurse(opts.freeze_cgroup, THAWED)) {
			pr_err("Unable to thaw tasks\n");
			exit_code = -1;
		}
	} else if (origin_freezer_state == THAWED) {
		/*
		 * Let's separately non-recursively unfreeze freeze_cgroup in
		 * case we want to undo (on error path) that we've just tried
		 * to freeze it.
		 */
		if (freezer_write_state(fd, THAWED))
			pr_err("Unable to thaw tasks\n");
	}

	if (close(fd)) {
		pr_perror("Failed to close freezer.state");
		return -1;
	}

	return exit_code;
}

static inline bool child_collected(struct pstree_item *i, pid_t pid)
{
	struct pstree_item *c;

	list_for_each_entry(c, &i->children, sibling)
		if (c->pid->real == pid)
			return true;

	return false;
}

static int parse_task_status(int pid, struct seize_task_status *ss, void *item)
{
	return parse_pid_status(pid, ss, item, NULL);
}

static int collect_task(struct pstree_item *item);
static int collect_children(struct pstree_item *item)
{
	pid_t *ch;
	int ret, i, nr_children, nr_inprogress;

	ret = parse_children(item->pid->real, &ch, &nr_children);
	if (ret < 0)
		return ret;

	nr_inprogress = 0;
	for (i = 0; i < nr_children; i++) {
		struct pstree_item *c;
		struct proc_status_creds creds;
		pid_t pid = ch[i];

		/* Is it already frozen? */
		if (child_collected(item, pid))
			continue;

		nr_inprogress++;

		if (alarm_timeouted()) {
			ret = -1;
			goto free;
		}

		pr_info("Seized task %d, state %d\n", pid, ret);

		c = alloc_pstree_item();
		if (c == NULL) {
			ret = -1;
			goto free;
		}

		if (!opts.freeze_cgroup)
			/* fails when meets a zombie */
			__ignore_value(compel_interrupt_task(pid));

		ret = compel_wait_task(pid, item->pid->real, parse_task_status, NULL, &creds.s, c);
		if (ret < 0) {
			/*
			 * Here is a race window between parse_children() and seize(),
			 * so the task could die for these time.
			 * Don't worry, will try again on the next attempt. The number
			 * of attempts is restricted, so it will exit if something
			 * really wrong.
			 */
			ret = 0;
			free_pstree_item(c);
			continue;
		}

		if (ret == TASK_ZOMBIE)
			ret = TASK_DEAD;
		else
			processes_to_wait--;

		if (ret == TASK_STOPPED)
			c->pid->stop_signo = compel_parse_stop_signo(pid);

		c->pid->real = pid;
		c->parent = item;
		c->pid->state = ret;
		add_child_task(c, item);

		ret = seccomp_collect_entry(pid, creds.s.seccomp_mode);
		if (ret < 0)
			goto free;

		/* Here is a recursive call (Depth-first search) */
		ret = collect_task(c);
		if (ret < 0)
			goto free;
	}
free:
	xfree(ch);
	return ret < 0 ? ret : nr_inprogress;
}

static void unseize_task_and_threads(const struct pstree_item *item, int st)
{
	int i;

	if (item->pid->state == TASK_DEAD)
		return;

	/*
	 * The st is the state we want to switch tasks into,
	 * the item->state is the state task was in when we seized one.
	 */

	compel_resume_task_sig(item->pid->real, item->pid->state, st, item->pid->stop_signo);

	if (st == TASK_DEAD)
		return;

	for (i = 1; i < item->nr_threads; i++)
		if (ptrace(PTRACE_DETACH, item->threads[i]->real, NULL, NULL))
			pr_perror("Unable to detach from %d", item->threads[i]->real);
}

static void pstree_wait(struct pstree_item *root_item)
{
	struct pstree_item *item = root_item;
	int pid, status, i;

	for_each_pstree_item(item) {
		if (item->pid->state == TASK_DEAD)
			continue;

		for (i = 0; i < item->nr_threads; i++) {
			pid = wait4(-1, &status, __WALL, NULL);
			if (pid < 0) {
				pr_perror("wait4 failed");
				break;
			} else {
				if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
					pr_err("Unexpected exit code %d of %d: %s\n", status, pid, strsignal(status));
					BUG();
				}
			}
		}
	}

	pid = wait4(-1, &status, __WALL, NULL);
	if (pid > 0) {
		pr_err("Unexpected child %d\n", pid);
		BUG();
	}
}

void pstree_switch_state(struct pstree_item *root_item, int st)
{
	struct pstree_item *item = root_item;

	if (!root_item)
		return;

	if (st != TASK_DEAD)
		freezer_restore_state();

	/*
	 * We need to detach from all processes before waiting the init
	 * process, because one of these processes may collect processes from a
	 * target pid namespace. The pid namespace is destroyed only when all
	 * processes have been killed and collected.
	 */
	freezer_detach();

	pr_info("Unfreezing tasks into %d\n", st);
	for_each_pstree_item(item)
		unseize_task_and_threads(item, st);

	if (st == TASK_DEAD)
		pstree_wait(root_item);
}

static pid_t item_ppid(const struct pstree_item *item)
{
	item = item->parent;
	return item ? item->pid->real : -1;
}

static inline bool thread_collected(struct pstree_item *i, pid_t tid)
{
	int t;

	if (i->pid->real == tid) /* thread leader is collected as task */
		return true;

	for (t = 0; t < i->nr_threads; t++)
		if (tid == i->threads[t]->real)
			return true;

	return false;
}

static int parse_thread_status(int pid, struct seize_task_status *ss, void *thread)
{
	return parse_pid_status(pid, ss, NULL, thread);
}

static int collect_threads(struct pstree_item *item)
{
	struct seccomp_entry *task_seccomp_entry;
	struct pid **threads = NULL;
	struct pid **tmp = NULL;
	int nr_threads = 0, i = 0, j, ret, nr_inprogress, nr_stopped = 0;
	int level = item->pid->level, id;

	task_seccomp_entry = seccomp_find_entry(item->pid->real);
	if (!task_seccomp_entry)
		return -1;

	ret = parse_threads(item->pid->real, &threads, &nr_threads);
	if (ret < 0)
		goto err;

	if ((item->pid->state == TASK_DEAD) && (nr_threads > 1)) {
		pr_err("Zombies with threads are not supported\n");
		goto err;
	}

	/* The number of threads can't be less than already frozen */
	tmp = xrealloc(item->threads, nr_threads * sizeof(struct pid *));
	if (tmp == NULL)
		goto err;

	item->threads = tmp;

	if (item->nr_threads == 0) {
		item->threads[0] = xmalloc(PID_SIZE(level));
		if (!item->threads[0])
			goto err;
		item->threads[0]->real = item->pid->real;
		item->nr_threads = 1;
		item->threads[0]->item = NULL;
		item->threads[0]->level = level;
		for (j = 0; j < level; j++) {
			item->threads[0]->ns[j].virt = -1;
			rb_init_node(&item->threads[0]->ns[j].node);
		}
	}

	nr_inprogress = 0;
	for (i = 0; i < nr_threads; i++) {
		pid_t pid = threads[i]->real;
		struct proc_status_creds t_creds = {};

		if (thread_collected(item, pid))
			continue;

		nr_inprogress++;

		pr_info("\tSeizing %d's %d thread\n", item->pid->real, pid);

		if (!opts.freeze_cgroup && compel_interrupt_task(pid))
			continue;

		id = item->nr_threads;
		BUG_ON(id >= nr_threads);
		item->threads[id] = xmalloc(PID_SIZE(level));
		if (!item->threads[id])
			goto err;
		item->threads[id]->real = pid;
		item->threads[id]->item = NULL;
		item->threads[id]->state = TASK_THREAD;
		item->threads[id]->level = level;
		for (j = 0; j < level; j++) {
			item->threads[id]->ns[j].virt = -1;
			rb_init_node(&item->threads[id]->ns[j].node);
		}

		ret = compel_wait_task(pid, item_ppid(item), parse_thread_status, NULL,
				       &t_creds.s, &item->threads[id]);
		if (ret < 0) {
			/*
			 * Here is a race window between parse_threads() and seize(),
			 * so the task could die for these time.
			 * Don't worry, will try again on the next attempt. The number
			 * of attempts is restricted, so it will exit if something
			 * really wrong.
			 */
			xfree(item->threads[id]);
			continue;
		}

		if (ret == TASK_ZOMBIE)
			ret = TASK_DEAD;
		else
			processes_to_wait--;

		item->nr_threads++;

		if (ret == TASK_DEAD) {
			pr_err("Zombie thread not supported\n");
			goto err;
		}

		if (seccomp_collect_entry(pid, t_creds.s.seccomp_mode))
			goto err;

		if (ret == TASK_STOPPED) {
			nr_stopped++;
		}
	}

	if (nr_stopped && nr_stopped != nr_inprogress) {
		pr_err("Individually stopped threads not supported\n");
		goto err;
	}

	while (nr_threads-- > 0)
		xfree(threads[nr_threads]);
	xfree(threads);
	return nr_inprogress;

err:
	while (item->nr_threads-- > 0)
		xfree(item->threads[item->nr_threads]);
	xfree(item->threads);

	while (nr_threads-- > 0)
		xfree(threads[nr_threads]);
	xfree(threads);
	return -1;
}

static int collect_loop(struct pstree_item *item, int (*collect)(struct pstree_item *))
{
	int attempts = NR_ATTEMPTS, nr_inprogress = 1;

	if (opts.freeze_cgroup)
		attempts = 1;

	/*
	 * While we scan the proc and seize the children/threads
	 * new ones can appear (with clone(CLONE_PARENT) or with
	 * pthread_create). Thus, after one go, we need to repeat
	 * the scan-and-freeze again collecting new arrivals. As
	 * new guys may appear again we do NR_ATTEMPTS passes and
	 * fail to seize the item if new tasks/threads still
	 * appear.
	 */

	while (nr_inprogress > 0 && attempts >= 0) {
		attempts--;
		nr_inprogress = collect(item);
	}

	pr_info("Collected (%d attempts, %d in_progress)\n", attempts, nr_inprogress);

	/*
	 * We may fail to collect items or run out of attempts.
	 * In the former case nr_inprogress will be negative, in
	 * the latter -- positive. Thus it's enough just to check
	 * for "no more new stuff" and say "we're OK" if so.
	 */

	return (nr_inprogress == 0) ? 0 : -1;
}

static int collect_task(struct pstree_item *item)
{
	int ret;

	ret = collect_loop(item, collect_threads);
	if (ret < 0)
		goto err_close;

	/* Depth-first search (DFS) is used for traversing a process tree. */
	ret = collect_loop(item, collect_children);
	if (ret < 0)
		goto err_close;

	if ((item->pid->state == TASK_DEAD) && !list_empty(&item->children)) {
		pr_err("Zombie with children?! O_o Run, run, run!\n");
		goto err_close;
	}

	if (pstree_alloc_cores(item))
		goto err_close;

	pr_info("Collected %d in %d state\n", item->pid->real, item->pid->state);
	return 0;

err_close:
	close_pid_proc();
	return -1;
}

static int cgroup_version(void)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/freezer.state", opts.freeze_cgroup);
	if (access(path, F_OK) == 0) {
		cgroup_v2 = false;
		return 0;
	}

	snprintf(path, sizeof(path), "%s/cgroup.freeze", opts.freeze_cgroup);
	if (access(path, F_OK) == 0) {
		cgroup_v2 = true;
		return 0;
	}

	pr_err("Neither a cgroupv1 (freezer.state) or cgroupv2 (cgroup.freeze) control file found.\n");

	return -1;
}

int collect_pstree(void)
{
	pid_t pid = root_item->pid->real;
	int ret = -1;
	struct proc_status_creds creds;

	timing_start(TIME_FREEZING);

	/*
	 * wait4() may hang for some reason. Enable timer and fire SIGALRM
	 * if timeout reached. SIGALRM handler will do  the necessary
	 * cleanups and terminate current process.
	 */
	alarm(opts.timeout);

	if (opts.freeze_cgroup && cgroup_version())
		goto err;

	pr_debug("Detected cgroup V%d freezer\n", cgroup_v2 ? 2 : 1);

	if (opts.freeze_cgroup && freeze_processes())
		goto err;

	if (!opts.freeze_cgroup && compel_interrupt_task(pid)) {
		set_cr_errno(ESRCH);
		goto err;
	}

	ret = compel_wait_task(pid, -1, parse_task_status, NULL, &creds.s, root_item);
	if (ret < 0)
		goto err;

	if (ret == TASK_ZOMBIE)
		ret = TASK_DEAD;
	else
		processes_to_wait--;

	if (ret == TASK_STOPPED)
		root_item->pid->stop_signo = compel_parse_stop_signo(pid);

	pr_info("Seized task %d, state %d\n", pid, ret);
	root_item->pid->state = ret;

	ret = seccomp_collect_entry(pid, creds.s.seccomp_mode);
	if (ret < 0)
		goto err;

	ret = collect_task(root_item);
	if (ret < 0)
		goto err;

	if (opts.freeze_cgroup && freezer_wait_processes()) {
		ret = -1;
		goto err;
	}

	ret = 0;
	timing_stop(TIME_FREEZING);
	timing_start(TIME_FROZEN);

err:
	/* Freezing stage finished in time - disable timer. */
	alarm(0);
	return ret;
}
