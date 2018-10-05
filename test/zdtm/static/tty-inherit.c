#define _XOPEN_SOURCE 500

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc = "Test teminals inheritance";
const char *test_author = "Cyrill Gorcunov <gorcunov@openvz.org>";

#define PROC_TASK_COMM_LEN     32
#define PROC_TASK_COMM_LEN_FMT "(%31s"

struct proc_pid_stat {
	int pid;
	char comm[PROC_TASK_COMM_LEN];
	char state;
	int ppid;
	int pgid;
	int sid;
	int tty_nr;
	int tty_pgrp;
	unsigned int flags;
	unsigned long min_flt;
	unsigned long cmin_flt;
	unsigned long maj_flt;
	unsigned long cmaj_flt;
	unsigned long utime;
	unsigned long stime;
	long cutime;
	long cstime;
	long priority;
	long nice;
	int num_threads;
	int zero0;
	unsigned long long start_time;
	unsigned long vsize;
	long mm_rss;
	unsigned long rsslim;
	unsigned long start_code;
	unsigned long end_code;
	unsigned long start_stack;
	unsigned long esp;
	unsigned long eip;
	unsigned long sig_pending;
	unsigned long sig_blocked;
	unsigned long sig_ignored;
	unsigned long sig_handled;
	unsigned long wchan;
	unsigned long zero1;
	unsigned long zero2;
	int exit_signal;
	int task_cpu;
	unsigned int rt_priority;
	unsigned int policy;
	unsigned long long delayacct_blkio_ticks;
	unsigned long gtime;
	long cgtime;
	unsigned long start_data;
	unsigned long end_data;
	unsigned long start_brk;
	unsigned long arg_start;
	unsigned long arg_end;
	unsigned long env_start;
	unsigned long env_end;
	int exit_code;
};

int parse_pid_stat(pid_t pid, struct proc_pid_stat *s)
{
	char path[128], buf[4096];
	char bufcpy[sizeof(buf)];
	char *tok, *p;
	int fd;
	int n;

	memset(buf, 0, sizeof(buf));
	memset(bufcpy, 0, sizeof(bufcpy));

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	n = read(fd, buf, sizeof(buf));
	close(fd);
	if (n < 1) {
		pr_err("stat for %d is corrupted\n", pid);
		return -1;
	}

	memcpy(bufcpy, buf, sizeof(bufcpy));
	memset(s, 0, sizeof(*s));

	tok = strchr(buf, ' ');
	if (!tok)
		goto err;
	*tok++ = '\0';
	if (*tok != '(')
		goto err;

	s->pid = atoi(buf);

	p = strrchr(tok + 1, ')');
	if (!p)
		goto err;
	*tok = '\0';
	*p = '\0';

	strcpy(s->comm, tok + 1);

	n = sscanf(p + 1,
	       " %c %d %d %d %d %d %u %lu %lu %lu %lu "
	       "%lu %lu %ld %ld %ld %ld %d %d %llu %lu %ld %lu %lu %lu %lu "
	       "%lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld "
	       "%lu %lu %lu %lu %lu %lu %lu %d",
		&s->state,
		&s->ppid,
		&s->pgid,
		&s->sid,
		&s->tty_nr,
		&s->tty_pgrp,
		&s->flags,
		&s->min_flt,
		&s->cmin_flt,
		&s->maj_flt,
		&s->cmaj_flt,
		&s->utime,
		&s->stime,
		&s->cutime,
		&s->cstime,
		&s->priority,
		&s->nice,
		&s->num_threads,
		&s->zero0,
		&s->start_time,
		&s->vsize,
		&s->mm_rss,
		&s->rsslim,
		&s->start_code,
		&s->end_code,
		&s->start_stack,
		&s->esp,
		&s->eip,
		&s->sig_pending,
		&s->sig_blocked,
		&s->sig_ignored,
		&s->sig_handled,
		&s->wchan,
		&s->zero1,
		&s->zero2,
		&s->exit_signal,
		&s->task_cpu,
		&s->rt_priority,
		&s->policy,
		&s->delayacct_blkio_ticks,
		&s->gtime,
		&s->cgtime,
		&s->start_data,
		&s->end_data,
		&s->start_brk,
		&s->arg_start,
		&s->arg_end,
		&s->env_start,
		&s->env_end,
		&s->exit_code);
	if (n < 50)
		goto err;

	return 0;

err:
	pr_err("Parsing %d's stat failed (#fields do not match: "
	       "expected 50 but got %d)\n",
	       pid, n);
	pr_err("Original buffer value: '%s'\n", bufcpy);
	return -1;
}

static futex_t *futex_master;
static futex_t *futex_child;
static futex_t *futex_grandchild;

int main(int argc, char **argv)
{
	struct proc_pid_stat stat_before, stat_after;
	int fdm, fds, ret, tty, i, status;
	char *slavename, buf[1024];
	char teststr[] = "Hello\n";
	task_waiter_t t, m;
	pid_t pid, pid_ret;
	void *mem;

	test_init(argc, argv);
	task_waiter_init(&t);
	task_waiter_init(&m);

	mem = mmap(NULL, sizeof(futex_t) * 3, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (mem == MAP_FAILED) {
		pr_perror("Can't allocate memory");
		return 1;
	}

	futex_master = mem;
	futex_child = &futex_master[1];
	futex_grandchild = &futex_master[2];

	futex_init(futex_master);
	futex_init(futex_child);
	futex_init(futex_grandchild);

	pid = test_fork();
	if (pid < 0) {
		pr_perror("fork failed");
		return 1;
	} else if (pid == 0) {
		test_msg("Master child %d\n", getpid());

		if (setsid() == -1) {
			pr_perror("setsid failed");
			futex_abort_and_wake(futex_master);
			exit(1);
		}

		fdm = open("/dev/ptmx", O_RDWR);
		if (fdm == -1) {
			pr_perror("open(%s) failed", "/dev/ptmx");
			futex_abort_and_wake(futex_master);
			exit(1);
		}

		grantpt(fdm);
		unlockpt(fdm);

		slavename = ptsname(fdm);
		fds = open(slavename, O_RDWR);
		if (fds == -1) {
			pr_perror("open(%s) failed", slavename);
			futex_abort_and_wake(futex_master);
			exit(1);
		}

		if (ioctl(fds, TIOCSCTTY, 1)) {
			pr_perror("ioctl(%s, TIOCSCTTY, 1) failed", slavename);
			futex_abort_and_wake(futex_master);
			exit(1);
		}

		pid = test_fork();
		if (pid < 0) {
			pr_perror("fork failed");
			futex_abort_and_wake(futex_master);
			exit(1);
		} else if (pid == 0) {
			test_msg("Slave child %d\n", getpid());

			if (parse_pid_stat(getpid(), &stat_before)) {
				futex_abort_and_wake(futex_child);
				exit(1);
			}

			tty = open("/dev/tty", O_RDWR);
			if (tty < 0) {
				pr_perror("open(%s) failed", "/dev/tty");
				futex_abort_and_wake(futex_child);
				exit(1);
			}

			futex_set_and_wake(futex_child, 1);
			task_waiter_wait4(&t, 1);

			for (i = 0; i < 10; i++) {
				ret = read(fds, buf, sizeof(teststr) - 1);
				if (ret != sizeof(teststr) - 1) {
					pr_perror("read(tty) failed");
					futex_abort_and_wake(futex_child);
					exit(1);
				}

				if (strncmp(teststr, buf, sizeof(teststr) - 1)) {
					fail("data mismatch");
					futex_abort_and_wake(futex_child);
					exit(1);
				}
			}

			task_waiter_complete(&t, 2);
			task_waiter_wait4(&t, 3);

			for (i = 0; i < 10; i++) {
				ret = read(fds, buf, sizeof(teststr) - 1);
				if (ret != sizeof(teststr) - 1) {
					pr_perror("read(tty) failed");
					exit(1);
				}

				if (strncmp(teststr, buf, sizeof(teststr) - 1)) {
					fail("data mismatch");
					exit(1);
				}
			}

			close(tty);

			if (parse_pid_stat(getpid(), &stat_after)) {
				fail("parsing stat failed");
				exit(1);
			}

			if (stat_before.tty_pgrp != stat_after.tty_pgrp) {
				fail("tty pgrp mismatch %d %d",
				     stat_before.tty_pgrp, stat_after.tty_pgrp);
				exit(1);
			}

			task_waiter_complete(&t, 4);
			task_waiter_wait4(&t, 5);
			exit(0);
		}

		for (i = 0; i < 10; i++) {
			/* Check connectivity */
			ret = write(fdm, teststr, sizeof(teststr) - 1);
			if (ret != sizeof(teststr) - 1) {
				pr_perror("write(fdm) failed");
				exit(1);
			}
		}

		if (futex_wait_while(futex_child, 0) & FUTEX_ABORT_FLAG) {
			waitpid(pid, &status, 0);
			futex_abort_and_wake(futex_master);
			fail("unable to complete grandchild initialization");
			exit(1);
		}

		futex_set_and_wake(futex_master, 1);

		task_waiter_complete(&t, 1);
		task_waiter_wait4(&t, 2);

		task_waiter_complete(&m, 1);
		/* --- C/R --- */
		task_waiter_wait4(&m, 2);

		for (i = 0; i < 10; i++) {
			/* Check connectivity */
			ret = write(fdm, teststr, sizeof(teststr) - 1);
			if (ret != sizeof(teststr) - 1) {
				fail("write(fdm) failed");
				exit(1);
			}
		}

		task_waiter_complete(&t, 3);
		task_waiter_wait4(&t, 4);

		if (kill(pid, SIGTERM) == -1) {
			fail("kill %d failed", pid);
			exit(1);
		}

		close(fdm);
		close(fds);
		exit(0);
	}

	if (futex_wait_while(futex_master, 0) & FUTEX_ABORT_FLAG) {
		waitpid(pid, &status, 0);
		fail("unable to complete child initialization");
		return 1;
	}

	task_waiter_wait4(&m, 1);

	test_daemon();
	test_waitsig();

	task_waiter_complete(&m, 2);

	pid_ret = waitpid(pid, &status, 0);
	if (pid_ret < 0) {
		fail("waitpid %d failed", pid);
		return 1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fail("waitpid %d %d status failed %d %d %d",
		     pid, pid_ret, status, WIFEXITED(status),
		     WEXITSTATUS(status));
		return 1;
	}

	task_waiter_fini(&t);
	task_waiter_fini(&m);

	pass();
	return 0;
}
