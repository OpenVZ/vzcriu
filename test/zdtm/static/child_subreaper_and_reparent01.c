#include <sys/mman.h>
#include <sched.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/mount.h>

#include "zdtmtst.h"

const char *test_doc	= "Check child subreaper and reparenting";
const char *test_author	= "Yuriy Vasiliev <yuriy.vasiliev@virtuozzo.com>";

struct process {
	pid_t pid;
	pid_t sid;
	pid_t pgid;
	pid_t ppid;
	int sks[2];
	int dead;
};

struct process *processes;
int nr_processes = 37;
int current;

static void cleanup(void)
{
	kill(processes[0].pid, SIGKILL);
	/* It's enough to kill pidns init for others to die */
	kill(processes[1].pid, SIGKILL);
}

enum commands {
	TEST_FORK,
	TEST_WAIT,
	TEST_SUBREAPER,
	TEST_SETSID,
	TEST_DIE,
	TEST_GETSID,
	TEST_SETNS,
	TEST_SETPGID,
	TEST_GETPGID,
	TEST_GETPPID,
};

struct command {
	enum commands	cmd;
	int		arg1;
	int		arg2;
};

static void handle_command(void);

static void mainloop(void)
{
	while (1)
		handle_command();
}

#define CLONE_STACK_SIZE	4096
/* All arguments should be above stack, because it grows down */
struct clone_args {
	char stack[CLONE_STACK_SIZE] __stack_aligned__;
	char stack_ptr[0];
	int id;
};

static int clone_func(void *_arg)
{
	struct clone_args *args = (struct clone_args *) _arg;

	current = args->id;

	test_msg("%3d: Hello. My pid is %d\n", args->id, getpid());
	mainloop();
	exit(0);
}

static int make_child(int id, int flags)
{
	struct clone_args args;
	pid_t cid;

	args.id = id;

	cid = clone(clone_func, args.stack_ptr,
			flags | SIGCHLD, &args);

	if (cid < 0)
		pr_perror("clone(%d, %d)", id, flags);

	processes[id].pid = cid;

	return cid;
}

static int open_proc(void)
{
	int fd;
	char proc_mountpoint[] = "child_subreaper_and_reparent01_proc.XXXXXX";

	if (mkdtemp(proc_mountpoint) == NULL) {
		pr_perror("mkdtemp failed %s", proc_mountpoint);
		return -1;
	}

	if (mount("proc", proc_mountpoint, "proc", MS_MGC_VAL | MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL)) {
		pr_perror("mount proc failed");
		rmdir(proc_mountpoint);
		return -1;
	}

	fd = open(proc_mountpoint, O_RDONLY | O_DIRECTORY, 0);
	if (fd < 0)
		pr_perror("can't open proc");

	if (umount2(proc_mountpoint, MNT_DETACH)) {
		pr_perror("can't umount proc");
		goto err_close;
	}

	if (rmdir(proc_mountpoint)) {
		pr_perror("can't remove tmp dir");
		goto err_close;
	}

	return fd;
err_close:
	if (fd >= 0)
		close(fd);
	return -1;
}

static int open_pidns(int pid)
{
	int proc, fd;
	char pidns_path[PATH_MAX];

	proc = open_proc();
	if (proc < 0) {
		pr_err("open proc");
		return -1;
	}

	sprintf(pidns_path, "%d/ns/pid", pid);
	fd = openat(proc, pidns_path, O_RDONLY);
	if (fd == -1)
		pr_err("open pidns fd");

	close(proc);
	return fd;
}

static int setns_pid(int pid, int nstype)
{
	int pidns, ret;

	pidns = open_pidns(pid);
	if (pidns < 0)
		return -1;

	ret = setns(pidns, nstype);
	if (ret == -1)
		pr_perror("setns");

	close(pidns);
	return ret;
}

static void handle_command(void)
{
	int sk = processes[current].sks[0], ret, status = 0;
	struct command cmd;

	ret = read(sk, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd)) {
		pr_perror("Unable to get command");
		goto err;
	}

	switch (cmd.cmd) {
	case TEST_FORK:
		{
			pid_t pid;

			pid = make_child(cmd.arg1, cmd.arg2);
			if (pid == -1) {
				status = -1;
				goto err;
			}

			test_msg("%3d: fork(%d, %x) = %d\n",
					current, cmd.arg1, cmd.arg2, pid);
			processes[cmd.arg1].pid = pid;
		}
		break;
	case TEST_WAIT:
		test_msg("%3d: wait(%d) = %d\n", current,
				cmd.arg1, processes[cmd.arg1].pid);

		if (waitpid(processes[cmd.arg1].pid, NULL, 0) == -1) {
			pr_perror("waitpid(%d)", processes[cmd.arg1].pid);
			status = -1;
		}
		break;
	case TEST_SUBREAPER:
		test_msg("%3d: subreaper(%d)\n", current, cmd.arg1);
		if (prctl(PR_SET_CHILD_SUBREAPER, cmd.arg1, 0, 0, 0) == -1) {
			pr_perror("PR_SET_CHILD_SUBREAPER");
			status = -1;
		}
		break;
	case TEST_SETSID:
		test_msg("%3d: setsid()\n", current);
		if (setsid() == -1) {
			pr_perror("setsid");
			status = -1;
		}
		break;
	case TEST_GETSID:
		test_msg("%3d: getsid()\n", current);
		status = getsid(getpid());
		if (status == -1)
			pr_perror("getsid");
		break;
	case TEST_SETPGID:
		test_msg("%3d: setpgid(%d, %d)\n", current, cmd.arg1, cmd.arg2);
		if (setpgid(processes[cmd.arg1].pid, processes[cmd.arg2].pid) == -1) {
			pr_perror("setpgid");
			status = -1;
		}
		break;
	case TEST_GETPGID:
		test_msg("%3d: getpgid()\n", current);
		status = getpgid(0);
		if (status == -1)
			pr_perror("getpgid");
		break;
	case TEST_GETPPID:
		test_msg("%3d: getppid()\n", current);
		status = getppid();
		if (status == -1)
			pr_perror("getppid");
		break;
	case TEST_SETNS:
		test_msg("%3d: setns(%d, %d) = %d\n", current,
				cmd.arg1, cmd.arg2, processes[cmd.arg1].pid);
		setns_pid(processes[cmd.arg1].pid, cmd.arg2);

		break;
	case TEST_DIE:
		test_msg("%3d: die()\n", current);
		processes[current].dead = 1;
		shutdown(sk, SHUT_RDWR);
		exit(0);
	}

	ret = write(sk, &status, sizeof(status));
	if (ret != sizeof(status)) {
		pr_perror("Unable to answer");
		goto err;
	}

	if (status < 0)
		goto err;

	return;
err:
	shutdown(sk, SHUT_RDWR);
	exit(1);
}

static int send_command(int id, enum commands op, int arg1, int arg2)
{
	int sk = processes[id].sks[1], ret, status;
	struct command cmd = {op, arg1, arg2};

	if (op == TEST_FORK) {
		if (processes[arg1].pid) {
			pr_perror("%d is busy", arg1);
			return -1;
		}
	}

	ret = write(sk, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd)) {
		pr_perror("Unable to send command");
		goto err;
	}

	status = 0;
	ret = read(sk, &status, sizeof(status));
	if (ret != sizeof(status) && !(status == 0 && op == TEST_DIE)) {
		pr_perror("Unable to get answer");
		goto err;
	}

	if (status != -1 && (op == TEST_GETSID || op == TEST_GETPGID || op == TEST_GETPPID))
		return status;

	if (status) {
		pr_perror("The command(%d, %d, %d) failed", op, arg1, arg2);
		goto err;
	}

	return 0;
err:
	cleanup();
	exit(1);
}

int main(int argc, char **argv)
{
	int pid, i;
	int fail_cnt = 0;

	test_init(argc, argv);

	processes = mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ,
				MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (processes == NULL) {
		pr_perror("Unable to map share memory");
		return 1;
	}

	for (i = 0; i < nr_processes; i++) {
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, processes[i].sks) == -1) {
			pr_perror("socketpair");
			return 1;
		}
	}

	pid = make_child(0, 0);
	if (pid < 0)
		return -1;
	send_command(0, TEST_FORK,	1, CLONE_NEWPID);
	send_command(1, TEST_SETSID,	0, 0);

#ifdef ZDTM_CHILD_SUBREAPER_AND_REPARENT01
	/*
	 * Test leader and orphaned process subreaper mismatch (should fail)
	 * pid	sid		pidns pid
	 *	 6	  6				1	\_ child_subreaper_and_reparent
	 *	 7	  7				2		\_ child_subreaper_and_reparent (subreaper)
	 *	 8	  7				3			\_ child_subreaper_and_reparent (subreaper)
	 *	 9	  9				4			|	\_ child_subreaper_and_reparent
	 *	11	  9				6			\_ child_subreaper_and_reparent
	*/
	send_command(1, TEST_FORK,		2, 0);

	send_command(2, TEST_SETSID,	0, 0);
	send_command(2, TEST_FORK,		3, 0);
	send_command(3, TEST_FORK,		4, 0);

	send_command(4, TEST_SETSID,	0, 0);
	send_command(4, TEST_FORK,		5, 0);
	send_command(5, TEST_FORK,		6, 0);

	send_command(2, TEST_SUBREAPER,	1, 0);

	send_command(5, TEST_DIE,		0, 0);
	send_command(4, TEST_WAIT,		5, 0);

	send_command(3, TEST_SUBREAPER,	1, 0);
#elif defined(ZDTM_CHILD_SUBREAPER_AND_REPARENT02)
	/*
	 * Test leader and orphaned process subreaper match (should pass)
	 * pid	sid		pidns pid
	 *	 6	  6				1	\_ child_subreaper_and_reparent
	 *	 7	  7				2		\_ child_subreaper_and_reparent (subreaper)
	 *	 8	  7				3			\_ child_subreaper_and_reparent
	 *	 9	  9				4			|	\_ child_subreaper_and_reparent
	 *	11	  9				6			\_ child_subreaper_and_reparent
	 */
	send_command(1, TEST_FORK,		2, 0);

	send_command(2, TEST_SETSID,	0, 0);
	send_command(2, TEST_FORK,		3, 0);
	send_command(3, TEST_FORK,		4, 0);

	send_command(4, TEST_SETSID,	0, 0);
	send_command(4, TEST_FORK,		5, 0);
	send_command(5, TEST_FORK,		6, 0);

	send_command(2, TEST_SUBREAPER,	1, 0);

	send_command(5, TEST_DIE,		0, 0);
	send_command(4, TEST_WAIT,		5, 0);
#elif defined(ZDTM_CHILD_SUBREAPER_AND_REPARENT03)
	/*
	 * Test nested subreapers (should pass)
	 * pid	sid		pidns pid
	 *	 6	  6				1	\_ child_subreaper_and_reparent
	 *	 7	  6				2		\_ child_subreaper_and_reparent (subreaper)
	 *	 8	  8				3			\_ child_subreaper_and_reparent
	 *	10	 10				5			\_ child_subreaper_and_reparent (subreaper)
	 *	11	  8				6				\_ child_subreaper_and_reparent
	 */
	send_command(1, TEST_FORK,		2, 0);

	send_command(2, TEST_FORK,		3, 0);
	send_command(2, TEST_SUBREAPER,	1, 0);

	send_command(3, TEST_SETSID,	0, 0);
	send_command(3, TEST_FORK,		4, 0);
	send_command(4, TEST_FORK,		5, 0);

	send_command(5, TEST_SUBREAPER,	1, 0);
	send_command(5, TEST_FORK,		6, 0);
	send_command(5, TEST_SETSID,	0, 0);

	send_command(4, TEST_DIE,		0, 0);
	send_command(3, TEST_WAIT,		4, 0);
#elif defined(ZDTM_CHILD_SUBREAPER_AND_REPARENT04)
	/*
	 * Test nested subreapers (should pass)
	 * pid	sid		pidns pid
	 *	 6	  6				1	\_ child_subreaper_and_reparent
	 *	 7	  6				2		\_ child_subreaper_and_reparent (subreaper)
	 *	 8	  8				3			\_ child_subreaper_and_reparent
	 *	10	 10				5			\_ child_subreaper_and_reparent (subreaper)
	 *	11	  8				6				\_ child_subreaper_and_reparent
	 *	12	 12				7					\_ child_subreaper_and_reparent
	 *	13	 13				8						\_ child_subreaper_and_reparent (subreaper)
	 *	15	 15			   10							\_ child_subreaper_and_reparent
	 *	16	 12			   11								\_ child_subreaper_and_reparent
	 */
	send_command(1, TEST_FORK,		2, 0);

	send_command(2, TEST_FORK,		3, 0);
	send_command(2, TEST_SUBREAPER,	1, 0);

	send_command(3, TEST_SETSID,	0, 0);
	send_command(3, TEST_FORK,		4, 0);
	send_command(4, TEST_FORK,		5, 0);

	send_command(5, TEST_SUBREAPER,	1, 0);
	send_command(5, TEST_FORK,		6, 0);
	send_command(5, TEST_SETSID,	0, 0);

	send_command(6, TEST_FORK,		7, 0);
	send_command(7, TEST_SETSID,	0, 0);
	send_command(7, TEST_FORK,		8, 0);

	send_command(8, TEST_FORK,		9, 0);
	send_command(9, TEST_FORK,		10, 0);
	send_command(10, TEST_FORK,		11, 0);

	send_command(10, TEST_SETSID,	0, 0);
	send_command(8, TEST_SETSID,	0, 0);
	send_command(8, TEST_SUBREAPER,	1, 0);

	send_command(4, TEST_DIE,		0, 0);
	send_command(3, TEST_WAIT,		4, 0);

	send_command(9, TEST_DIE,		0, 0);
	send_command(8, TEST_WAIT,		9, 0);
#elif defined(ZDTM_CHILD_SUBREAPER_AND_REPARENT05)
	/*
	 * Test nested subreapers (should pass)
	 * pid	sid		pidns pid
	 *	 6	  6				1	\_ child_subreaper_and_reparent
	 *	 7	  6				2		\_ child_subreaper_and_reparent (subreaper)
	 *	 8	  8				3			\_ child_subreaper_and_reparent
	 *	10	 10				5			\_ child_subreaper_and_reparent (subreaper)
	 *	11	  8				6				\_ child_subreaper_and_reparent (subreaper)
	 *	12	 12				7				|	\_ child_subreaper_and_reparent
	 *	13	 13				8				|		\_ child_subreaper_and_reparent
	 *	15	 15			   10				\_ child_subreaper_and_reparent
	 *	16	 12			   11					\_ child_subreaper_and_reparent
	 */
	send_command(1, TEST_FORK,		2, 0);

	send_command(2, TEST_FORK,		3, 0);
	send_command(2, TEST_SUBREAPER,	1, 0);

	send_command(3, TEST_SETSID,	0, 0);
	send_command(3, TEST_FORK,		4, 0);
	send_command(4, TEST_FORK,		5, 0);

	send_command(5, TEST_SUBREAPER,	1, 0);
	send_command(5, TEST_FORK,		6, 0);
	send_command(5, TEST_SETSID,	0, 0);

	send_command(6, TEST_FORK,		7, 0);
	send_command(7, TEST_SETSID,	0, 0);
	send_command(7, TEST_FORK,		8, 0);

	send_command(8, TEST_FORK,		9, 0);
	send_command(9, TEST_FORK,		10, 0);
	send_command(10, TEST_FORK,		11, 0);

	send_command(10, TEST_SETSID,	0, 0);
	send_command(8, TEST_SETSID,	0, 0);
	send_command(6, TEST_SUBREAPER,	1, 0);

	send_command(4, TEST_DIE,		0, 0);
	send_command(3, TEST_WAIT,		4, 0);

	send_command(9, TEST_DIE,		0, 0);
	send_command(8, TEST_WAIT,		9, 0);
#else
#error "ZDTM_CHILD_SUBREAPER_AND_REPARENT* not defined"
#endif

	for (i = 0; i < nr_processes; i++) {
		if (processes[i].dead)
			continue;
		if (processes[i].pid == 0)
			continue;

		processes[i].sid = send_command(i, TEST_GETSID, 0, 0);
		if (processes[i].sid == -1) {
			pr_perror("getsid(%d)", i);
			goto err;
		}

		processes[i].pgid = send_command(i, TEST_GETPGID, 0, 0);
		if (processes[i].pgid == -1) {
			pr_perror("getpgid(%d)", i);
			goto err;
		}

		processes[i].ppid = send_command(i, TEST_GETPPID, 0, 0);
		if (processes[i].ppid == -1) {
			pr_perror("getppid(%d)", i);
			goto err;
		}
	}

	test_daemon();

	test_waitsig();

	for (i = 0; i < nr_processes; i++) {
		pid_t sid, pgid, ppid;

		if (processes[i].dead)
			continue;
		if (processes[i].pid == 0)
			continue;

		sid = send_command(i, TEST_GETSID, 0, 0);
		if (sid == -1) {
			pr_perror("getsid(%d)", i);
			goto err;
		}

		if (sid != processes[i].sid) {
			fail("%d, %d: wrong sid %d (expected %d)",
				i, processes[i].pid, sid, processes[i].sid);
			fail_cnt++;
		}

		pgid = send_command(i, TEST_GETPGID, 0, 0);
		if (pgid == -1) {
			pr_perror("getpgid(%d)", i);
			goto err;
		}

		if (pgid != processes[i].pgid) {
			fail("%d, %d: wrong pgid %d (expected %d)",
				i, processes[i].pid, pgid, processes[i].pgid);
			fail_cnt++;
		}

		ppid = send_command(i, TEST_GETPPID, 0, 0);
		if (ppid == -1) {
			pr_perror("getppid(%d)", i);
			goto err;
		}

		if (ppid != processes[i].ppid) {
			fail("%d, %d: wrong ppid %d (expected %d)",
				i, processes[i].pid, ppid, processes[i].ppid);
			fail_cnt++;
		}
	}

	if (fail_cnt)
		goto err;

	pass();

	return 0;
err:
	cleanup();
	return 1;
}
