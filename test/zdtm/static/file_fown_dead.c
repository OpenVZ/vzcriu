#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <utime.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include "zdtmtst.h"

#ifndef F_SETSIG
#define F_SETSIG	10	/* for sockets. */
#define F_GETSIG	11	/* for sockets. */
#endif

const char *test_doc	= "Check for restore with dead file owners";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

struct params {
	int	sigio;
	int	pipe_flags[2];
	int	pipe_pid[2];
	int	pipe_sig[2];
} *shared;

static void signal_handler_io(int status)
{
	shared->sigio++;
}

static void fill_pipe_params(struct params *p, int *pipes)
{
	p->pipe_flags[0] = fcntl(pipes[0], F_GETFL);
	p->pipe_flags[1] = fcntl(pipes[1], F_GETFL);

	test_msg("pipe_flags0 %08o\n", p->pipe_flags[0]);
	test_msg("pipe_flags1 %08o\n", p->pipe_flags[1]);

	p->pipe_pid[0] = fcntl(pipes[0], F_GETOWN);
	p->pipe_pid[1] = fcntl(pipes[1], F_GETOWN);

	p->pipe_sig[0] = fcntl(pipes[0], F_GETSIG);
	p->pipe_sig[1] = fcntl(pipes[1], F_GETSIG);
}

static int cmp_pipe_params(struct params *p1, struct params *p2)
{
	int i;

	for (i = 0; i < 2; i++) {
		if (p1->pipe_flags[i] != p2->pipe_flags[i]) {
			fail("pipe flags failed [%d] expected %08o got %08o\n",
			     i, p1->pipe_flags[i], p2->pipe_flags[i]);
			return -1;
		}
		if (p1->pipe_pid[i] != p2->pipe_pid[i]) {
			fail("pipe pid failed [%d] expected %d got %d\n",
			     i, p1->pipe_pid[i], p2->pipe_pid[i]);
			return -1;
		}
		if (p1->pipe_sig[i] != p2->pipe_sig[i]) {
			fail("pipe sig failed [%d] expected %d got %d\n",
			     i, p1->pipe_sig[i], p2->pipe_sig[i]);
			return -1;
		}
	}

	return 0;
}

#ifdef ZDTM_FILE_FOWN_REUSE
static int reuse_pid(pid_t pid)
{
	int fd, len, cpid;
	char buf[32];

	fd = open("/proc/sys/kernel/ns_last_pid", O_WRONLY);
	if (fd < 0) {
		pr_perror("open ns_last_pid");
		return -1;
	}
	len = snprintf(buf, sizeof(buf), "%d", pid - 1);
	if (write(fd, buf, len) != len) {
		pr_perror("write ns_last_pid");
		close(fd);
		return -1;
	}
	close(fd);

	cpid = fork();
	if (cpid < 0) {
		pr_perror("can't fork");
		return -1;
	} else if (cpid == 0) {
		while (1)
			sleep(1);
		exit(0);
	} else if (cpid != pid) {
		pr_err("pid reuse failed %d != %d\n", cpid, pid);
		kill(cpid, SIGKILL);
		wait(NULL);
		return -1;
	}

	return cpid;
}
#endif

int main(int argc, char *argv[])
{
	struct sigaction saio = { };
	struct params obtained = { };
	uid_t ruid, euid, suid;
	int status, pipes[2];
	pid_t pid;
	int fd;
#ifdef ZDTM_FILE_FOWN_REUSE
	pid_t cpid;
#endif

	test_init(argc, argv);

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0644);
	if (fd < 0) {
		pr_perror("Can't create %s", filename);
		exit(1);
	}
	close(fd);

	fd = open(filename, O_PATH, 0644);
	if (fd < 0) {
		pr_perror("Can't open %s as O_PATH", filename);
		exit(1);
	}

	shared = (void *)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if ((void *)shared == MAP_FAILED) {
		pr_perror("mmap failed");
		exit(1);
	}

	if (getresuid(&ruid, &euid, &suid)) {
		pr_perror("getresuid failed");
		exit(1);
	}

	if (pipe(pipes)) {
		pr_perror("Can't create pipe");
		exit(1);
	}

	saio.sa_handler	= (sig_t)signal_handler_io;
	saio.sa_flags	= SA_RESTART;
	if (sigaction(SIGIO, &saio, 0)) {
		pr_perror("sigaction failed");
		exit(1);
	}

	if (!getuid() && setresuid(-1, 1, -1)) {
		pr_err("setresuid failed\n");
		exit(1);
	}

	if (fcntl(pipes[0], F_SETOWN, getpid())					||
	    fcntl(pipes[1], F_SETOWN, getpid())					||
	    fcntl(pipes[0], F_SETSIG, SIGIO)					||
	    fcntl(pipes[1], F_SETSIG, SIGIO)					||
	    fcntl(pipes[0], F_SETFL, fcntl(pipes[0], F_GETFL) | O_ASYNC)	||
	    fcntl(pipes[1], F_SETFL, fcntl(pipes[1], F_GETFL) | O_ASYNC)) {
		pr_err("fcntl failed\n");
		exit(1);
	}

	fill_pipe_params(shared, pipes);

	if (setresuid(-1, euid, -1)) {
		pr_perror("setresuid failed\n");
		exit(1);
	}

	pid = test_fork();
	if (pid < 0) {
		pr_perror("can't fork");
		exit(1);
	} else if (pid == 0) {
		struct params p = { };

		fcntl(pipes[1], F_SETOWN, getpid());
		fill_pipe_params(&p, pipes);

		if (write(pipes[1], &p, sizeof(p)) != sizeof(p)) {
			pr_perror("write failed\n");
			exit(1);
		}

		exit(0);
	}

	if (waitpid(pid, &status, P_ALL) == -1) {
		pr_perror("waitpid %d failed\n", pid);
		exit(1);
	}

#ifdef ZDTM_FILE_FOWN_REUSE
	cpid = reuse_pid(pid);
	if (cpid < 0)
		exit(1);
#endif

	test_daemon();
	test_waitsig();

	if (read(pipes[0], &obtained, sizeof(obtained)) != sizeof(obtained)) {
		fail("read failed\n");
		goto err;
	}

	if (shared->sigio < 1) {
		fail("shared->sigio = %d (> 0 expected)\n", shared->sigio);
		goto err;
	}

	shared->pipe_pid[1] = pid;

	if (cmp_pipe_params(shared, &obtained)) {
		fail("params comparison failed\n");
		goto err;
	}

	/*
	 * The F_SETOWN above operates on child which
	 * is already exited so in criu we should skip
	 * setting PID back and in result there must
	 * be a zero.
	 */
	obtained.pipe_pid[1] = 0;

	fill_pipe_params(shared, pipes);

	if (cmp_pipe_params(shared, &obtained)) {
		fail("params comparison failed\n");
		goto err;
	}

	close(fd);

#ifdef ZDTM_FILE_FOWN_REUSE
	kill(cpid, SIGKILL);
	wait(NULL);
#endif

	pass();
	return 0;
err:
#ifdef ZDTM_FILE_FOWN_REUSE
	kill(cpid, SIGKILL);
	wait(NULL);
#endif
	exit(1);
}
