#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <linux/limits.h>
#include <signal.h>

#include "zdtmtst.h"
#include "fs.h"

const char *test_doc	= "Check multiple bind-mounts of unix socket (dgram, stream, seqpacket)";
const char *test_author	= "Alexander Mikhalitsyn <alexander@mihalicyn.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#ifdef ZDTM_BM_UNIX_MULT_STREAM
#define SOCK_TYPE SOCK_STREAM
#endif

#ifdef ZDTM_BM_UNIX_MULT_SEQPACKET
#define SOCK_TYPE SOCK_SEQPACKET
#endif

#ifndef SOCK_TYPE
#define SOCK_TYPE SOCK_DGRAM
#endif

#define BINDS_NUM 3

static inline pid_t forkwrite(char *path_bind, task_waiter_t t, int sk)
{
	int skc, ret = 1;
	pid_t pid;
	struct sockaddr_un addr;
	unsigned int addrlen;

	pid = test_fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		_exit(1);
	} else if (pid == 0) {
		skc = socket(AF_UNIX, SOCK_TYPE, 0);
		if (skc < 0) {
			pr_perror("Can't create client socket");
			goto err1;
		}

		addr.sun_family = AF_UNIX;
		sstrncpy(addr.sun_path, path_bind);
		addrlen = sizeof(addr.sun_family) + strlen(path_bind);

		ret = connect(skc, (struct sockaddr *)&addr, addrlen);
		if (ret) {
			pr_perror("Can't connect\n");
			goto err1;
		} else
			test_msg("Connected to %s\n", addr.sun_path);

		task_waiter_complete(&t, 1);
		task_waiter_wait4(&t, 2);

		ret = send(skc, "111", 3, 0);
		if (ret != (int)3) {
			pr_perror("Can't send data on client");
			goto err1;
		}

		close(skc);

		_exit(0);

err1:
		kill(getppid(), SIGKILL);
		_exit(1);
	}

	task_waiter_wait4(&t, 1);
	return pid;
}

struct task_data {
	char path_bind[PATH_MAX];
	task_waiter_t waiter;
	pid_t pid;
	int csk; /* socket to read on check */
};

int main(int argc, char **argv)
{
	char path_unix[PATH_MAX];
	char unix_name[] = "criu-log";
	char bind_name[] = "criu-bind-log";
	int sk = -1, ret = 1, fd, k;
	struct sockaddr_un addr;
	unsigned int addrlen;
	struct stat st;
	int status;
	struct task_data task[BINDS_NUM];

	char buf[] =  "1111111111111111111111111111111111";
	char rbuf[] = "9999999999999999999999999999999999";

	test_init(argc, argv);

	for (k = 0; k < BINDS_NUM; k++) {
		task[k].csk = -1;
		task[k].pid = -1;
		task_waiter_init(&task[k].waiter);
	}

#ifdef ZDTM_BM_UNIX_MULT_SUBMNTNS
	if (unshare(CLONE_NEWNS)) {
		pr_perror("Unable to create a new mntns");
		goto err;
	}
#endif

	if (prepare_dirname(dirname))
		goto err;

	for (k = 0; k < BINDS_NUM; k++)
		ssprintf(task[k].path_bind, "%s/%s%d", dirname, bind_name, k);

	ssprintf(path_unix, "%s/%s", dirname, unix_name);

	for (k = 0; k < BINDS_NUM; k++) {
		fd = open(task[k].path_bind, O_RDONLY | O_CREAT);
		if (fd < 0) {
			pr_perror("Can't open %s", task[k].path_bind);
			goto err;
		}
		close(fd);
	}

	addr.sun_family = AF_UNIX;
	sstrncpy(addr.sun_path, path_unix);
	addrlen = sizeof(addr.sun_family) + strlen(path_unix);

	sk = socket(AF_UNIX, SOCK_TYPE, 0);
	if (sk < 0) {
		pr_perror("Can't create socket %s", path_unix);
		goto err;
	}

	ret = bind(sk, (struct sockaddr *)&addr, addrlen);
	if (ret) {
		pr_perror("Can't bind socket %s", path_unix);
		goto err;
	}

#if defined(ZDTM_BM_UNIX_MULT_STREAM) || defined(ZDTM_BM_UNIX_MULT_SEQPACKET)
	ret = listen(sk, BINDS_NUM);
	if (ret) {
		pr_perror("can't listen on a socket %s", path_unix);
		goto err;
	}
#endif

	if (stat(path_unix, &st) == 0) {
		test_msg("path %s st.st_dev %#x st.st_rdev %#x st.st_ino %#lx st.st_mode 0%o (sock %d)\n",
			 path_unix, (int)st.st_dev, (int)st.st_rdev, (unsigned long)st.st_ino,
			 (int)st.st_mode, !!S_ISSOCK(st.st_mode));
	} else {
		pr_perror("Can't stat on %s", path_unix);
		goto err;
	}

	for (k = 0; k < BINDS_NUM; k++) {
		if (mount(path_unix, task[k].path_bind, NULL, MS_BIND, NULL)) {
			pr_perror("Unable to bindmount %s -> %s", path_unix, task[k].path_bind);
			goto err;
		}

		if (stat(task[k].path_bind, &st) == 0) {
			test_msg("path %s st.st_dev %#x st.st_rdev %#x st.st_ino %#lx st.st_mode 0%o (sock %d)\n",
				task[k].path_bind, (int)st.st_dev, (int)st.st_rdev, (unsigned long)st.st_ino,
				(int)st.st_mode, !!S_ISSOCK(st.st_mode));
		} else {
			pr_perror("Can't stat on %s", task[k].path_bind);
			goto err;
		}
	}

	for (k = 0; k < BINDS_NUM; k++)
		task[k].pid = forkwrite(task[k].path_bind, task[k].waiter, sk);

#if defined(ZDTM_BM_UNIX_MULT_STREAM) || defined(ZDTM_BM_UNIX_MULT_SEQPACKET)
	for (k = 0; k < BINDS_NUM; k++) {
		task[k].csk = accept(sk, NULL, NULL);
		if (task[k].csk < 0) {
			pr_perror("accept() failed");
			goto err;
		}
	}
#else
	/*
	 * For DGRAM socket we will just read datagrams from
	 * one socket. There is no term "connection socket" here.
	 */
	for (k = 0; k < BINDS_NUM; k++)
		task[k].csk = sk;
#endif

	test_daemon();
	test_waitsig();

	for (k = 0; k < BINDS_NUM; k++)
		task_waiter_complete(&task[k].waiter, 2);

	for (k = 0; k < BINDS_NUM; k++) {
		ret = recv(task[k].csk, rbuf+3*k, 3, 0);
		if (ret < 0) {
			fail("Can't recv data");
			goto err;
		}
	}

	if (memcmp(buf, rbuf, 3*BINDS_NUM)) {
		fail("Data mismatch %s -> %s", buf, rbuf);
		goto err;
	}

	for (k = 0; k < BINDS_NUM; k++) {
		ret = waitpid(task[k].pid, &status, 0);
		if (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
			kill(task[k].pid, SIGKILL);
			fail("Unable to wait child");
			goto err;
		}
	}

	ret = 0;
	pass();

err:
	umount2(dirname, MNT_DETACH);
	close(sk);

#if defined(ZDTM_BM_UNIX_MULT_STREAM) || defined(ZDTM_BM_UNIX_MULT_SEQPACKET)
	for (k = 0; k < BINDS_NUM; k++) {
		if (task[k].csk > 0)
			close(task[k].csk);
	}
#endif

	if (ret)
		fail();

	return ret ? 1 : 0;
}
