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

const char *test_doc	= "Check multiple bind-mounts with unix socket";
const char *test_author	= "Alexander Mikhalitsyn <alexander@mihalicyn.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define BINDS_NUM 3

static inline pid_t forkwrite(char path_bind[BINDS_NUM][PATH_MAX], int idx, task_waiter_t t, int sk)
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
		skc = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (skc < 0) {
			pr_perror("Can't create client socket");
			goto err1;
		}

		addr.sun_family = AF_UNIX;
		sstrncpy(addr.sun_path, path_bind[idx]);
		addrlen = sizeof(addr.sun_family) + strlen(path_bind[idx]);

		ret = connect(skc, (struct sockaddr *)&addr, addrlen);
		if (ret) {
			pr_perror("Can't connect\n");
			goto err1;
		} else
			test_msg("Connected to %s\n", addr.sun_path);

		task_waiter_complete(&t, 1);
		task_waiter_wait4(&t, 2);

		ret = sendto(skc, "111", 3, 0, (struct sockaddr *)&addr, addrlen);
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

int main(int argc, char **argv)
{
	char path_unix[PATH_MAX], path_bind[BINDS_NUM][PATH_MAX];
	char unix_name[] = "criu-log";
	char bind_name[] = "criu-bind-log";
	int sk = -1, ret = 1, fd, k;
	struct sockaddr_un addr;
	unsigned int addrlen;
	task_waiter_t t[BINDS_NUM];
	struct stat st;
	int status;
	pid_t pids[BINDS_NUM];

	char buf[] =  "1111111111111111111111111111111111";
	char rbuf[] = "9999999999999999999999999999999999";

	test_init(argc, argv);

#ifdef ZDTM_BM_UNIX_MULT_SUBMNTNS
	if (unshare(CLONE_NEWNS)) {
		pr_perror("Unable to create a new mntns");
		return 1;
	}
#endif

	for (k = 0; k < BINDS_NUM; k++)
		task_waiter_init(&t[k]);

	if (prepare_dirname(dirname))
		return 1;

	for (k = 0; k < BINDS_NUM; k++)
		ssprintf(path_bind[k], "%s/%s%d", dirname, bind_name, k);

	ssprintf(path_unix, "%s/%s", dirname, unix_name);

	for (k = 0; k < BINDS_NUM; k++) {
		fd = open(path_bind[k], O_RDONLY | O_CREAT);
		if (fd < 0) {
			pr_perror("Can't open %s", path_bind[k]);
			return 1;
		}
		close(fd);
	}

	addr.sun_family = AF_UNIX;
	sstrncpy(addr.sun_path, path_unix);
	addrlen = sizeof(addr.sun_family) + strlen(path_unix);

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("Can't create socket %s", path_unix);
		return 1;
	}

	ret = bind(sk, (struct sockaddr *)&addr, addrlen);
	if (ret) {
		pr_perror("Can't bind socket %s", path_unix);
		return 1;
	}

	if (stat(path_unix, &st) == 0) {
		test_msg("path %s st.st_dev %#x st.st_rdev %#x st.st_ino %#lx st.st_mode 0%o (sock %d)\n",
			 path_unix, (int)st.st_dev, (int)st.st_rdev, (unsigned long)st.st_ino,
			 (int)st.st_mode, !!S_ISSOCK(st.st_mode));
	} else {
		pr_perror("Can't stat on %s", path_unix);
		return 1;
	}

	for (k = 0; k < BINDS_NUM; k++) {
		if (mount(path_unix, path_bind[k], NULL, MS_BIND, NULL)) {
			pr_perror("Unable to bindmount %s -> %s", path_unix, path_bind[k]);
			return 1;
		}

		if (stat(path_bind[k], &st) == 0) {
			test_msg("path %s st.st_dev %#x st.st_rdev %#x st.st_ino %#lx st.st_mode 0%o (sock %d)\n",
				path_bind[k], (int)st.st_dev, (int)st.st_rdev, (unsigned long)st.st_ino,
				(int)st.st_mode, !!S_ISSOCK(st.st_mode));
		} else {
			pr_perror("Can't stat on %s", path_bind[k]);
			return 1;
		}
	}

	for (k = 0; k < BINDS_NUM; k++)
		pids[k] = forkwrite(path_bind, k, t[k], sk);

	test_daemon();
	test_waitsig();

	for (k = 0; k < BINDS_NUM; k++)
		task_waiter_complete(&t[k], 2);

	for (k = 0; k < BINDS_NUM; k++) {
		ret = read(sk, rbuf+3*k, 3);
		if (ret < 0) {
			fail("Can't read data");
			goto err;
		}
	}

	if (memcmp(buf, rbuf, 3*BINDS_NUM)) {
		fail("Data mismatch %s -> %s", buf, rbuf);
		goto err;
	}

	for (k = 0; k < BINDS_NUM; k++) {
		ret = waitpid(pids[k], &status, 0);
		if (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
			kill(pids[k], SIGKILL);
			fail("Unable to wait child");
			goto err;
		}
	}

	ret = 0;
	pass();

err:
	umount2(dirname, MNT_DETACH);
	close(sk);

	return ret ? 1 : 0;
}
