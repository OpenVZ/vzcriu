#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>

#include "zdtmtst.h"

const char *test_doc = "Check if we can c/r fd from overmounted procfs";
const char *test_author = "Andrey Zhadchenko <andrey.zhadchenko@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char path[PATH_MAX];
	int fd, ret = -1;
#if defined(ZDTM_DEAD_PID_REMAP) || defined(ZDTM_DEAD_PID_REMAP_FILE)
	pid_t result, pid;
#endif

	test_init(argc, argv);

	mkdir(dirname, 0600);

	if (mount("none", dirname, "proc", 0, NULL) < 0) {
		pr_perror("mount() failed");
		return -1;
	}

#if defined(ZDTM_DEAD_PID_REMAP) || defined(ZDTM_DEAD_PID_REMAP_FILE)
	pid = fork();
	if (pid < 0) {
		fail("fork() failed");
		goto out_proc;
	}

	if (pid == 0) {
		/*
		 * Child process just sleeps until it is killed. All we need
		 * here is a process to open the mountinfo of.
		 */
		while (1)
			sleep(10);
	}
	test_msg("child is %d\n", pid);
#endif

#if defined(ZDTM_DEAD_PID_REMAP)
	ssprintf(path, "%s/%d", dirname, pid);
#elif defined(ZDTM_DEAD_PID_REMAP_FILE)
	ssprintf(path, "%s/%d/mountinfo", dirname, pid);
#else
	ssprintf(path, "%s/self", dirname);
#endif

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fail("failed to open fd");
		goto out_proc;
	}

#if defined(ZDTM_DEAD_PID_REMAP) || defined(ZDTM_DEAD_PID_REMAP_FILE)
	kill(pid, SIGKILL);
	result = waitpid(pid, NULL, 0);
	if (result < 0) {
		fail("failed waitpid()");
		goto out_fd;
	}
#endif

	if (mount("dummy1", dirname, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		goto out_fd;
	}

	test_daemon();
	test_waitsig();

	ret = fcntl(fd, F_GETFD);
	close(fd);

	if (ret) {
		fail("bad fd after restore");
		goto out_ovm;
	}

	pass();
	ret = 0;

out_ovm:
	umount2(dirname, MNT_DETACH);
out_fd:
	close(fd);
out_proc:
	umount2(dirname, MNT_DETACH);
	return ret;
}
