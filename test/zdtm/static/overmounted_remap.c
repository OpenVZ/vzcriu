#include <sched.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Check overmounted remap";
const char *test_author	= "Andrey Zhadchenko <andrey.zhadchenko@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

char *name1 = "testfile";
char *name2 = "testfile.link";

int main(int argc, char **argv)
{
	char path1[PATH_MAX], path2[PATH_MAX];
	int fd1 = -1, fd2 = -1, ret = 1;
	struct stat st1, st2;

	test_init(argc, argv);

	mkdir(dirname, 0755);

	ssprintf(path1, "%s/%s", dirname, name1);
	ssprintf(path2, "%s/%s", dirname, name2);

	fd1 = open(path1, O_RDWR | O_CREAT, 0666);
	if (fd1 < 0) {
		pr_perror("open");
		goto out_rm;
	}

	ret = link(path1, path2);
	if (ret < 0) {
		pr_perror("link");
		goto out_fd;
	}

	fd2 = open(path2, O_RDWR);
	if (fd1 < 0) {
		pr_perror("open");
		goto out_fd;
	}

	unlink(path2);

	if (mount("dummy1", dirname, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		goto out_fd;
	}

	test_daemon();
	test_waitsig();

	if (fstat(fd1, &st1) < 0) {
		pr_perror("fstat %d", fd1);
		goto out_umount;
	}

	if (fstat(fd2, &st2) < 0) {
		pr_perror("fstat %d", fd1);
		goto out_umount;
	}

	if (st1.st_ino == st2.st_ino) {
		pass();
		ret = 0;
	} else {
		fail("fd1 and fd2 inodes are different after c/r");
	}

out_umount:
	umount2(dirname, MNT_DETACH);
out_fd:
	close(fd2);
	close(fd1);
out_rm:
	unlink(path2);
	unlink(path1);
	rmdir(dirname);

	return ret;
}
