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

const char *test_doc	= "Check if we can c/r overmounted ghost";
const char *test_author	= "Andrey Zhadchenko <andrey.zhadchenko@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

char *name = "ghostfile";
#define TEST_STR "This file has some data"

int main(int argc, char **argv)
{
	char path[PATH_MAX], buf[sizeof(TEST_STR)];
	int fd, ret;

	test_init(argc, argv);

	mkdir(dirname, 0755);
	ssprintf(path, "%s/%s", dirname, name);

	fd = open(path, O_RDWR | O_CREAT, 0600);
	if (fd < 0) {
		pr_perror("open");
		return 1;
	}

	unlink(path);

	if (write(fd, TEST_STR, sizeof(TEST_STR)) != sizeof(TEST_STR)) {
		perror("write");
		goto out_rmdir;
	}

	if (mount("dummy1", dirname, "tmpfs", 0, NULL)) {
		pr_perror("mount");
		goto out_rmdir;
	}

	test_daemon();
	test_waitsig();

	if (lseek(fd, 0, SEEK_SET)) {
		pr_perror("lseek");
		goto out_umount;
	}

	if (read(fd, buf, sizeof(buf)) != sizeof(TEST_STR)) {
		pr_perror("read");
		goto out_umount;
	}

	if (strcmp(TEST_STR, buf)) {
		fail("ghost file content is corrupted");
		goto out_umount;
	}

	pass();
	ret = 0;

out_umount:
	umount2(dirname, MNT_DETACH);
	close(fd);
out_rmdir:
	rmdir(dirname);

	return ret;
}
