#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>

#include <sys/mount.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>

#include "zdtmtst.h"

#ifndef CLONE_NEWNS
#define CLONE_NEWNS     0x00020000
#endif

const char *test_doc	= "Check the restore of bindmounts with deleted sources those nested";
const char *test_author	= "Alexander Mikhalitsyn <alexander.mikhalitsyn@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_DIR_SRC2	"test-src2"
#define TEST_DIR_SRC1	"test-src1"
#define TEST_DIR_DST1	"test-dst1"
#define TEST_DIR_DST2	"test-dst2"

int main(int argc, char *argv[])
{
	char path_src1[PATH_MAX], path_src2[PATH_MAX],
	     path_dst1[PATH_MAX], path_dst2[PATH_MAX];

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir %s", dirname);
		exit(1);
	}

	if (mount("none", dirname, "tmpfs", MS_MGC_VAL, NULL)) {
		pr_perror("mount %s", dirname);
		return 1;
	}

	snprintf(path_src1, sizeof(path_src1), "%s/%s", dirname, TEST_DIR_SRC1);
	snprintf(path_src2, sizeof(path_src2), "%s/%s/%s", dirname, TEST_DIR_SRC1, TEST_DIR_SRC2);
	snprintf(path_dst1, sizeof(path_dst1), "%s/%s", dirname, TEST_DIR_DST1);
	snprintf(path_dst2, sizeof(path_dst2), "%s/%s", dirname, TEST_DIR_DST2);

	if (mkdir(path_src1, 0700) ||
	    mkdir(path_src2, 0700) ||
	    mkdir(path_dst1, 0700) ||
	    mkdir(path_dst2, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if (mount(path_src2, path_dst2, NULL, MS_BIND | MS_MGC_VAL, NULL)) {
		pr_perror("mount %s -> %s", path_src2, path_dst2);
		return 1;
	}

	if (mount(path_src1, path_dst1, NULL, MS_BIND | MS_MGC_VAL, NULL)) {
		pr_perror("mount %s -> %s", path_src1, path_dst1);
		return 1;
	}

	if (rmdir(path_src2)) {
		pr_perror("rmdir %s", path_src2);
		return 1;
	}

	if (rmdir(path_src1)) {
		pr_perror("rmdir %s", path_src1);
		return 1;
	}

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
