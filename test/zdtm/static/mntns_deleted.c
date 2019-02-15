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

const char *test_doc	= "Check the restore of deleted bindmounts";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_DIR_SRC	"test-src"
#define TEST_DIR_MID	"test-mid"
#define TEST_DIR_DST	"test-dst"

#define TEST_FILE_SRC	"mntns-deleted-src"
#define TEST_FILE_DST	"mntns-deleted-dst"

int main(int argc, char *argv[])
{
	char path_mid[PATH_MAX], path_src[PATH_MAX], path_dst[PATH_MAX];
	char path_dst_file[PATH_MAX], path_src_file[PATH_MAX];
	int fd1, fd2;

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir %s", dirname);
		exit(1);
	}

	if (mount("none", dirname, "tmpfs", MS_MGC_VAL, NULL)) {
		pr_perror("mount %s", dirname);
		return 1;
	}

	snprintf(path_mid, sizeof(path_mid), "%s/%s", dirname, TEST_DIR_MID);
	snprintf(path_src, sizeof(path_src), "%s/%s/%s", dirname, TEST_DIR_MID, TEST_DIR_SRC);
	snprintf(path_dst, sizeof(path_dst), "%s/%s", dirname, TEST_DIR_DST);
	snprintf(path_src_file, sizeof(path_src_file), "%s/%s/%s", dirname, TEST_DIR_MID, TEST_FILE_SRC);
	snprintf(path_dst_file, sizeof(path_dst_file), "%s/%s", dirname, TEST_FILE_DST);

	rmdir(path_src);
	rmdir(path_dst);

	unlink(path_src_file);
	unlink(path_dst_file);

	rmdir(path_mid);

	if (mkdir(path_mid, 0700) ||
	    mkdir(path_src, 0700) ||
	    mkdir(path_dst, 0700)) {
		pr_perror("mkdir");
		return 1;
	}

	if ((fd1 = open(path_src_file, O_WRONLY | O_CREAT | O_TRUNC, 0600) < 0)) {
		pr_perror("touching %s", path_src_file);
		return 1;
	}
	close(fd1);

	if ((fd2 = open(path_dst_file, O_WRONLY | O_CREAT | O_TRUNC, 0600) < 0)) {
		pr_perror("touching %s", path_dst_file);
		return 1;
	}
	close(fd2);

	if (mount(path_src, path_dst, NULL, MS_BIND | MS_MGC_VAL, NULL)) {
		pr_perror("mount %s -> %s", path_src, path_dst);
		return 1;
	}

	if (mount(path_src_file, path_dst_file, NULL, MS_BIND | MS_MGC_VAL, NULL)) {
		pr_perror("mount %s -> %s", path_src_file, path_dst_file);
		return 1;
	}

	if (rmdir(path_src)) {
		pr_perror("rmdir %s", path_src);
		return 1;
	}

	if (unlink(path_src_file)) {
		pr_perror("unlink %s", path_src_file);
		return 1;
	}

	if (rmdir(path_mid)) {
		pr_perror("rmdir %s", path_mid);
		return 1;
	}

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
