#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check cleanup order of ghost directory and files inside";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char ** argv)
{
	int fds[4], dirfd1, dirfd2, i, len;
	char path_dir1[PATH_MAX];
	char path_dir2[PATH_MAX];
	char path[PATH_MAX];

	int lo = ARRAY_SIZE(fds) / 2;
	int hi = ARRAY_SIZE(fds);

	test_init(argc, argv);

	if (mkdir(dirname, 0700) < 0) {
		pr_perror("Can't create directory %s", dirname);
		return 1;
	}

	len = snprintf(path_dir1, sizeof(path_dir1), "%s/%s", dirname, "gd1");
	if (len == sizeof(path_dir1)) path_dir1[len-1] = '\0';
	if (mkdir(path_dir1, 0700) < 0) {
		pr_perror("Can't create directory %s", path_dir1);
		return 1;
	}

	len = snprintf(path_dir2, sizeof(path_dir2), "%s/%s/%s", dirname, "gd1", "gd2");
	if (len == sizeof(path_dir2)) path_dir2[len-1] = '\0';
	if (mkdir(path_dir2, 0700) < 0) {
		pr_perror("Can't create directory %s", path_dir2);
		return 1;
	}

	for (i = 0; i < lo; i++) {
		len = snprintf(path, sizeof(path), "%s/%d", path_dir1, i);
		if (len == sizeof(path)) path[len-1] = '\0';
		fds[i] = open(path, O_RDONLY | O_CREAT | O_TRUNC);
		if (fds[i] < 0) {
			pr_perror("Can't open %s", path);
			return 1;
		}
		if (unlink(path)) {
			pr_perror("Can't unlink %s", path);
			return 1;
		}
	}

	dirfd2 = open(path_dir2, O_RDONLY | O_DIRECTORY);
	if (dirfd2 < 0) {
		pr_perror("Can't open %s", path_dir2);
		return 1;
	}

	for (i = lo; i < hi; i++) {
		len = snprintf(path, sizeof(path), "%s/%d", path_dir2, i);
		if (len == sizeof(path)) path[len-1] = '\0';
		fds[i] = open(path, O_RDONLY | O_CREAT | O_TRUNC);
		if (fds[i] < 0) {
			pr_perror("Can't open %s", path);
			return 1;
		}
		if (unlink(path)) {
			pr_perror("Can't unlink %s", path);
			return 1;
		}
	}

	dirfd1 = open(path_dir1, O_RDONLY | O_DIRECTORY);
	if (dirfd1 < 0) {
		pr_perror("Can't open %s", path_dir1);
		return 1;
	}

	if (rmdir(path_dir2)) {
		pr_perror("Can't rmdir %s", path_dir2);
		return 1;
	}

	if (rmdir(path_dir1)) {
		pr_perror("Can't rmdir %s", path_dir1);
		return 1;
	}

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
