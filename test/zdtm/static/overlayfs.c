#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <linux/limits.h>

#include "zdtmtst.h"
#include "fs.h"

const char *test_doc    = "Check overlayfs mounts";
const char *test_author = "Alexander Mikhalitsyn <alexander.mikhalitsyn@virtuozzo.com>";
// and Pavel Tikhomirov <ptikhomirov@virtuozzo.com>

char *dirname = "overlayfs_mount";
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_WORD	"testtest"
#define TEST_WORD2	"TESTTEST"

static int create_test_file(const char *dirpath, const char *buf, size_t size)
{
	int fdo;
	char fname[PATH_MAX];

	snprintf(fname, PATH_MAX, "%s/test.file", dirpath);
	fdo = open(fname, O_RDWR | O_CREAT, 0644);
	if (fdo < 0) {
		pr_perror("open failed");
		return 1;
	}

	if (write(fdo, buf, size) != size) {
		pr_perror("write() failed");
		close(fdo);
		return 1;
	}

	close(fdo);
	return 0;
}

static int check_test_file(const char *prefixdir)
{
	int fdo;
	char fname[PATH_MAX],
             buf[1024];

	ssprintf(fname, "%s/%s/overlayfs/test.file", dirname, prefixdir);
	fdo = open(fname, O_RDONLY, 0644);
	if (fdo < 0) {
		pr_perror("open failed");
		return 1;
	}

	buf[sizeof(TEST_WORD) + 1] = '\0';
	if (read(fdo, buf, sizeof(TEST_WORD)) != sizeof(TEST_WORD)) {
		fail("Read failed");
		close(fdo);
		return 1;
	}
	close(fdo);

	if (strcmp(buf, TEST_WORD)) {
		fail("File corrupted");
		return 1;
	}

	return 0;
}

/* overlayfs mount without upperdir */
static int create_overlayfs_mount_ro(const char *prefixdir)
{
	const char *lower_list[] = { "lower0", "lower1", NULL };
	char dir[PATH_MAX],
	     lowerdir1[PATH_MAX],
	     lowerdir2[PATH_MAX];

	snprintf(dir, PATH_MAX, "%s/%s", dirname, prefixdir);
	snprintf(lowerdir1, PATH_MAX, "%s/%s", dir, lower_list[0]);
	snprintf(lowerdir2, PATH_MAX, "%s/%s", dir, lower_list[1]);

	mkdir(dir, 0700);

	if (overlayfs_setup(dir, lower_list, NULL, NULL, "overlayfs")) {
		fail("failed to setup overlayfs for %s test", prefixdir);
		return 1;
	}

	/*
	 * Creating files on two lower layers with the same name,
	 * in result mount we should see the file from the lowest
	 * layer.
	 */
	if (create_test_file(lowerdir1, TEST_WORD, sizeof(TEST_WORD)))
		return 1;
	if (create_test_file(lowerdir2, TEST_WORD2, sizeof(TEST_WORD2)))
		return 1;

	return 0;
}

/* overlayfs mount with upperdir (as docker uses) */
static int create_overlayfs_mount_rw(const char *prefixdir)
{
	const char *lower_list[] = { "lower0", "lower1", NULL };
	const char *upper = "upper";
	char dir[PATH_MAX],
	     upperdir[PATH_MAX],
	     lowerdir2[PATH_MAX];

	snprintf(dir, PATH_MAX, "%s/%s", dirname, prefixdir);
	snprintf(upperdir, PATH_MAX, "%s/%s", dir, upper);
	snprintf(lowerdir2, PATH_MAX, "%s/%s", dir, lower_list[1]);
	mkdir(dir, 0700);

	if (overlayfs_setup(dir, lower_list, upper, "work", "overlayfs")) {
		fail("failed to setup overlayfs for %s test", prefixdir);
		return 1;
	}

	/*
	 * Creating files on two lower layers with the same name,
	 * in result mount we should see the file from upper
	 * layer.
	 */
	if (create_test_file(upperdir, TEST_WORD, sizeof(TEST_WORD)))
		return 1;
	if (create_test_file(lowerdir2, TEST_WORD2, sizeof(TEST_WORD2)))
		return 1;

	return 0;
}

/* overlayfs mount with overmounted source dirs */
static int create_overlayfs_mount_overmount(const char *prefixdir)
{
	const char *lower_list[] = { "tmp/lower1", "lower2", NULL };
	char dir[PATH_MAX],
	     lowerdir1[PATH_MAX];

	snprintf(dir, PATH_MAX, "%s/%s", dirname, prefixdir);
	snprintf(lowerdir1, PATH_MAX, "%s/%s", dir, lower_list[0]);

	mkdir(dir, 0700);

	if (overlayfs_setup(dir, lower_list, NULL, NULL, "overlayfs")) {
		fail("failed to setup overlayfs for %s test", prefixdir);
		return 1;
	}

	/*
	 * Creating first file on the lowest layer, after overmount
	 * the lowest layer path, and create second file on overmounted
	 * path. We should see first file (overlayfs must be mounted
	 * before lowerest layer path will be overmounted).
	 */
	if (create_test_file(lowerdir1, TEST_WORD, sizeof(TEST_WORD)))
		return 1;

	/*
	 * Let's mount tmpfs on lowerdir
	 */
	if (mount("none", lowerdir1, "tmpfs", 0, NULL)) {
		pr_perror("Failed to mount tmpfs on %s", lowerdir1);
		return 1;
	}

	if (mount(NULL, lowerdir1, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Failed to make mount %s private", lowerdir1);
		return 1;
	}

	if (create_test_file(lowerdir1, TEST_WORD2, sizeof(TEST_WORD2)))
		return 1;

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 1;

	test_init(argc, argv);

	if (prepare_dirname(dirname))
		return 1;

	if (create_overlayfs_mount_ro("ro"))
		goto err;
	if (create_overlayfs_mount_rw("rw"))
		goto err;
	if (create_overlayfs_mount_overmount("om"))
		goto err;

	test_daemon();
	test_waitsig();

	if (check_test_file("ro"))
		goto err;
	if (check_test_file("rw"))
		goto err;
	if (check_test_file("om"))
		goto err;

	pass();
	ret = 0;
err:
	return ret;
}
