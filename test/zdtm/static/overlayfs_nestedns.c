#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/mman.h>

#include "zdtmtst.h"
#include "lock.h"
#include "fs.h"

const char *test_doc = "Check overlayfs mounts in nested mntns";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname = "overlayfs_mount";
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_WORD  "testtest"
#define TEST_WORD2 "TESTTEST"

enum {
	FUTEX_INITIALIZED = 0,
	OVERLAYFS_MOUNTED,
	OVERLAYFS_CHECK,
	OVERLAYFS_CHECK_OK,
	EMERGENCY_ABORT,
};

futex_t *futex;

static int create_test_file(const char *dirpath, const char *buf, size_t size)
{
	int fdo;
	char fname[PATH_MAX];

	ssprintf(fname, "%s/test.file", dirpath);
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
	char fname[PATH_MAX], buf[1024];

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
	char dir[PATH_MAX], lowerdir1[PATH_MAX], lowerdir2[PATH_MAX];

	ssprintf(dir, "%s/%s", dirname, prefixdir);
	ssprintf(lowerdir1, "%s/%s", dir, lower_list[0]);
	ssprintf(lowerdir2, "%s/%s", dir, lower_list[1]);

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
	char dir[PATH_MAX], upperdir[PATH_MAX], lowerdir2[PATH_MAX];

	ssprintf(dir, "%s/%s", dirname, prefixdir);
	ssprintf(upperdir, "%s/%s", dir, upper);
	ssprintf(lowerdir2, "%s/%s", dir, lower_list[1]);
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
	char dir[PATH_MAX], lowerdir1[PATH_MAX];

	ssprintf(dir, "%s/%s", dirname, prefixdir);
	ssprintf(lowerdir1, "%s/%s", dir, lower_list[0]);

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

int overlayfs_child(void)
{
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);

	if (unshare(CLONE_NEWNS)) {
		pr_perror("unshare");
		goto err;
	}

	if (prepare_dirname(dirname))
		goto err;

	if (create_overlayfs_mount_ro("ro"))
		goto err;
	if (create_overlayfs_mount_rw("rw"))
		goto err;
	if (create_overlayfs_mount_overmount("om"))
		goto err;

	futex_set_and_wake(futex, OVERLAYFS_MOUNTED);
	futex_wait_while_lt(futex, OVERLAYFS_CHECK);
	if (futex_get(futex) == EMERGENCY_ABORT) {
		pr_err("Fail in parent\n");
		return 1;
	}

	if (check_test_file("ro"))
		goto err;
	if (check_test_file("rw"))
		goto err;
	if (check_test_file("om"))
		goto err;

	futex_set_and_wake(futex, OVERLAYFS_CHECK_OK);
	return 0;
err:
	futex_set_and_wake(futex, EMERGENCY_ABORT);
	return 1;
}

int main(int argc, char **argv)
{
	pid_t pid;

	test_init(argc, argv);

	futex = mmap(NULL, sizeof(*futex), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (futex == MAP_FAILED) {
		pr_perror("Failed to mmap futex");
		return 1;
	}
	futex_init(futex);

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}
	if (pid == 0)
		exit(overlayfs_child());

	futex_wait_while_lt(futex, OVERLAYFS_MOUNTED);
	if (futex_get(futex) == EMERGENCY_ABORT) {
		pr_err("Fail in child\n");
		return 1;
	}

	test_daemon();
	test_waitsig();

	futex_set_and_wake(futex, OVERLAYFS_CHECK);
	futex_wait_while_lt(futex, OVERLAYFS_CHECK_OK);
	if (futex_get(futex) == EMERGENCY_ABORT) {
		pr_err("Fail in child\n");
		return 1;
	}

	waitpid(pid, NULL, 0);
	pass();
	return 0;
}
