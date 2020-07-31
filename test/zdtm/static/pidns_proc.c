#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <linux/limits.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc = "Check procfs mounted from nested pidns";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname = "pidns_proc";
TEST_OPTION(dirname, string, "directory name", 1);

enum {
	FUTEX_INITIALIZED = 0,
	PROC_MOUNTED,
	TEST_FINISH,
	EMERGENCY_ABORT,
};

futex_t *futex;

static int pidns_child(void *arg)
{
	char *path = (char *)arg;

	if (mount("zdtm_nested_pidns_proc", path, "proc", 0, NULL)) {
		pr_perror("Failed to mount nested pidns proc");
		futex_set_and_wake(futex, EMERGENCY_ABORT);
		return 1;
	}

	futex_set_and_wake(futex, PROC_MOUNTED);
	futex_wait_while_lt(futex, TEST_FINISH);
	return 0;
}

/**
 * Prepare dirname, so that all mounts in it will not propagate and
 * will be destroyed together with our mount namespace. All files
 * created in it will not be visible on host and will remove together
 * with our mountns too.
 */
static int prepare_dirname(void)
{
	if (mkdir(dirname, 0700) && errno != EEXIST) {
		pr_perror("Failed to create %s", dirname);
		return -1;
	}

	if (mount("none", dirname, "tmpfs", 0, NULL)) {
		pr_perror("Failed to mount tmpfs on %s", dirname);
		return -1;
	}

	if (mount(NULL, dirname, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Failed to make mount %s private", dirname);
		return -1;
	}

	return 0;
}

static int bind_and_remount_ro(char *path)
{
	if (mount(path, path, NULL, MS_BIND, NULL)) {
		pr_perror("Failed to make %s bind", path);
		return -1;
	}

	if (mount(NULL, path, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL)) {
		pr_perror("Failed to make %s fs bind ro", path);
		return -1;
	}

	return 0;
}

static int check_ns_proc_differ(char *proca, char *procb)
{
	char bufa[PATH_MAX], bufb[PATH_MAX];
	int len;

	len = readlink(proca, bufa, sizeof(bufa) - 1);
	if (len == -1) {
		pr_perror("Failed to readlink %s", proca);
		return -1;
	}
	bufa[len] = '\0';

	len = readlink(procb, bufb, sizeof(bufb) - 1);
	if (len == -1) {
		pr_perror("Failed to readlink %s", procb);
		return -1;
	}
	bufb[len] = '\0';

	if (!strcmp(bufa, bufb)) {
		fail("Pid namespaces should be different");
		return -1;
	}

	return 0;
}

#define CLONE_STACK_SIZE 4096

int main(int argc, char **argv)
{
	char sibling[PATH_MAX], proc[PATH_MAX], proc_ns_pid[PATH_MAX];
	char fs_bind[PATH_MAX], sys_bind[PATH_MAX], sysrq_bind[PATH_MAX];
	char dir[PATH_MAX], dir_bind[PATH_MAX];
	char stack[CLONE_STACK_SIZE] __stack_aligned__;
	int pid, status, ret = 1;

	test_init(argc, argv);
	futex = mmap(NULL, sizeof(*futex), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (futex == MAP_FAILED) {
		pr_perror("Failed to mmap futex");
		return 1;
	}
	futex_init(futex);

	if (prepare_dirname())
		return 1;

	snprintf(sibling, sizeof(sibling), "%s/sibling", dirname);
	if (mkdir(sibling, 0700)) {
		pr_perror("Failed to create %s", sibling);
		return 1;
	}

	snprintf(proc, sizeof(proc), "%s/sibling/proc", dirname);
	if (mkdir(proc, 0700)) {
		pr_perror("Failed to create %s", proc);
		return 1;
	}

	pid = clone(pidns_child, &stack[CLONE_STACK_SIZE], CLONE_NEWPID | SIGCHLD, proc);
	if (pid == -1) {
		pr_perror("Failed to clone child with nested pid namespace");
		return 1;
	}

	futex_wait_while_lt(futex, PROC_MOUNTED);
	if (futex_get(futex) == EMERGENCY_ABORT) {
		pr_err("Fail in child\n");
		goto err;
	}

	snprintf(fs_bind, sizeof(fs_bind), "%s/sibling/proc/fs", dirname);
	if (bind_and_remount_ro(fs_bind))
		goto err;

	snprintf(sys_bind, sizeof(sys_bind), "%s/sibling/proc/sys", dirname);
	if (bind_and_remount_ro(sys_bind))
		goto err;

	snprintf(sysrq_bind, sizeof(sysrq_bind), "%s/sibling/proc/sysrq-trigger", dirname);
	if (bind_and_remount_ro(sysrq_bind))
		goto err;

	snprintf(dir, sizeof(dir), "%s/dir", dirname);
	if (mkdir(dir, 0700)) {
		pr_perror("Failed to create %s", dir);
		goto err;
	}

	snprintf(dir_bind, sizeof(dir_bind), "%s/sibling/proc/vz", dirname);
	if (mount(dir, dir_bind, NULL, MS_BIND, NULL)) {
		pr_perror("Failed to make %s bind to %s", dir, dir_bind);
		goto err;
	}

	if (mount("none", sibling, "tmpfs", 0, NULL)) {
		pr_perror("Failed to mount tmpfs on %s", sibling);
		goto err;
	}

	test_daemon();
	test_waitsig();

	if (umount(sibling)) {
		pr_perror("Failed to umount %s", sibling);
		goto err;
	}

	snprintf(proc_ns_pid, sizeof(proc_ns_pid), "%s/sibling/proc/1/ns/pid", dirname);
	if (check_ns_proc_differ("/proc/1/ns/pid", proc_ns_pid))
		goto err;

	ret = 0;
err:
	futex_set_and_wake(futex, TEST_FINISH);
	waitpid(pid, &status, 0);
	munmap(futex, sizeof(*futex));

	if (!ret)
		pass();
	return ret;
}
