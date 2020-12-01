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
#include "fs.h"

const char *test_doc    = "Check sysfs mounted from nested netns";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname = "netns_sysfs";
TEST_OPTION(dirname, string, "directory name", 1);

enum {
	FUTEX_INITIALIZED = 0,
	SYSFS_MOUNTED,
	TEST_FINISH,
	EMERGENCY_ABORT,
};

futex_t *futex;

#define NETNS_SYSFS_ZDTMBR "zdtmbr_sys"

static int netns_child(void *arg)
{
	char ip_cmd[64];
	char *path = (char *)arg;

	if (system("ip link set up dev lo")) {
		futex_set_and_wake(futex, EMERGENCY_ABORT);
		return 1;
	}

	snprintf(ip_cmd, sizeof(ip_cmd), "ip link add name %s type bridge",
		 NETNS_SYSFS_ZDTMBR);

	if (system(ip_cmd)) {
		pr_perror("Failed to create bridge in netns");
		futex_set_and_wake(futex, EMERGENCY_ABORT);
		return 1;
	}

	if (mount("zdtm_nested_netns_sysfs", path, "sysfs", 0, NULL)) {
		pr_perror("Failed to mount nested netns sysfs");
		futex_set_and_wake(futex, EMERGENCY_ABORT);
		return 1;
	}

	futex_set_and_wake(futex, SYSFS_MOUNTED);
	futex_wait_while_lt(futex, TEST_FINISH);
	return 0;
}

#define CLONE_STACK_SIZE 4096

int main(int argc, char **argv)
{
	char sysfs[PATH_MAX], sysfs_bridge[PATH_MAX];
	char stack[CLONE_STACK_SIZE] __stack_aligned__;
	int pid, status, ret = 1;

	test_init(argc, argv);
	futex = mmap(NULL, sizeof(*futex), PROT_WRITE | PROT_READ,
		     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (futex == MAP_FAILED) {
		pr_perror("Failed to mmap futex");
		return 1;
	}
	futex_init(futex);

	if (prepare_dirname(dirname))
		return 1;

	snprintf(sysfs, sizeof(sysfs), "%s/sysfs", dirname);
	if (mkdir(sysfs, 0700)) {
		pr_perror("Failed to create %s", sysfs);
		return 1;
	}

	pid = clone(netns_child, &stack[CLONE_STACK_SIZE],
		    CLONE_NEWNET | SIGCHLD, sysfs);
	if (pid == -1) {
		pr_perror("Failed to clone child with nested net namespace");
		return 1;
	}

	futex_wait_while_lt(futex, SYSFS_MOUNTED);
	if (futex_get(futex) == EMERGENCY_ABORT) {
		pr_err("Fail in child");
		goto err;
	}

	test_daemon();
	test_waitsig();

	snprintf(sysfs_bridge, sizeof(sysfs_bridge), "%s/sysfs/class/net/%s",
		 dirname, NETNS_SYSFS_ZDTMBR);

	if (access(sysfs_bridge, F_OK)) {
		fail("No %s", sysfs_bridge);
		goto err;
	}

	ret = 0;
err:
	futex_set_and_wake(futex, TEST_FINISH);
	waitpid(pid, &status, 0);
	munmap(futex, sizeof(*futex));

	if (!ret)
		pass();
	return ret;
}
