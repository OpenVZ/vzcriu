#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <linux/limits.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc = "Check c/r simple tunnel using vxlan";
const char *test_author = "Alexander Mikhalitsyn <alexander@mihalicyn.com>";

enum {
	FUTEX_INITIALIZED = 0,
	CHILD_READY,
	DEVICES_READY,
	CHILD_DO_CR,
	CHILD_AFTER_CR,
	TEST_FINISH,
	EMERGENCY_ABORT,
};

futex_t *futex;

#define EXEC_CMD(cmdfmt, arg...)                           \
	do {                                               \
		snprintf(cmd, sizeof(cmd), cmdfmt, ##arg); \
		if (system(cmd)) {                         \
			pr_err("FAILED: %s\n", cmd);       \
			goto err;                          \
		}                                          \
	} while (0)

#define EXEC_CHILD_CMD(cmdfmt, arg...)                              \
	do {                                                        \
		snprintf(cmd, sizeof(cmd), cmdfmt, ##arg);          \
		if (system(cmd)) {                                  \
			pr_err("FAILED: %s\n", cmd);                \
			futex_set_and_wake(futex, EMERGENCY_ABORT); \
			return 1;                                   \
		}                                                   \
	} while (0)

static int netns_child(void *arg)
{
	char cmd[128];

	futex_set_and_wake(futex, CHILD_READY);
	futex_wait_while_lt(futex, DEVICES_READY);

	/* setup veth connectivity */
	EXEC_CHILD_CMD("ip addr add 172.31.0.2/24 dev veth2");
	EXEC_CHILD_CMD("ip link set veth2 up");

	/* setup vxlan2 */
	EXEC_CHILD_CMD("ip link add vxlan2 type vxlan id 1 remote 172.31.0.1 dstport 3333 dev veth2");
	EXEC_CHILD_CMD("ip link set vxlan2 up");
	EXEC_CHILD_CMD("ip addr add 10.0.0.2/24 dev vxlan2");

	EXEC_CHILD_CMD("ip -d link show vxlan2");

	/* we are ready to C/R */
	futex_set_and_wake(futex, CHILD_DO_CR);
	futex_wait_while_lt(futex, CHILD_AFTER_CR);

	EXEC_CHILD_CMD("ip -d link show vxlan2");

	futex_wait_while_lt(futex, TEST_FINISH);
	return 0;
}

#define CLONE_STACK_SIZE 4096

int main(int argc, char **argv)
{
	char cmd[128];
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

	pid = clone(netns_child, &stack[CLONE_STACK_SIZE],
		    CLONE_NEWNET | SIGCHLD, NULL);
	if (pid == -1) {
		pr_perror("Failed to clone child with nested net namespace");
		return 1;
	}

	futex_wait_while_lt(futex, CHILD_READY);

	/*
	 * Test plan is simple:
	 * two net namespaces, veth-pair to connect this namespaces,
	 * in each netns one vxlan device with incapsulates traffic
	 * in UDP packets that transmits through veth.
	 */

	/* create veth pair to connect two net namespaces */
	EXEC_CMD("ip link add veth1 type veth peer name veth2");

	/* move second peer to second netns */
	EXEC_CMD("ip link set veth2 netns %d", pid);

	/* setup veth1 */
	EXEC_CMD("ip addr add 172.31.0.1/24 dev veth1");
	EXEC_CMD("ip link set veth1 up");

	/* vxlan1 setup */
	EXEC_CMD("ip link add vxlan1 type vxlan id 1 remote 172.31.0.2 dstport 3333 dev veth1");
	EXEC_CMD("ip addr add 10.0.0.1/24 dev vxlan1");
	EXEC_CMD("ip link set vxlan1 up");

	system("ip -d link show vxlan1");

	futex_set_and_wake(futex, DEVICES_READY);

	futex_wait_while_lt(futex, CHILD_DO_CR);
	if (futex_get(futex) == EMERGENCY_ABORT) {
		pr_err("Fail in child\n");
		goto err;
	}

	test_daemon();
	test_waitsig();

	futex_set_and_wake(futex, CHILD_AFTER_CR);
	EXEC_CMD("ip -d link show vxlan1");

	/* check veth connectivity */
	snprintf(cmd, sizeof(cmd), "ping -c 1 -W 2 172.31.0.2");
	if (system(cmd)) {
		fail("FAILED: %s", cmd);
		goto err;
	}

	/* check vxlan connectivity */
	snprintf(cmd, sizeof(cmd), "ping -c 1 -W 2 10.0.0.2");
	if (system(cmd)) {
		fail("FAILED: %s", cmd);
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
