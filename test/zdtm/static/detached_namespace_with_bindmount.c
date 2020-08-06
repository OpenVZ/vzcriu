#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <linux/limits.h>
#include <sys/mman.h>

#include "zdtmtst.h"
#include "lock.h"
#include "fs.h"

const char *test_doc    = "Check detached namespace held by bindmount";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname = "detached_namespace_with_bindmount";
TEST_OPTION(dirname, string, "directory name", 1);

enum {
	FUTEX_INITIALIZED = 0,
	DETACHED_NETNS_BIND,
	TEST_FINISH,
	EMERGENCY_ABORT,
};

futex_t *futex;

static int create_self_netns_bind(char *net_bind)
{
	char *self_netns_path = "/proc/self/ns/net";
	int fd;

	fd = creat(net_bind, 0600);
	if (fd == -1) {
		pr_perror("Failed to create file %s", net_bind);
		return -1;
	}
	close(fd);

	if (mount(self_netns_path, net_bind, NULL, MS_BIND, NULL)) {
		pr_perror("Failed to bind %s to %s", self_netns_path, net_bind);
		return -1;
	}

	return 0;
}

static int set_netns(char *path) {
	int fd, ret = -1;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Failed to open %s", path);
		goto err;
	}

	if (setns(fd, CLONE_NEWNET)) {
		pr_perror("Failed to setns to %s", path);
		goto err;
	}

	ret = 0;
err:
	close(fd);
	return ret;
}

#define SOCKET_NAME "X/zdtm/static/detached_namespace_with_bindmount"

static int create_socket(char *name)
{
	struct sockaddr_un addr;
	int len, sk;

	addr.sun_family = AF_LOCAL;
	snprintf(addr.sun_path, 108, "%s", name);
	len = SUN_LEN(&addr);
	addr.sun_path[0] = 0;

	sk = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("Failed to create socket %s", name);
		return -1;
	}

	if (bind(sk, (struct sockaddr *) &addr, len) < 0) {
		pr_perror("Failed to bind socket %s", name);
		close(sk);
		return -1;
	}

	return sk;
}

static int check_socket(char *name)
{
	struct sockaddr_un addr;
	int len, sk;

	addr.sun_family = AF_LOCAL;
	snprintf(addr.sun_path, 108, "%s", name);
	len = SUN_LEN(&addr);
	addr.sun_path[0] = 0;

	sk = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("Failed to create socket %s", name);
		return -1;
	}

	if (connect(sk, (struct sockaddr *) &addr, len) < 0) {
		pr_perror("Failed to connect to socket %s", name);
		close(sk);
		return -1;
	}
	close(sk);

	return 0;
}

static int child(void *arg)
{
	char ns_path[PATH_MAX], *net_bind = (char *)arg;
	int ppid = getppid(), ret = 1, sk = -1;

	if (create_self_netns_bind(net_bind))
		goto err;

	sk = create_socket(SOCKET_NAME);
	if (sk < 0)
		goto err;

	snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/net", ppid);
	if (set_netns(ns_path))
		goto err;

	futex_set_and_wake(futex, DETACHED_NETNS_BIND);
	futex_wait_while_lt(futex, TEST_FINISH);

	ret = 0;
err:
	if (ret)
		futex_set_and_wake(futex, EMERGENCY_ABORT);
	if (sk >= 0)
		close(sk);
	return ret;
}

#define CLONE_STACK_SIZE 4096

int main(int argc, char **argv)
{
	char stack[CLONE_STACK_SIZE] __stack_aligned__;
	char net_bind[PATH_MAX];
	int pid, ret = 1;

	test_init(argc, argv);
	futex = mmap(NULL, sizeof(*futex), PROT_WRITE | PROT_READ,
		     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (futex == MAP_FAILED) {
		pr_perror("Failed to mmap futex");
		return 1;
	}

	if (prepare_dirname(dirname))
		return 1;

	snprintf(net_bind, sizeof(net_bind), "%s/net_bind", dirname);

	pid = clone(child,  &stack[CLONE_STACK_SIZE - 1],
		    CLONE_NEWNET | SIGCHLD, net_bind);
	if (pid == -1) {
		pr_perror("Failed to clone child with nested namespaces");
		return 1;
	}

	futex_wait_while_lt(futex, DETACHED_NETNS_BIND);
	if (futex_get(futex) == EMERGENCY_ABORT) {
		pr_err("Fail in child initialization");
		goto err;
	}

	test_daemon();
	test_waitsig();

	if (set_netns(net_bind))
		goto err;

	if (check_socket(SOCKET_NAME)) {
		fail();
		goto err;
	}

	futex_set_and_wake(futex, TEST_FINISH);
	pass();
	ret = 0;
err:
	if (ret)
		kill(pid, SIGKILL);
	wait(NULL);
	return ret;
}
