#include <sched.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <linux/if.h>
#include <sys/ioctl.h>

#include <netinet/ether.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>

#include "zdtmtst.h"

const char *test_doc	= "Check dump and restore a few network namespaces";

#define ID_MAP "0 0 1"
static int init_proc_id_maps(pid_t pid)
{
	char path[128];
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		pr_perror("Unable to open %s", path);
		return -1;
	}
	if (write(fd, ID_MAP, sizeof(ID_MAP)) != sizeof(ID_MAP)) {
		pr_perror("Unable to write into %s", path);
		close(fd);
		return -1;
	}
	close(fd);

	snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		pr_perror("Unable to open %s", path);
		return -1;
	}
	if (write(fd, ID_MAP, sizeof(ID_MAP)) != sizeof(ID_MAP)) {
		pr_perror("Unable to write into %s", path);
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

#ifndef NSIO
#define NSIO    0xb7
#define NS_GET_USERNS   _IO(NSIO, 0x1)
#define NS_GET_PARENT   _IO(NSIO, 0x2)
#endif

int main(int argc, char **argv)
{
	task_waiter_t lock;
	pid_t pid[2];
	int status = -1, ret, i;
        struct rtnl_link *link = NULL, *new;
	struct nl_sock *sk;
	int has_index = 1;
	bool userns;

	test_init(argc, argv);
	task_waiter_init(&lock);

	userns = getenv("ZDTM_USERNS") != NULL;
	if (userns) {
		int fd, ufd;
		fd = open("/proc/self/ns/net", O_RDONLY);
		if (fd < 0) {
			pr_perror("Unable to open /proc/self/ns/net");
			return 1;
		}
		ufd = ioctl(fd, NS_GET_USERNS);
		if (ufd < 0) {
			userns = false;
		} else
			close(ufd);
		close(fd);
	}

	for (i = 0; i < 2; i++) {
		pid[i] = fork();
		if (pid[i] < 0) {
			pr_perror("fork");
			return -1;
		}
		if (pid[i] == 0) {
			if (userns && unshare(CLONE_NEWUSER)) {
				task_waiter_complete(&lock, i);
				return 1;
			}
			if (unshare(CLONE_NEWNET)) {
				task_waiter_complete(&lock, i);
				return 1;
			}

			system("ip link set up dev lo");
			task_waiter_complete(&lock, i);
			test_waitsig();

			return 0;
		}
		task_waiter_wait4(&lock, i);
		if (userns && init_proc_id_maps(pid[i]))
			return 1;
	}

	sk = nl_socket_alloc();
	if (sk == NULL)
		return -1;

	ret = nl_connect(sk, NETLINK_ROUTE);
	if (ret < 0) {
		nl_socket_free(sk);
		pr_err("Unable to connect socket: %s", nl_geterror(ret));
		return -1;
	}

	if (system("ip link add name zdtmbr type bridge"))
		return -1;

	for (i = 0; i < 2; i++) {
		char cmd[4096];

		snprintf(cmd, sizeof(cmd), "ip link add name zdtm%d index %d netns %d type veth peer name zdtm%d index %d",
				i, i * 10 + 12, pid[i], i, i * 10 + 12);
		if (system(cmd)) {
			has_index = 0;
			snprintf(cmd, sizeof(cmd), "ip link add name zdtm%d netns %d type veth peer name zdtm%d", i, pid[i], i);
			if (system(cmd))
				return 1;
		}
		snprintf(cmd, sizeof(cmd), "ip link set dev zdtm%d master zdtmbr", i);
		if (system(cmd))
			return 1;
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < 2; i++) {
		link = rtnl_link_alloc();
		new = rtnl_link_alloc();
		if (has_index)
			rtnl_link_set_ifindex(link, i * 10 + 12);
		else {
			char name[43];
			snprintf(name, sizeof(name), "zdtm%d", i);
			rtnl_link_set_name(link, name);
			rtnl_link_set_name(new, name);
		}
		rtnl_link_set_flags(new, IFF_UP);
		ret = rtnl_link_change(sk, link, new, 0);
		if (ret) {
			fail("Unable to up the link: %s", nl_geterror(ret));
			return 1;
		}
	}

	for (i = 0; i < 2; i++) {
		kill(pid[i], SIGTERM);
		waitpid(pid[i], &status, 0);
		if (status) {
			fail();
			return 1;
		}
	}

	pass();
	return 0;
}
