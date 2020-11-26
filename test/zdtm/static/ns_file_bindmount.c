#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <linux/limits.h>

#include "zdtmtst.h"
#include "fs.h"

const char *test_doc    = "Check namespace file (/proc/pid/ns/name) bindmounts";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname = "ns_file_bindmount";
TEST_OPTION(dirname, string, "directory name", 1);

static int child(void *unused)
{
	while (1)
		sleep(1);
	return 0;
}

static int create_ns_bind(char *ns, int pid, char *file, char *bind)
{
	int fd;

	snprintf(file, PATH_MAX, "/proc/%d/ns/%s", pid, ns);
	snprintf(bind, PATH_MAX, "%s/%s_bind", dirname, ns);

	fd = creat(bind, 0600);
	if (fd == -1) {
		pr_perror("Failed to create file %s", bind);
		return -1;
	}
	close(fd);

	if (mount(file, bind, NULL, MS_BIND, NULL)) {
		pr_perror("Failed to bind %s to %s", file, bind);
		return -1;
	}

	return 0;
}

#define BUF_SIZE 4096

static int self_mntinfo_get_root(char *mountpoint_tail, char *buf, int size)
{
	char line[BUF_SIZE], root[PATH_MAX], mountpoint[PATH_MAX];
	FILE *mountinfo;
	int ret;

	mountinfo = fopen("/proc/self/mountinfo", "r");
	if (!mountinfo) {
		pr_perror("fopen");
		return -1;
	}

	while (fgets(line, sizeof(line), mountinfo)) {

		ret = sscanf(line, "%*i %*i %*u:%*u %s %s", root, mountpoint);
		if (ret != 2) {
			pr_perror("Failed to sscanf mountinfo");
			fclose(mountinfo);
			return -1;
		}

		if (!strstr(mountpoint, mountpoint_tail))
			continue;

		snprintf(buf, size, "%s", root);
		fclose(mountinfo);
		return 0;
	}

	fclose(mountinfo);
	return -1;
}

static int check_ns_bind(char *file, char *bind)
{
	char buf_bind_root[PATH_MAX], buf_file_readlink[PATH_MAX];
	int len;

	if (self_mntinfo_get_root(bind, buf_bind_root, sizeof(buf_bind_root))) {
		pr_err("Failed to find %s in mountinfo", bind);
		return -1;
	}

	len = readlink(file, buf_file_readlink, sizeof(buf_file_readlink) - 1);
	if (len == -1) {
		pr_perror("Failed to readlink %s", file);
		return -1;
	}
	buf_file_readlink[len] = '\0';

	if (strcmp(buf_bind_root, buf_file_readlink)) {
		fail("mount root does not match readlink");
		return -1;
	}

	return 0;
}

#define PROC_SELF_FD "/proc/self/fd/%d"

static int prepare_ns_bind_fd(char *path, char *fd_link, int size)
{
	char fd_proc[PATH_MAX];
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Failed to open %s", path);
		return -1;
	}
	snprintf(fd_proc, sizeof(fd_proc), PROC_SELF_FD, fd);

	if (readlink(fd_proc, fd_link, size) == -1) {
		pr_perror("Failed to readlink");
		return -1;
	}

	return fd;
}

static int check_ns_bind_fd(int fd, char *fd_link)
{
	char fd_proc[PATH_MAX], new_fd_link[PATH_MAX];

	snprintf(fd_proc, sizeof(fd_proc), "/proc/self/fd/%d", fd);

	if (readlink(fd_proc, new_fd_link, sizeof(new_fd_link)) == -1) {
		pr_perror("Failed to readlink");
		return -1;
	}

	return strcmp(fd_link, new_fd_link);
}

#define CLONE_STACK_SIZE 4096

int main(int argc, char **argv)
{
	char ipc_file[PATH_MAX], uts_file[PATH_MAX], net_file[PATH_MAX],
	     ipc_bind[PATH_MAX], uts_bind[PATH_MAX], net_bind[PATH_MAX];
	char ipc_fd_link[PATH_MAX], uts_fd_link[PATH_MAX], net_fd_link[PATH_MAX];
	int ipc_fd = -1, uts_fd = -1, net_fd = -1;
	char stack[CLONE_STACK_SIZE] __stack_aligned__;
	int pid, ret = 1;

	test_init(argc, argv);

	if (prepare_dirname(dirname))
		return 1;

	pid = clone(child,  &stack[CLONE_STACK_SIZE],
		    CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | SIGCHLD,
		    NULL);
	if (pid == -1) {
		pr_perror("Failed to clone child with nested namespaces");
		return 1;
	}

	if (create_ns_bind("ipc", pid, ipc_file, ipc_bind))
		goto err;
	if (create_ns_bind("uts", pid, uts_file, uts_bind))
		goto err;
	if (create_ns_bind("net", pid, net_file, net_bind))
		goto err;

	ipc_fd = prepare_ns_bind_fd(ipc_bind, ipc_fd_link, sizeof(ipc_fd_link));
	if (ipc_fd < 0)
		goto err;
	uts_fd = prepare_ns_bind_fd(uts_bind, uts_fd_link, sizeof(uts_fd_link));
	if (uts_fd < 0)
		goto err;
	net_fd = prepare_ns_bind_fd(net_bind, net_fd_link, sizeof(net_fd_link));
	if (net_fd < 0)
		goto err;

	test_daemon();
	test_waitsig();

	if (check_ns_bind(ipc_file, ipc_bind))
		goto err;
	if (check_ns_bind(uts_file, uts_bind))
		goto err;
	if (check_ns_bind(net_file, net_bind))
		goto err;

	if (check_ns_bind_fd(ipc_fd, ipc_fd_link)) {
		fail("ipc link missmatch");
		goto err;
	}
	if (check_ns_bind_fd(uts_fd, uts_fd_link)) {
		fail("uts link missmatch");
		goto err;
	}
	if (check_ns_bind_fd(net_fd, net_fd_link)) {
		fail("net link missmatch");
		goto err;
	}

	pass();
	ret = 0;
err:
	if (ipc_fd != -1)
		close(ipc_fd);
	if (uts_fd != -1)
		close(uts_fd);
	if (net_fd != -1)
		close(net_fd);
	kill(pid, SIGKILL);
	wait(NULL);
	return ret;
}
