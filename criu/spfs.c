#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <libgen.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include "mount.h"
#include "log.h"
#include "util.h"
#include "cr_options.h"
#include "namespaces.h"
#include "pstree.h"
#include "spfs.h"
#include "proc_parse.h"
#include "cgroup.h"

#define SPFS_MANAGER_WORK_DIR		"/run/spfs-manager/%d"
#define SPFS_MANAGER_SOCK_FILE		"control.sock"

static int sock_seqpacket_connect(char *path)
{
	int sock, err;
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock < 0) {
		pr_perror("Failed to create packet socket");
		return -1;
	}
	memset(&addr, 0, sizeof(struct sockaddr_un));

	addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	err = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (err) {
		pr_perror("failed to connect to socket %s (-%d)", addr.sun_path, errno);
		close(sock);
		return -1;
	}
	return sock;
}

static int spfs_send_request(int sock, void *req, size_t len)
{
	ssize_t bytes;
	int status;

	bytes = send(sock, req, len, MSG_EOR);
	if (bytes < 0) {
		pr_perror("failed to send request");
		return -1;
	}

	bytes = recv(sock, &status, sizeof(status), 0);
	if (bytes < 0) {
		pr_perror("failed to receive reply via sock %d", sock);
		return -1;
	}
	if (bytes == 0) {
		pr_debug("%s: peer was closed\n", __func__);
		return -ECONNABORTED;
	}

	return status;
}

int spfs_remap_path(const char *path, const char *link_remap)
{
	if (setxattr(path, "security.spfs.link_remap", link_remap, strlen(link_remap) + 1,  XATTR_CREATE)) {
		pr_perror("failed to set xattr security.spfs.link_remap with value %s for file %s", link_remap, path);
		return -1;
	}
	pr_debug("set xattr security.spfs.link_remap with value %s for file %s\n", link_remap, path);
	return 0;
}


static char *spfs_manager_work_dir(void)
{
	static char work_dir[PATH_MAX] = { };

	if (strlen(work_dir) == 0) {
		snprintf(work_dir, PATH_MAX, SPFS_MANAGER_WORK_DIR,
				root_item->pid.real);
	}
	return work_dir;
}

char *spfs_manager_socket_path(void)
{
	static char socket_path[PATH_MAX] = { };

	if (strlen(socket_path) == 0) {
		snprintf(socket_path, PATH_MAX, "%s/%s",
			 spfs_manager_work_dir(), SPFS_MANAGER_SOCK_FILE);
	}
	return socket_path;
}

static int start_spfs_manager(void)
{
	char *spfs_manager = "spfs-manager";
	char *socket_path = spfs_manager_socket_path();
	int err = -ENOMEM, sock;

	err = cr_system(-1, -1, -1, spfs_manager,
			(char *[]){ "spfs-manager", "-vvvv",
				 "-d",
				 "--socket-path", socket_path,
				 "--work-dir", spfs_manager_work_dir(),
				 "--exit-with-spfs", NULL },
			0);
	pr_info("%s: spfs manager start result: %d\n", __func__, err);
	if (err)
		return err;

	sock = sock_seqpacket_connect(socket_path);
	if (sock < 0)
		return sock;

	err = install_service_fd(SPFS_MNGR_SK, sock);
	if (err < 0) {
		close(sock);
		pr_err("failed to install SPFS manager service socket\n");
		return err;
	}

	return sock;
}

static int get_spfs_mngr_sock(void *arg, int fd, pid_t pid)
{
	int sock;

	sock = get_service_fd(SPFS_MNGR_SK);
	if (sock < 0)
		sock = start_spfs_manager();
	return sock;
}

static int spfs_request_mount(int sock, struct mount_info *mi, const char *source,
			      const char *type, unsigned long mountflags)
{
	int err;
	char *mountpoint, *freeze_cgroup, *mount, *replace, *bindmounts = NULL;
	struct mount_info *bm;
	int len;
	char *freezer_root;

	if (opts.new_global_cg_root)
		freezer_root = opts.new_global_cg_root;
	else {
		err = new_cg_root_get("freezer", &freezer_root);
		if (err) {
			pr_err("failed to get freezer root: %d\n", err);
			return err;
		}
	}

	list_for_each_entry(bm, &mi->mnt_bind, mnt_bind) {
		bindmounts = xstrcat(bindmounts, "%s,", bm->ns_mountpoint);
		if (!bindmounts) {
			pr_err("failed to construct bindmounts parameter\n");
			return -ENOMEM;
		}
	}
	/* Trim last comma */
	bindmounts[strlen(bindmounts)] = '\0';

	err = -ENOMEM;

	mountpoint = xsprintf("%s", mi->ns_mountpoint);
	if (!mountpoint) {
		pr_err("failed to allocate\n");
		goto free_bindmounts;
	}

	freeze_cgroup = xsprintf("/sys/fs/cgroup/freezer%s", freezer_root);
	if (!freeze_cgroup) {
		pr_err("failed to construct freeze_cgroup\n");
		goto free_mountpoint;
	}

	mount = xsprintf("mount;id=%d;mode=restore;mountpoint=%s;"
			 "ns_pid=%d;root=%s", mi->mnt_id,
			 mountpoint, root_item->pid.real, opts.root);
	if (!mount) {
		pr_err("failed to allocate mount request\n");
		goto free_freeze_cgroup;
	}

	replace = xsprintf("replace;id=%d;source=%s;type=%s;flags=%ld;bindmounts=%s;freeze_cgroup=%s;",
			   mi->mnt_id, source, type, mountflags, bindmounts, freeze_cgroup);
	if (!replace) {
		pr_err("failed to allocate replace request\n");
		goto free_mount;
	}
	len = strlen(replace);

	replace = xstrcat(replace, "%s", mi->options);
	if (!replace) {
		pr_err("failed to add options to replace request\n");
		goto free_replace;
	}
	replace[len-1] = '\0';

	pr_debug("Sending mount request: %s\n", mount);

	err = spfs_send_request(sock, mount, strlen(mount) + 1);
	if (err) {
		pr_err("mount request failed: %d\n", err);
		goto free_replace;
	}

	pr_debug("Mount request succeeded\n");

	pr_debug("Sending replace request: %s\n", replace);
	err = spfs_send_request(sock, replace, strlen(replace) + 1 +
					       strlen(mi->options) + 1);
	if (err)
		pr_err("replace request failed: %d\n", err);
	else
		pr_debug("Replace request succeeded\n");


free_replace:
	free(replace);
free_mount:
	free(mount);
free_freeze_cgroup:
	free(freeze_cgroup);
free_mountpoint:
	free(mountpoint);
free_bindmounts:
	free(bindmounts);
	return err;

}

int spfs_mount(struct mount_info *mi, const char *source,
	       const char *filesystemtype, unsigned long mountflags)
{
	int ret;
	int ns_fd;
	int sock;

	ns_fd = open_proc(PROC_SELF, "ns");
	if (ns_fd < 0)
		return ns_fd;

	sock = userns_call(get_spfs_mngr_sock, UNS_FDOUT, NULL, 0, ns_fd);
	close(ns_fd);
	if (sock < 0) {
		pr_err("failed to mount NFS to path %s\n", mi->mountpoint);
		return sock;
	}

	ret = spfs_request_mount(sock, mi, source, filesystemtype, mountflags);
	close(sock);
	if (ret) {
		pr_err("mount of %s (%s) failed: %d\n", source, filesystemtype, ret);
		return ret;
	}

	return 0;
}

int spfs_set_env(void)
{
	char *mode, *socket_path;

	if ((root_item == NULL) || (root_item->pid.real == -1))
		return 0;

	mode = "stub";
	socket_path = spfs_manager_socket_path();

	if (setenv("SPFS_MODE", mode, 1)) {
		pr_perror("Can't set SPFS_MODE=%s", mode);
		return -1;

	}

	if (setenv("SPFS_MANAGER_SOCK", socket_path, 1)) {
		pr_perror("Can't set SPFS_MANAGER_SOCK=%s", socket_path);
		return -1;

	}

	return 0;
}
