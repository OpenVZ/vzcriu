#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sched.h>

#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc = "Check that mntid of unix file is correct after c/r";
const char *test_author = "Andrey Zhadchenko <andrey.zhadchenko@viruozzo.com>";

#define SIOCUNIXFILE 0x89E0

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

static int sk_alloc_bind(int type, struct sockaddr_un *addr)
{
	int sk;

	sk = socket(PF_UNIX, type, 0);
	if (sk < 0) {
		pr_perror("socket");
		return -1;
	}

	if (addr && bind(sk, (const struct sockaddr *)addr, sizeof(*addr))) {
		pr_perror("bind %s", addr->sun_path);
		close(sk);
		return -1;
	}

	return sk;
}

static int get_mnt_id(int fd)
{
	char buf[sizeof(struct file_handle) + MAX_HANDLE_SZ];
	struct file_handle *fhp = (struct file_handle *)&buf;
	int mnt_id;

	fhp->handle_bytes = MAX_HANDLE_SZ;

	if (name_to_handle_at(fd, "", fhp, &mnt_id, AT_EMPTY_PATH)) {
		pr_perror("Unable to get mnt_id");
		return -1;
	}

	return mnt_id;
}

int main(int argc, char **argv)
{
	struct sockaddr_un addr;
	int sk, fd, ret = -1, mnt_id1, mnt_id2;
	char sk_bind_path[PATH_MAX], testpath[PATH_MAX];

	test_init(argc, argv);

	unshare(CLONE_NEWNS);

	mkdir(dirname, 0755);

	ssprintf(sk_bind_path, "%s/sock.unix.bind", dirname);
	ssprintf(addr.sun_path, "%s/sock.unix", dirname);
	addr.sun_family = AF_UNIX;

	sk = sk_alloc_bind(SOCK_DGRAM, &addr);
	if (sk < 0)
		goto out_rmdir;

	fd = open(sk_bind_path, O_RDONLY | O_CREAT, 0600);
	if (fd < 0) {
		pr_perror("create bind file");
		goto out_unlink;
	}
	close(fd);

	if (mount(addr.sun_path, sk_bind_path, NULL, MS_BIND, NULL) < 0) {
		pr_perror("overmount");
		goto out_unlink;
	}

	test_daemon();
	test_waitsig();

	fd = ioctl(sk, SIOCUNIXFILE);
	if (fd < 0) {
		pr_perror("SIOCUNIXFILE");
		goto out_umount;
	}

	mnt_id1 = get_mnt_id(fd);
	if (mnt_id1 < 0) {
		pr_err("SIOCUNIXFILE mnt_id\n");
		goto out_umount;
	}
	test_msg("socket backing file mnt_id %d\n", mnt_id1);

	close(fd);

	ssprintf(testpath, "%s/file", dirname);
	fd = open(testpath, O_CREAT | O_RDONLY, 0600);
	if (fd < 0) {
		pr_perror("create mntid testfile");
		goto out_umount;
	}

	mnt_id2 = get_mnt_id(fd);
	if (mnt_id2 < 0) {
		pr_err("control file mnt_id\n");
		goto out_clean;
	}
	test_msg("control file mnt_id %d\n", mnt_id2);

	close(fd);

	if (mnt_id1 != mnt_id2) {
		fail("Bindmounted socket restored on wrong mnt_id");
		goto out_clean;
	}

	ret = 0;
	pass();

out_clean:
	unlink(testpath);
out_umount:
	umount2(sk_bind_path, MNT_DETACH);
out_unlink:
	unlink(sk_bind_path);
	unlink(addr.sun_path);
	close(sk);
out_rmdir:
	rmdir(dirname);

	return ret;
}
