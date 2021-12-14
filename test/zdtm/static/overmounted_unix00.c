#ifndef _GNU_SOURCE
# define _GNU_SOURCE
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

#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that we can c/r overmounted connected/non-connected unix socket";
const char *test_author	= "Andrey Zhadchenko <andrey.zhadchenko@viruozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

static int sk_alloc_bind(int type, struct sockaddr_un *addr)
{
	int sk;

	sk = socket(AF_UNIX, type, 0);
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

#ifdef ZDTM_OVM_UNIX_CONNECT
static int sk_alloc_connect(int type, struct sockaddr_un *addr)
{
	int sk;

	sk = socket(AF_UNIX, type, 0);
	if (sk < 0) {
		pr_perror("socket");
		return -1;
	}

	if (connect(sk, (const struct sockaddr *)addr, sizeof(*addr))) {
		pr_perror("connect %s", addr->sun_path);
		close(sk);
		return -1;
	}

	return sk;
}
#endif

int main(int argc, char **argv)
{
	struct sockaddr_un addr;
	int sk1 = -1, sk2 = -1, ret = -1;

	test_init(argc, argv);

	mkdir(dirname, 0755);

	ssprintf(addr.sun_path, "%s/sock", dirname);
	addr.sun_family = AF_UNIX;

	sk1 = sk_alloc_bind(SOCK_DGRAM, &addr);
	if (sk1 < 0)
		goto out_rmdir;

#ifdef ZDTM_OVM_UNIX_CONNECT
	sk2 = sk_alloc_connect(SOCK_DGRAM, &addr);
	if (sk2 < 0)
		goto out_unlink;
#endif

	if (mount("dummy", dirname, "tmpfs", 0, NULL) < 0) {
		pr_perror("overmount");
		goto out_unlink;
	}

	if (!access(addr.sun_path, F_OK)) {
		fail("overmount didn't hide the socket");
		goto out_umount;
	}

	test_daemon();
	test_waitsig();

	if (!access(addr.sun_path, F_OK)) {
		fail("Socket restored on wrong mount");
		goto out_umount;
	}

	ret = 0;
	pass();

out_umount:
	umount2(dirname, MNT_DETACH);
out_unlink:
	unlink(addr.sun_path);
	close(sk1);
	close(sk2);
out_rmdir:
	rmdir(dirname);

	return ret;
}
