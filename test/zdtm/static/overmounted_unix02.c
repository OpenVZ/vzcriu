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

const char *test_doc	= "Check that we can c/r connected unix socket overmounted with another connected unix socket";
const char *test_author	= "Andrey Zhadchenko <andrey.zhadchenko@viruozzo.com>";

#define SIOCUNIXFILE 0x89E0

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


int main(int argc, char **argv)
{
	struct sockaddr_un addr1, addr2;
	int sk1[2] = {-1, -1}, sk2[2] = {-1, -1}, ret = -1;

	test_init(argc, argv);

	mkdir(dirname, 0755);

	ssprintf(addr1.sun_path, "%s/sock1.unix", dirname);
	addr1.sun_family = AF_UNIX;

	ssprintf(addr2.sun_path, "%s/sock2.unix", dirname);
	addr2.sun_family = AF_UNIX;

	sk1[0] = sk_alloc_bind(SOCK_DGRAM, &addr1);
	if (sk1[0] < 0)
		goto out_unlink;

	sk1[1] = sk_alloc_connect(SOCK_DGRAM, &addr1);
	if (sk1[1] < 0)
		goto out_unlink;

	sk2[0] = sk_alloc_bind(SOCK_DGRAM, &addr2);
	if (sk2[0] < 0)
		goto out_unlink;

	if (mount(addr2.sun_path, addr1.sun_path, NULL, MS_BIND, NULL) < 0) {
		pr_perror("overmount");
		goto out_unlink;
	}

	sk2[1] = sk_alloc_connect(SOCK_DGRAM, &addr1);
	if (sk2[1] < 0)
		goto out_umount;

	test_daemon();
	test_waitsig();

	ret = 0;
	pass();

out_umount:
	umount2(addr1.sun_path, MNT_DETACH);
out_unlink:
	unlink(addr1.sun_path);
	unlink(addr1.sun_path);
	close(sk1[0]);
	close(sk1[1]);
	close(sk2[0]);
	close(sk2[1]);
	rmdir(dirname);

	return ret;
}
