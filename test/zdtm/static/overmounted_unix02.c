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
	int sk1[3] = {-1, -1, -1}, sk2[3] = {-1, -1, -1}, ret = -1;
#ifdef ZDTM_OVM_UNIX_STREAM
	int sock_type = SOCK_STREAM | SOCK_NONBLOCK;
#else
	int sock_type = SOCK_DGRAM;
#endif
	test_init(argc, argv);

	mkdir(dirname, 0755);

	ssprintf(addr1.sun_path, "%s/sock1.unix", dirname);
	addr1.sun_family = AF_UNIX;

	ssprintf(addr2.sun_path, "%s/sock2.unix", dirname);
	addr2.sun_family = AF_UNIX;

	sk1[0] = sk_alloc_bind(sock_type, &addr1);
	if (sk1[0] < 0)
		goto out_unlink;

#ifdef ZDTM_OVM_UNIX_STREAM
	if (listen(sk1[0], 10) < 0) {
		pr_perror("listen sk1");
		goto out_unlink;
	}
#endif

	sk1[1] = sk_alloc_connect(sock_type, &addr1);
	if (sk1[1] < 0)
		goto out_unlink;

#ifdef ZDTM_OVM_UNIX_STREAM
	sk1[2] = accept(sk1[0], NULL, NULL);
	if (sk1[2] < 0) {
		pr_perror("accept sk1");
		goto out_unlink;
	}
#endif

	sk2[0] = sk_alloc_bind(sock_type, &addr2);
	if (sk2[0] < 0)
		goto out_unlink;

#ifdef ZDTM_OVM_UNIX_STREAM
	if (listen(sk2[0], 10) < 0) {
		pr_perror("listen sk2");
		goto out_unlink;
	}
#endif

	if (mount(addr2.sun_path, addr1.sun_path, NULL, MS_BIND, NULL) < 0) {
		pr_perror("overmount");
		goto out_unlink;
	}

	sk2[1] = sk_alloc_connect(sock_type, &addr1);
	if (sk2[1] < 0)
		goto out_umount;

#ifdef ZDTM_OVM_UNIX_STREAM
	sk2[2] = accept(sk2[0], NULL, NULL);
	if (sk2[2] < 0) {
		pr_perror("accept sk2");
		goto out_unlink;
	}
#endif

#ifdef ZDTM_OVM_UNIX_BIND
	if (mount("dummy", dirname, "tmpfs", 0, NULL) < 0) {
		pr_perror("overmount");
		goto out_unlink;
	}
#endif

	test_daemon();
	test_waitsig();

	ret = 0;
	pass();

#ifdef ZDTM_OVM_UNIX_BIND
	umount2(dirname, MNT_DETACH);
#endif
out_umount:
	umount2(addr1.sun_path, MNT_DETACH);
out_unlink:
	unlink(addr1.sun_path);
	unlink(addr1.sun_path);
	close(sk1[0]);
	close(sk1[1]);
	close(sk1[2]);
	close(sk2[0]);
	close(sk2[1]);
	close(sk2[2]);
	rmdir(dirname);

	return ret;
}
