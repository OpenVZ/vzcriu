#include <unistd.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <linux/socket.h>

#include "zdtmtst.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK     270
#endif

const char *test_doc	= "Check that blocking sockets remain blocking";
const char *test_author	= "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

int main(int argc, char ** argv)
{
	int sk, skn = -1, ret;

	test_init(argc, argv);

	sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sk < 0) {
		pr_perror("Can't create generic raw socket");
		return 1;
	}

	if (fcntl(sk, F_SETFL, 0) == -1) {
		pr_perror("Can't drop file status flags");
		goto err;
	}

	skn = socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (skn < 0) {
		pr_perror("Can't create generic raw socket");
		goto err;
	}

	if (fcntl(skn, F_SETFL, O_NONBLOCK) == -1) {
		pr_perror("Can't set O_NONBLOCK");
		goto err;
	}

	test_daemon();
	test_waitsig();

	ret = fcntl(sk, F_GETFL, 0);
	if (ret == -1) {
		pr_perror("Can't get status flags for %d", sk);
		goto err;
	}

	if (ret & O_NONBLOCK) {
		fail("Unexpected O_NONBLOCK for %d", sk);
		goto err;
	}

	ret = fcntl(skn, F_GETFL, 0);
	if (ret == -1) {
		pr_perror("Can't get status flags for %d", skn);
		goto err;
	}

	if (!(ret & O_NONBLOCK)) {
		fail("%d should have O_NONBLOCK", skn);
		goto err;
	}

	close(sk);
	close(skn);
	pass();

	return 0;
err:
	if (sk >= 0)
		close(sk);
	if (skn >= 0)
		close(skn);
	return 1;
}
