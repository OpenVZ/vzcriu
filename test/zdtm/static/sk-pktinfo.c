#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <linux/in.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that IP_PKTINFO is restored";
const char *test_author	= "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

int main(int argc, char **argv)
{
	socklen_t len;
	int val, sock;

	test_init(argc, argv);

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1) {
		pr_perror("socket() failed");
		return -1;
	}

	val = 1;
	if (setsockopt(sock, SOL_IP, IP_PKTINFO, &val, sizeof(int)) == -1) {
		pr_perror("setsockopt() error");
		return -1;
	}

	test_daemon();
	test_waitsig();

	len = sizeof(int);
	if (getsockopt(sock, SOL_IP, IP_PKTINFO, &val, &len) == -1) {
		pr_perror("setsockopt() error");
		return -1;
	}

	if (val != 1) {
		fail("Unexpected value: %d", val);
		return -1;
	}

	pass();

	return 0;
}
