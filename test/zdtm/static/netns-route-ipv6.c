#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc = "Check that ipv6 route tables are kept";
const char *test_author = "Yuriy Vasilev <yuriy.vasilev@virtuozzo.com>";

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (system("ip link set lo up")) {
		fail("Can't set lo up");
		return -1;
	}

	if (system("ip -6 route add ::1/128 dev lo table 100")) {
		fail("Can't add ipv6 route");
		return -1;
	}

	if (system("ip -6 route show table 100 >> netns-route-ipv6.first.test")) {
		fail("Can't get first ip routes");
		return -1;
	}

	test_daemon();
	test_waitsig();

	if (system("ip -6 route show table 100 >> netns-route-ipv6.second.test")) {
		fail("Can't get second ip routes");
		return -1;
	}

	if (system("diff netns-route-ipv6.first.test netns-route-ipv6.second.test")) {
		fail("Route tables differ after restore");
		return -1;
	}

	pass();
	return 0;
}
