#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc = "Check that ipv4 route tables are kept";
const char *test_author = "Yuriy Vasilev <yuriy.vasilev@virtuozzo.com>";

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (system("ip link set lo up")) {
		fail("Can't set lo up");
		return -1;
	}

	if (system("ip route add 1.2.3.4 dev lo table 100")) {
		fail("Can't add ipv4 route");
		return -1;
	}

	if (system("ip route show table 100 >> netns-route.first.test")) {
		fail("Can't get first ip routes");
		return -1;
	}

	test_daemon();
	test_waitsig();

	if (system("ip route show table 100 >> netns-route.second.test")) {
		fail("Can't get second ip routes");
		return -1;
	}

	if (system("diff netns-route.first.test netns-route.second.test")) {
		fail("Route tables differ after restore");
		return -1;
	}

	pass();
	return 0;
}
