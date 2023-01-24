#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "zdtmtst.h"

const char *test_doc = "Check that iptables-nft icmpv6 type rules preserve";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	char cmd[128];

	test_init(argc, argv);

	sprintf(cmd, "ip6tables-nft -L > /dev/null");
	if (system(cmd)) {
		pr_perror("Can't save nftables");
		return -1;
	}

	/* Multicast Listener Query [RFC2710] */
	if (system("ip6tables-nft -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j ACCEPT")) {
		pr_perror("Can't set input rule");
		return -1;
	}

	/* Multicast Listener Report [RFC2710] */
	if (system("ip6tables-nft -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j ACCEPT")) {
		pr_perror("Can't set input rule");
		return -1;
	}

	/* Multicast Listener Report [RFC2710] */
	if (system("ip6tables-nft -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 132 -j ACCEPT")) {
		pr_perror("Can't set input rule");
		return -1;
	}

	sprintf(cmd, "ip6tables-nft -L > pre-%s", filename);
	if (system(cmd)) {
		pr_perror("Can't save nftables");
		return -1;
	}

	test_daemon();
	test_waitsig();

	sprintf(cmd, "ip6tables-nft -L > post-%s", filename);
	if (system(cmd)) {
		fail("Can't get nftables");
		return -1;
	}

	sprintf(cmd, "diff pre-%s post-%s", filename, filename);
	if (system(cmd)) {
		fail("Nftables differ");
		return -1;
	}

	pass();
	return 0;
}
