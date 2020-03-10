#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that ipset are dumped and restored correctly";

const char *test_author	= "Valeriy Vdovin <valeriy.vdovin@virtuozzo.com>";

#define RUN_OR_ERR(cmd, failmsg) if (system(cmd)) { pr_perror(failmsg); return -1; }
#define RUN_OR_FAIL(cmd, failmsg) if (system(cmd)) { fail(failmsg); return -1; }

#define FILE_PREFIX "netns-ipset."

#define FILE_IPSET_OLD FILE_PREFIX "ipset.old"
#define FILE_IPSET_NEW FILE_PREFIX "ipset.new"

#define FILE_IPTABLES_OLD FILE_PREFIX "iptables.old"
#define FILE_IPTABLES_NEW FILE_PREFIX "iptables.new"

int main(int argc, char **argv)
{
	char dump_ipset_old[]    = "ipset save > " FILE_IPSET_OLD;
	char dump_ipset_new[]    = "ipset save > " FILE_IPSET_NEW;
	char dump_iptables_old[] = "iptables -w -L INPUT 1 > " FILE_IPTABLES_OLD;
	char dump_iptables_new[] = "iptables -w -L INPUT 1 > " FILE_IPTABLES_NEW;
	char cmp_ipset[]         = "diff " FILE_IPSET_OLD " " FILE_IPSET_NEW;
	char cmp_iptables[]      = "diff " FILE_IPTABLES_OLD " " FILE_IPTABLES_NEW;
	char rm_ipset_files[]    = "rm -fv " FILE_IPSET_OLD " " FILE_IPSET_NEW;
	char rm_iptables_files[] = "rm -fv " FILE_IPTABLES_OLD " " FILE_IPTABLES_NEW;

	test_init(argc, argv);

	/* create ipset group and add some ip addresses to it */
	RUN_OR_ERR("ipset create netns-ipset-group nethash", "Can't create test ipset");
	RUN_OR_ERR("ipset add netns-ipset-group 127.0.0.1/8", "Can't add ip addresses to ipset group");

	/* Use netns-ipset-group in iptables rule */
	RUN_OR_ERR("iptables -w -I INPUT 1 -p tcp -m set --match-set netns-ipset-group src,dst -j ACCEPT",
		"Failed to setup iptables rule with ipset group");

	/* dump ipset and iptables states to text files */
	RUN_OR_ERR(dump_iptables_old, "Can't save iptables rules.");
	RUN_OR_ERR(dump_ipset_old   , "Can't save ipset list.");

	test_daemon();
	test_waitsig();

	/* again dump ipset and iptables states to other text files */
	RUN_OR_ERR(dump_iptables_new, "Can't dump restored iptables rules.");
	RUN_OR_ERR(dump_ipset_new   , "Can't save restored ipset list to file.");

	/* compare original and restored iptables rules */
	RUN_OR_FAIL(cmp_iptables, "iptables rules differ");

	/* compare original and restored ipset rules */
	RUN_OR_FAIL(cmp_ipset, "ipset lists differ");

	RUN_OR_ERR(rm_ipset_files, "Can't remove ipset files");
	RUN_OR_ERR(rm_iptables_files, "Can't remove iptables files");

	pass();
	return 0;
}
