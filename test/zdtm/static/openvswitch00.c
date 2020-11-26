#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc    = "Check if datapath and vports links are restored correctly";
const char *test_author = "Andrey Zhadchenko <andrey.zhadchenko@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "test directory name", 1);

#define EXEC_CMD(cmdfmt, arg...)	do {			\
		ssprintf(cmd, cmdfmt, ## arg); \
		if (system(cmd)) { \
			pr_err("FAILED: %s\n", cmd); \
			goto err; \
		} \
	} while (0)

int main(int argc, char **argv)
{
	char cmd[128] = {0};
	char before[128] = {0};
	char after[128] = {0};
	int ret = 0;

	test_init(argc, argv);

#ifdef OPENVSWITCH01
	if (unshare(CLONE_NEWNET)) {
		pr_perror("can't unshare");
		return 1;
	}
#endif

	if (mkdir(dirname, 0700) < 0) {
		pr_perror("Can't make dir");
		exit(1);
	}

	system("mknod /dev/urandom c 1 9");
	EXEC_CMD("ovs-dpctl add-dp dp0");

	/* create veth and plug it into dp0 */
	EXEC_CMD("ip link add veth1 type veth peer name veth2");
	EXEC_CMD("ovs-dpctl add-if dp0 veth1");
	EXEC_CMD("ip link set veth1 up");
	EXEC_CMD("ip link set veth2 up");

	/* create vxlan and internal vports */
	EXEC_CMD("ovs-dpctl add-if dp0 vx,type=vxlan,remote_ip=10.0.0.0");
	EXEC_CMD("ovs-dpctl add-if dp0 int0,type=internal");

	ssprintf(before, "%s/before", dirname);
	EXEC_CMD("ip a > %s", before);

	test_daemon();
	test_waitsig();

	ssprintf(after, "%s/after", dirname);
	EXEC_CMD("ip a > %s", after);

	ssprintf(cmd, "diff %s %s", before, after);
	if (system(cmd)) {
		pr_err("links before/after c/r differ!\n");
		goto err;
	}
	pass();
	goto clean;

err:
	fail();
	ret = -1;
clean:
	rmdir(dirname);
	return ret;
}
