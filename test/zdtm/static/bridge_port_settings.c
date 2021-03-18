#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "zdtmtst.h"

const char *test_doc	= "Check brige link properties and fdb table after restore";
const char *test_author	= "Andrey Zhadchenko <andrey.zhadchenko@virtuozzo.com>";

#define EXEC_CMD(cmdfmt, arg...) \
	do { \
		ssprintf(cmd, cmdfmt, ## arg); \
		if (system(cmd)) { \
			pr_err("FAILED: %s\n", cmd); \
			goto out; \
		} \
	} while (0)

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv) {
	char file1[256], file2[256];
	char cmd[128];
	int ret = -1;

	test_init(argc, argv);

	ssprintf(file1, "%s/settings_before", dirname);
	ssprintf(file2, "%s/settings_after", dirname);

	if (mkdir(dirname, 0700)) {
		pr_perror("can't make directory %s", dirname);
		exit(1);
	}

	EXEC_CMD("ip link add br0 type bridge");
	EXEC_CMD("ip link add veth0 type veth peer name veth1");
	EXEC_CMD("ip link set veth0 master br0");

#ifdef BRIDGE_FDB
	EXEC_CMD("bridge fdb add FF:FF:00:00:00:0F dev veth0");
#else
	EXEC_CMD("bridge link set dev veth0 flood off");
	EXEC_CMD("bridge link set dev veth0 cost 50");
	EXEC_CMD("bridge link set dev veth0 learning off");
#endif

	EXEC_CMD("ip link set br0 up");
	EXEC_CMD("ip link set veth0 up");
	EXEC_CMD("ip link set veth1 up");

#ifdef BRIDGE_FDB
	EXEC_CMD("bridge fdb show | grep permanent > %s", file1);
#else
	EXEC_CMD("bridge -d link show > %s", file1);
#endif

	test_daemon();
	test_waitsig();

#ifdef BRIDGE_FDB
	EXEC_CMD("bridge fdb show | grep permanent > %s", file2);
#else
	EXEC_CMD("bridge -d link show > %s", file2);
#endif
	EXEC_CMD("diff %s %s", file1, file2);

	ret = 0;
	pass();

out:
	unlink(file1);
	unlink(file2);
	rmdir(dirname);

	return ret;
}
