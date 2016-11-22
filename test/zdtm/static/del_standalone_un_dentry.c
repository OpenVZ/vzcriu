#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that deleted unix sockets with dirs are restored correctly";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

static int fill_sock_name(struct sockaddr_un *name, const char *filename)
{
	char *cwd;

	cwd = get_current_dir_name();
	if (strlen(filename) + strlen(cwd) + 1 >= sizeof(name->sun_path))
		return -1;

	name->sun_family = AF_LOCAL;
	sprintf(name->sun_path, "%s/%s", cwd, filename);
	return 0;
}

static int bind_and_listen(struct sockaddr_un *addr)
{
	int sk;

	sk = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sk < 0) {
		fail("socket");
		return -1;
	}

	if (bind(sk, addr, sizeof(*addr))) {
		fail("bind %s", addr->sun_path);
		close(sk);
		return -1;
	}

	if (listen(sk, 1)) {
		fail("listen");
		close(sk);
		return -1;
	}

	return sk;
}

int main(int argc, char **argv)
{
	struct sockaddr_un addr;
	int sk1 = -1, sk2 = -1, sk3 = -1, ret = 1;
	char filename[PATH_MAX], subdir[PATH_MAX];
	char nestedname[PATH_MAX], temp[PATH_MAX];

	test_init(argc, argv);

	sprintf(subdir, "%s/%s", dirname, dirname);
	sprintf(nestedname, "%s/sock", subdir);
	sprintf(filename, "%s/sock", dirname);
	sprintf(temp, "%s/temp", dirname);

	if (mkdir(dirname, 0755) < 0 || mkdir(subdir, 0755) < 0) {
		fail("mkdir");
		goto out;
	}

	if (fill_sock_name(&addr, filename) < 0) {
		pr_err("filename \"%s\" is too long\n", filename);
		goto out;
	}

	sk1 = bind_and_listen(&addr);
	if (sk1 < 0)
		goto out;

	if (rename(filename, temp) < 0) {
		fail("rename");
		goto out;
	}

	sk2 = bind_and_listen(&addr);
	if (sk2 < 0)
		goto out;

	if (rename(temp, filename) < 0) {
		fail("rename2");
		goto out;
	}

	if (fill_sock_name(&addr, nestedname) < 0) {
		pr_err("nestedname \"%s\" is too long\n", nestedname);
		goto out;
	}

	sk3 = bind_and_listen(&addr);
	if (sk1 < 0)
		goto out;

	unlink(nestedname);
	rmdir(subdir);

	test_daemon();
	test_waitsig();

	if (getsockopt(sk1, 0, 0, NULL, 0) && errno != EOPNOTSUPP) {
		fail("socket 1 didn't survive restore");
		goto out;
	}

	if (getsockopt(sk2, 0, 0, NULL, 0) && errno != EOPNOTSUPP) {
		fail("socket 2 didn't survive restore");
		goto out;
	}

	if (getsockopt(sk3, 0, 0, NULL, 0) && errno != EOPNOTSUPP) {
		fail("socket 3 didn't survive restore");
		goto out;
	}

	pass();
	ret = 0;
out:
	if (sk1 > 0)
		close(sk1);
	if (sk2 > 0)
		close(sk2);
	rmdir(dirname);
	return ret;
}
