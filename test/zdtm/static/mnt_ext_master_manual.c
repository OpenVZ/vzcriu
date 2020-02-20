#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check external mount with external slavery and bind";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *source = "zdtm_ext_master_manual";
char *share_source = "zdtm_ext_master_manual.share";
char *dirname = "mnt_ext_master_manual.test";
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char *root;
	char share[PATH_MAX], src[PATH_MAX];
	char dst[PATH_MAX], bind[PATH_MAX];
	char *tmp = "/tmp/zdtm_ext_master_manual.tmp";
	char *zdtm_newns = getenv("ZDTM_NEWNS");

	root = getenv("ZDTM_ROOT");
	if (root == NULL) {
		pr_perror("root");
		return 1;
	}

	if (!zdtm_newns) {
		pr_perror("ZDTM_NEWNS is not set");
		return 1;
	} else if (strcmp(zdtm_newns, "1")) {
		goto test;
	}

	/* Prepare directories in test root */
	sprintf(dst, "%s/%s", root, dirname);
	mkdir(dst, 0755);
	sprintf(dst, "%s/%s/dst", root, dirname);
	mkdir(dst, 0755);
	sprintf(bind, "%s/%s/bind", root, dirname);
	mkdir(bind, 0755);

	/* Prepare mount in criu root */
	mkdir(tmp, 0755);
	if (mount(source, tmp, "tmpfs", 0, NULL)) {
		pr_perror("mount tmpfs");
		return 1;
	}
	if (mount(NULL, tmp, NULL, MS_PRIVATE, NULL)) {
		pr_perror("make private");
		return 1;
	}

	sprintf(share, "%s/share", tmp);
	mkdir(share, 0755);
	if (mount(share_source, share, "tmpfs", 0, NULL)) {
		pr_perror("mount tmpfs");
		return 1;
	}
	if (mount(NULL, share, NULL, MS_SHARED, NULL)) {
		pr_perror("make shared");
		return 1;
	}
	sprintf(src, "%s/src", tmp);
	mkdir(src, 0755);
	if (mount(share, src, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}
	if (mount(NULL, src, NULL, MS_SLAVE, NULL)) {
		pr_perror("make slave");
		return 1;
	}

	/*
	 * Create temporary mntns, next mounts will not show up in criu mntns
	 */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("unshare");
		return 1;
	}

	/*
	 * Populate to the tests mntns root mounts
	 */
	if (mount(src, dst, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}

	if (mount(dst, bind, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}

test:
	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
