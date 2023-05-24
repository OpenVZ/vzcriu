#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <linux/limits.h>
#include <errno.h>

#include "mountinfo.h"
#include "zdtmtst.h"

const char *test_doc = "Check complex sharing options for mounts with non-common roots and external";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname = "mount_complex_sharing02.test";
char *tmp_source = "zdtm_mount_complex_sharing02";
char *ext_source = "zdtm_mount_complex_sharing02.ext";
TEST_OPTION(dirname, string, "directory name", 1);

/*
 * Description for creating a single file:
 * path - path to create file in (relative to mount)
 * dir - true if file is a directory
 * content - if file is not a directory, this string is written into the file
 */
struct file {
	char *path;
	bool dir;
	char *content;
};

enum post_action_t {
	POST_ACTION_NONE,
	POST_ACTION_UMOUNT,
};

/*
 * Description for creating a single mount:
 * mountpoint - path to create mount on (relative to dirname)
 * bind - id of bind source if any or -1
 * bind_root - root offset from bind source
 * fstype - needed for non-binds, always tmpfs
 * source - source for mounting
 * flags - array of sharing options or mount flags applied after
 *         mounting (ending with -1)
 * mounted - identifies implicitly propagated mounts
 * post_action - umount or make private after everything is mounted
 * files - array of files we need to create on mount (ending with zeroed file)
 */
struct mountinfo {
	char *mountpoint;
	int bind;
	char *bind_root;
	char *fstype;
	char *source;
	int flags[3];
	bool mounted;
	enum post_action_t post_action;
	struct file files[64];
};

/* clang-format off */
struct mountinfo mounts[] = {
	/* 0 */
	{"", -1, "", "tmpfs", "dummy", {-1}, true, 0,
                {
			{"level_0", true},
			{"level_1", true},
			{"level_2", true},
			{"level_3", true},
			{"level_4", true},
                        {NULL}
                }
        },

	/* 1 */
	{"dst_a", -1, "", NULL, NULL, {MS_SLAVE, -1}, true, 0,
		{
			{"sub_a", true},
			{"sub_a/a_0", true},
			{"sub_a/a_1", true},
			{"sub_a/a_0/a_2", true},
			{"a_3", true},
			{"sub_a/a_0/a_4", true},
			{NULL}
		}
	},
	/* 2 */
	{"dst_b", -1, "", NULL, NULL, {MS_SLAVE, -1}, true, 0,
		{
			{"sub_b", true},
			{"sub_b/b_4_1", true},
			{"sub_b/b_4_2", true},
			{"sub_b/b_4_3", true},
			{"sub_b/b_4_4", true},
			{NULL}
		}
	},
	/* 3 */
	{"dst_c", -1, "", NULL, NULL, {MS_SLAVE, -1}, true, 0,
		{
			{"sub_c", true},
			{"sub_c/c_0", true},
			{"sub_c/c_0/c_1", true},
			{"sub_c/c_0/c_1/c_2", true},
			{"sub_c/c_0/c_1/c_2/c_3", true},
			{"sub_c/c_0/c_1/c_2/c_3/c_4", true},
			{"sub_c/c_0_", true},
			{"sub_c/c_0/c_1_", true},
			{"sub_c/c_0/c_1/c_2_", true},
			{"sub_c/c_0/c_1/c_2/c_3_", true},
			{"sub_c/c_0/c_1/c_2/c_3/c_4_", true},
			{NULL}
		}
	},
	/* 4 */
	{"dst_d", -1, "", NULL, NULL, {MS_SLAVE, -1}, true, 0,
		{
			{"sub_d", true},
			{"sub_d/d_0", true},
			{"sub_d/d_1", true},
			{"sub_d/d_2", true},
			{"sub_d/d_3", true},
			{NULL}
		}
	},

	/* 5 */
	{"level_0", -1, "", "tmpfs", "level_0_tmpfs", {-1}, false, 0,
		{
			{"mnt_a", true},
			{"mnt_a_0", true},
			{"mnt_b", true},
			{"mnt_sub_b", true},
			{"mnt_c", true},
			{"mnt_c_0", true},
			{"mnt_c_0_", true},
			{"mnt_d", true},
			{"mnt_d_0", true},
			{NULL}
		}
	},
	/* 6 */
	{"level_1", -1, "", "tmpfs", "level_1_tmpfs", {-1}, false, 0,
		{
			{"mnt_a", true},
			{"mnt_a_1", true},
			{"mnt_b", true},
			{"mnt_sub_b", true},
			{"mnt_c", true},
			{"mnt_c_1", true},
			{"mnt_c_1_", true},
			{"mnt_d", true},
			{"mnt_d_1", true},
			{NULL}
		}
	},
	/* 7 */
	{"level_2", -1, "", "tmpfs", "level_2_tmpfs", {-1}, false, 0,
		{
			{"mnt_a", true},
			{"mnt_a_2", true},
			{"mnt_b", true},
			{"mnt_sub_b", true},
			{"mnt_c", true},
			{"mnt_c_2", true},
			{"mnt_c_2_", true},
			{"mnt_d", true},
			{"mnt_d_2", true},
			{NULL}
		}
	},
	/* 8 */
	{"level_3", -1, "", "tmpfs", "level_3_tmpfs", {-1}, false, 0,
		{
			{"mnt_a", true},
			{"mnt_a_3", true},
			{"mnt_b", true},
			{"mnt_sub_b", true},
			{"mnt_c", true},
			{"mnt_c_3", true},
			{"mnt_c_3_", true},
			{"mnt_d", true},
			{"mnt_d_3", true},
			{NULL}
		}
	},
	/* 9 */
	{"level_4", -1, "", "tmpfs", "level_4_tmpfs", {-1}, false, 0,
		{
			{"mnt_a", true},
			{"mnt_a_4", true},
			{"mnt_b", true},
			{"mnt_b_4_1", true},
			{"mnt_b_4_2", true},
			{"mnt_b_4_3", true},
			{"mnt_b_4_4", true},
			{"mnt_c", true},
			{"mnt_c_4", true},
			{"mnt_c_4_", true},
			{"mnt_d", true},
			{"mnt_sub_d", true},
			{NULL}
		}
	},

	/* 10 */
	{"level_0/mnt_a", 1, "", NULL, NULL, {MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 11 */
	{"level_0/mnt_b", 2, "", NULL, NULL, {MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 12 */
	{"level_0/mnt_c", 3, "", NULL, NULL, {MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 13 */
	{"level_0/mnt_d", 4, "", NULL, NULL, {MS_SHARED, -1}, false, POST_ACTION_UMOUNT},

	/* 14 */
	{"level_1/mnt_a", 10, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 15 */
	{"level_1/mnt_b", 11, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 16 */
	{"level_1/mnt_c", 12, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 17 */
	{"level_1/mnt_d", 13, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},

	/* 18 */
	{"level_2/mnt_a", 14, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 19 */
	{"level_2/mnt_b", 15, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 20 */
	{"level_2/mnt_c", 16, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 21 */
	{"level_2/mnt_d", 17, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},

	/* 22 */
	{"level_3/mnt_a", 18, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 23 */
	{"level_3/mnt_b", 19, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 24 */
	{"level_3/mnt_c", 20, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 25 */
	{"level_3/mnt_d", 21, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},

	/* 26 */
	{"level_4/mnt_a", 22, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 27 */
	{"level_4/mnt_b", 23, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 28 */
	{"level_4/mnt_c", 24, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},
	/* 29 */
	{"level_4/mnt_d", 25, "", NULL, NULL, {MS_SLAVE, MS_SHARED, -1}, false, POST_ACTION_UMOUNT},


	/* 30 */
	{"level_0/mnt_a_0", 10, "sub_a/a_0", NULL, NULL, {-1}, false, 0},
	/* 31 */
	{"level_1/mnt_a_1", 14, "sub_a/a_1", NULL, NULL, {-1}, false, 0},
	/* 32 */
	{"level_2/mnt_a_2", 18, "sub_a/a_0/a_2", NULL, NULL, {-1}, false, 0},
	/* 33 */
	{"level_3/mnt_a_3", 22, "a_3", NULL, NULL, {-1}, false, 0},
	/* 34 */
	{"level_4/mnt_a_4", 26, "sub_a/a_0/a_4", NULL, NULL, {-1}, false, 0},

	/* 35 */
	{"level_0/mnt_sub_b", 11, "sub_b", NULL, NULL, {-1}, false, 0},
	/* 36 */
	{"level_1/mnt_sub_b", 15, "sub_b", NULL, NULL, {-1}, false, 0},
	/* 37 */
	{"level_2/mnt_sub_b", 19, "sub_b", NULL, NULL, {-1}, false, 0},
	/* 38 */
	{"level_3/mnt_sub_b", 23, "sub_b", NULL, NULL, {-1}, false, 0},
	/* 39 */
	{"level_4/mnt_b_4_1", 27, "sub_b/b_4_1", NULL, NULL, {-1}, false, 0},
	/* 40 */
	{"level_4/mnt_b_4_2", 27, "sub_b/b_4_2", NULL, NULL, {-1}, false, 0},
	/* 41 */
	{"level_4/mnt_b_4_3", 27, "sub_b/b_4_3", NULL, NULL, {-1}, false, 0},
	/* 42 */
	{"level_4/mnt_b_4_4", 27, "sub_b/b_4_4", NULL, NULL, {-1}, false, 0},

	/* 43 */
	{"level_0/mnt_c_0", 12, "sub_c/c_0", NULL, NULL, {-1}, false, 0},
	/* 44 */
	{"level_0/mnt_c_0_", 12, "sub_c/c_0_", NULL, NULL, {-1}, false, 0},
	/* 45 */
	{"level_1/mnt_c_1", 16, "sub_c/c_0/c_1", NULL, NULL, {-1}, false, 0},
	/* 46 */
	{"level_1/mnt_c_1_", 16, "sub_c/c_0/c_1_", NULL, NULL, {-1}, false, 0},
	/* 47 */
	{"level_2/mnt_c_2", 20, "sub_c/c_0/c_1/c_2", NULL, NULL, {-1}, false, 0},
	/* 48 */
	{"level_2/mnt_c_2_", 20, "sub_c/c_0/c_1/c_2_", NULL, NULL, {-1}, false, 0},
	/* 49 */
	{"level_3/mnt_c_3", 24, "sub_c/c_0/c_1/c_2/c_3", NULL, NULL, {-1}, false, 0},
	/* 50 */
	{"level_3/mnt_c_3_", 24, "sub_c/c_0/c_1/c_2/c_3_", NULL, NULL, {-1}, false, 0},
	/* 51 */
	{"level_4/mnt_c_4", 28, "sub_c/c_0/c_1/c_2/c_3/c_4", NULL, NULL, {-1}, false, 0},
	/* 52 */
	{"level_4/mnt_c_4_", 28, "sub_c/c_0/c_1/c_2/c_3/c_4_", NULL, NULL, {-1}, false, 0},

	/* 53 */
	{"level_0/mnt_d_0", 13, "sub_d/d_0", NULL, NULL, {-1}, false, 0},
	/* 54 */
	{"level_1/mnt_d_1", 17, "sub_d/d_1", NULL, NULL, {-1}, false, 0},
	/* 55 */
	{"level_2/mnt_d_2", 21, "sub_d/d_2", NULL, NULL, {-1}, false, 0},
	/* 56 */
	{"level_3/mnt_d_3", 25, "sub_d/d_3", NULL, NULL, {-1}, false, 0},
	/* 57 */
	{"level_4/mnt_sub_d", 29, "sub_d", NULL, NULL, {-1}, false, 0},
};
/* clang-format on */

static int fill_content(struct mountinfo *mi)
{
	struct file *file = &mi->files[0];
	char path[PATH_MAX];

	while (file->path != NULL) {
		snprintf(path, sizeof(path), "/%s/%s/%s", dirname, mi->mountpoint, file->path);

		if (file->dir) {
			test_msg("Mkdir %s\n", path);

			if (mkdir(path, 0755) && errno != EEXIST) {
				pr_perror("Failed to create dir %s", path);
				return -1;
			}
		} else {
			int fd, len = strlen(file->content);

			test_msg("Create file %s with content %s\n", path, file->content);
			fd = open(path, O_WRONLY | O_CREAT, 0777);
			if (fd < 0) {
				pr_perror("Failed to create file %s", path);
				return -1;
			}

			if (write(fd, file->content, len) != len) {
				pr_perror("Failed to write %s to file %s", file->content, path);
				close(fd);
				return -1;
			}
			close(fd);
		}

		file++;
	}

	return 0;
}

static int mount_one(struct mountinfo *mi)
{
	char source[PATH_MAX], target[PATH_MAX];
	int *flags = mi->flags, mflags = 0;
	char *fstype = NULL;

	test_msg("Mounting %s %d %s %s %d\n", mi->mountpoint, mi->bind, mi->fstype, mi->source, mi->mounted);

	snprintf(target, sizeof(target), "/%s/%s", dirname, mi->mountpoint);

	if (mi->mounted)
		goto fill_content;

	if (mi->bind != -1) {
		snprintf(source, sizeof(source), "/%s/%s/%s", dirname, mounts[mi->bind].mountpoint, mi->bind_root);
		fstype = NULL;
		mflags = MS_BIND;
	} else {
		snprintf(source, sizeof(source), "%s", mi->source);
		fstype = mi->fstype;
	}

	if (mount(source, target, fstype, mflags, NULL)) {
		pr_perror("Failed to mount %s %s %s", source, target, fstype);
		return -1;
	}

fill_content:
	if (fill_content(mi))
		return -1;

	while (flags[0] != -1) {
		test_msg("Making mount %s 0x%x\n", target, flags[0]);
		if (mount(NULL, target, NULL, flags[0], NULL)) {
			pr_perror("Failed to make mount %s 0x%x", target, flags[0]);
			return -1;
		}
		flags++;
	}

	return 0;
}

static int post_action_one(struct mountinfo *mi)
{
	char target[PATH_MAX];

	if (mi->post_action == POST_ACTION_NONE)
		return 0;

	test_msg("Doing post action on %s %d %s %s %d %d\n", mi->mountpoint, mi->bind, mi->fstype, mi->source,
		 mi->mounted, mi->post_action);

	snprintf(target, sizeof(target), "/%s/%s", dirname, mi->mountpoint);

	if (mi->post_action == POST_ACTION_UMOUNT) {
		if (umount(target)) {
			pr_perror("Failed to umount %s", target);
			return -1;
		}
	}

	return 0;
}

static int mount_loop(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(mounts); i++) {
		if (mount_one(&mounts[i]))
			return 1;
	}

	for (i = 0; i < ARRAY_SIZE(mounts); i++) {
		if (post_action_one(&mounts[i]))
			return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	char *root, testdir[PATH_MAX];
	char dst_a[PATH_MAX], dst_b[PATH_MAX];
	char dst_c[PATH_MAX], dst_d[PATH_MAX];
	char src[PATH_MAX];
	char src_a[PATH_MAX], src_b[PATH_MAX];
	char src_c[PATH_MAX], src_d[PATH_MAX];
	char *tmp = "/tmp/zdtm_mount_complex_sharing02.tmp";
	char *zdtm_newns = getenv("ZDTM_NEWNS");

	MNTNS_ZDTM(mntns_before);
	MNTNS_ZDTM(mntns_after);
	int ret = 1;

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

	/* Prepare directories in criu root */
	mkdir(tmp, 0755);
	if (mount(tmp_source, tmp, "tmpfs", 0, NULL)) {
		pr_perror("mount tmpfs");
		return 1;
	}
	if (mount(NULL, tmp, NULL, MS_PRIVATE, NULL)) {
		pr_perror("make private");
		return 1;
	}
	sprintf(src, "%s/src", tmp);
	mkdir(src, 0755);

	/* Create a shared mount in criu mntns */
	if (mount(ext_source, src, "tmpfs", 0, NULL)) {
		pr_perror("mount tmpfs");
		return 1;
	}
	if (mount(NULL, src, NULL, MS_PRIVATE, NULL)) {
		pr_perror("make private");
		return 1;
	}
	if (mount(NULL, src, NULL, MS_SHARED, NULL)) {
		pr_perror("make shared");
		return 1;
	}

	/*
	 * Create temporary mntns, next mounts will not show up in criu mntns
	 */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("unshare");
		return 1;
	}

	/* Prepare directories in test root */
	sprintf(testdir, "%s/%s", root, dirname);
	mkdir(testdir, 0755);

	if (mount("tmpfs", testdir, "tmpfs", 0, NULL)) {
		pr_perror("mount tmpfs");
		return 1;
	}
	if (mount(NULL, testdir, NULL, MS_PRIVATE, NULL)) {
		pr_perror("make private");
		return 1;
	}

	sprintf(dst_a, "%s/%s/dst_a", root, dirname);
	mkdir(dst_a, 0755);
	sprintf(dst_b, "%s/%s/dst_b", root, dirname);
	mkdir(dst_b, 0755);
	sprintf(dst_c, "%s/%s/dst_c", root, dirname);
	mkdir(dst_c, 0755);
	sprintf(dst_d, "%s/%s/dst_d", root, dirname);
	mkdir(dst_d, 0755);

	/*
	 * Populate to the tests root subdirectories of the src mount
	 */
	sprintf(src_a, "%s/src/a", tmp);
	mkdir(src_a, 0755);
	if (mount(src_a, dst_a, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}
	sprintf(src_b, "%s/src/b", tmp);
	mkdir(src_b, 0755);
	if (mount(src_b, dst_b, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}
	sprintf(src_c, "%s/src/c", tmp);
	mkdir(src_c, 0755);
	if (mount(src_c, dst_c, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}
	sprintf(src_d, "%s/src/d", tmp);
	mkdir(src_d, 0755);
	if (mount(src_d, dst_d, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}

test:
	test_init(argc, argv);

	if (mount_loop())
		goto err;

	if (mntns_parse_mountinfo(&mntns_before))
		goto err;

	test_daemon();
	test_waitsig();

	if (mntns_parse_mountinfo(&mntns_after))
		goto err;

	if (mntns_compare(&mntns_before, &mntns_after))
		goto err;

	pass();
	ret = 0;
err:
	mntns_free_all(&mntns_before);
	mntns_free_all(&mntns_after);
	if (ret)
		fail();
	return ret;
}
