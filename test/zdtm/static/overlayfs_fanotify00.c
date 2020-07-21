#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <linux/limits.h>
#include <linux/fanotify.h>
#include "fsnotify.h"
#include "zdtmtst.h"
#include "fs.h"

#define BUFF_SIZE (8192)

const char *test_doc    = "Check fanotify on overlayfs";
const char *test_author = "Valeriy Vdovin <valeriy.vdovin@virtuozzo.com>";

char *dirname = "overlayfs_mount";
TEST_OPTION(dirname, string, "directory name", 1);

#define TEST_WORD	"testtest"
#define TEST_WORD2	"TESTTEST"

struct test_context {
	int fa_fd;
	int opened_fd;
	char *ovl_dir;
	char *ovl_file;
	char *fanotify_file;
	struct fanotify_obj old;
	struct fanotify_obj new;
};

static int fanotify_setup(struct test_context *ctx)
{
	char ovl_file[PATH_MAX];
	snprintf(ovl_file, sizeof(ovl_file), "%s/ovl_file", ctx->ovl_dir);
	ctx->ovl_file = strdup(ovl_file);

	if (!ctx->ovl_file) {
		pr_perror("Can't copy ovl file name");
		return 1;
	}

	ctx->fa_fd = fanotify_init(FAN_NONBLOCK | FAN_CLASS_NOTIF | FAN_UNLIMITED_QUEUE,
			      O_RDONLY | O_LARGEFILE);
	if (ctx->fa_fd < 0) {
		pr_perror("fanotify_init failed");
		return 1;
	}

	ctx->opened_fd = open(ctx->ovl_file, O_CREAT | O_TRUNC);
	if (ctx->opened_fd < 0) {
		pr_perror("open failed");
		return 1;
	}

	/*
	 * Mark "ovl_dir/ovl_file" for notifications on modify/access/open/close
	 * file operations
	 */
	if (fanotify_mark(ctx->fa_fd, FAN_MARK_ADD,
			  FAN_MODIFY | FAN_ACCESS | FAN_OPEN | FAN_CLOSE,
			  AT_FDCWD, ctx->ovl_file)) {
		pr_perror("fanotify_mark failed");
		return 1;
	}

	/*
	 * Monitor open/close events for all files including directories
	 * (FAN_ONDIR), within the scope of "olv_dir" mountpoint.
	 */
	if (fanotify_mark(ctx->fa_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
			  FAN_ONDIR | FAN_OPEN | FAN_CLOSE,
			  AT_FDCWD, ctx->ovl_dir)) {
		pr_perror("fanotify_mark failed");
		return 1;
	}

	/*
	 * Ignore modify/access events for all files withing the scope of "ovl_dir"
	 * mountpoint.
	 */
	if (fanotify_mark(ctx->fa_fd, FAN_MARK_ADD | FAN_MARK_MOUNT |
			  FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY,
			  FAN_MODIFY | FAN_ACCESS,
			  AT_FDCWD, ctx->ovl_dir)) {
		pr_perror("fanotify_mark failed");
		return 1;
	}

	if (fanotify_obj_parse(ctx->fa_fd, &ctx->old, 3)) {
		pr_perror("parsing fanotify fdinfo failed");
		return 1;
	}

	fanotify_obj_show(&ctx->old);
	return 0;
}

static int fanotify_check(struct test_context *ctx)
{
	int fd, length;
	char buf[BUFF_SIZE];
	fd = open("/", O_RDONLY);
	close(fd);

	fd = open(ctx->ovl_file, O_RDWR);
	close(fd);

	if (unlink(ctx->ovl_file)) {
		fail("can't unlink %s\n", ctx->ovl_file);
		return 1;
	}

	if (fanotify_obj_parse(ctx->fa_fd, &ctx->new, 3)) {
		fail("parsing fanotify fdinfo failed\n");
		return 1;
	}

	fanotify_obj_show(&ctx->new);

	if (fanotify_obj_cmp(&ctx->old, &ctx->new, false)) {
		fail("fanotify mismatch on fdinfo level\n");
		return 1;
	}

	length = read(ctx->fa_fd, buf, sizeof(buf));
	if (length <= 0) {
		fail("No events in fanotify queue\n");
		return 1;
	}

	if (fanotify_mark(ctx->fa_fd, FAN_MARK_REMOVE | FAN_MARK_MOUNT,
			  FAN_ONDIR | FAN_OPEN | FAN_CLOSE,
			  AT_FDCWD, ctx->ovl_dir)) {
		pr_perror("fanotify_mark failed");
		return 1;
	}
	return 0;
}

/**
 * Prepare dirname, so that all mounts in it will not propagate and
 * will be destroyed together with our mount namespace. All files
 * created in it will not be visible on host and will remove together
 * with our mountns too.
 */
static int prepare_dirname(void)
{
	if (mkdir(dirname, 0700) && errno != EEXIST) {
		pr_perror("Failed to create %s", dirname);
		return -1;
	}

	if (mount("none", dirname, "tmpfs", 0, NULL)) {
		pr_perror("Failed to mount tmpfs on %s", dirname);
		return -1;
	}

	if (mount(NULL, dirname, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Failed to make mount %s private", dirname);
		return -1;
	}

	return 0;
}

/* overlayfs mount with upperdir (as docker uses) */
static int prepare_overlayfs(struct test_context *ctx)
{
	const char *lower_list[] = { "lower", NULL };
	const char *mountdir = "overlayfs";
	char mountpath[PATH_MAX];

	if (overlayfs_setup(dirname, lower_list, "upper", "work", mountdir)) {
		fail("failed to setup overlayfs for ro test");
		return 1;
	}

	snprintf(mountpath, sizeof(mountpath), "%s/%s", dirname, mountdir);
	ctx->ovl_dir = strdup(mountpath);
	if (!ctx->ovl_dir) {
		fail("Can't copy ovl dir name");
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 1;
	struct test_context ctx;
	memset(&ctx, 0, sizeof(ctx));

	test_init(argc, argv);

	if (prepare_dirname())
		return 1;

	if (prepare_overlayfs(&ctx))
		goto err;

	if (fanotify_setup(&ctx))
		goto err;

	test_daemon();
	test_waitsig();

	if (fanotify_check(&ctx))
		goto err;

	pass();
	ret = 0;
err:
	return ret;
}
