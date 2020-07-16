#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <linux/fanotify.h>
#include "fsnotify.h"
#include "zdtmtst.h"

const char *test_doc = "Check for fanotify delivery";
const char *test_author = "Cyrill Gorcunov <gorcunov@openvz.org>";

const char fanotify_path[] = "fanotify-del-after-cr";

#define BUFF_SIZE (8192)

int main(int argc, char *argv[])
{
	struct fanotify_obj old = {}, new = {};
	int fa_fd, fd, del_after;
	char buf[BUFF_SIZE];
	ssize_t length;
	int ns = getenv("ZDTM_NEWNS") != NULL;

	test_init(argc, argv);

	if (ns) {
		if (mkdir("/tmp", 666) && errno != EEXIST) {
			pr_perror("Unable to create the /tmp directory");
			return -1;
		}
		if (mount("zdtm", "/tmp", "tmpfs", 0, NULL)) {
			pr_perror("Unable to mount tmpfs into %s", "/tmp");
		}
	}

	fa_fd = fanotify_init(FAN_NONBLOCK | FAN_CLASS_NOTIF | FAN_UNLIMITED_QUEUE, O_RDONLY | O_LARGEFILE);
	if (fa_fd < 0) {
		pr_perror("fanotify_init failed");
		exit(1);
	}

	del_after = open(fanotify_path, O_CREAT | O_TRUNC);
	if (del_after < 0) {
		pr_perror("open failed");
		exit(1);
	}

	if (fanotify_mark(fa_fd, FAN_MARK_ADD, FAN_MODIFY | FAN_ACCESS | FAN_OPEN | FAN_CLOSE, AT_FDCWD,
			  fanotify_path)) {
		pr_perror("fanotify_mark failed");
		exit(1);
	}

	if (fanotify_mark(fa_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_ONDIR | FAN_OPEN | FAN_CLOSE, AT_FDCWD, "/tmp")) {
		pr_perror("fanotify_mark failed");
		exit(1);
	}

	if (fanotify_mark(fa_fd, FAN_MARK_ADD | FAN_MARK_MOUNT | FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY,
			  FAN_MODIFY | FAN_ACCESS, AT_FDCWD, "/tmp")) {
		pr_perror("fanotify_mark failed");
		exit(1);
	}

	if (fanotify_obj_parse(fa_fd, &old, 3)) {
		pr_perror("parsing fanotify fdinfo failed");
		exit(1);
	}

	fanotify_obj_show(&old);

	test_daemon();
	test_waitsig();

	fd = open("/", O_RDONLY);
	close(fd);

	fd = open(fanotify_path, O_RDWR);
	close(fd);

	if (unlink(fanotify_path)) {
		fail("can't unlink %s", fanotify_path);
		exit(1);
	}

	if (fanotify_obj_parse(fa_fd, &new, 3)) {
		fail("parsing fanotify fdinfo failed");
		exit(1);
	}

	fanotify_obj_show(&new);

	if (fanotify_obj_cmp(&old, &new, true)) {
		fail("fanotify mismatch on fdinfo level");
		exit(1);
	}

	length = read(fa_fd, buf, sizeof(buf));
	if (length <= 0) {
		fail("No events in fanotify queue");
		exit(1);
	}

	if (fanotify_mark(fa_fd, FAN_MARK_REMOVE | FAN_MARK_MOUNT, FAN_ONDIR | FAN_OPEN | FAN_CLOSE, AT_FDCWD,
			  "/tmp")) {
		pr_perror("fanotify_mark failed");
		exit(1);
	}

	pass();

	return 0;
}
