#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <mqueue.h>
#include <sys/mount.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that criu can dump inotify on mqueue mount";
const char *test_author	= "Andrey Zhadchenko <andrey.zhadchenko@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "mqueue mount directory name", 1);
#define MQ_NAME "/test_q"
#define BUFSZ	2048

int main(int argc, char **argv)
{
	int fd = -1, ret;
	mqd_t mq;
	char buf[BUFSZ] = {0};
	struct inotify_event *event;
	void *ptr;
	unsigned int mask = IN_CREATE;
	int event_count = 0;
	int fail = 1;

	test_init(argc, argv);

	if (mkdir(dirname, 0666) < 0) {
		pr_perror("Unable to create dir");
		return 1;
	}

	if (mount("none", dirname, "mqueue", 0, 0)) {
		pr_perror("Can't mount mqueue");
		goto out;
	}

	fd = inotify_init1(IN_NONBLOCK);
	if (fd < 0) {
		pr_perror("inotify_init failed");
		goto out_umount;
	}

	if (inotify_add_watch(fd, dirname, mask) < 0) {
		pr_perror("inotify_add_watch failed");
		goto out_umount;
	}

	/*
	 * Generally mqueue mount is not supported.
	 * Dumping is only possible if there is no mqueues and mount is empty
	 */

	test_daemon();
	test_waitsig();

	mq = mq_open(MQ_NAME, O_RDWR | O_CREAT, 0666, NULL);
	if (mq == (mqd_t)-1) {
		pr_perror("Unable to create mqueue");
		goto out_umount;
	}

	ret = read(fd, buf, BUFSZ);
	if (ret == -1) {
		pr_perror("expected event did not occure!");
		goto out_mq;
	}

	for (ptr = buf; (char *)ptr < buf + ret; ptr += sizeof(struct inotify_event) + event->len) {

		event = (struct inotify_event *) ptr;

		if (event->mask & IN_CREATE)
			test_msg("Event: create\n");
		else
			test_msg("Unknown event!\n");

		if (event->len)
			test_msg("\t%s\n", event->name);

		event_count++;
	}

	if (event_count == 1 && (event->mask & IN_CREATE)) {
		pass();
		fail  = 0;
	} else {
		test_msg("Too less or too much events!");
	}

out_mq:
	mq_close(mq);
	mq_unlink(MQ_NAME);
out_umount:
	umount(dirname);
	close(fd);
out:
	rmdir(dirname);

	return fail;
}
