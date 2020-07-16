#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>

#include "zdtmtst.h"

const char *test_doc = "Check that criu can dump inotify on cgroup";
const char *test_author = "Andrey Zhadchenko <andrey.zhadchenko@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "cgin_zdtmtst";
#define SUBNAME	   "incg00"
#define SUBSUBNAME "in_test"
#define BUFSZ	   1028

int main(int argc, char **argv)
{
	int fd = -1, ret, cgfd;
	char buf[BUFSZ] = { 0 };
	char aux[128] = { 0 };
	char incg[128] = { 0 };
	char tasks[256] = { 0 };
	char intest[256] = { 0 };
	struct inotify_event *event;
	void *ptr;
	unsigned int mask = IN_CREATE;
	int event_count = 0;
	int fail = 1;

	test_init(argc, argv);

	if (mkdir(dirname, 0700) < 0) {
		pr_perror("Can't make dir");
		return 1;
	}

	sprintf(aux, "none,name=%s", cgname);
	if (mount("none", dirname, "cgroup", 0, aux)) {
		pr_perror("Can't mount cgroups");
		goto out_rd;
	}

	fd = inotify_init1(IN_NONBLOCK);
	if (fd < 0) {
		pr_perror("inotify_init failed");
		goto out;
	}

	sprintf(incg, "%s/%s", dirname, SUBNAME);
	ret = mkdir(incg, 0775);
	if (ret) {
		pr_perror("error at mkdir %d", ret);
		goto out;
	}

	sprintf(tasks, "%s/tasks", incg);

	cgfd = open(tasks, O_WRONLY);
	if (cgfd < 0) {
		pr_perror("Can't open tasks");
		goto out;
	}

	ret = write(cgfd, "0", 2);
	close(cgfd);

	if (ret < 0) {
		pr_perror("Can't move self to cg");
		goto out;
	}

	if (inotify_add_watch(fd, incg, mask) < 0) {
		pr_perror("inotify_add_watch failed");
		goto out;
	}

	test_daemon();
	test_waitsig();

	sprintf(intest, "%s/%s", incg, SUBSUBNAME);
	ret = mkdir(intest, 0775);
	if (ret) {
		pr_perror("error at mkdir %s %d", intest, ret);
		goto out;
	}

	ret = read(fd, buf, BUFSZ);
	if (ret == -1) {
		pr_perror("expected event did not occur!");
		goto out;
	}

	for (ptr = buf; (char *)ptr < buf + ret; ptr += sizeof(struct inotify_event) + event->len) {
		event = (struct inotify_event *)ptr;

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
		fail = 0;
	} else {
		test_msg("Too less or too much events!");
	}

out:
	umount(dirname);
out_rd:
	rmdir(dirname);
	close(fd);

	return fail;
}
