#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "zdtmtst.h"

#ifndef F_SETSIG
#define F_SETSIG	10	/* for sockets. */
#define F_GETSIG	11	/* for sockets. */
#endif

const char *test_doc	= "Check for eventfs";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

#define EVENTFD_INITIAL	30
#define EVENTFD_FINAL1	90
#define EVENTFD_FINAL2	(EVENTFD_FINAL1 * 2)
#define DUPFDNO		999

int main(int argc, char *argv[])
{
	uint64_t v = EVENTFD_INITIAL;
	int efd, ret, epollfd, fd;
	struct epoll_event ev;
	int i;

	struct {
		int	pipefd1[2];
		int	pipefd2[2];
	} pipes[10];

	test_init(argc, argv);

	epollfd = epoll_create(1);
	if (epollfd < 0) {
		pr_perror("epoll_create failed");
		exit(1);
	}

	efd = eventfd((unsigned int)v, EFD_NONBLOCK);
	if (efd < 0) {
		pr_perror("eventfd failed");
		exit(1);
	}

	test_msg("created eventfd with %lld\n", (long long)v);

	memset(&ev, 0xff, sizeof(ev));
	ev.events = EPOLLIN | EPOLLOUT;

	for (i = 0; i < ARRAY_SIZE(pipes); i++) {
		if (pipe(pipes[i].pipefd1) || pipe(pipes[i].pipefd2)) {
			pr_err("Can't create pipe %d\n", i);
			exit(1);
		}

		test_msg("epoll %d add %d native\n", epollfd, pipes[i].pipefd1[0]);
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, pipes[i].pipefd1[0], &ev)) {
			pr_perror("Can't add pipe %d", pipes[i].pipefd1[0]);
			exit(1);
		}

		fd = dup2(pipes[i].pipefd2[0], DUPFDNO);
		if (fd < 0) {
			pr_perror("Can't dup %d to %d", pipes[i].pipefd2[0], DUPFDNO);
			exit(1);
		}
		test_msg("epoll %d add %d dup'ed from %d\n", epollfd, fd, pipes[i].pipefd2[0]);

		close(fd);
		test_msg("epoll source %d closed\n", fd);
	}

	ret = write(efd, &v, sizeof(v));
	if (ret != sizeof(v)) {
		pr_perror("write failed");
		exit(1);
	}

	ret = write(efd, &v, sizeof(v));
	if (ret != sizeof(v)) {
		pr_perror("write failed");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	ret = read(efd, &v, sizeof(v));
	if (ret != sizeof(v)) {
		pr_perror("read failed");
		exit(1);
	}

	if (v != EVENTFD_FINAL1) {
		fail("EVENTFD_FINAL1 mismatch (got %lld but %lld expected)\n",
		     (long long)v, (long long)EVENTFD_FINAL1);
		exit(1);
	}

	ret = write(efd, &v, sizeof(v));
	if (ret != sizeof(v)) {
		pr_perror("write failed");
		exit(1);
	}

	ret = write(efd, &v, sizeof(v));
	if (ret != sizeof(v)) {
		pr_perror("write failed");
		exit(1);
	}

	ret = read(efd, &v, sizeof(v));
	if (ret != sizeof(v)) {
		pr_perror("read failed");
		exit(1);
	}

	if (v != EVENTFD_FINAL2) {
		fail("EVENTFD_FINAL2 mismatch (got %lld but %lld expected)\n",
		     (long long)v, (long long)EVENTFD_FINAL2);
		exit(1);
	}

	pass();
	return 0;
}
