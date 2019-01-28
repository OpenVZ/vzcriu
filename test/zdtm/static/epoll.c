#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
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
#include <sys/socket.h>
#include <sys/un.h>

#include "zdtmtst.h"

const char *test_doc	= "Check for epoll";
const char *test_author	= "Andrei Vagin <avagin@openvz.org>";

#define DUPFDNO		999

int main(int argc, char *argv[])
{
	int epollfd1, epollfd2, fd;
	struct epoll_event ev;
	task_waiter_t t;
	int i, ret;
	pid_t pid;

	struct pipes_s {
		int	pipefd[2];
	} pipes[250];

	test_init(argc, argv);
	task_waiter_init(&t);

	epollfd1 = epoll_create(1);
	if (epollfd1 < 0) {
		pr_perror("epoll_create failed");
		exit(1);
	}
	epollfd2 = epoll_create(1);
	if (epollfd2 < 0) {
		pr_perror("epoll_create failed");
		exit(1);
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN | EPOLLOUT;

	for (i = 0; i < ARRAY_SIZE(pipes); i++) {
		if (pipe(pipes[i].pipefd)) {
			pr_err("Can't create pipe %d\n", i);
			exit(1);
		}

		if (i % 2) {
			int nfd;

			nfd = dup2(pipes[i].pipefd[0], i + 700);
			if (nfd < 0) {
				pr_err("dup2");
				exit(1);
			}
			close(pipes[i].pipefd[0]);
			pipes[i].pipefd[0] = nfd;
		}

		ev.data.u64 = i;
		fd = dup2(pipes[i].pipefd[0], DUPFDNO);
		if (fd < 0) {
			pr_perror("Can't dup %d to %d", pipes[i].pipefd[0], DUPFDNO);
			exit(1);
		}

		test_msg("epoll %d add %d native\n", epollfd1, pipes[i].pipefd[0]);
		if (epoll_ctl(epollfd1, EPOLL_CTL_ADD, pipes[i].pipefd[0], &ev)) {
			pr_perror("Can't add pipe %d", pipes[i].pipefd[0]);
			exit(1);
		}

		test_msg("epoll %d add %d dup'ed from %d\n", epollfd1, fd, pipes[i].pipefd[0]);
		if (epoll_ctl(epollfd2, EPOLL_CTL_ADD, fd, &ev)) {
			pr_perror("Can't add pipe %d", fd);
			exit(1);
		}

		close(fd);
		test_msg("epoll source %d closed\n", fd);
	}

	pid = test_fork();
	if (pid < 0) {
		pr_err("Can't fork()\n");
		exit(1);
	} else if (pid == 0) {
		struct pipes_s subpipes[2];
		uint8_t cw = 1, cr;
		int epollfd3;

		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN | EPOLLOUT;

		epollfd3 = epoll_create(1);
		if (epollfd3 < 0) {
			pr_perror("epoll_create failed");
			exit(1);
		}

		for (i = 0; i < ARRAY_SIZE(subpipes); i++) {
			if (pipe(subpipes[i].pipefd)) {
				pr_perror("Can't create subpipe\n");
				exit(1);
			}
		}

		for (i = 0; i < ARRAY_SIZE(subpipes); i++) {
			ev.data.u64 = i;
			ret = dup(subpipes[i].pipefd[0]);
			if (ret < 0) {
				pr_perror("Can't dup");
				exit(1);
			}

			test_msg("epoll %d add subpipe %d duped from %d to parent\n",
				 epollfd1, ret, subpipes[i].pipefd[0]);
			if (epoll_ctl(epollfd1, EPOLL_CTL_ADD, ret, &ev)) {
				pr_perror("Can't add duped pipe %d to parent", ret);
				exit(1);
			}

			test_msg("epoll %d add subpipe %d duped from %d to own\n",
				 epollfd3, ret, subpipes[i].pipefd[0]);
			if (epoll_ctl(epollfd3, EPOLL_CTL_ADD, ret, &ev)) {
				pr_perror("Can't add duped pipe %d to own", ret);
				exit(1);
			}

			close(subpipes[i].pipefd[0]);
			subpipes[i].pipefd[0] = ret;
		}

		task_waiter_complete(&t, 1);
		task_waiter_wait4(&t, 2);

		for (i = 0; i < ARRAY_SIZE(subpipes); i++) {
			if (write(subpipes[i].pipefd[1], &cw, sizeof(cw)) != sizeof(cw)) {
				pr_perror("Unable to write into a pipe\n");
				exit(1);
			}

			if (epoll_wait(epollfd1, &ev, 1, -1) != 1) {
				pr_perror("Unable to wain events");
				exit(1);
			}

			if (ev.data.u64 != i) {
				pr_err("ev.fd=%d ev.data.u64=%#llx (%d expected)\n",
				       ev.data.fd, (long long)ev.data.u64, i);
				exit(1);
			}

			if (epoll_wait(epollfd3, &ev, 1, -1) != 1) {
				pr_perror("Unable to wain events");
				exit(1);
			}

			if (ev.data.u64 != i) {
				pr_err("ev.fd=%d ev.data.u64=%#llx (%d expected)\n",
				       ev.data.fd, (long long)ev.data.u64, i);
				exit(1);
			}

			if (read(subpipes[i].pipefd[0], &cr, sizeof(cr)) != sizeof(cr)) {
				pr_perror("read");
				exit(1);
			}
		}

		exit(0);
	}

	task_waiter_wait4(&t, 1);

	test_daemon();
	test_waitsig();

	ret = 0;
	for (i = 0; i < ARRAY_SIZE(pipes); i++) {
		uint8_t cw = 1, cr;

		if (write(pipes[i].pipefd[1], &cw, sizeof(cw)) != sizeof(cw)) {
			pr_perror("Unable to write into a pipe\n");
			return 1;
		}

		if (epoll_wait(epollfd1, &ev, 1, -1) != 1) {
			pr_perror("Unable to wain events");
			return 1;
		}
		if (ev.data.u64 != i) {
			pr_err("ev.fd=%d ev.data.u64=%#llx (%d expected)\n",
			       ev.data.fd, (long long)ev.data.u64, i);
			ret |= 1;
		}

		if (epoll_wait(epollfd2, &ev, 1, -1) != 1) {
			pr_perror("Unable to wain events");
			return 1;
		}
		if (ev.data.u64 != i) {
			pr_err("ev.fd=%d ev.data.u64=%#llx (%d expected)\n",
			       ev.data.fd, (long long)ev.data.u64, i);
			ret |= 1;
		}

		if (read(pipes[i].pipefd[0], &cr, sizeof(cr)) != sizeof(cr)) {
			pr_perror("read");
			return 1;
		}
	}

	if (ret)
		return 1;

	task_waiter_complete(&t, 2);

	if (waitpid(pid, &ret, 0) != pid) {
		pr_perror("Can't wait child");
		return 1;
	}

	if (!WIFEXITED(ret) || WEXITSTATUS(ret) != 0) {
		pr_perror("Can't finish child");
		return 1;
	}

	pass();
	return 0;
}
