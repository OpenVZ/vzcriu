#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#include "servicefd.h"
#include "bitops.h"
#include "log.h"

#include "common/bug.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "sfd: "

static DECLARE_BITMAP(sfd_map, SERVICE_FD_MAX);

static int service_fd_rlim_cur;
static int service_fd_id;

int init_service_fd(void)
{
	struct rlimit64 rlimit;

	/*
	 * Service FDs are those that most likely won't
	 * conflict with any 'real-life' ones
	 */
	if (syscall(__NR_prlimit64, getpid(), RLIMIT_NOFILE, NULL, &rlimit)) {
		pr_perror("Can't get rlimit");
		return -1;
	}

	service_fd_rlim_cur = (int)rlimit.rlim_cur;
	BUG_ON(service_fd_rlim_cur < SERVICE_FD_MAX);

	return 0;
}

static int __get_service_fd(enum sfd_type type, int service_fd_id)
{
	return service_fd_rlim_cur - type - SERVICE_FD_MAX * service_fd_id;
}

int service_fd_min_fd(void)
{
	return service_fd_rlim_cur - (SERVICE_FD_MAX - 1) - SERVICE_FD_MAX * service_fd_id;
}

int reserve_service_fd(enum sfd_type type)
{
	int sfd = __get_service_fd(type, service_fd_id);

	BUG_ON((int)type <= SERVICE_FD_MIN || (int)type >= SERVICE_FD_MAX);

	set_bit(type, sfd_map);
	return sfd;
}

int install_service_fd(enum sfd_type type, int fd)
{
	int sfd = __get_service_fd(type, service_fd_id);

	BUG_ON((int)type <= SERVICE_FD_MIN || (int)type >= SERVICE_FD_MAX);

	if (dup3(fd, sfd, O_CLOEXEC) != sfd) {
		pr_perror("Dup %d -> %d failed", fd, sfd);
		return -1;
	}

	set_bit(type, sfd_map);
	return sfd;
}

int get_service_fd(enum sfd_type type)
{
	BUG_ON((int)type <= SERVICE_FD_MIN || (int)type >= SERVICE_FD_MAX);

	if (!test_bit(type, sfd_map))
		return -1;

	return __get_service_fd(type, service_fd_id);
}

int close_service_fd(enum sfd_type type)
{
	int fd = get_service_fd(type);
	if (fd < 0)
		return 0;

	close(fd);
	clear_bit(type, sfd_map);
	return 0;
}

int clone_service_fd(int id)
{
	int ret = -1, i;

	if (service_fd_id == id)
		return 0;

	for (i = SERVICE_FD_MIN + 1; i < SERVICE_FD_MAX; i++) {
		int old = get_service_fd(i);
		int new = __get_service_fd(i, id);

		if (old < 0)
			continue;
		ret = dup2(old, new);
		if (ret == -1) {
			if (errno == EBADF)
				continue;
			pr_perror("Unable to clone %d->%d", old, new);
		}
	}

	service_fd_id = id;
	ret = 0;

	return ret;
}

bool is_any_service_fd(int fd)
{
	return fd > __get_service_fd(SERVICE_FD_MAX, service_fd_id) &&
		fd < __get_service_fd(SERVICE_FD_MIN, service_fd_id);
}

bool is_service_fd(int fd, enum sfd_type type)
{
	return fd == get_service_fd(type);
}
