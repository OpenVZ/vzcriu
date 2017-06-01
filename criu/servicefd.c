#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#include "servicefd.h"
#include "bitops.h"
#include "criu-log.h"

#include "common/bug.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "sfd: "

// #define SFD_DEBUG

#ifdef SFD_DEBUG
# define pr_sfd_debug(fmt, ...)	pr_debug(fmt, ##__VA_ARGS__)
#else
# define pr_sfd_debug(fmt, ...)
#endif

static DECLARE_BITMAP(sfd_map, SERVICE_FD_MAX);

static int service_fd_rlim_cur;
static int service_fd_id;

#define __gen_type_str(x)	[x] = __stringify_1(x)
static char * const type_str[SERVICE_FD_MAX] = {
	__gen_type_str(LOG_FD_OFF),
	__gen_type_str(IMG_FD_OFF),
	__gen_type_str(PROC_FD_OFF),
	__gen_type_str(CTL_TTY_OFF),
	__gen_type_str(SELF_STDIN_OFF),
	__gen_type_str(CR_PROC_FD_OFF),
	__gen_type_str(ROOT_FD_OFF),
	__gen_type_str(CGROUP_YARD),
	__gen_type_str(USERNSD_SK),
	__gen_type_str(NS_FD_OFF),
	__gen_type_str(TRANSPORT_FD_OFF),
	__gen_type_str(RPC_SK_OFF),
	__gen_type_str(FDSTORE_SK_OFF),
	__gen_type_str(SPFS_MNGR_SK),
};
#undef __gen_type_str

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
	int ret;

	BUG_ON((int)type <= SERVICE_FD_MIN || (int)type >= SERVICE_FD_MAX);
	BUG_ON(type >= ARRAY_SIZE(type_str));

	pr_sfd_debug("install %d/%d (%s)\n", service_fd_id, sfd, type_str[type]);
	if (test_bit(type, sfd_map)) {
		pr_sfd_debug("\tclose previous %d/%d (%s)\n",
			     service_fd_id, sfd, type_str[type]);
		close_service_fd(type);
	}

	ret = fcntl(fd, F_DUPFD_CLOEXEC, sfd);
	if (ret != sfd) {
		if (ret < 0) {
			pr_perror("%d/%d -> %d/%d (%s) transition failed",
				  service_fd_id, fd, sfd,
				  service_fd_id, type_str[type]);
		} else {
			pr_err("%d/%d (%s) is busy\n",
			       service_fd_id, sfd,
			       type_str[type]);
			close(ret);
		}
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
	pr_sfd_debug("close %d/%d (%s)\n", service_fd_id, fd, type_str[type]);
	return 0;
}

int clone_service_fd(int id)
{
	int ret, i;

	if (service_fd_id == id)
		return 0;

	pr_sfd_debug("clone %d/%d\n", service_fd_id, id);
	for (i = SERVICE_FD_MIN + 1; i < SERVICE_FD_MAX; i++) {
		int old = get_service_fd(i);
		int new = __get_service_fd(i, id);

		if (old < 0)
			continue;

		/*
		 * Cloning of service fds happen at early stage
		 * where no other files needed are opened, so
		 * for simplicity just close the destination.
		 *
		 * FIXME: Still better to invent more deep tracking
		 * of service files opened, say every rsti(item)
		 * structure should have own sfd_map and everything
		 * should be under appropriate shared locking.
		 */
		close(new);
		ret = fcntl(old, F_DUPFD, new);
		if (ret < 0 || ret != new) {
			if (ret < 0) {
				/*
				 * The source fd might be reserved
				 * and not yet created.
				 */
				if (errno == EBADF)
					continue;
				pr_perror("clone %d/%d -> %d/%d (%s) transition failed",
					  service_fd_id, old, id, new, type_str[i]);
			} else {
				pr_err("clone %d/%d -> %d/%d (%s) busy\n",
				       service_fd_id, old, id, new, type_str[i]);
				close(ret);
			}
			return -1;
		}
		pr_sfd_debug("clone %d/%d -> %d/%d (%s)\n",
			     service_fd_id, old, id, new, type_str[i]);
	}

	service_fd_id = id;
	return 0;
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
