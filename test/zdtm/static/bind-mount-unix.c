#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check bind-mounts with unix socket";
const char *test_author	= "Cyrill Gorcunov <gorcunov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#ifdef ZDTM_BM_UNIX_SK_AND_GHOST
int create_ghost_sk(char *cwd, char *unix_name)
{
	int sk;
	int ret;
	struct sockaddr_un addr;
	char path_unix[PATH_MAX];

	/*
	 * Let's bind our ghost socket to the same
	 * path as we will bind bindmounted socket.
	 */
	ssprintf(path_unix, "%s/%s/aaa/bbb/%s",
		 cwd, dirname, unix_name);

	addr.sun_family = AF_UNIX;
	sstrncpy(addr.sun_path, path_unix);

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("open ghost sk");
		ret = 1;
		goto exit;
	}

	if (bind(sk, (struct sockaddr *) &addr, sizeof(struct sockaddr_un))) {
		pr_perror("bind ghost sk");
		ret = 1;
		goto exit;
	}

	unlink(addr.sun_path);
	ret = 0;

exit:
	return ret;
}
#endif

int main(int argc, char **argv)
{
	char path_unix[PATH_MAX], path_bind[PATH_MAX], path[PATH_MAX];
	char unix_name[] = "criu-log";
	char bind_name[] = "criu-bind-log";
	int sk = -1, skc = -1, ret = 1, fd;
	struct sockaddr_un addr;
	unsigned int addrlen;
	task_waiter_t t;
	struct stat st;
	int status;
	pid_t pid;
	char *cwd;

	char buf[] = "123456";
	char rbuf[sizeof(buf)];

	test_init(argc, argv);
	task_waiter_init(&t);

	mkdir(dirname, 0700);
	if (mount("none", dirname, "tmpfs", 0, NULL)) {
		pr_perror("Unable to mount %s", dirname);
		return 1;
	}

	ssprintf(path, "%s/%s", dirname, "aaa");
	mkdir(path, 0700);
	ssprintf(path, "%s/%s", dirname, "aaa/bbb");
	mkdir(path, 0700);

	cwd = get_current_dir_name();
	if (!cwd) {
		pr_perror("getcwd");
		exit(1);
	}
	ssprintf(path_bind, "%s/%s/%s", cwd, dirname, bind_name);

#ifdef ZDTM_BM_UNIX_SK_AND_GHOST
	if (create_ghost_sk(cwd, unix_name)) {
		pr_err("create_ghost_sk\n");
		exit(1);
	}
#endif

	/*
	 * Mounts-v2 engine uses "plain" structure of mounts,
	 * all mounts within mount namespace are mounted in
	 * one yard directory without nesting. This approach
	 * gives us big advantages: plain mounts allows us
	 * support overmounting case. But with unix sockets
	 * there is a problem.
	 * Generally, working with unix socket on server side
	 * looks like this:
	 *
	 * sizeof(struct sockaddr_un) = 110
	 * but may be we have a long path, so, we want to chdir
	 * somewhere and use relative path in addr.sun_path
	 * to make path shorter.
	 * chdir(namedir(.))
	 *
	 * addr.sun_family = AF_UNIX;
	 * sstrncpy(addr.sun_path, name(%)); <- max 108 bytes
	 *
	 * addrlen = sizeof(addr.sun_family) + strlen(addr.sun_path);
	 * sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	 * ret = bind(sk, (struct sockaddr *)&addr, addrlen);
	 *
	 * We binding socket to somewhere on vfs, path where we bind
	 * socket corresponds to some mount. Let's assume that
	 * full path in mount namespace to mountpoint of this mount is
	 * ns_mountpoint(+).
	 *
	 * Let's set up some symbols:
	 * namedir (.) - full path to CWD of process from where we bind sk
	 * ns_mountpoint (+) - full path to mountpoint where we binding sk
	 * name (%) - relative to namedir (.) path where we binding sk
	 * So, namedir (.) + name (%) - full path to binding place of sk
	 * in mount namespace.
	 *
	 * Now we are ready to draw pictures:
	 * full_path = /zdtm/static/bind-mount-unix.test/aaa/bbb/sk
	 *
	 * 1st case:
	 *                          %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
	 * full_path = /zdtm/static/bind-mount-unix.test/aaa/bbb/sk
	 *             ............^
	 *             +++++++++++++++++++++++++++++++++^
	 * in this case we have ns_mountpoint (+) > namedir(.)
	 * in mount-v2 with plain mounts structure we couldn't get "parent"
	 * directories for mount! In this case we "reconstructing" fake
	 * directory tree, chdir to some point, bind sk, then destroy tree.
	 * We should check in test that this case works fine.
	 *
	 * 2nd case:
	 *                                              %%%%%%%%%%%
	 * full_path = /zdtm/static/bind-mount-unix.test/aaa/bbb/sk
	 *             .................................^
	 *             +++++++++++++++++++++++++++++++++^
	 * this is corner case. We can (!) chdir to ns_mountpoint (+)
	 * and bind sk.
	 *
	 * 3rd case:
	 *                                                  %%%%%%%
	 * full_path = /zdtm/static/bind-mount-unix.test/aaa/bbb/sk
	 *             .....................................^
	 *             +++++++++++++++++++++++++++++++++^
	 * this is good and easy case - we just chdir to some path
	 * under (!) ns_mountpoint and bind sk. No problem here.
	 *
	 * 4th case (full path case):
	 *             %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
	 * full_path = /zdtm/static/bind-mount-unix.test/aaa/bbb/sk
	 *             +++++++++++++++++++++++++++++++++^
	 */

#ifdef ZDTM_BM_UNIX_SK_CASE1
	/* CWD = /test/zdtm
	 * path_unix = bind-mount-unix.test/aaa/bbb/sk
	 */
	ssprintf(path_unix, "%s/aaa/bbb/%s", dirname, unix_name);
#endif

#ifdef ZDTM_BM_UNIX_SK_CASE2
	if (chdir(dirname)) {
		pr_perror("Unable to chdir %s", dirname);
		return 1;
	}

	/* CWD = /test/zdtm/bind-mount-unix02.test
	 * path_unix = aaa/bbb/sk
	 */
	ssprintf(path_unix, "aaa/bbb/%s", unix_name);
#endif

#ifdef ZDTM_BM_UNIX_SK_CASE3
	ssprintf(path, "%s/%s", dirname, "aaa");
	if (chdir(path)) {
		pr_perror("Unable to chdir %s", path);
		return 1;
	}

	/* CWD = /test/zdtm/bind-mount-unix03.test/aaa
	 * path_unix = bbb/sk
	 */
	ssprintf(path_unix, "bbb/%s", unix_name);
#endif

#ifdef ZDTM_BM_UNIX_SK_CASE4
	/* CWD = *not important*
	 * path_unix = /zdtm/static/bind-mount-unix.test/aaa/bbb/sk
	 */
	ssprintf(path_unix, "%s/%s/aaa/bbb/%s",
		 cwd, dirname, unix_name);
#endif

	unlink(path_bind);
	unlink(path_unix);

	fd = open(path_bind, O_RDONLY | O_CREAT);
	if (fd < 0) {
		pr_perror("Can't open %s", path_bind);
		return 1;
	}
	close(fd);

	addr.sun_family = AF_UNIX;
	sstrncpy(addr.sun_path, path_unix);
	addrlen = sizeof(addr.sun_family) + strlen(path_unix);

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("Can't create socket %s", path_unix);
		return 1;
	}

	ret = bind(sk, (struct sockaddr *)&addr, addrlen);
	if (ret) {
		pr_perror("Can't bind socket %s", path_unix);
		return 1;
	}

	if (stat(path_unix, &st) == 0) {
		test_msg("path %s st.st_ino %#lx st.st_mode 0%o (sock %d)\n",
			 path_unix, (unsigned long)st.st_ino,
			 (int)st.st_mode, !!S_ISSOCK(st.st_mode));
	} else {
		pr_perror("Can't stat on %s", path_unix);
		return 1;
	}

	if (mount(path_unix, path_bind, NULL, MS_BIND | MS_REC, NULL)) {
		pr_perror("Unable to bindmount %s -> %s", path_unix, path_bind);
		return 1;
	}

	if (stat(path_unix, &st) == 0) {
		test_msg("path %s st.st_dev %#x st.st_rdev %#x st.st_ino %#lx st.st_mode 0%o (sock %d)\n",
			 path_unix, (int)st.st_dev, (int)st.st_rdev, (unsigned long)st.st_ino,
			 (int)st.st_mode, !!S_ISSOCK(st.st_mode));
	} else {
		pr_perror("Can't stat on %s", path_unix);
		return 1;
	}

	if (stat(path_bind, &st) == 0) {
		test_msg("path %s st.st_dev %#x st.st_rdev %#x st.st_ino %#lx st.st_mode 0%o (sock %d)\n",
			 path_bind, (int)st.st_dev, (int)st.st_rdev, (unsigned long)st.st_ino,
			 (int)st.st_mode, !!S_ISSOCK(st.st_mode));
	} else {
		pr_perror("Can't stat on %s", path_bind);
		return 1;
	}

	pid = test_fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		return 1;
	} else if (pid == 0) {
		skc = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (skc < 0) {
			pr_perror("Can't create client socket");
			_exit(1);
		}

		addr.sun_family = AF_UNIX;
		sstrncpy(addr.sun_path, path_bind);
		addrlen = sizeof(addr.sun_family) + strlen(path_bind);

		ret = connect(skc, (struct sockaddr *)&addr, addrlen);
		if (ret) {
			pr_perror("Can't connect\n");
			_exit(1);
		} else
			test_msg("Connected to %s", addr.sun_path);

		task_waiter_complete(&t, 1);
		task_waiter_wait4(&t, 2);

		ret = sendto(skc, buf, sizeof(buf), 0, (struct sockaddr *)&addr, addrlen);
		if (ret != (int)sizeof(buf)) {
			pr_perror("Can't send data on client");
			_exit(1);
		}

		close(skc);
		_exit(0);
	}

	task_waiter_wait4(&t, 1);

	test_daemon();
	test_waitsig();

	task_waiter_complete(&t, 2);

	ret = read(sk, rbuf, sizeof(rbuf));
	if (ret < 0) {
		fail("Can't read data");
		goto err;
	}

	if (ret != sizeof(buf) || memcmp(buf, rbuf, sizeof(buf))) {
		fail("Data mismatch");
		goto err;
	}

	ret = wait(&status);
	if (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
		kill(pid, SIGKILL);
		fail("Unable to wait child");
	} else {
		ret = 0;
		pass();
	}

err:
	umount2(path_bind, MNT_DETACH);
	umount2(dirname, MNT_DETACH);
	unlink(path_bind);
	unlink(path_unix);
	close(sk);

	return ret ? 1 : 0;
}
