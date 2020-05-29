#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sched.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Check that utsname sub hasn't changed";
const char *test_author = "Alexander Mikhalitsyn <alexander@mihalicyn.com>";

static struct utsname utsnames[2] = {
	{ .nodename = "zdtm1.nodename.ru", .domainname = "nodename.ru" },
	{ .nodename = "zdtm2.nodename.ru", .domainname = "nodename.ru" }
};

static struct utsname after;

int setup_uts_ns(int i)
{
	if (unshare(CLONE_NEWUTS) < 0) {
		pr_perror("unshare");
		return 1;
	}

	if (sethostname(utsnames[i].nodename, strlen(utsnames[i].nodename) + 1)) {
		pr_perror("Unable to set hostname");
		return 1;
	}

	if (setdomainname(utsnames[i].domainname, strlen(utsnames[i].domainname) + 1)) {
		pr_perror("Unable to set domainname");
		return 1;
	}

	return 0;
}

int check_uts_ns(int i)
{
	uname(&after);

	if (strcmp(utsnames[i].nodename, after.nodename)) {
		fail("Nodename doesn't match");
		return 1;
	}
	if (strcmp(utsnames[i].domainname, after.domainname)) {
		fail("Domainname doesn't match");
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret, status;
	pid_t pid;
	task_waiter_t t1, t2;

	test_init(argc, argv);
	task_waiter_init(&t1);
	task_waiter_init(&t2);

	ret = setup_uts_ns(1);
	if (ret)
		exit(1);

	pid = test_fork();
	if (pid < 0) {
		pr_perror("can't fork");
		exit(1);
	}

	if (pid == 0) {
		pid = test_fork();
		if (pid < 0) {
			pr_perror("can't fork");
			exit(1);
		}

		if (pid == 0) {
			/* we should be in uts 1 */
			task_waiter_complete(&t2, 1);
			task_waiter_wait4(&t2, 2);

			ret = check_uts_ns(1);
			exit(ret);
		}

		ret = setup_uts_ns(0);
		if (ret) {
			kill(pid, SIGKILL);
			goto child_exit;
		}

		task_waiter_complete(&t1, 1);
		task_waiter_wait4(&t1, 2);

child_exit:
		ret = wait(&status);
		if (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
			kill(pid, SIGKILL);
			fail("Unable to wait child");
		} else {
			ret = 0;
		}

		if (!ret)
			ret = check_uts_ns(0);

		exit(ret);
	}

	task_waiter_wait4(&t1, 1);
	task_waiter_wait4(&t2, 1);
	test_daemon();
	test_waitsig();
	task_waiter_complete(&t1, 2);
	task_waiter_complete(&t2, 2);

	ret = wait(&status);
	if (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
		kill(pid, SIGKILL);
		fail("Unable to wait child");
	} else {
		ret = 0;
	}

	if (!ret)
		ret = check_uts_ns(1);

	if (!ret)
		pass();
	else
		fail();

	return 0;
}
