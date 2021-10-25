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

const char *test_doc = "Check bind-mounting DGRAM unix socket with or without data or querer";
const char *test_author = "Andrey Zhadchenko <andrey.zhadchenko@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define MSG "Bindmounts are very easy and simple"

struct conf {
	int index;
	int bind_sk;
	int conn_sk;
	char *sk_path;
	char *bind_path;
	bool do_fill;
	bool do_bindmount;
	bool do_close_peer;
};

static struct conf tests[] = {
	{
		.do_fill = true,
		.do_bindmount = false,
		.do_close_peer = true,
		.bind_sk = -1,
		.conn_sk = -1,
	},
	{
		.do_fill = false,
		.do_bindmount = true,
		.do_close_peer = false,
		.bind_sk = -1,
		.conn_sk = -1,

	},
	{
		.do_fill = true,
		.do_bindmount = true,
		.do_close_peer = true,
		.bind_sk = -1,
		.conn_sk = -1,

	}
};

int prepare(struct conf *cfg)
{
	struct sockaddr_un addr;
	int addrlen, ret;

	cfg->sk_path = malloc(PATH_MAX);
	if (!cfg->sk_path) {
		pr_perror("malloc");
		return -1;
	}

	snprintf(cfg->sk_path, PATH_MAX, "%s/sk%d", dirname, cfg->index);

	addr.sun_family = AF_UNIX;
	sstrncpy(addr.sun_path, cfg->sk_path);
	addrlen = sizeof(addr.sun_family) + strlen(cfg->sk_path);

	cfg->bind_sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (cfg->bind_sk < 0) {
		pr_perror("socket %d", cfg->index);
		return -1;
	}

	ret = bind(cfg->bind_sk, (struct sockaddr *)&addr, addrlen);
	if (ret) {
		pr_perror("bind %d", cfg->index);
		return -1;
	}

	if (cfg->do_fill) {
		cfg->conn_sk = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (cfg->conn_sk < 0) {
			pr_perror("socket %d", cfg->index);
			return -1;
		}

		ret = connect(cfg->conn_sk, (struct sockaddr *)&addr, addrlen);
		if (ret) {
			pr_perror("connect %d", cfg->index);
			return -1;
		}

		ret = write(cfg->conn_sk, MSG, sizeof(MSG));

		if (ret < 0) {
			pr_perror("write %d", cfg->index);
			return -1;
		}

		if (cfg->do_close_peer) {
			close(cfg->conn_sk);
			cfg->conn_sk = -1;
		}
	}

	if (cfg->do_bindmount) {
		int fd;

		cfg->bind_path = malloc(PATH_MAX);
		if (!cfg->bind_path) {
			pr_perror("malloc");
			return -1;
		}

		snprintf(cfg->bind_path, PATH_MAX, "%s/bindsk%d", dirname, cfg->index);

		fd = creat(cfg->bind_path, 0600);
		if (fd < 0) {
			pr_perror("creat %s", cfg->bind_path);
			return -1;
		}
		close(fd);

		if (mount(cfg->sk_path, cfg->bind_path, NULL, MS_BIND, NULL)) {
			pr_perror("bindmount %d", cfg->index);
			return -1;
		}
	}

	return 0;
}

int check(struct conf *cfg)
{
	char buf[sizeof(MSG)];
	int ret;

	if (!cfg->do_fill)
		return 0;

	ret = read(cfg->bind_sk, buf, sizeof(buf));
	if (ret < 0) {
		pr_perror("after c/r: read %d", cfg->index);
		return -1;
	} else if (ret == 0) {
		fail("message lost after c/r");
		return -1;
	} else if (ret != sizeof(MSG)) {
		fail("corrupted message");
		return -1;
	}

	return 0;
}

void cleanup(struct conf *cfg)
{
	close(cfg->bind_sk);
	close(cfg->conn_sk);

	if (cfg->bind_path) {
		umount2(cfg->bind_path, MNT_DETACH);
		free(cfg->bind_path);
		cfg->bind_path = NULL;
	}

	if (cfg->sk_path) {
		unlink(cfg->sk_path);
		free(cfg->sk_path);
		cfg->sk_path = NULL;
	}
}

int main(int argc, char **argv)
{
	int i, ret = 1;

	test_init(argc, argv);

	if (mkdir(dirname, 0700)) {
		pr_perror("mkdir");
		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		tests[i].index = i;
		if (prepare(&tests[i])) {
			fail("failed to setup subcase #%d", i);
			goto out;
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (check(&tests[i])) {
			fail("failed to check subcase #%d", i);
			goto out;
		}
	}

	pass();
	ret = 0;

out:
	for (i = 0; i < ARRAY_SIZE(tests); i++)
		cleanup(&tests[i]);

	unlink(dirname);

	return ret;
}
