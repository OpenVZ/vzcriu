#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <sys/resource.h>

#include "zdtmtst.h"

const char *test_doc	= "Test huge number of pipes";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

#define TEST_STRING "Hello world"
#define NR_PIPES 2048
#define FD_MAX (NR_PIPES * 2 + 16)

int main(int argc, char ** argv)
{
	int pfd[NR_PIPES][2];
	struct rlimit lim;
	uint8_t buf[256];
	int ret, size, pipe_count = NR_PIPES;
	size_t i;

	test_init(argc, argv);

	if (getrlimit(RLIMIT_NOFILE, &lim) < 0) {
		pr_perror("Unable to getrlimit");
		return 1;
	}

	if (lim.rlim_cur < FD_MAX) {
		test_msg("Insufficient soft file descriptor rlimit to run original test. Trying to increase limit or lower pipe count.\n");

		if (lim.rlim_cur < lim.rlim_max) {
			rlim_t old_lim = lim.rlim_cur;
			lim.rlim_cur = lim.rlim_max;
			if (setrlimit(RLIMIT_NOFILE, &lim) < 0) {
				test_msg("Unable to raise fd limit from softlim to hardlim\n");
				lim.rlim_cur = old_lim;
			}
		}

		pipe_count = (FD_MAX < lim.rlim_cur) ? NR_PIPES : (lim.rlim_cur - 16) / 2;
		test_msg("Set pipe count to %d\n", pipe_count);
	}

	for (i = 0; i < pipe_count; i++) {
		ret = pipe(pfd[i]);
		if (ret < 0) {
			pr_perror("Can't create pipe %zu", i);
			return 1;
		}

		memset(buf, (unsigned char)i, sizeof(buf));

		size = 0;
		while (size < sizeof(buf)) {
			ret = write(pfd[i][1], buf, sizeof(buf));
			if (ret == -1) {
				if (errno == EAGAIN)
					break;
				pr_perror("write() on %zu failed", i);
				return 1;
			}
			size += ret;
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < pipe_count; i++) {
		size = 0;
		while (size < sizeof(buf)) {
			ret = read(pfd[i][0], buf, sizeof(buf));
			if (ret == 0)
				break;
			if (ret == -1) {
				pr_perror("read() on %zu failed", i);
				goto err;
			}
			size += ret;

			if ((unsigned char)buf[0] != (unsigned char)i) {
				pr_err("data mismatch on %zu\n", i);
				goto err;
			}
		}
		close(pfd[i][0]);
		close(pfd[i][1]);
	}

	pass();
	return 0;
err:
	fail();
	return 1;
}
