#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <string.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <time.h>
#include <stdio.h>

#include "zdtmtst.h"

const char *test_doc    = "Check a netlink socket with in-kernel state with buffer overflow";
const char *test_author = "Alexander Mikhalitsyn <alexander.mikhalitsyn@virtuozzo.com>";

/*
 * We set SO_RCVBUF to 1-byte, but really in kernel
 * it will be equal to SOCK_MIN_RCVBUF and this value may
 * change in the future. So, we will try to send RTM_GETLINK
 * requests until we get ENOBUFS error. MAX_REQ it's maximum
 * number of such requests.
 */
#define MAX_REQ 256
#define BUF_SIZE 512

static int open_netlink(void)
{
	struct sockaddr_nl saddr;
	int sk;

	sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sk < 0) {
		perror("Failed to open netlink socket");
		return -1;
	}

	memset(&saddr, 0, sizeof(saddr));

	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid();

	if (bind(sk, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		perror("Failed to bind netlink socket");
		close(sk);
		return -1;
	}

	return sk;
}

static int do_link_get_request(int sock)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
	} req;

	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_seq = time(NULL);
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = 1;

	return send(sock, &req, sizeof(req), 0);
}

static int get_netlink_sk_drops(unsigned long sk_ino)
{
	static char buf[BUF_SIZE];
	FILE *netlink;
	int ret = -1;

	netlink = fopen("/proc/net/netlink", "r");
	if (!netlink) {
		pr_err("Failed to open /proc/net/netlink file: %m\n");
		return -1;
	}

	/* skip header line */
	if (fgets(buf, BUF_SIZE, netlink) == NULL)
		goto exit_close;

	while (true) {
		int drops;
		unsigned long ino;

		if (fgets(buf, BUF_SIZE, netlink) == NULL)
			break;

		/* see net/netlink/af_netlink.c netlink_native_seq_show() */
		if (sscanf(buf, "%*s %*s %*s %*s %*s %*s %*s %*s %u %lu",
			   &drops, &ino) != 2) {
			pr_err("Failed to parse /proc/net/netlink file\n");
			goto exit_close;
		}

		test_msg("drops %u sk_ino %lu\n", drops, ino);

		if (ino == sk_ino) {
			test_msg("FOUND drops %u sk_ino %lu\n", drops, ino);
			ret = drops;
			goto exit_close;
		}
	}

	pr_err("Netlink sk ino %lu not found in /proc/net/netlink\n", sk_ino);

exit_close:
	if (fclose(netlink)) {
		pr_err("Failed to close /proc/net/netlink file: %m\n");
		return -1;
	}

	return ret;
}

static int has_enobufs(int sk)
{
	int err;
	socklen_t optlen;

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &optlen) == -1) {
		pr_perror("Can't get so_error");
		return 0;
	}

	if (err == ENOBUFS)
		return 1;

	return 0;
}

int main(int argc, char **argv)
{
	int sk, i, drops = 0, sk_bsize;
	socklen_t optlen = sizeof(sk_bsize);
	struct stat st;

	test_init(argc, argv);

	sk = open_netlink();
	if (sk < 0)
		return 1;

	if (fstat(sk, &st) < 0) {
		pr_perror("Can't stat on netlink sk");
		close(sk);
		return 1;
	}

	/*
	 * Set 1 byte buffer, but really in kernel
	 * minimal value will be SOCK_MIN_RCVBUF > 2K bytes.
	 */
	sk_bsize = 1;
	if (setsockopt(sk, SOL_SOCKET, SO_RCVBUF,
		&sk_bsize, sizeof(sk_bsize)) == -1) {
		pr_perror("Can't set rcv buf");
		close(sk);
		return 1;
	}

	if (getsockopt(sk, SOL_SOCKET, SO_RCVBUF,
		&sk_bsize, &optlen) == -1) {
		pr_perror("Can't get rcv buf");
		close(sk);
		return 1;
	}
	test_msg("SO_RCVBUF=%d\n", sk_bsize);

	/*
	 * Send RTM_GETLINK requests until we
	 * have drops = 0 in /proc/net/netlink for
	 * our socket.
	 */
	for (i = 0; i < MAX_REQ && !drops; i++) {
		test_msg("iter %d\n", i);
		if (do_link_get_request(sk) < 0) {
			perror("netlink send failed");
			close(sk);
			return 1;
		}

		drops = get_netlink_sk_drops(st.st_ino);
		if (drops < 0) {
			close(sk);
			return 1;
		}
	}

	test_msg("final drops %d\n", drops);

	test_daemon();
	test_waitsig();

	if (has_enobufs(sk)) {
		pass();
	} else {
		pr_err("Socket has no ENOBUFS error after c/r\n");
		fail();
	}

	close(sk);

	return 0;
}
