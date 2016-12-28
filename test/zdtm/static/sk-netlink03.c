#include <unistd.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <string.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "zdtmtst.h"

const char *test_doc	= "Check a netlink socket with in-kernel state";
const char *test_author	= "Andrew Vagin <avagin@virtuozzo.com>";

int main(int argc, char ** argv)
{
	int sk, i;
	struct msghdr msg;
	struct {
                struct nlmsghdr nlh;
                struct rtgenmsg g;
        } req;
        struct iovec iov;
	char buf[4096];
	int data_len[3], len;

	test_init(argc, argv);

	sk = socket(PF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
	if (sk < 0)
		return 1;

	for (i = 0; i < 3; i++) {
		memset(&req, 0, sizeof(req));
		req.nlh.nlmsg_len = sizeof(req);
		req.nlh.nlmsg_type = RTM_GETLINK;
		req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
		req.nlh.nlmsg_pid = 0;
		req.nlh.nlmsg_seq = 666;
		req.g.rtgen_family = AF_PACKET;

		if (write(sk, &req, sizeof(req)) < 0)
			return 1;

		if (i == 1) {
			test_daemon();
			test_waitsig();
		}

		memset(&msg, 0, sizeof(msg));
		msg.msg_namelen = 0;
		msg.msg_iov     = &iov;
		msg.msg_iovlen  = 1;

		len = 0;
		while (1) {
			int ret;

			iov.iov_base    = buf;
			iov.iov_len     = sizeof(buf);

			ret = recvmsg(sk, &msg, 0);
			if (ret < 0) {
				if (errno == EAGAIN)
					break;
				pr_perror("recvmsg");
				return 1;
			}
			len += ret;
		}
		data_len[i] = len;
		if (len == 0)
			return 1;
		if (i > 0) {
			if (data_len[i - 1] != len) {
				fail("A wrong response");
				return -1;
			}
		}
	}

	pass();

	return 0;
}
