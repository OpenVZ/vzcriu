#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <uuid/uuid.h>

#include "criu-log.h"
#include "util.h"

#include "istor/istor-net.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif

#define LOG_PREFIX "istor-net: "

#define ISTOR_BUF_DEFAULT_SIZE	(512)

static inline __always_unused void __check_self(void)
{
	struct istor_raw_id {
		uint64_t uuid_hi;
		uint64_t uuid_lo;
	};

	istor_msghdr_t __always_unused v;

	BUILD_BUG_ON(sizeof(istor_msghdr_t) > ISTOR_BUF_DEFAULT_SIZE);
	BUILD_BUG_ON(sizeof(istor_msghdr_t) != ISTOR_MSG_LENGTH(0));
	BUILD_BUG_ON(sizeof(v.msghdr_oid) != sizeof(struct istor_raw_id));
}

const char * const cmd_repr(unsigned int cmd)
{
#define __declare_cmd(_x) [_x] = __stringify_1(_x)
	static const char * const cmds[ISTOR_CMD_MAX] = {
		__declare_cmd(ISTOR_CMD_NONE),
		__declare_cmd(ISTOR_CMD_DOCK_INIT),
		__declare_cmd(ISTOR_CMD_DOCK_FINI),
		__declare_cmd(ISTOR_CMD_DOCK_LIST),
		__declare_cmd(ISTOR_CMD_IMG_OPEN),
		__declare_cmd(ISTOR_CMD_IMG_STAT),
		__declare_cmd(ISTOR_CMD_IMG_WRITE),
		__declare_cmd(ISTOR_CMD_IMG_READ),
		__declare_cmd(ISTOR_CMD_IMG_CLOSE),
		__declare_cmd(ISTOR_CMD_ACK),
		__declare_cmd(ISTOR_CMD_ERR),
	};
#undef __declare_cmd

	if (cmd < ARRAY_SIZE(cmds))
		return cmds[cmd];
	return "UNKNOWN";
}

ssize_t istor_send(int sk, void *buf, size_t size)
{
	ssize_t len = send(sk, buf, size, 0);
	if (len < size) {
		if (len < 0) {
			len = -errno;
			pr_perror("Can't send data to a socket %d\n", sk);
		} else if (len == 0) {
			/* To eliminate time-wait */
			pr_debug("Remote peer on %d shutted down the connection\n", sk);
			if (read(sk, buf, 1) != 0)
				pr_perror("Unexpected data on %d", sk);
			len = -ECONNRESET;
		} else {
			pr_err("Sent %zd bytes while %zd expected on  a socket %d\n",
			       len, size, sk);
			len = -ENODATA;
		}
	}
	return len;
}

ssize_t istor_recv_flush(int sk)
{
	ssize_t len, sum = 0;
	char buf[1024];

	for (;;) {
		len = recv(sk, buf, sizeof(buf), MSG_DONTWAIT);
		if (len > 0) {
			sum += len;
			continue;
		}
		break;
	}

	pr_debug("in  : sk %d flush %zd bytes\n", sk, sum);
	return len;
}

ssize_t istor_recv(int sk, void *buf, size_t size)
{
	ssize_t len = recv(sk, buf, size, 0);
	if (len < size) {
		if (len < 0) {
			len = -errno;
			pr_perror("Can't read data from a socket %d\n", sk);
		} else if (len == 0) {
			/* To eliminate time-wait */
			pr_debug("Remote peer on %d shutted down the connection\n", sk);
			if (read(sk, buf, 1) != 0)
				pr_perror("Unexpected data on %d", sk);
			len = -ECONNRESET;
		} else {
			pr_err("Read %zd bytes while %zd expected on a socket %d\n",
			       len, size, sk);
			len = -ENODATA;
		}
	}
	return len;
}

static inline bool istor_msg_ok(const char *prefix, const istor_msghdr_t *m)
{
	if (!ISTOR_MSG_OK(m, m->msghdr_len)) {
		pr_err("msg-ok: %s wrong packet size %zu < %zu\n",
		       prefix, m->msghdr_len, ISTOR_MSG_HDRLEN);
		return false;
	}
	return true;
}

ssize_t istor_send_msghdr(int sk, void *out)
{
	istor_uuid_str_t oidbuf;
	istor_msghdr_t *m = out;
	ssize_t len;

	if (!istor_msg_ok("outh:", m))
		return -EINVAL;

	len = istor_send(sk, m, ISTOR_MSG_HDRLEN);
	if (len == ISTOR_MSG_HDRLEN) {
		pr_debug("outh: sk %-4d cmd %-26s flags %#-10x id %s size %zd wrote %zd\n",
			 sk, cmd_repr(m->msghdr_cmd), m->msghdr_flags,
			 __istor_repr_id(m->msghdr_oid, oidbuf),
			 m->msghdr_len, len);
	}

	return len;
}

ssize_t istor_send_msgpayload(int sk, const istor_msghdr_t *m, void *payload)
{
	istor_uuid_str_t oidbuf;
	ssize_t len;

	if (!istor_msg_ok("outp:", m))
		return -EINVAL;

	len = istor_send(sk, payload, istor_msg_len(m));
	if (len == istor_msg_len(m)) {
		pr_debug("outp: sk %-4d cmd %-26s flags %#-10x id %s size %zd read %zd\n",
			 sk, cmd_repr(m->msghdr_cmd), m->msghdr_flags,
			 __istor_repr_id(m->msghdr_oid, oidbuf),
			 m->msghdr_len, len);
	}
	return len;
}

ssize_t istor_send_msg(int sk, void *out)
{
	istor_uuid_str_t oidbuf;
	istor_msghdr_t *m = out;
	ssize_t len;

	if (!istor_msg_ok("out :", m))
		return -EINVAL;

	len = istor_send(sk, m, m->msghdr_len);
	if (len == m->msghdr_len) {
		pr_debug("out : sk %-4d cmd %-26s flags %#-10x id %s size %zd\n",
			 sk, cmd_repr(m->msghdr_cmd), m->msghdr_flags,
			 __istor_repr_id(m->msghdr_oid, oidbuf),
			 m->msghdr_len);
	}

	return len;
}

ssize_t istor_recv_msghdr(int sk, void *in)
{
	istor_uuid_str_t oidbuf;
	istor_msghdr_t *m = in;
	ssize_t len;

	len = istor_recv(sk, in, ISTOR_MSG_HDRLEN);
	if (len == ISTOR_MSG_HDRLEN) {
		if (!istor_msg_ok("inh :", m))
			return -EINVAL;
		pr_debug("inh : sk %-4d cmd %-26s flags %#-10x id %s size %zd read %zd\n",
			 sk, cmd_repr(m->msghdr_cmd), m->msghdr_flags,
			 __istor_repr_id(m->msghdr_oid, oidbuf),
			 m->msghdr_len, len);
	}

	return len;
}

ssize_t istor_recv_msgpayload(int sk, const istor_msghdr_t *m, void *payload)
{
	istor_uuid_str_t oidbuf;
	ssize_t len;

	if (!istor_msg_ok("inp :", m))
		return -EINVAL;

	len = istor_recv(sk, payload, istor_msg_len(m));
	if (len == istor_msg_len(m)) {
		pr_debug("inp : sk %-4d cmd %-26s flags %#-10x id %s size %zd read %zd\n",
			 sk, cmd_repr(m->msghdr_cmd), m->msghdr_flags,
			 __istor_repr_id(m->msghdr_oid, oidbuf),
			 m->msghdr_len, len);
	}
	return len;
}

static void gen_transport_addr(struct sockaddr_un *addr,
			       unsigned int *addrlen)
{
	addr->sun_family = AF_UNIX;
	*addrlen = snprintf(addr->sun_path, sizeof(addr->sun_path), "X/istor-con-%d", getpid());
	addr->sun_path[0] = '\0';
	*addrlen += sizeof(addr->sun_family);
}

static int __istor_serve_connection(int sk, const struct istor_ops * const ops)
{
	char *buf, *buf_in, *buf_out;
	struct sockaddr_un addr;
	unsigned int addrlen;
	int ret = 0, usk = -1;

	__check_self();

	log_init_by_pid(getpid());
	pr_debug("Start session on sk %d\n", sk);

	usk = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (usk < 0) {
		int _errno = -errno;
		pr_perror("Can't create unix transport socket");
		return -_errno;
	}
	gen_transport_addr(&addr, &addrlen);

	if (bind(usk, (struct sockaddr *)&addr, addrlen)) {
		int _errno = errno;
		pr_perror("Unable to bind unix transport socket");
		return -_errno;
	}

	buf = xmalloc(2 * ISTOR_BUF_DEFAULT_SIZE);
	if (!buf) {
		istor_send_msg_err(sk, -ENOMEM);
		pr_err("Can't allocate receive/send buffers\n");
		close(usk);
		close(sk);
		return -ENOMEM;
	}
	buf_in = buf, buf_out = buf + ISTOR_BUF_DEFAULT_SIZE;

	tcp_nodelay(sk, true);
	for (;;) {
		istor_msghdr_t *out = (void *)buf_out;
		istor_msghdr_t *in = (void *)buf_in;

		istor_msghdr_init(in);
		if (istor_recv_msghdr(sk, in) < 0)
			break;

		/* End of session */
		if (in->msghdr_cmd == ISTOR_CMD_NONE &&
		    in->msghdr_flags & ISTOR_FLAG_FIN)
			break;

		switch (in->msghdr_cmd) {
		case ISTOR_CMD_DOCK_INIT:
			ret = ops->dock_init(sk, in, &out);
			break;
		case ISTOR_CMD_DOCK_FINI:
			ret = ops->dock_fini(sk, in, &out);
			break;
		case ISTOR_CMD_DOCK_LIST:
			ret = ops->dock_list(sk, in, &out);
			break;
		case ISTOR_CMD_IMG_OPEN:
			ret = ops->img_open(sk, usk, in, &out);
			break;
		case ISTOR_CMD_IMG_STAT:
			ret = ops->img_stat(sk, usk, in, &out);
			break;
		case ISTOR_CMD_IMG_WRITE:
			ret = ops->img_write(sk, usk, in, &out);
			break;
		case ISTOR_CMD_IMG_READ:
			ret = ops->img_read(sk, usk, in, &out);
			break;
		case ISTOR_CMD_IMG_CLOSE:
			ret = ops->img_close(sk, usk, in, &out);
			break;
		default:
			istor_enc_err(out, -EINVAL);
			break;
		}

		if (ret) {
			pr_debug("Force exit on a socket %d: %d\n", sk, ret);
			istor_send_msg_err(sk, ret);
			break;
		}

		if (out) {
			ret = istor_send_msg(sk, out);
			if (out->msghdr_cmd == ISTOR_CMD_ERR)
				istor_recv_flush(sk);
			if (ret < 0)
				break;
		}

		/* It was one-shot packet */
		if (in->msghdr_flags & ISTOR_FLAG_FIN)
			break;
	}

	xfree(buf);
	pr_debug("Stop session on sk %d: %d\n", sk, ret);
	close(usk);
	close(sk);

	return 0;
}

int istor_serve_connection(int sk, const struct istor_ops * const ops)
{
	pid_t pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork new session on a socket %d", sk);
		return -1;
	} else if (pid == 0)
		exit(__istor_serve_connection(sk, ops));

	return pid;
}
