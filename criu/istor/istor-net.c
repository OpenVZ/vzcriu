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

	istor_msg_t __always_unused v;

	BUILD_BUG_ON(sizeof(istor_msg_t) > ISTOR_BUF_DEFAULT_SIZE);
	BUILD_BUG_ON(sizeof(v.oid) != sizeof(struct istor_raw_id));
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

ssize_t istor_send_msg(int sk, istor_msg_t *out)
{
	istor_uuid_str_t oidbuf;
	ssize_t len;

	/* FIXME huge size attack! */
	if (out->size < sizeof(*out)) {
		pr_err("out: wrong packet size %zu < %zu\n",
		       out->size, sizeof(*out));
		return -EINVAL;
	}

	len = istor_send(sk, out, out->size);
	if (len == out->size) {
		pr_debug("out: sk %-4d cmd %-26s flags %#-4x id %s size %zd\n",
			 sk, cmd_repr(out->cmd), out->flags,
			 __istor_repr_id(out->oid, oidbuf), out->size);
	}

	return len;
}

ssize_t istor_recv_msg(int sk, istor_msg_t *in)
{
	istor_uuid_str_t oidbuf;
	ssize_t len, size;

	/* FIXME huge size attack! */
	if (in->size < sizeof(*in)) {
		pr_err("in : wrong packet size %zu < %zu\n",
		       in->size, sizeof(*in));
		return -EINVAL;
	}

	size = in->size;
	len = istor_recv(sk, in, size);
	if (len == size) {
		pr_debug("in : sk %-4d cmd %-26s flags %#-4x id %s size %zd / %zd\n",
			 sk, cmd_repr(in->cmd), in->flags,
			 __istor_repr_id(in->oid, oidbuf),
			 in->size, size);
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
		istor_msg_t *out = (void *)buf_out;
		istor_msg_t *in = (void *)buf_in;

		istor_msg_init(in);
		if (istor_recv_msg(sk, in) < 0)
			break;

		/* End of session */
		if (in->cmd == ISTOR_CMD_NONE &&
		    in->flags & ISTOR_FLAG_FIN)
			break;

		switch (in->cmd) {
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

		if (out && istor_send_msg(sk, out) < 0)
			break;

		/* It was one-shot packet */
		if (in->flags & ISTOR_FLAG_FIN)
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
