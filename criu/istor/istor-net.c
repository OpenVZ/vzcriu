#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <uuid/uuid.h>

#include "util.h"
#include "log.h"

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
		__declare_cmd(ISTOR_CMD_INIT),
		__declare_cmd(ISTOR_CMD_FINI),
		__declare_cmd(ISTOR_CMD_FIND),
		__declare_cmd(ISTOR_CMD_LIST),
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
			pr_perror("Can't send data to a socket %d\n", sk);
		} else if (len == 0) {
			/* To eliminate time-wait */
			pr_debug("Remote peer on %d shutted down the connection\n", sk);
			if (read(sk, buf, 1) != 0)
				pr_perror("Unexpected data on %d", sk);
		} else {
			pr_err("Sent %zd bytes while %zd expected on  a socket %d\n",
			       len, size, sk);
			len = -1;
		}
	}
	return len;
}

ssize_t istor_recv(int sk, void *buf, size_t size)
{
	ssize_t len = recv(sk, buf, size, MSG_WAITALL);
	if (len < size) {
		if (len < 0) {
			pr_perror("Can't read data from a socket %d\n", sk);
		} else if (len == 0) {
			/* To eliminate time-wait */
			pr_debug("Remote peer on %d shutted down the connection\n", sk);
			if (read(sk, buf, 1) != 0)
				pr_perror("Unexpected data on %d", sk);
		} else {
			pr_err("Read %zd bytes while %zd expected on a socket %d\n",
			       len, size, sk);
			len = -1;
		}
	}
	return len;
}

ssize_t istor_send_msg(int sk, istor_msg_t *out)
{
	istor_uuid_str_t oidbuf;
	ssize_t len;

	len = istor_send(sk, out, sizeof(*out));
	if (len == sizeof(*out)) {
		pr_debug("out: sk %-4d cmd %-16s flags %#-4x id %s size %zd\n",
			 sk, cmd_repr(out->cmd), out->flags,
			 __istor_repr_id(out->oid, oidbuf), out->size);

	} else
		len = -1;

	return len;
}

ssize_t istor_recv_msg(int sk, istor_msg_t *in)
{
	istor_uuid_str_t oidbuf;
	ssize_t len;

	len = istor_recv(sk, in, sizeof(*in));
	if (len == sizeof(*in)) {
		pr_debug("in : sk %-4d cmd %-16s flags %#-4x id %s size %zd\n",
			 sk, cmd_repr(in->cmd), in->flags,
			 __istor_repr_id(in->oid, oidbuf), in->size);
	} else
		len = -1;

	return len;
}

int istor_serve_connection(int sk, const struct istor_ops * const ops)
{
	char *buf, *buf_in, *buf_out;
	int ret = 0;

	__check_self();

	pr_debug("Start session on sk %d\n", sk);

	buf = xmalloc(2 * ISTOR_BUF_DEFAULT_SIZE);
	if (!buf) {
		istor_send_msg_err(sk, -ENOMEM);
		pr_err("Can't allocate receive/send buffers\n");
		close(sk);
		return 0;
	}
	buf_in = buf, buf_out = buf + ISTOR_BUF_DEFAULT_SIZE;

	tcp_nodelay(sk, true);
	for (;;) {
		istor_msg_t *out = (void *)buf_out;
		istor_msg_t *in = (void *)buf_in;

		if (istor_recv_msg(sk, in) < 0)
			break;

		/* End of session */
		if (in->cmd == ISTOR_CMD_NONE &&
		    in->flags & ISTOR_FLAG_FIN)
			break;

		switch (in->cmd) {
		case ISTOR_CMD_INIT:
			ret = ops->init(sk, in, &out);
			break;
		case ISTOR_CMD_FINI:
			ret = ops->fini(sk, in, &out);
			break;
		case ISTOR_CMD_LIST:
			ret = ops->list(sk, in, &out);
			break;
		default:
			/* Unknown command */
			ret = -EINVAL;
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
	close(sk);

	return ret;
}
