#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <uuid/uuid.h>

#include "cr_options.h"
#include "util.h"
#include "log.h"

#include "istor/istor-net.h"
#include "istor/istor.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif

#define LOG_PREFIX "istor: "

static struct sigaction istor_original_act;

static void istor_sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	int status, pid, exit;

	while (1) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid <= 0)
			return;
		exit = WIFEXITED(status);
		status = exit ? WEXITSTATUS(status) : WTERMSIG(status);
		break;
	}

	if (exit) {
		if (!status)
			pr_debug("child: %d exited, status=%d\n", pid, status);
		else
			pr_err("child: %d exited, status=%d\n", pid, status);
	} else
		pr_err("child: %d killed by signal %d: %s\n", pid, status, strsignal(status));
}

static int istor_setup_signals(void)
{
	struct sigaction act = { };
	int ret;

	ret = sigaction(SIGCHLD, NULL, &istor_original_act);
	if (ret < 0) {
		pr_perror("Can't fetch original sigactions");
		return -1;
	}

	act.sa_flags		|= SA_NOCLDSTOP | SA_SIGINFO | SA_RESTART;
	act.sa_sigaction	= istor_sigchld_handler;

	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGCHLD);

	ret = sigaction(SIGCHLD, &act, NULL);
	if (ret < 0) {
		pr_perror("Can't setup new sigactions");
		return -1;
	}

	return 0;
}

void istor_map_opts(const struct cr_options *s, istor_opts_t *d)
{
	d->server_addr	= s->addr;
	d->server_port	= s->port;
	d->daemon_mode	= s->daemon_mode;
}

static int istor_serve_dock_init(int sk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply)
{
	clean_on_fork_t args = {
		.fds[0]	= sk,
		.nr_fds	= 1,
	};
	istor_msghdr_t *reply = *ptr_reply;
	istor_dock_t *e = NULL;

	e = istor_lookup_alloc(m->msghdr_oid, true, &args);
	if (IS_ERR(e)) {
		istor_enc_err(reply, PTR_ERR(e));
		return 0;
	}

	istor_enc_ok(reply, e->oid);
	return 0;
}

static int istor_serve_dock_fini(int sk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply)
{
	istor_msghdr_t *reply = *ptr_reply;
	int ret;

	ret = istor_delete(m->msghdr_oid);
	if (ret) {
		istor_enc_err(reply, ret);
		return 0;
	}

	istor_enc_ok(reply, m->msghdr_oid);
	return 0;
}

struct dock_list_iter_args {
	int			sk;
	istor_msghdr_t		hdr;
	istor_dock_stat_t	dock_st;
};

static int dock_list_iter(const istor_dock_t * const dock, void *args)
{
	struct dock_list_iter_args *a = args;

	istor_dock_fill_stat(dock, &a->dock_st);

	istor_enc_ok(&a->hdr, dock->oid);
	a->hdr.msghdr_len = ISTOR_MSG_LENGTH(sizeof(a->dock_st));

	if (istor_send_msg(a->sk, &a->hdr) < 0)
		return -1;
	return 0;
}

static int istor_serve_dock_list(int sk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply)
{
	istor_msghdr_t *reply = *ptr_reply;
	istor_stat_t st;

	struct dock_list_iter_args args = {
		.sk		= sk,
	};

	istor_fill_stat(&st);

	istor_enc_ok(reply, NULL);
	reply->msghdr_ret = st.nr_docks;
	if (istor_send_msg(sk, reply) < 0)
		return -1;

	if (istor_iterate(dock_list_iter, &args))
		return -1;

	*ptr_reply = NULL;
	return 0;
}

static int istor_serve_img_open(int sk, int usk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply)
{
	istor_msghdr_t *reply = *ptr_reply;
	istor_msg_img_open_t *mopen;
	istor_msghdr_t *msgh;
	istor_dock_t *dock;
	int ret;

	if (m->msghdr_len > sizeof(dock->notify.data)) {
		istor_enc_err(reply, -ENAMETOOLONG);
		return 0;
	}

	dock = istor_lookup_get(m->msghdr_oid);
	if (IS_ERR(dock)) {
		istor_enc_err(reply, PTR_ERR(dock));
		return 0;
	}

	istor_dock_notify_lock(dock);

	msgh = (void *)dock->notify.data;
	memcpy(msgh, m, sizeof(*m));

	mopen = ISTOR_MSG_DATA(msgh);
	ret = istor_recv_msgpayload(sk, m, mopen);
	if (ret < 0) {
		istor_dock_notify_unlock(dock);
		istor_enc_err(reply, ret);
		return 0;
	}

	dock->notify.cmd	= ISTOR_CMD_IMG_OPEN;
	dock->notify.flags	= DOCK_NOTIFY_F_NONE;
	dock->notify.data_len	= m->msghdr_len;

	ret = istor_dock_serve_cmd_locked(dock);
	if (ret == 0)
		ret = dock->notify.ret;
	istor_dock_notify_unlock(dock);

	if (ret < 0) {
		istor_enc_err(reply, ret);
	} else {
		istor_enc_ok(reply, m->msghdr_oid);
		reply->msghdr_ret = ret;
	}

	return 0;
}

static int istor_serve_img_stat(int sk, int usk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply)
{
	istor_msghdr_t *reply = *ptr_reply;
	istor_dock_t *dock;

	dock = istor_lookup_get(m->msghdr_oid);
	if (IS_ERR(dock)) {
		istor_enc_err(reply, PTR_ERR(dock));
		return 0;
	}

	istor_enc_err(reply, -EINVAL);
	return 0;
}

static int istor_serve_img_write(int sk, int usk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply)
{
	istor_msghdr_t *reply = *ptr_reply;
	istor_msg_img_rdwr_t *mwrite;
	istor_msghdr_t *msgh;
	istor_dock_t *dock;
	int ret;

	if (m->msghdr_len > sizeof(dock->notify.data)) {
		istor_enc_err(reply, -ENAMETOOLONG);
		return 0;
	}

	dock = istor_lookup_get(m->msghdr_oid);
	if (IS_ERR(dock)) {
		istor_enc_err(reply, PTR_ERR(dock));
		return 0;
	}

	istor_dock_notify_lock(dock);

	msgh = (void *)dock->notify.data;
	memcpy(msgh, m, sizeof(*m));

	mwrite = ISTOR_MSG_DATA(msgh);

	ret = istor_recv_msgpayload(sk, m, mwrite);
	if (ret < 0) {
		istor_enc_err(reply, (int)ret);
		istor_dock_notify_unlock(dock);
		return 0;
	}

	dock->notify.cmd	= ISTOR_CMD_IMG_WRITE;
	dock->notify.data_len	= m->msghdr_len;

	ret = istor_dock_send_data_sk(dock, usk, sk);
	if (ret < 0) {
		istor_dock_notify_unlock(dock);
		istor_enc_err(reply, -EIO);
		return 0;
	} else if (ret > 0) {
		istor_dock_close_data_sk(dock);
		dock->notify.flags = DOCK_NOTIFY_F_DATA_SK;
	} else
		dock->notify.flags = DOCK_NOTIFY_F_NONE;

	ret = istor_dock_serve_cmd_locked(dock);
	if (ret == 0)
		ret = dock->notify.ret;

	istor_dock_close_data_sk(dock);
	istor_dock_notify_unlock(dock);

	if (ret < 0)
		istor_enc_err(reply, ret);
	else
		istor_enc_ok(reply, m->msghdr_oid);
	return 0;
}

static int istor_serve_img_read(int sk, int usk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply)
{
	istor_msghdr_t *reply = *ptr_reply;
	istor_msg_img_rdwr_t *mread;
	istor_msghdr_t *msgh;
	istor_dock_t *dock;
	int ret;

	if (m->msghdr_len > sizeof(dock->notify.data)) {
		istor_enc_err(reply, -ENAMETOOLONG);
		return 0;
	}

	dock = istor_lookup_get(m->msghdr_oid);
	if (IS_ERR(dock)) {
		istor_enc_err(reply, PTR_ERR(dock));
		return 0;
	}

	istor_dock_notify_lock(dock);

	msgh = (void *)dock->notify.data;
	memcpy(msgh, m, sizeof(*m));

	mread = ISTOR_MSG_DATA(msgh);

	ret = istor_recv_msgpayload(sk, m, mread);
	if (ret < 0) {
		istor_enc_err(reply, (int)ret);
		istor_dock_notify_unlock(dock);
		return 0;
	}

	dock->notify.cmd	= ISTOR_CMD_IMG_READ;
	dock->notify.data_len	= m->msghdr_len;

	ret = istor_dock_send_data_sk(dock, usk, sk);
	if (ret < 0) {
		istor_dock_notify_unlock(dock);
		istor_enc_err(reply, -EIO);
		return 0;
	} else if (ret > 0) {
		istor_dock_close_data_sk(dock);
		dock->notify.flags = DOCK_NOTIFY_F_DATA_SK;
	} else
		dock->notify.flags = DOCK_NOTIFY_F_NONE;

	ret = istor_dock_serve_cmd_locked(dock);
	if (ret < 0)
		ret = dock->notify.ret;

	istor_dock_close_data_sk(dock);
	istor_dock_notify_unlock(dock);

	/*
	 * If case if no error happened
	 * don't send anything!
	 */
	if (ret < 0)
		istor_enc_err(reply, ret);
	else
		*ptr_reply = NULL;
	return 0;
}

static int istor_serve_img_close(int sk, int usk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply)
{
	istor_msghdr_t *reply = *ptr_reply;
	istor_dock_t *dock;

	dock = istor_lookup_get(m->msghdr_oid);
	if (IS_ERR(dock)) {
		istor_enc_err(reply, PTR_ERR(dock));
		return 0;
	}

	istor_enc_err(reply, -EINVAL);
	return 0;
}

int istor_server(istor_opts_t *opts)
{
	int istor_sk, accept_sk = -1, ret = 0;
	struct sockaddr_in accept_addr;
	socklen_t accept_len = sizeof(accept_addr);

	const struct istor_ops ops = {
		.dock_init	= istor_serve_dock_init,
		.dock_fini	= istor_serve_dock_fini,
		.dock_list	= istor_serve_dock_list,

		.img_open	= istor_serve_img_open,
		.img_stat	= istor_serve_img_stat,
		.img_write	= istor_serve_img_write,
		.img_read	= istor_serve_img_read,
		.img_close	= istor_serve_img_close,
	};

	if (istor_setup_signals())
		return -1;

	if (istor_init_shared())
		return -1;

	if (opts->server_sk >= 0) {
		istor_sk = opts->server_sk;
		pr_info("Reusing socket %d\n", opts->server_sk);
		goto reuse_socket;
	}

	istor_sk = setup_tcp_server("istor", opts->server_addr,
				    &opts->server_port);
	if (istor_sk < 0) {
		pr_err("Can't setup server\n");
		return -1;
	}

reuse_socket:
	ret = run_tcp_server(opts->daemon_mode, &accept_sk, -1, -1);
	if (ret != 0)
		return ret > 0 ? 0 : -1;

	for (;;) {
		accept_sk = accept(istor_sk, (struct sockaddr *)&accept_addr,
				   &accept_len);
		if (accept_sk < 0) {
			ret = -1;
			pr_perror("Can't accept connection");
			break;
		}

		pr_debug("Accepted connection from %s:%u\n",
			 inet_ntoa(accept_addr.sin_addr),
			 (unsigned)ntohs(accept_addr.sin_port));

		ret = istor_serve_connection(accept_sk, &ops);
		if (ret > 0)
			close(accept_sk);
		else
			break;
	}
	close(istor_sk);

	if (opts->daemon_mode)
		exit(ret);
	return ret;
}
