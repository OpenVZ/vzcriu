#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
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

void istor_map_opts(const struct cr_options *s, istor_opts_t *d)
{
	d->server_addr	= s->addr;
	d->server_port	= s->port;
	d->daemon_mode	= s->daemon_mode;
}

static int istor_serve_init(int sk, const istor_msg_t * const m, istor_msg_t **ptr_reply)
{
	istor_msg_t *reply = *ptr_reply;
	istor_obj_t *e = NULL;

	if (!istor_oid_is_zero(m->oid)) {
		istor_enc_err(reply, -EINVAL);
		return 0;
	}

	e = istor_lookup_alloc(m->oid, true);
	if (IS_ERR_OR_NULL(e)) {
		istor_enc_err(reply, -ENOMEM);
		return 0;
	}

	istor_enc_ok(reply, e->oid);
	return 0;
}

static int istor_serve_fini(int sk, const istor_msg_t * const m, istor_msg_t **ptr_reply)
{
	istor_msg_t *reply = *ptr_reply;

	if (istor_oid_is_zero(m->oid)) {
		istor_enc_ok(reply, NULL);
		return 0;
	}

	if (istor_delete(m->oid)) {
		istor_enc_err(reply, -ENOENT);
		return 0;
	}

	istor_enc_ok(reply, m->oid);
	return 0;
}

struct list_iter_args {
	int		sk;
	istor_msg_t	*reply;
};

static int list_iter(const istor_obj_t * const obj, void *args)
{
	struct list_iter_args *a = args;

	istor_enc_ok(a->reply, obj->oid);
	if (istor_send_msg(a->sk, a->reply) < 0)
		return -1;
	return 0;
}

static int istor_serve_list(int sk, const istor_msg_t * const m, istor_msg_t **ptr_reply)
{
	istor_msg_t *reply = *ptr_reply;
	istor_alloc_stat_t st;

	struct list_iter_args args = {
		.sk	= sk,
		.reply	= reply,
	};

	istor_fill_stat(&st);

	istor_enc_ok(reply, NULL);
	reply->size = st.nr_objs;
	if (istor_send_msg(sk, reply) < 0)
		return -1;

	if (istor_iterate(list_iter, &args))
		return -1;

	*ptr_reply = NULL;
	return 0;
}

int istor_server(istor_opts_t *opts)
{
	int istor_sk, accept_sk = -1, ret = 0;
	struct sockaddr_in accept_addr;
	socklen_t accept_len = sizeof(accept_addr);

	const struct istor_ops ops = {
		.init	= istor_serve_init,
		.fini	= istor_serve_fini,
		.list	= istor_serve_list,
	};

	if (istor_alloc_init())
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
		accept_sk = accept(istor_sk,
				   (struct sockaddr *)&accept_addr,
				   &accept_len);
		if (accept_sk < 0) {
			ret = -1;
			pr_perror("Can't accept connection");
			break;
		}

		pr_debug("Accepted connection from %s:%u\n",
			 inet_ntoa(accept_addr.sin_addr),
			 (unsigned)ntohs(accept_addr.sin_port));

		if ((ret = istor_serve_connection(accept_sk, &ops)))
			break;
	}

	close(istor_sk);

	if (opts->daemon_mode)
		exit(ret);
	return ret;
}
