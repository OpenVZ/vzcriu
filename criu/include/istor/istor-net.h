#ifndef __CR_ISTOR_NET_H__
#define __CR_ISTOR_NET_H__

#include <stdint.h>
#include <string.h>

#include <uuid/uuid.h>

#include "istor/istor-api.h"

struct istor_ops {
	int	(*dock_init)(int sk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply);
	int	(*dock_fini)(int sk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply);
	int	(*dock_list)(int sk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply);

	int	(*img_open)(int sk, int usk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply);
	int	(*img_stat)(int sk, int usk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply);
	int	(*img_write)(int sk, int usk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply);
	int	(*img_read)(int sk, int usk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply);
	int	(*img_close)(int sk, int usk, const istor_msghdr_t * const m, istor_msghdr_t **ptr_reply);
};

static inline void istor_enc_err(istor_msghdr_t *m, int error_code)
{
	m->msghdr_cmd	= ISTOR_CMD_ERR;
	m->msghdr_ret	= error_code;
	m->msghdr_len	= ISTOR_MSG_LENGTH(0);

	memset(m->msghdr_oid, 0, sizeof(m->msghdr_oid));
}

static inline void istor_enc_ok(istor_msghdr_t *m, const uuid_t oid)
{
	m->msghdr_cmd	= ISTOR_CMD_ACK;
	m->msghdr_ret	= 0;
	m->msghdr_len	= ISTOR_MSG_LENGTH(0);

	if (oid)
		memcpy(m->msghdr_oid, oid, sizeof(m->msghdr_oid));
	else
		memset(m->msghdr_oid, 0, sizeof(m->msghdr_oid));
}

extern const char * const cmd_repr(unsigned int cmd);
extern ssize_t istor_send(int sk, void *buf, size_t size);
extern ssize_t istor_recv(int sk, void *buf, size_t size);
extern ssize_t istor_recv_flush(int sk);

extern ssize_t istor_send_msg(int sk, void *out);
extern ssize_t istor_send_msghdr(int sk, void *out);
extern ssize_t istor_send_msgpayload(int sk, const istor_msghdr_t *m, void *payload);
extern ssize_t istor_recv_msghdr(int sk, void *in);
extern ssize_t istor_recv_msgpayload(int sk, const istor_msghdr_t *m, void *payload);

static inline ssize_t istor_send_msg_err(int sk, int err)
{
	istor_msghdr_t m;

	istor_enc_err(&m, err);
	return istor_send_msg(sk, &m);
}

extern int istor_serve_connection(int sk, const struct istor_ops * const ops);

#endif /* __CR_ISTOR_NET_H__ */
