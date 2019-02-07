#ifndef __CR_ISTOR_NET_H__
#define __CR_ISTOR_NET_H__

#include <stdint.h>
#include <string.h>

#include <uuid/uuid.h>

#include "istor/istor-api.h"

struct istor_ops {
	int	(*dock_init)(int sk, const istor_msg_t * const m, istor_msg_t **ptr_reply);
	int	(*dock_fini)(int sk, const istor_msg_t * const m, istor_msg_t **ptr_reply);
	int	(*dock_list)(int sk, const istor_msg_t * const m, istor_msg_t **ptr_reply);
};

static inline void istor_enc_err(istor_msg_t *m, int error_code)
{
	memset(m, 0, sizeof(*m));
	m->cmd = ISTOR_CMD_ERR;
	m->flags = error_code;
}

static inline void istor_enc_ok(istor_msg_t *m, const uuid_t oid)
{
	memset(m, 0, sizeof(*m));
	m->cmd = ISTOR_CMD_ACK;
	if (oid)
		memcpy(m->oid, oid, sizeof(m->oid));
}

extern const char * const cmd_repr(unsigned int cmd);
extern ssize_t istor_send(int sk, void *buf, size_t size);
extern ssize_t istor_recv(int sk, void *buf, size_t size);
extern ssize_t istor_send_msg(int sk, istor_msg_t *out);
extern ssize_t istor_recv_msg(int sk, istor_msg_t *in);

static inline ssize_t istor_send_msg_err(int sk, int err)
{
	istor_msg_t m;
	istor_enc_err(&m, err);
	return istor_send_msg(sk, &m);
}

extern int istor_serve_connection(int sk, const struct istor_ops * const ops);

#endif /* __CR_ISTOR_NET_H__ */
