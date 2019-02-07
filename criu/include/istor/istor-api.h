#ifndef CR_ISTOR_API_H__
#define CR_ISTOR_API_H__

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <alloca.h>

#include <uuid/uuid.h>

enum {
	ISTOR_CMD_NONE		= 0,

	ISTOR_CMD_DOCK_INIT	= 1,
	ISTOR_CMD_DOCK_FINI	= 2,
	ISTOR_CMD_DOCK_FIND	= 3,
	ISTOR_CMD_DOCK_LIST	= 4,

	ISTOR_CMD_IMG_OPEN	= 5,

	ISTOR_CMD_ACK		= 128,
	ISTOR_CMD_ERR		= 129,

	ISTOR_CMD_MAX
};

enum {
	ISTOR_FLAG_NONE		= 0,
	ISTOR_FLAG_FIN		= 1,

	ISTOR_FLAG_MAX
};

typedef struct {
	uint32_t	cmd;
	uint32_t	flags;
	uuid_t		oid;
	uint64_t	size;
} istor_msg_t;

typedef struct {
	istor_msg_t	hdr;
	uint32_t	oflags;
	uint32_t	mode;
	uint32_t	path_len;
	char		path[0];
} istor_msg_img_open_t;

typedef struct {
	int		server_sk;
	bool		daemon_mode;
	char		*server_addr;
	uint16_t	server_port;
} istor_opts_t;

#define ISTOR_ZERO_UUID_STR		"00000000-0000-0000-0000-000000000000"
#define ISTOR_UUID_STR_FMT_SIZE		sizeof(ISTOR_ZERO_UUID_STR)
#define ISTOR_UUID_STR_FMT		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"

typedef char istor_uuid_str_t[ISTOR_UUID_STR_FMT_SIZE];

static inline bool istor_oid_is_zero(const uuid_t oid)
{
	const uuid_t zero = { };
	return memcmp(oid, zero, sizeof(zero)) == 0;
}

typedef struct {
	uint32_t	time_low;
	uint16_t	time_mid;
	uint16_t	time_hi_and_version;
	uint8_t		clock_seq_hi_and_reserved;
	uint8_t		clock_seq_low;
	uint8_t		node[6];
} istor_uuid_t;

static inline char *istor_oid_repr(void *data, char *buf, size_t len)
{
	istor_uuid_t *u = (void *)data;
	if (snprintf(buf, len, ISTOR_UUID_STR_FMT,
		       u->time_low, u->time_mid, u->time_hi_and_version,
		       u->clock_seq_hi_and_reserved, u->clock_seq_low,
		       u->node[0], u->node[1], u->node[2], u->node[3],
		       u->node[4], u->node[5]) == len)
		buf[len-1] = '\0';
	return buf;
}

#define ___istor_repr_id(__oid)			istor_oid_repr((void *)(__oid), alloca(ISTOR_UUID_STR_FMT_SIZE), ISTOR_UUID_STR_FMT_SIZE)
#define __istor_repr_id(__oid, __buf)		istor_oid_repr((void *)(__oid), __buf, sizeof(__buf))
#define istor_repr_id(__oid, __buf, __len)	istor_oid_repr((void *)(__oid), __buf, __len)

#define DECLARE_ISTOR_OPTS(__name)		\
	istor_opts_t __name = {			\
		.server_sk	= -1,		\
		.daemon_mode	= false,	\
	}

static inline void INIT_ISTOR_OPTS(istor_opts_t *opts)
{
	memset(opts, 0, sizeof(*opts));

	opts->server_sk = -1;
}

#endif /* CR_ISTOR_API_H__ */
