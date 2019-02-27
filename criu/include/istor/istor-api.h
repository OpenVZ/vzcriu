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
	ISTOR_CMD_DOCK_LIST	= 3,

	ISTOR_CMD_IMG_OPEN	= 21,
	ISTOR_CMD_IMG_STAT	= 22,
	ISTOR_CMD_IMG_WRITE	= 23,
	ISTOR_CMD_IMG_READ	= 24,
	ISTOR_CMD_IMG_CLOSE	= 25,

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

#define DECLARE_ISTOR_MSG(_v)					\
	istor_msg_t _v = { .size = sizeof(istor_msg_t) }

#define DECLARE_ISTOR_MSG_T(_type, _v)				\
	_type _v = { .hdr.size = sizeof(_type) }

#define istor_msg_init(_p)					\
	do {							\
		*(_p) = (istor_msg_t) {				\
			.size = sizeof(istor_msg_t),		\
		};						\
	} while (0)

#define istor_msg_t_init(_type,_p)				\
	do {							\
		*(_p) = (_type) {				\
			.hdr.size = sizeof(_type),		\
		};						\
	} while (0)

typedef struct {
	istor_msg_t	hdr;
	uint32_t	idx;
	char		data[0];
} istor_msg_img_write_t;

typedef struct {
	istor_msg_t	hdr;
	uint32_t	flags;
	uint32_t	mode;
	uint32_t	path_size;
	char		path[0];
} istor_msg_img_open_t;

#define istor_msg_t_osize(_p)	(sizeof(*(_p)) - sizeof((_p)->hdr))
#define istor_msg_t_psize(_p)	((_p)->hdr.size - istor_msg_t_osize(_p))

typedef struct {
	int		server_sk;
	bool		daemon_mode;
	char		*server_addr;
	uint16_t	server_port;
} istor_opts_t;

#define ISTOR_ZERO_UUID_STR		"00000000-0000-0000-0000-000000000000"
#define ISTOR_UUID_STR_FMT_SIZE		sizeof(ISTOR_ZERO_UUID_STR)
#define ISTOR_UUID_STR_FMT		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"

#define ISTOR_SHORT_ZERO_UUID_STR	"00000000"
#define ISTOR_SHORT_UUID_STR_FMT_SIZE	sizeof(ISTOR_SHORT_ZERO_UUID_STR)
#define ISTOR_SHORT_UUID_STR_FMT	"%08x"

typedef char istor_uuid_str_t[ISTOR_UUID_STR_FMT_SIZE];
typedef char istor_short_uuid_str_t[ISTOR_SHORT_UUID_STR_FMT_SIZE];

#define ISTOR_ZERO_UUID			"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"

static inline bool istor_oid_is_zero(const uuid_t oid)
{
	return memcmp(oid, ISTOR_ZERO_UUID, sizeof(ISTOR_ZERO_UUID)-1) == 0;
}

typedef struct {
	uint32_t	time_low;
	uint16_t	time_mid;
	uint16_t	time_hi_and_version;
	uint8_t		clock_seq_hi_and_reserved;
	uint8_t		clock_seq_low;
	uint8_t		node[6];
} istor_uuid_t;

static inline char *istor_repr_oid(void *data, char *buf, size_t len)
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

static inline char *istor_repr_short_oid(void *data, char *buf, size_t len)
{
	istor_uuid_t *u = (void *)data;
	if (snprintf(buf, len, ISTOR_SHORT_UUID_STR_FMT, u->time_low) == len)
		buf[len-1] = '\0';
	return buf;
}

#define ___istor_repr_id(__oid)						\
	istor_repr_oid((void *)(__oid),					\
		       alloca(ISTOR_UUID_STR_FMT_SIZE),			\
		       ISTOR_UUID_STR_FMT_SIZE)

#define __istor_repr_id(__oid, __buf)					\
	istor_repr_oid((void *)(__oid), __buf, sizeof(__buf))

#define istor_repr_id(__oid, __buf, __len)				\
	istor_repr_oid((void *)(__oid), __buf, __len)

#define ___istor_repr_short_id(__oid)					\
	istor_short_oid_repr((void *)(__oid),				\
			     alloca(ISTOR_SHORT_UUID_STR_FMT_SIZE),	\
			     ISTOR_SHORT_UUID_STR_FMT_SIZE)

#define __istor_repr_short_id(__oid, __buf)				\
	istor_repr_short_oid((void *)(__oid), __buf, sizeof(__buf))

#define istor_repr_short_id(__oid, __buf, __len)			\
	istor_repr_short_oid((void *)(__oid), __buf, __len)

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
