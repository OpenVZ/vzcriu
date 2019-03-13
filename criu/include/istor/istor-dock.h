#ifndef __CR_ISTOR_DOCK_H__
#define __CR_ISTOR_DOCK_H__

#include <sys/types.h>
#include <limits.h>

#include <uuid/uuid.h>

#include "common/lock.h"
#include "atomic.h"

#include "criu-log.h"

#include "istor/istor-api.h"
#include "istor/istor-image.h"
#include "istor/istor-rbtree.h"

enum {
	DOCK_STAGE_NONE		= 0 << 0,
	DOCK_STAGE_CREATED	= 1 << 1,
	DOCK_STAGE_READY	= 1 << 2,

	DOCK_STAGE_NOTIFY	= 1 << 3,
	DOCK_STAGE_COMPLETE	= 1 << 4,

	DOCK_STAGE_MAX
};

typedef struct {
	int			fds[255];
	size_t			nr_fds;
} clean_on_fork_t;

#define DOCK_CMD_MAX_DATA	512

#define DOCK_NOTIFY_F_NONE	(0 << 0)
#define DOCK_NOTIFY_F_DATA_SK	(1 << 0)

typedef struct {
	uint32_t		cmd;
	int32_t			ret;
	uint32_t		flags;
	uint32_t		data_len;
	uint8_t			data[DOCK_CMD_MAX_DATA];
} istor_notify_t;

typedef struct {
	istor_rbnode_t		node;
	futex_t			stage;

	mutex_t			notify_mutex;
	istor_notify_t		notify;

	int			unix_sk;
	int			data_sk;

	istor_imgset_t		*owner_iset;
	pid_t			owner_pid;
	istor_short_uuid_str_t	oidbuf;
	uuid_t			oid;
	atomic_t		ref;
} istor_dock_t;

extern const char *istor_dock_stage_repr(uint32_t stage);

extern int istor_dock_serve_cmd_locked(istor_dock_t *dock);
extern void istor_dock_close_data_sk(istor_dock_t *dock);
extern int istor_dock_recv_data_sk(istor_dock_t *dock);
extern int istor_dock_send_data_sk(const istor_dock_t *dock, int usk, int data_sk);

static inline void istor_dock_notify_lock(istor_dock_t *dock)
{
	mutex_lock(&dock->notify_mutex);
}

static inline void istor_dock_notify_unlock(istor_dock_t *dock)
{
	mutex_unlock(&dock->notify_mutex);
}

static inline void istor_dock_get_locked(istor_dock_t *dock)
{
	atomic_inc(&dock->ref);
}

static inline int istor_dock_put_locked(istor_dock_t *dock)
{
	return atomic_dec_and_test(&dock->ref);
}

static inline void istor_dock_put(istor_dock_t *dock)
{
	atomic_dec(&dock->ref);
}

static inline void istor_dock_stage_init(istor_dock_t *dock)
{
	futex_init(&dock->stage);

	if (!pr_quelled(LOG_DEBUG)) {
		uint32_t stage = futex_get(&dock->stage);
		const char *str_stage = istor_dock_stage_repr(stage);
		pr_debug("stage init: %s %10s\n",
			 ___istor_repr_id(dock->oid), str_stage);
	}
}

static inline void istor_dock_stage_set(istor_dock_t *dock, uint32_t stage)
{
	if (!pr_quelled(LOG_DEBUG)) {
		const char *str_stage = istor_dock_stage_repr(stage);
		pr_debug("stage  set: %s %10s\n",
			 ___istor_repr_id(dock->oid), str_stage);
	}

	futex_set_and_wake(&dock->stage, stage);
}

static inline void istor_dock_stage_abort(istor_dock_t *dock)
{
	if (!pr_quelled(LOG_DEBUG))
		pr_debug("stage abrt: %s\n", ___istor_repr_id(dock->oid));
	futex_abort_and_wake(&dock->stage);
}

static inline int istor_dock_stage_wait(istor_dock_t *dock, uint32_t stage)
{
	if (!pr_quelled(LOG_DEBUG)) {
		uint32_t old = futex_get(&dock->stage);
		const char *str_stage_old = istor_dock_stage_repr(old);
		const char *str_stage_new = istor_dock_stage_repr(stage);
		pr_debug("stage wait: %s %10s -> %10s\n",
			 ___istor_repr_id(dock->oid),
			 str_stage_old, str_stage_new);
	}

	futex_wait_until(&dock->stage, stage);
	stage = futex_get(&dock->stage);

	if (!pr_quelled(LOG_DEBUG)) {
		const char *str_stage = istor_dock_stage_repr(stage);
		pr_debug("stage wake: %s %10s\n",
			 ___istor_repr_id(dock->oid), str_stage);
	}

	return stage & FUTEX_ABORT_FLAG ? -EINTR : 0;
}

typedef int (*iter_t)(const istor_dock_t * const dock, void *args);

extern void istor_fill_stat(istor_stat_t *st);
extern void istor_dock_fill_stat(const istor_dock_t *dock, istor_dock_stat_t *st);
extern int istor_iterate(iter_t iter, void *args);
extern istor_dock_t *istor_lookup_alloc(const uuid_t oid, bool alloc, clean_on_fork_t *args);

static inline istor_dock_t *istor_lookup_get(const uuid_t oid)
{
	return istor_lookup_alloc(oid, false, NULL);
}

extern int istor_delete(const uuid_t oid);

extern int istor_init_shared(void);

#endif /* __CR_ISTOR_DOCK_H__ */
