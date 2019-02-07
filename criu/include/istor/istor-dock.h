#ifndef __CR_ISTOR_DOCK_H__
#define __CR_ISTOR_DOCK_H__

#include <sys/types.h>

#include <uuid/uuid.h>

#include "common/lock.h"
#include "atomic.h"

#include "criu-log.h"

#include "istor/istor-api.h"
#include "istor/istor-rbtree.h"

enum {
	DOCK_STAGE_NONE		= 0 << 0,
	DOCK_STAGE_CREATED	= 1 << 1,
	DOCK_STAGE_READY	= 1 << 2,
	DOCK_STAGE_NOTIFY	= 1 << 3,

	DOCK_STAGE_MAX
};

typedef struct {
	int			fds[255];
	size_t			nr_fds;
} clean_on_fork_t;

typedef struct {
	istor_rbnode_t		node;
	futex_t			stage;
	int			unix_sk;
	int			data_sk;
	pid_t			owner_pid;
	uuid_t			oid;
	atomic_t		ref;
} istor_dock_t;

typedef struct {
	int32_t			pid;
	int32_t			unix_sk;
	int32_t			data_sk;
	uint8_t			transport[32];
} istor_dock_stat_t;

typedef struct {
	size_t			nr_docks;
} istor_stat_t;

extern const char *istor_dock_stage_repr(uint32_t stage);

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

	return stage & FUTEX_ABORT_FLAG ? -1 : 0;
}

typedef int (*iter_t)(const istor_dock_t * const dock, void *args);

extern void istor_fill_stat(istor_stat_t *st);
extern void istor_dock_fill_stat(const istor_dock_t *dock, istor_dock_stat_t *st);
extern int istor_iterate(iter_t iter, void *args);
extern istor_dock_t *istor_lookup_alloc(const uuid_t oid, bool alloc, clean_on_fork_t *args);
extern int istor_delete(const uuid_t oid);

extern int istor_init_shared(void);

#endif /* __CR_ISTOR_DOCK_H__ */
