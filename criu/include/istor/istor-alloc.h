#ifndef __CR_ISTOR_ALLOC_H__
#define __CR_ISTOR_ALLOC_H__

#include <sys/types.h>

#include <uuid/uuid.h>

#include "atomic.h"
#include "rbtree.h"

#include "istor/istor-api.h"

typedef struct {
	struct rb_node		node;
	uuid_t			oid;
	pid_t			pid;
	atomic_t		ref;
} istor_obj_t;

typedef struct {
	size_t			nr_objs;
} istor_alloc_stat_t;

typedef int (*iter_t)(const istor_obj_t * const obj, void *args);

extern void istor_fill_stat(istor_alloc_stat_t *st);
extern int istor_iterate(iter_t iter, void *args);
extern istor_obj_t *istor_lookup_alloc(const uuid_t oid, bool alloc);
extern int istor_delete(const uuid_t oid);

extern int istor_alloc_init(void);

#endif /* __CR_ISTOR_ALLOC_H__ */
