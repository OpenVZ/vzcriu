#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "common/lock.h"
#include "common/err.h"
#include "bitops.h"
#include "log.h"

#include "istor/istor-alloc.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif

#define LOG_PREFIX "istor-alloc: "

#define ISTOR_MAX_OBJS	640

static struct {
	struct rb_root	root;
	size_t		nr_objs;
	mutex_t		lock;
	unsigned long	free_mark[BITS_TO_LONGS(ISTOR_MAX_OBJS)];
	istor_obj_t	objs[ISTOR_MAX_OBJS];
} *shared;

void istor_fill_stat(istor_alloc_stat_t *st)
{
	memset(st, 0, sizeof(*st));
	st->nr_objs = shared->nr_objs;
}

static istor_obj_t *istor_alloc_locked(struct rb_node *parent)
{
	unsigned long size = BITS_TO_LONGS(ISTOR_MAX_OBJS);
	unsigned long pos = 0;
	istor_obj_t *obj;

	if (shared->nr_objs >= ISTOR_MAX_OBJS)
		return ERR_PTR(-ENOSPC);

	pos = find_next_bit(shared->free_mark, size, 0);
	if (pos >= size) {
		pr_err("Internal error: free_mark is full but has space\n");
		return ERR_PTR(-ENOSPC);
	}
	clear_bit(pos, shared->free_mark);
	obj = &shared->objs[pos];
	shared->nr_objs++;

	memset(obj, 0, sizeof(*obj));
	uuid_generate(obj->oid);

	rb_init_node(&obj->node);
	rb_link_and_balance(&shared->root, &obj->node,
			    parent, &shared->root.rb_node);

	pr_debug("alloc: obj %p oid %s pos %4lu\n",
		 obj, ___istor_repr_id(obj->oid), pos);
	return obj;
}

static inline int oidcmp(const uuid_t a, const uuid_t b)
{
	return memcmp(a, b, sizeof(uuid_t));
}

static istor_obj_t *istor_lookup_locked(const uuid_t oid, struct rb_node **parent)
{
	struct rb_node *node = shared->root.rb_node;
	struct rb_node **new = &shared->root.rb_node;
	struct rb_node *last_parent = NULL;

	while (node) {
		istor_obj_t *e = rb_entry(node, istor_obj_t, node);
		int ret = oidcmp(oid, e->oid);

		last_parent = *new;

		if (ret < 0)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (ret > 0)
			node = node->rb_right, new = &((*new)->rb_right);
		else if (ret == 0)
			return e;
	}

	if (parent)
		*parent = last_parent;
	return NULL;
}

int istor_delete(const uuid_t oid)
{
	istor_obj_t *obj = NULL;
	int ret = -ENOENT;

	mutex_lock(&shared->lock);
	if (!istor_oid_is_zero(oid)) {
		obj = istor_lookup_locked(oid, NULL);
		if (obj) {
			unsigned long pos = (obj - shared->objs) / sizeof(shared->objs[0]);
			pr_debug("free : obj %p oid %s pos %4lu\n",
				 obj, ___istor_repr_id(obj->oid), pos);
			shared->nr_objs--;
			set_bit(pos, shared->free_mark);
			rb_erase(&obj->node, &shared->root);
			ret = 0;
		}
	}
	mutex_unlock(&shared->lock);
	return ret;
}

istor_obj_t *istor_lookup_alloc(const uuid_t oid, bool alloc)
{
	struct rb_node *parent = NULL;
	istor_obj_t *e = NULL;

	mutex_lock(&shared->lock);
	e = istor_lookup_locked(oid, &parent);
	if (!e && alloc)
		e = istor_alloc_locked(parent);
	mutex_unlock(&shared->lock);
	return e;
}

int istor_iterate(iter_t iter, void *args)
{
	struct rb_node *node;
	int ret = 0;

	mutex_lock(&shared->lock);
	for (node = rb_first(&shared->root); node; node = rb_next(node)) {
		istor_obj_t *obj = rb_entry(node, istor_obj_t, node);
		ret = iter(obj, args);
		if (ret)
			break;
	}
	mutex_unlock(&shared->lock);
	return ret;
}

int istor_alloc_init(void)
{
	shared = mmap(NULL, sizeof(*shared),
				PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if ((void *)shared == MAP_FAILED) {
		pr_perror("Can't allocate root resource");
		return -ENOMEM;
	}

	shared->root = RB_ROOT;
	memset(shared->free_mark, 0xff, sizeof(shared->free_mark));
	mutex_init(&shared->lock);

	pr_debug("shared data at %p took %zd bytes\n", shared, sizeof(*shared));
	return 0;
}
