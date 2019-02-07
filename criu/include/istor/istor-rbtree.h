#ifndef __CR_ISTOR_RBTREE_H__
#define __CR_ISTOR_RBTREE_H__

#include <string.h>

#include "rbtree.h"

struct istor_rbnode_s;

typedef int (*istor_rbtree_cmp_t)(const struct istor_rbnode_s * const e, const void * const param);
typedef int (*istor_rbtree_iter_t)(const struct istor_rbnode_s * const e, void *param);

typedef struct {
	struct rb_root		root;
	struct rb_node		*parent;
	istor_rbtree_cmp_t	cmp;
} istor_rbtree_t;

typedef struct istor_rbnode_s {
	struct rb_node	node;
} istor_rbnode_t;

static inline void istor_rbtree_init(istor_rbtree_t *tree, istor_rbtree_cmp_t cmp)
{
	memset(tree, 0, sizeof(*tree));
	tree->root	= RB_ROOT;
	tree->cmp	= cmp;
}

static inline void istor_rbnode_init(istor_rbnode_t *e)
{
	rb_init_node(&e->node);
}

static inline void istor_rbtree_insert(istor_rbtree_t *tree, istor_rbnode_t *e)
{
	rb_init_node(&e->node);
	/* Make sure @parent is proper if tree is not empty! */
	rb_link_and_balance(&tree->root, &e->node, tree->parent, &tree->root.rb_node);
}

static inline void istor_rbnode_delete(istor_rbtree_t *tree, istor_rbnode_t *e)
{
	rb_erase(&e->node, &tree->root);
	istor_rbnode_init(e);
}

static inline int istor_rbtree_iterate(istor_rbtree_t *tree, istor_rbtree_iter_t iter, void *param)
{
	struct rb_node *node;

	for (node = rb_first(&tree->root); node; node = rb_next(node)) {
		istor_rbnode_t *e = rb_entry(node, istor_rbnode_t, node);
		int ret = iter(e, param);
		if (ret)
			return ret;
	}
	return 0;
}

static inline istor_rbnode_t *istor_rbtree_lookup(istor_rbtree_t *tree, const void * const param)
{
	struct rb_node *node = tree->root.rb_node;
	struct rb_node **new = &tree->root.rb_node;
	struct rb_node *last_parent = NULL;

	while (node) {
		istor_rbnode_t *e = rb_entry(node, istor_rbnode_t, node);
		int ret = tree->cmp(e, param);

		last_parent = *new;

		if (ret < 0)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (ret > 0)
			node = node->rb_right, new = &((*new)->rb_right);
		else if (ret == 0)
			return e;
	}

	tree->parent = last_parent;
	return NULL;
}

#endif /* __CR_ISTOR_RBTREE_H__ */
