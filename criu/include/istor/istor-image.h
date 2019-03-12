#ifndef __CR_ISTOR_IMAGE_H__
#define __CR_ISTOR_IMAGE_H__

#include <fcntl.h>

#include "istor/istor-rbtree.h"

#define ISTOR_IMG_NAME_LEN	64

typedef struct {
	char			name[ISTOR_IMG_NAME_LEN];
	long			idx;
	size_t			size;
} istor_img_stat_t;

typedef struct {
	istor_rbnode_t		node_name;
	istor_rbnode_t		node_idx;

	char			name[ISTOR_IMG_NAME_LEN];
	long			idx;

	unsigned int		flags;
	unsigned int		mode;

	size_t			size;

	void			*data;
} istor_img_t;

typedef struct {
	istor_rbtree_t		name_root;
	istor_rbtree_t		idx_root;
	long			last_idx;
} istor_imgset_t;

extern istor_img_t *istor_img_lookup(istor_imgset_t *iset, const char *const name, const long idx);
extern int istor_img_stat(const istor_img_t * const img, istor_img_stat_t *st);
extern istor_img_t *istor_img_alloc(istor_imgset_t *iset, const char * const name);

extern void istor_imgset_free(istor_imgset_t *iset);
extern istor_imgset_t *istor_imgset_alloc(void);

#endif /* __CR_ISTOR_IMAGE_H__ */
