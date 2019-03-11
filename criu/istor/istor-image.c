#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "criu-log.h"

#include "common/err.h"
#include "common/xmalloc.h"

#include "istor/istor-image.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif

#define LOG_PREFIX "istor-img: "

static int namecmp(const struct istor_rbnode_s * const e, const void * const param)
{
	const char *name = param;
	istor_img_t *i = container_of(e, istor_img_t, node_name);
	return strcmp(i->name, name);
}

static int idxcmp(const struct istor_rbnode_s * const e, const void * const param)
{
	const long idx = (const long)param;
	istor_img_t *i = container_of(e, istor_img_t, node_idx);
	return i->idx == idx ? 0 : ((i->idx > idx) ? 1 : -1);
}

istor_img_t *istor_img_lookup(istor_imgset_t *iset, const char * const name, const long idx)
{
	istor_rbnode_t *e;

	if (name) {
		e = istor_rbtree_lookup(&iset->name_root, name);
		if (e)
			return container_of(e, istor_img_t, node_name);
	}

	if (idx > -1) {
		e = istor_rbtree_lookup(&iset->idx_root, (void *)idx);
		if (e)
			return container_of(e, istor_img_t, node_idx);
	}

	return NULL;
}

int istor_img_stat(const istor_img_t * const img, istor_img_stat_t *st)
{
	BUILD_BUG_ON(sizeof(img->name) != sizeof(st->name));

	if (img) {
		memset(st, 0, sizeof(*st));
		if (img->name[0])
			strcpy(st->name, img->name);
		st->size= img->size;
		st->idx	= img->idx;
		st->off	= img->off;
	}
	return -ENOENT;
}

istor_img_t *istor_img_alloc(istor_imgset_t *iset, const char * const name)
{
	istor_img_t *img;

	if (!name)
		return ERR_PTR(-EINVAL);

	img = xmalloc(sizeof(*img));
	if (!img)
		return ERR_PTR(-ENOMEM);

	img->flags	= 0;
	img->mode	= 0;
	img->off	= 0;
	img->size	= 0;
	img->data	= NULL;

	istor_rbnode_init(&img->node_name);
	istor_rbnode_init(&img->node_idx);

	strncpy(img->name, name, sizeof(img->name));
	img->name[sizeof(img->name)-1] = '\0';
	istor_rbtree_insert_new(&iset->name_root, &img->node_name, (void *)img->name);

	img->idx = ++iset->last_idx;
	istor_rbtree_insert_new(&iset->idx_root, &img->node_idx, (void *)img->idx);

	return img;
}

void istor_imgset_free(istor_imgset_t *iset)
{
	/* FIXME */
	xfree(iset);
}

istor_imgset_t *istor_imgset_alloc()
{
	istor_imgset_t *iset = xmalloc(sizeof(*iset));
	if (!iset)
		return ERR_PTR(-ENOMEM);

	istor_rbtree_init(&iset->name_root, namecmp);
	istor_rbtree_init(&iset->idx_root, idxcmp);
	iset->last_idx = 0;

	return iset;
}
