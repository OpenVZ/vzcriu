#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "criu-log.h"

#include "common/err.h"
#include "common/xmalloc.h"
#include "common/page.h"

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
	const long idx = *(const long *)param;
	istor_img_t *i = container_of(e, istor_img_t, node_idx);
	return i->idx == idx ? 0 : ((i->idx > idx) ? 1 : -1);
}

//static void show_set(char *prefix, istor_imgset_t *iset)
//{
//	istor_img_t *img;
//
//	pr_debug("%s\n", prefix);
//	list_for_each_entry(img, &iset->img_list, list)
//		pr_debug("\t\timg %p name %s idx %ld\n",
//			 img, img->name, img->idx);
//}

istor_img_t *istor_img_lookup(istor_imgset_t *iset, const char * const name, const long idx)
{
	istor_rbnode_t *e;

	if (name) {
		e = istor_rbtree_lookup(&iset->name_root, name);
		if (e)
			return container_of(e, istor_img_t, node_name);
	}

	if (idx > -1) {
		e = istor_rbtree_lookup(&iset->idx_root, (void *)&idx);
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
		st->size= img->dhdr.size;
		st->idx	= img->idx;
	}
	return -ENOENT;
}

int istor_img_data_malloc(istor_img_t *img, size_t size)
{
	istor_data_hdr_t *dhdr = &img->dhdr;

	if (dhdr->length < size) {
		size = ALIGN(size + PAGE_SIZE, PAGE_SIZE);
		if (xrealloc_safe(&dhdr->data, size))
			return -ENOMEM;
		dhdr->length = size;
	}

	return 0;
}

istor_img_t *istor_img_alloc(istor_imgset_t *iset, const char * const name)
{
	istor_img_t *img;

	if (!name)
		return ERR_PTR(-EINVAL);

	img = xzalloc(sizeof(*img));
	if (!img)
		return ERR_PTR(-ENOMEM);

	istor_rbnode_init(&img->node_name);
	istor_rbnode_init(&img->node_idx);

	strncpy(img->name, name, sizeof(img->name));
	img->name[sizeof(img->name)-1] = '\0';
	istor_rbtree_insert_new(&iset->name_root, &img->node_name, (void *)img->name);

	img->idx = ++iset->last_idx;
	istor_rbtree_insert_new(&iset->idx_root, &img->node_idx, (void *)&img->idx);
	list_add(&img->list, &iset->img_list);

	return img;
}

void istor_imgset_free(istor_imgset_t *iset)
{
	istor_img_t *img, *tmp;

	list_for_each_entry_safe(img, tmp, &iset->img_list, list)
		xfree(img);
	xfree(iset);
}

istor_imgset_t *istor_imgset_alloc()
{
	istor_imgset_t *iset = xmalloc(sizeof(*iset));
	if (!iset)
		return ERR_PTR(-ENOMEM);

	istor_rbtree_init(&iset->name_root, namecmp);
	istor_rbtree_init(&iset->idx_root, idxcmp);
	INIT_LIST_HEAD(&iset->img_list);
	iset->last_idx = 0;

	return iset;
}
