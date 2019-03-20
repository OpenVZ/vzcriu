#ifndef __CR_ISTOR_IMAGE_H__
#define __CR_ISTOR_IMAGE_H__

#include <fcntl.h>

#include "common/list.h"
#include "istor/istor-rbtree.h"

#define ISTOR_IMG_NAME_LEN	64

typedef struct {
	char			name[ISTOR_IMG_NAME_LEN];
	long			idx;
	size_t			size;
} istor_img_stat_t;

#define IMG_STATE_NONE		0
#define IMG_STATE_CLOSED	1
#define IMG_STATE_MALLOC	2
#define IMG_STATE_MMAP		4

typedef struct {
	size_t			size;
	size_t			length;
	void			*data;
} istor_data_hdr_t;

typedef struct {
	istor_data_hdr_t	dhdr;
	unsigned long		*pagemap;
	unsigned long		vm_start;
	unsigned long		vm_end;

	unsigned int		prot;
	unsigned int		flags;
} istor_img_vma_t;

typedef struct {
	istor_data_hdr_t	dhdr;
} istor_img_reg_t;

typedef struct {
	istor_rbnode_t		node_name;
	istor_rbnode_t		node_idx;
	struct list_head	list;

	unsigned long		state;

	char			name[ISTOR_IMG_NAME_LEN];
	long			idx;

	union {
		istor_data_hdr_t	dhdr;
		istor_img_reg_t		reg;
		istor_img_vma_t		vma;
	};

	unsigned int		flags;
	unsigned int		mode;
} istor_img_t;

typedef struct {
	istor_rbtree_t		name_root;
	istor_rbtree_t		idx_root;
	struct list_head	img_list;
	long			last_idx;
} istor_imgset_t;

extern istor_img_t *istor_img_lookup(istor_imgset_t *iset, const char *const name, const long idx);
extern int istor_img_stat(const istor_img_t * const img, istor_img_stat_t *st);

extern int istor_img_data_malloc(istor_img_t *img, size_t size);

extern istor_img_t *istor_img_alloc(istor_imgset_t *iset, const char * const name);

extern void istor_imgset_free(istor_imgset_t *iset);
extern istor_imgset_t *istor_imgset_alloc(void);

#endif /* __CR_ISTOR_IMAGE_H__ */
