#ifndef __CR_MOUNT_V2_H__
#define __CR_MOUNT_V2_H__

#include <sys/types.h>

#include "common/list.h"
#include "mount.h"

#define MS_SET_GROUP (1<<26)

struct sharing_group {
	/* This pair identifies the group */
	int                     shared_id;
	int                     master_id;

	/* List of shared groups */
	struct list_head        list;

	/* List of mounts in this group */
	struct list_head        mnt_list;

	/*
	 * List of dependant shared groups:
	 * - all siblings have equal master_id
	 * - the parent has shared_id equal to children's master_id
	 *
	 * This is a bit tricky: parent pointer indicates if there is one
	 * parent sharing_group in list or only siblings.
	 * So for traversal if parent pointer is set we can do:
	 *   list_for_each_entry(t, &sg->parent->children, siblings)
	 * and overvise we can do:
	 *   list_for_each_entry(t, &sg->siblings, siblings)
	 */
	struct list_head        children;
	struct list_head        siblings;
	struct sharing_group    *parent;

	char			*source;
};

extern int prepare_mnt_ns_v2(void);

#endif /* __CR_MOUNT_V2_H__ */
