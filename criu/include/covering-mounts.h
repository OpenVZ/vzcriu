#ifndef __CR_COVERING_MOUNTS_H__
#define __CR_COVERING_MOUNTS_H__

#include "common/list.h" /* list_head */

struct covering_mounts {
	struct list_head list;
	int count;
};

#include "mount.h" /* mount_info */

struct covering_mount {
	struct list_head siblings;
	struct mount_info *mnt;
};

extern struct covering_mount *get_covering_mount(struct covering_mounts *cms, char *root);
extern bool cms_fully_covered(struct covering_mounts *cms, char *root);
extern void pop_covered_mounts(struct covering_mounts *cms, char *root, struct list_head *covered);
extern int update_covering_mounts(struct covering_mounts *cms, struct mount_info *mi);

#endif /* __CR_COVERING_MOUNTS_H__ */
