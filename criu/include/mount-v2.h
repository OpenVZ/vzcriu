#ifndef __CR_MOUNT_V2_H__
#define __CR_MOUNT_V2_H__

#include "linux/mount.h"
#include "linux/openat2.h"

#include "common/list.h"
#include "covering-mounts.h"

#include <compel/plugins/std/syscall-codes.h>

/* Fallback for vz7 without openat2 */
#ifndef MS_SET_GROUP
#define MS_SET_GROUP (1 << 26)
#endif

#ifndef MOVE_MOUNT_SET_GROUP
#define MOVE_MOUNT_SET_GROUP 0x00000100 /* Set sharing group instead */
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004 /* Empty from path permitted */
#endif
#ifndef MOVE_MOUNT_T_EMPTY_PATH
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040 /* Empty to path permitted */
#endif

static inline int sys_move_mount(int from_dirfd, const char *from_pathname, int to_dirfd, const char *to_pathname,
				 unsigned int flags)
{
	return syscall(__NR_move_mount, from_dirfd, from_pathname, to_dirfd, to_pathname, flags);
}

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1 /* Clone the target tree and attach the clone */
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC /* Close the file on execve() */
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100 /* Do not follow symbolic links. */
#endif
#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0x800 /* Suppress terminal automount traversal */
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000 /* Allow empty relative pathname */
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000 /* Apply to the entire subtree */
#endif

static inline int sys_open_tree(int dfd, const char *filename, unsigned int flags)
{
	return syscall(__NR_open_tree, dfd, filename, flags);
}

#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV 0x01 /* Block mount-point crossings (includes bind-mounts). */
#endif

static inline long sys_openat2(int dirfd, const char *pathname, struct open_how *how, size_t size)
{
	return syscall(__NR_openat2, dirfd, pathname, how, size);
}

static inline long sys_mount_setattr(int dfd, const char *path, unsigned int flags, struct mount_attr *uattr,
				     size_t usize)
{
	return syscall(__NR_mount_setattr, dfd, path, flags, uattr, usize);
}

extern int check_mount_v2(void);

struct sharing_group {
	/* This pair identifies the group */
	int shared_id;
	int master_id;

	/* List of shared groups */
	struct list_head list;

	/* List of mounts in this group */
	struct list_head mnt_list;

	/*
	 * List of dependent shared groups:
	 * - all siblings have equal master_id
	 * - the parent has shared_id equal to children's master_id
	 *
	 * This is a bit tricky: parent pointer indicates if there is one
	 * parent sharing_group in list or only siblings.
	 * So for traversal if parent pointer is set we can do:
	 *   list_for_each_entry(t, &sg->parent->children, siblings)
	 * and otherwise we can do:
	 *   list_for_each_entry(t, &sg->siblings, siblings)
	 */
	struct list_head children;
	struct list_head siblings;
	struct sharing_group *parent;

	char *source;

	struct covering_mounts cms;
};

extern struct list_head nested_pidns_procs;

extern void search_nested_pidns_proc(void);
extern int resolve_shared_mounts_v2(void);
extern int setup_internal_yards(void);
extern int handle_nested_pidns_proc(void);
extern int prepare_mnt_ns_v2(void);
extern int fini_restore_mntns_v2(void);
extern int cleanup_internal_yards(void);
extern int add_wide_mounts_for_sharing_groups(void);

extern int create_plain_mountpoint(struct mount_info *mi);
#endif /* __CR_MOUNT_V2_H__ */
