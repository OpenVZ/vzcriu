#ifndef __CR_MOUNT_H__
#define __CR_MOUNT_H__

#include <stdio.h>
#include <sys/types.h>

#include "common/list.h"
#include "cr_options.h"
#include "kerndat.h"

struct proc_mountinfo;
struct pstree_item;
struct fstype;
struct ns_id;

/*
 * Put a : in here since those are invalid on
 * the cli, so we know it's autogenerated in
 * debugging.
 */
#define AUTODETECTED_MOUNT "CRIU:AUTOGENERATED"
#define EXTERNAL_DEV_MOUNT "CRIU:EXTERNAL_DEV"
#define NO_ROOT_MOUNT "CRIU:NO_ROOT"
#define MS_PROPAGATE (MS_SHARED | MS_PRIVATE | MS_UNBINDABLE | MS_SLAVE)

/*
 * Here are a set of flags which we know how to handle for the one mount call.
 * All of them except MS_RDONLY are set only as mnt flags.
 * MS_RDONLY is set for both mnt ans sb flags, so we can restore it for one
 * mount call only if it set for both masks.
 */
#define MS_MNT_KNOWN_FLAGS (MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_NOATIME | \
				MS_NODIRATIME | MS_RELATIME | MS_RDONLY)


#define BINFMT_MISC_HOME "proc/sys/fs/binfmt_misc"

#define HELPER_MNT_ID 0

#define MOUNT_INVALID_DEV	(0)

#define MNT_UNREACHABLE INT_MIN

/*
 * enum values indicate the mode of remounting mount as read-write:
 *
 * REMOUNT_IN_SERVICE_MNTNS - it means that remountable mount exists in
 * service mount namespace only and will *not* be moved into restorable
 * mount namespaces. So, these mounts will *not* be remounted as RO back.
 *
 * REMOUNT_IN_SERVICE_MNTNS_MOVED - it means that remountable mount
 * exists in one of the restorable mount namespaces and it flags *must* be
 * restored back. But you should use this flag *only* if you can't enter
 * to mount namespace (because it doesn't exist at the moment). MOVED
 * suffix means that mount was already moved into the future mntns yard
 * tree from a plain structure.
 *
 * REMOUNT_IN_REAL_MNTNS - it means that remountable mount exists
 * in one of restorable mount namespaces and it flags *must* be
 * restored back. In this case, remounting will be done from real
 * restored mount namespace context.
 *
 */

enum remount_rw_mode {
	REMOUNT_IN_SERVICE_MNTNS,
	REMOUNT_IN_SERVICE_MNTNS_MOVED,
	REMOUNT_IN_REAL_MNTNS,
};

/*
 * We have remounted these mount writable temporary, and we
 * should return it back to readonly at the end of file restore.
 */
#define REMOUNTED_RW 1
/*
 * We have remounted these mount writable in service mount namespace,
 * thus we shouldn't return it back to readonly, as service mntns
 * will be destroyed anyway.
 */
#define REMOUNTED_RW_SERVICE 2

struct rst_mount_info {
	int	remounted_rw;
	int	mp_fd_id;
	int	mnt_fd_id;
	bool	mounted;
};

struct mount_namespaces {
	unsigned int pidns_id;
	unsigned int netns_id;
};

struct mount_info {
	int			mnt_id;
	int			parent_mnt_id;
	unsigned int		s_dev;
	unsigned int		s_dev_rt;
	char			*root;
	/*
	 * During dump mountpoint contains path with dot at the
	 * beginning. It allows to use openat, statat, etc without
	 * creating a temporary copy of the path.
	 *
	 * On restore mountpoint is prepended with so called ns
	 * root path -- it's a place in fs where the namespace
	 * mount tree is constructed. Check mnt_roots for details.
	 * The ns_mountpoint contains path w/o this prefix.
	 */
	char			*mountpoint;
	char			*ns_mountpoint;

	/* Mount-v2 specific */
	char			*plain_mountpoint;
	int			is_dir;
	struct sharing_group	*sg;
	struct list_head	mnt_sharing;

	int			fd;
	unsigned		flags;
	unsigned		sb_flags;
	int			master_id;
	int			shared_id;
	struct fstype		*fstype;
	char			*source;
	char			*options;
	char			*fsname;
	bool			dumped;
	bool			need_plugin;
	bool			is_ns_root;
	bool			deleted;
	int			deleted_level;
	struct list_head	deleted_list;
	struct mount_info	*next;
	struct ns_id		*nsid;

	char			*external;
	bool			internal_sharing;

	/* tree linkage */
	struct mount_info	*parent;
	struct mount_info	*bind;
	struct list_head	children;
	struct list_head	siblings;

	struct list_head	mnt_bind;	/* circular list of derivatives of one real mount */
	bool			mnt_no_bind;	/* no bind-mounts has been found for us */
	struct list_head	mnt_share;	/* circular list of shared mounts */
	struct list_head	mnt_slave_list;	/* list of slave mounts */
	struct list_head	mnt_slave;	/* slave list entry */
	struct list_head	mnt_ext_slave;	/* external slave list entry */
	struct mount_info	*mnt_master;	/* slave is on master->mnt_slave_list */
	struct list_head	mnt_propagate;	/* circular list of mounts which propagate from each other */
	struct list_head	mnt_notprop;	/* temporary list used in can_mount_now */
	struct list_head	mnt_unbindable;	/* list of mounts with delayed unbindable */

	struct list_head	postpone;

	struct list_head	mnt_usk_bind;	/* bindmounts of unix sk list entry */

	int			is_overmounted;

	bool			external_slavery;

	unsigned int		ns_bind_id;
	unsigned int		ns_bind_desc;

	struct mount_namespaces nses;
	struct list_head	mnt_proc;

	struct rst_mount_info	*rmi;
	struct mount_info	*helper;

	void			*private;	/* associated filesystem data */
};

static bool use_mounts_v2(void)
{
	return !opts.mounts_compat && kdat.has_mount_set_group;
}

static inline char *service_mountpoint(const struct mount_info *mi)
{
	if (use_mounts_v2() && mi->plain_mountpoint)
		return mi->plain_mountpoint;
	return mi->mountpoint;
}

extern struct mount_info *mntinfo;

static inline void mntinfo_add_list_before(struct mount_info **head, struct mount_info *new)
{
	new->next = *head;
	*head = new;
}

extern struct ns_desc mnt_ns_desc;
#ifdef CONFIG_BINFMT_MISC_VIRTUALIZED
extern int collect_binfmt_misc(void);
#else
static inline int collect_binfmt_misc(void) { return 0; }
#endif

extern struct mount_info *mnt_entry_alloc(bool rst);
extern void mnt_entry_free(struct mount_info *mi);

extern int __mntns_get_root_fd(pid_t pid);
extern int mntns_get_root_fd(struct ns_id *ns);
extern int mntns_get_root_by_mnt_id(int mnt_id);
extern struct ns_id *lookup_nsid_by_mnt_id(int mnt_id);

extern int open_mount(unsigned int s_dev);
extern int __open_mountpoint(struct mount_info *pm, int mnt_fd);
extern int mnt_is_dir(struct mount_info *pm);
extern int open_mountpoint(struct mount_info *pm);

extern struct mount_info *collect_mntinfo(struct ns_id *ns, bool for_dump);
extern int prepare_mnt_ns(void);

extern char *export_mnt_ns_roots(char *dst, size_t size);
extern char *export_criu_devtmpfs(char *dst, size_t size);

extern int pivot_root(const char *new_root, const char *put_old);

extern struct mount_info *lookup_overlayfs(char *rpath, unsigned int s_dev,
					   unsigned int st_ino, unsigned int mnt_id);
extern struct mount_info *lookup_mnt_id(unsigned int id);
extern struct mount_info *lookup_mnt_sdev(unsigned int s_dev);
extern struct mount_info *lookup_mnt_sdev_on_root(unsigned int s_dev);

extern dev_t phys_stat_resolve_dev(struct ns_id *, dev_t st_dev, char *path);
extern bool __phys_stat_dev_match(dev_t st_dev, dev_t phys_dev,
				struct ns_id *, char *path, struct mount_info *m);
extern bool phys_stat_dev_match(dev_t st_dev, dev_t phys_dev,
				struct ns_id *, char *path);
extern int mount_resolve_devpts_mnt_id(int mnt_id, int s_dev);
extern struct mount_info *lookup_first_fstype(int code);

extern int restore_task_mnt_ns(struct pstree_item *current);
extern void fini_restore_mntns(void);
extern int depopulate_roots_yard(int mntns_root, bool clean_remaps);

extern int rst_get_mnt_root(int mnt_id, char *path, int plen);
extern int ext_mount_add(char *key, char *val);
extern int ext_mount_parse_auto(char *key);
extern int mntns_maybe_create_roots(void);
extern int read_mnt_ns_img(void);
extern void cleanup_mnt_ns(void);
extern void clean_cr_time_mounts(void);

extern bool add_skip_mount(const char *mountpoint);
struct ns_id;
extern struct mount_info *parse_mountinfo(pid_t pid, struct ns_id *nsid, bool for_dump);

extern int check_mnt_id(void);

extern int remount_readonly_mounts(void);
extern int check_mounts(void);
extern int try_remount_writable(struct mount_info *mi, enum remount_rw_mode mode);
extern bool mnt_is_overmounted(struct mount_info *mi);
extern bool path_is_overmounted(char* path, struct mount_info *mi);
extern struct mount_info *get_path_overmount(char *path, struct mount_info *mi);

/* Exported for mount-v2.c */
extern struct mount_info *mnt_is_external(struct mount_info *m);
extern bool has_mounted_external_bind(struct mount_info *m);
extern struct mount_info *mnt_get_external_nodev(struct mount_info *m);
extern bool rst_mnt_is_root(struct mount_info *m);
extern struct mount_info *mnt_get_root(struct mount_info *m);
extern int do_simple_mount(struct mount_info *mi, const char *src,
			   const char *fstype, unsigned long mountflags);
extern char *resolve_source(struct mount_info *mi);
extern char *mnt_fsname(struct mount_info *mi);
extern int apply_sb_flags(void *args, int fd, pid_t pid);
extern int mount_root(void *args, int fd, pid_t pid);
extern int restore_ext_mount(struct mount_info *mi);
extern int fetch_rt_stat(struct mount_info *m, const char *where);
extern int print_ns_root(struct ns_id *ns, int remap_id, char *buf, int bs);
extern void search_bindmounts(void);
extern int merge_mount_trees(struct mount_info *root_yard);
extern struct mount_info
__maybe_unused *add_cr_time_mount(struct mount_info *root, char *fsname,
				  const char *path, unsigned int s_dev,
				  bool rst);
extern int validate_mounts(struct mount_info *info, bool for_dump);
extern int mnt_tree_for_each(struct mount_info *start,
			     int (*fn)(struct mount_info *));
extern int cr_pivot_root(char *root);
extern void set_is_overmounted(void);
extern int do_restore_task_mnt_ns(struct ns_id *nsid);
extern struct mount_info *mnt_subtree_next(struct mount_info *mi,
					   struct mount_info *root);

struct mount_info *root_yard_mp;
char *mnt_roots;

#endif /* __CR_MOUNT_H__ */
