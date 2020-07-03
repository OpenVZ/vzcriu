#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sched.h>

#include "cr_options.h"
#include "xmalloc.h"
#include "util.h"
#include "log.h"
#include "filesystems.h"
#include "mount.h"
#include "mount-v2.h"
#include "namespaces.h"
#include "fs-magic.h"
#include "path.h"
#include "files-reg.h"
#include "fdstore.h"
#include "common/list.h"
#include "common/bug.h"
#include "common/compiler.h"
#include "rst-malloc.h"

#include "images/mnt.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "mnt-v2: "

LIST_HEAD(sharing_groups);

static struct sharing_group *get_sharing_group(int shared_id, int master_id)
{
	struct sharing_group *sg;

	list_for_each_entry(sg, &sharing_groups, list) {
		if (sg->shared_id == shared_id &&
		    sg->master_id == master_id)
			return sg;
	}

	return NULL;
}

static struct sharing_group *alloc_sharing_group(int shared_id, int master_id)
{
	struct sharing_group *sg;

	sg = xzalloc(sizeof(struct sharing_group));
	if (!sg)
		return NULL;

	sg->shared_id = shared_id;
	sg->master_id = master_id;

	INIT_LIST_HEAD(&sg->list);
	INIT_LIST_HEAD(&sg->mnt_list);
	INIT_LIST_HEAD(&sg->children);
	INIT_LIST_HEAD(&sg->siblings);

	list_add(&sg->list, &sharing_groups);

	return sg;
}

static int resolve_shared_mounts_v2(struct mount_info *info)
{
	struct sharing_group *sg;
	struct mount_info *m;


	/* Create sharing groups for each unique shared_id+master_id pair */
	for (m = info; m; m = m->next) {
		if (!m->shared_id && !m->master_id)
			continue;

		pr_debug("Inspecting sharing on %2d shared_id %d master_id %d (@%s)\n",
			 m->mnt_id, m->shared_id, m->master_id, m->ns_mountpoint);

		sg = get_sharing_group(m->shared_id, m->master_id);
		if (!sg) {
			sg = alloc_sharing_group(m->shared_id, m->master_id);
			if (!sg)
				return -1;
		}

		list_add(&m->mnt_sharing, &sg->mnt_list);
		m->sg = sg;
	}

	/* Lookup dependant groups */
	list_for_each_entry(sg, &sharing_groups, list) {
		if (sg->master_id) {
			struct sharing_group *p;

			list_for_each_entry(p, &sharing_groups, list) {
				if (p->shared_id != sg->master_id)
					continue;
				BUG_ON(sg->parent ||
				       !list_empty(&sg->siblings));
				sg->parent = p;
				list_add(&sg->siblings, &p->children);
			}

			/* External slavery */
			if (!sg->parent && list_empty(&sg->siblings)) {
				struct mount_info *mi, *ext;
				struct sharing_group *s;
				char *source = NULL;

				/*
				 * Though we don't have parent sharing group
				 * (inaccessible sharing), we can still have
				 * siblings, so collect them to the list.
				 */
				list_for_each_entry(s, &sharing_groups, list) {
					if (s->master_id != sg->master_id)
						continue;
					BUG_ON(sg->parent ||
					       !list_empty(&sg->siblings));
					list_add(&s->siblings, &sg->siblings);
				}

				BUG_ON(list_empty(&sg->mnt_list));
				mi = list_entry(sg->mnt_list.next,
						struct mount_info,
						mnt_sharing);

				if ((ext = mnt_get_external_nodev(mi)))
					source = ext->external;
				else if (mnt_get_root(mi))
					source = opts.root;

				if (!source) {
					pr_err("Sharing group (%d, %d) "
					       "has unreachable sharing. Try --enable-external-masters.\n",
					       m->master_id, m->shared_id);
					return -1;
				}

				sg->source = source;
				list_for_each_entry(s, &sg->siblings, siblings) {
					s->source = source;
				}

				pr_debug("Detected external slavery for shared group (%d, %d) with source %s\n",
					 sg->shared_id, sg->master_id, source);
			}
		}
	}

	return 0;
}

static int propagate_mount_v2(struct mount_info *mi)
{
	struct mount_info *t;

	list_for_each_entry(t, &mi->mnt_bind, mnt_bind) {
		if (t->rmi->mounted)
			continue;
		if (t->bind)
			continue;
		if (!issubpath(t->root, mi->root))
			continue;
		pr_debug("\t\tPropagate %d to %d\n", mi->mnt_id, t->mnt_id);
		t->bind = mi;
		t->s_dev_rt = mi->s_dev_rt;
	}

	return 0;
}

static int do_new_mount_v2(struct mount_info *mi)
{
	unsigned long sflags = mi->sb_flags;
	unsigned long mflags = mi->flags & (~MS_PROPAGATE);
	char *src;
	struct fstype *tp = mi->fstype;
	bool remount_ro = (tp->restore && mi->sb_flags & MS_RDONLY);
	mount_fn_t do_mount = (tp->mount) ? tp->mount : do_simple_mount;

	src = resolve_source(mi);
	if (!src)
		return -1;

	/* Merge superblock and mount flags if it's possible */
	if (!(mflags & ~MS_MNT_KNOWN_FLAGS) && !((sflags ^ mflags) & MS_RDONLY)) {
		sflags |= mflags;
		mflags = 0;
	}

	if (remount_ro)
		sflags &= ~MS_RDONLY;

	if (do_mount(mi, src, mnt_fsname(mi), sflags) < 0) {
		pr_perror("Can't mount at %s", mi->plain_mountpoint);
		return -1;
	}

	if (mount(NULL, mi->plain_mountpoint, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Can't remount %s with MS_PRIVATE", mi->plain_mountpoint);
		return -1;
	}

	if (tp->restore && tp->restore(mi))
		return -1;

	if (!rst_mnt_is_root(mi) && remount_ro) {
		int fd;

		fd = open(mi->plain_mountpoint, O_PATH);
		if (fd < 0) {
			pr_perror("Unable to open %s", mi->plain_mountpoint);
			return -1;
		}
		sflags |= MS_RDONLY | MS_REMOUNT;
		if (userns_call(apply_sb_flags, 0,
				&sflags, sizeof(sflags), fd)) {
			pr_perror("Unable to apply mount flags %d for %s",
				  mi->sb_flags, mi->plain_mountpoint);
			close(fd);
			return -1;
		}
		close(fd);
	}

	if (mflags && mount(NULL, mi->plain_mountpoint, NULL,
			    MS_REMOUNT | MS_BIND | mflags, NULL)) {
		pr_perror("Unable to apply bind-mount options");
		return -1;
	}

	mi->rmi->mounted = true;
	return 0;
}

LIST_HEAD(deleted_mounts);

static int do_bind_mount_v2(struct mount_info *mi)
{
	char mnt_fd_path[PSFDS];
	char *root = NULL, *cut_root, rpath[PATH_MAX];
	unsigned long mflags;
	int exit_code = -1;
	char *mnt_path = NULL;
	struct stat st;
	int level = 0, fd;

	if (mi->need_plugin) {
		if (restore_ext_mount(mi))
			return -1;
		goto out;
	}

	if (mi->external) {
		root = mi->external;
		goto do_bind;
	}

	if (mi->ns_bind_id) {
		struct ns_desc *ns_d;
		struct ns_id *nsid;

		ns_d = get_ns_desc_by_cflags(mi->ns_bind_desc);
		if (!ns_d) {
			pr_err("Unsupported cflags %u for ns bind-mount %d\n",
					mi->ns_bind_desc, mi->mnt_id);
			return -1;
		}

		nsid = lookup_ns_by_id(mi->ns_bind_id, ns_d);
		if (!nsid) {
			pr_err("Can't find %s namespace %u for ns bind-mount %d\n",
			       ns_d->str, mi->ns_bind_id, mi->mnt_id);
			return -1;
		}

		if (nsid->nsfd_id < 0) {
			pr_err("There is no nsfd_id for %s ns %u for ns bind-mount %d\n",
			       ns_d->str, nsid->id, mi->mnt_id);
			return -1;
		}

		fd = fdstore_get(nsid->nsfd_id);
		if (fd < 0) {
			pr_err("Can't get fd from fdstore for %s ns %u for ns bind-mount %d\n",
			       ns_d->str, nsid->id, mi->mnt_id);
			return -1;
		}

		pr_info("\tBind %s ns %u fd %d to %s\n",
			ns_d->str, nsid->id, fd, mi->plain_mountpoint);
		goto do_bind_fd;
	}

	cut_root = get_relative_path(mi->root, mi->bind->root);
	if (!cut_root) {
		pr_err("Failed to find root for %d in our supposed bind %d\n",
		       mi->mnt_id, mi->bind->mnt_id);
		return -1;
	}

	/* Mount private can be initialized on mount() callback, which is
	 * called only once.
	 * It have to be copied to all it's sibling structures to provide users
	 * of it with actual data.
	 */
	mi->private = mi->bind->private;

	mnt_path = mi->bind->plain_mountpoint;

	if (cut_root[0]) {
		snprintf(rpath, sizeof(rpath), "%s/%s",
				mnt_path, cut_root);
		root = rpath;
	} else {
		root = mnt_path;
	}
do_bind:
	pr_info("\tBind %s[%s] to %s\n", root,
		mi->external ? "" : mi->bind->plain_mountpoint,
		mi->plain_mountpoint);

	if (unlikely(mi->deleted)) {
		if (stat(mi->plain_mountpoint, &st)) {
			pr_perror("Can't fetch stat on %s", mi->plain_mountpoint);
			goto err;
		}

		level = make_parent_dirs_if_need(-1, root);
		if (level < 0)
			goto err;

		if (mi->is_dir) {
			if (mkdir(root, (st.st_mode & ~S_IFMT))) {
				pr_perror("Can't re-create deleted directory %s", root);
				goto err;
			}
		} else {
			int fd = open(root, O_WRONLY | O_CREAT | O_EXCL,
				      st.st_mode & ~S_IFMT);
			if (fd < 0) {
				pr_perror("Can't re-create deleted file %s", root);
				goto err;
			}
			close(fd);
		}
	}

	/*
	 * Autofs hack: open with O_PATH does not trigger automounting, and
	 * thus we actually open file on autofs and if we bind-mount it it
	 * would be autofs bind-mount. If we skip this step, we will bind some
	 * child of autofs instead.
	 */
	fd = open(root, O_PATH);
	if (fd < 0) {
		pr_perror("Unable to open %s", root);
		goto err;
	}

do_bind_fd:
	snprintf(mnt_fd_path, sizeof(mnt_fd_path),
				"/proc/self/fd/%d", fd);

	if (mount(mnt_fd_path, mi->plain_mountpoint, NULL, MS_BIND, NULL)) {
		pr_perror("Can't mount at %s", mi->plain_mountpoint);
		close(fd);
		goto err;
	}
	close(fd);

	if (mount(NULL, mi->plain_mountpoint, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Can't remount %s with MS_PRIVATE", mi->plain_mountpoint);
		goto err;
	}

	mflags = mi->flags & (~MS_PROPAGATE);
	if (!mi->bind || mflags != (mi->bind->flags & (~MS_PROPAGATE)))
		if (mount(NULL, mi->plain_mountpoint, NULL,
			  MS_BIND | MS_REMOUNT | mflags, NULL)) {
			pr_perror("Can't bind remount 0x%lx at %s",
				  mflags, mi->plain_mountpoint);
			goto err;
		}

out:
	mi->rmi->mounted = true;
	if (mi->deleted) {
		/*
		 * Deleted mounts can't be moved, will delete source after
		 * moving to proper position in the mount tree FIXME.
		 */
		mi->deleted_level = level;
		level = 0;
		list_add(&mi->deleted_list, &deleted_mounts);
	}
	exit_code = 0;
err:
	if (level)
		rm_parent_dirs(-1, root, level);

	return exit_code;
}

static int do_mount_root_v2(struct mount_info *mi)
{
	unsigned long flags = MS_BIND;
	int fd;

	if (root_ns_mask & CLONE_NEWUSER) {
		fd = open(mi->plain_mountpoint, O_PATH);
		if (fd < 0) {
			pr_perror("Unable to open %s", mi->plain_mountpoint);
			return -1;
		}

		if (userns_call(mount_root, 0, &flags, sizeof(flags), fd)) {
			pr_err("Unable to mount %s\n", mi->plain_mountpoint);
			close(fd);
			return -1;
		}
		close(fd);
	} else {
		if (mount(opts.root, mi->plain_mountpoint, NULL, flags, NULL)) {
			pr_perror("Unable to mount %s %s (id=%d)", opts.root, mi->plain_mountpoint, mi->mnt_id);
			return -1;
		}
	}

	if (mount(NULL, mi->plain_mountpoint, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Can't remount %s with MS_PRIVATE", mi->plain_mountpoint);
		return -1;
	}

	mi->rmi->mounted = true;

	return 0;
}

static bool can_mount_now_v2(struct mount_info *mi)
{
	struct mount_info *ext, *root;

	/* Parent should be mounted already, that's how mnt_tree_for_each works */
	BUG_ON(mi->parent && !mi->parent->rmi->mounted);

	if (rst_mnt_is_root(mi)) {
		pr_debug("%s: true as %d is global root\n", __func__, mi->mnt_id);
		return true;
	}

	if ((root = mnt_get_root(mi)) && !root->rmi->mounted) {
		pr_debug("%s: false as %d is bind of not mounted global root %d\n",
			 __func__, mi->mnt_id, root->mnt_id);
		return false;
	}

	if (mi->external) {
		pr_debug("%s: true as %d is external\n", __func__, mi->mnt_id);
		return true;
	}

	if ((ext = mnt_is_external(mi)) && !has_mounted_external_bind(mi)) {
		pr_debug("%s: false as %d is a bind of not mounted external %d\n",
			 __func__, mi->mnt_id, ext->mnt_id);
		return false;
	}

	if (mi->ns_bind_id) {
		pr_debug("%s: true as %d is ns-bind\n", __func__, mi->mnt_id);
		return true;
	}

	if (!fsroot_mounted(mi) && (mi->bind == NULL) && !mi->need_plugin) {
		pr_debug("%s: false as %d is non-root without bind or plugin\n",
			 __func__, mi->mnt_id);
		return false;
	}

	if (mi->fstype->can_mount) {
		int can_mount = mi->fstype->can_mount(mi);

		if (can_mount == -1) {
			pr_err("fstype->can_mount error. mnt_id %d\n", mi->mnt_id);
			return false;
		}

		if (can_mount == 0) {
			pr_debug("mnt_id %d isn't mountable yet\n", mi->mnt_id);
			return false;
		}
	}

	return true;
}

static int set_unbindable_v2(struct mount_info *mi)
{
	if (mi->flags & MS_UNBINDABLE) {
		if (mount(NULL, mi->plain_mountpoint, NULL, MS_UNBINDABLE, NULL)) {
			pr_perror("Failed to set mount %d unbindable", mi->mnt_id);
			return -1;
		}
	}
	return 0;
}

static int create_plain_mountpoint(struct mount_info *mi) {
	char mountpoint[PATH_MAX], *rel_path;
	struct stat st;

	if (!mi->parent || mi->parent == root_yard_mp || mi->is_dir != -1)
		goto create;

	rel_path = get_relative_path(mi->ns_mountpoint, mi->parent->ns_mountpoint);
	BUG_ON(!rel_path);
	snprintf(mountpoint, sizeof(mountpoint), "%s%s%s",
		 mi->parent->plain_mountpoint, rel_path[0] ? "/" : "",
		 rel_path);

	if (stat(mountpoint, &st)) {
		pr_perror("Can't stat mountpoint %s", mountpoint);
		return -1;
	}

	if (S_ISDIR(st.st_mode))
		mi->is_dir = true;
	else
		mi->is_dir = false;
create:
	pr_info("Create plain mountpoint %s for %d\n", mi->plain_mountpoint, mi->mnt_id);
	if (mi->is_dir) {
		if (mkdir(mi->plain_mountpoint, 0600)) {
			pr_perror("Unable to mkdir mountpoint %s",
				  mi->plain_mountpoint);
			return -1;
		}
	} else {
		int fd;

		fd = creat(mi->plain_mountpoint, 0600);
		if (fd < 0) {
			pr_perror("Unable to create mountpoint %s", mi->plain_mountpoint);
			return -1;
		}
		close(fd);
	}

	return 0;
}

static bool is_internal_yard(struct mount_info *mi)
{
	return mi == mi->nsid->mnt.internal_yard;
}

static int do_internal_yard_mount_v2(struct mount_info *mi)
{
	struct mount_info *c;
	char proc[PATH_MAX], path[PATH_MAX], *rel_path;

	pr_info("Creating internal yard for mntns %d\n", mi->nsid->id);

	if (make_yard(mi->plain_mountpoint))
		return -1;

	snprintf(proc, sizeof(proc), "%s/proc", mi->plain_mountpoint);
	if (mkdir(proc, 0777)) {
		pr_perror("Failed to mkdir proc in internal yard for mntns %d",
			  mi->nsid->id);
		return -1;
	}

	/**
	 * Add service proc mount from host pidns it will be moved to the
	 * tree together with internal yard. It may have MNT_LOCKED mounts on
	 * top so we need a recursive bind.
	 */
	if (mount("/proc", proc, NULL, MS_BIND | MS_REC, NULL)) {
		pr_perror("Failed to mount proc in internal yard for mntns %d",
			  mi->nsid->id);
		return -1;
	}

	if (mount(NULL, proc, NULL, MS_PRIVATE | MS_REC, NULL)) {
		pr_perror("Can't remount %s with MS_PRIVATE", proc);
		return -1;
	}

	list_for_each_entry(c, &mi->children, siblings) {
		rel_path = get_relative_path(c->ns_mountpoint, mi->ns_mountpoint);
		if (!rel_path && !rel_path[0]) {
			pr_err("Failed to find %s in %s\n",
			       c->ns_mountpoint, mi->ns_mountpoint);
			return -1;
		}

		snprintf(path, sizeof(path), "%s/%s", mi->plain_mountpoint,
			 rel_path);

		if (mkdir(path, 0777)) {
			pr_perror("Failed to mkdir internal yard child %d for %d",
				  c->mnt_id, mi->mnt_id);
			return -1;

		}
	}

	mi->rmi->mounted = true;
	return 0;
}

static int do_mount_one_v2(struct mount_info *mi)
{
	int ret;

	if (mi->rmi->mounted)
		return 0;

	if (!can_mount_now_v2(mi)) {
		pr_debug("Postpone mount %d\n", mi->mnt_id);
		return 1;
	}

	if (create_plain_mountpoint(mi))
		return -1;

	pr_debug("\tMounting %s @%d (%d)\n", mi->fstype->name, mi->mnt_id, mi->need_plugin);

	if (is_internal_yard(mi)) {
		ret = do_internal_yard_mount_v2(mi);
	} else if (rst_mnt_is_root(mi)) {
		if (opts.root == NULL) {
			pr_err("The --root option is required to restore a mount namespace\n");
			return -1;
		}
		ret = do_mount_root_v2(mi);
	} else if (!mi->bind && !mi->need_plugin && !mi->ns_bind_id &&
		   (!mi->external || !strcmp(mi->external,
					     EXTERNAL_DEV_MOUNT)))
		ret = do_new_mount_v2(mi);
	else
		ret = do_bind_mount_v2(mi);

	if (ret == 0 && fetch_rt_stat(mi, mi->plain_mountpoint))
		return -1;

	if (ret == 0 && propagate_mount_v2(mi))
		return -1;

	if (mi->fstype->code == FSTYPE__UNSUPPORTED) {
		struct statfs st;

		if (statfs(mi->plain_mountpoint, &st)) {
			pr_perror("Unable to statfs %s", mi->plain_mountpoint);
			return -1;
		}
		if (st.f_type == BTRFS_SUPER_MAGIC)
			mi->fstype = find_fstype_by_name("btrfs");
	}

	return ret;
}

/*
 * All nested mount namespaces are restore as sub-trees of the root namespace.
 */
static int populate_roots_yard_v2(struct mount_info *cr_time)
{
	char path[PATH_MAX];
	struct ns_id *nsid;

	if (make_yard(mnt_roots))
		return -1;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &mnt_ns_desc)
			continue;

		print_ns_root(nsid, 0, path, sizeof(path));
		if (mkdir(path, 0600)) {
			pr_perror("Unable to create %s", path);
			return -1;
		}
	}

	if (cr_time && mkdirpat(AT_FDCWD, cr_time->mountpoint, 0755)) {
		pr_perror("Unable to create %s", cr_time->mountpoint);
		return -1;
	}

	return 0;
}

void insert_internal_yards(void)
{
	struct ns_id *nsid;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		struct mount_info *yard = nsid->mnt.internal_yard;

		if (nsid->nd != &mnt_ns_desc)
			continue;

		if (nsid->mnt.enable_internal_yard)
			list_add_tail(&yard->siblings, &yard->parent->children);
	}
}

void extract_internal_yards(void)
{
	struct ns_id *nsid;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		struct mount_info *yard = nsid->mnt.internal_yard;

		if (nsid->nd != &mnt_ns_desc)
			continue;

		if (nsid->mnt.enable_internal_yard)
			list_del_init(&yard->siblings);
	}
}

static int populate_mnt_ns_v2(void)
{
	struct mount_info *cr_time = NULL;
	int ret;

#ifdef CONFIG_BINFMT_MISC_VIRTUALIZED
	if (!opts.has_binfmt_misc && !list_empty(&binfmt_misc_list)) {
		/*
		 * Add to mount tree. Generic code will mount it later
		 *
		 * note: These is quiet risky to add a mount in random place
		 * in the mount tree not considering possible propagation and
		 * friends, you can make non-restorable tree. But it works yet,
		 * so leave it.
		 */
		cr_time = add_cr_time_mount(root_yard_mp, "binfmt_misc",
					    "binfmt_misc", 0, true);
		if (!cr_time)
			return -1;
	}
#endif

	if (validate_mounts(mntinfo, false))
		return -1;

	if (populate_roots_yard_v2(cr_time))
		return -1;

	insert_internal_yards();

	ret = mnt_tree_for_each(root_yard_mp, do_mount_one_v2);
	if (!ret)
		ret = mnt_tree_for_each(root_yard_mp, set_unbindable_v2);

	/*
	 * Remove auxiliary cr-time mount from the mount tree as early as
	 * possible, this is a temporary mount which is unmounted imediately
	 * after restore, so it should not be there in the tree for the sake of
	 * --check-mounts.
	 */
	if (cr_time) {
		/*
		 * This mount should not get to any list, but be on the safe
		 * side and never free an entry from the middle of an alive
		 * list.
		 */
		BUG_ON(!list_empty(&cr_time->children));
		BUG_ON(!list_empty(&cr_time->mnt_slave));
		BUG_ON(!list_empty(&cr_time->mnt_slave_list));
		BUG_ON(!list_empty(&cr_time->mnt_share));
		BUG_ON(!list_empty(&cr_time->mnt_bind));
		BUG_ON(!list_empty(&cr_time->mnt_propagate));
		BUG_ON(!list_empty(&cr_time->mnt_notprop));
		BUG_ON(!list_empty(&cr_time->postpone));
		BUG_ON(!list_empty(&cr_time->mnt_sharing));
		BUG_ON(!list_empty(&cr_time->deleted_list));

		cr_time->parent->next = cr_time->next;
		list_del(&cr_time->siblings);
		mnt_entry_free(cr_time);
	}

	return ret;
}

/*
 * Mounts in children list are sorted the way that sibling overmount goes after
 * all siblings which it overmounts (see __mnt_resort_children). The function
 * mnt_tree_for_each is effectively DFS (in case we don't postpone), thus all
 * descendants of all mounts which we sibling-overmount are mounted before us.
 *
 * Be carefull, we can't postpone (return >0) from this function because of it.
 */
static int move_mount_to_tree(struct mount_info *mi)
{
	int fd;

	/* Create temporary directory for the internal yard */
	if (is_internal_yard(mi)) {
		struct mount_info *c;
		int len;

		if (!mkdtemp(mi->mountpoint)) {
			pr_perror("Failed to create temporary dir for internal yard %d\n",
				  mi->nsid->id);
			return -1;
		}
		len = strlen(mi->mountpoint);

		/*
		 * Copy temporary directory path to all helper mounts. It is
		 * allocated on the shared memory so we will see this change
		 * later in main task.
		 */
		list_for_each_entry(c, &mi->children, siblings)
			strncpy(c->mountpoint, mi->mountpoint, len);
	}

	fd = open(mi->mountpoint, O_PATH);
	if (fd < 0) {
		pr_perror("Failed to open real mountpoint of %d", mi->mnt_id);
		return -1;
	}

	mi->rmi->mp_fd_id = fdstore_add(fd);
	close(fd);
	if (mi->rmi->mp_fd_id < 0) {
		pr_err("Can't add mountpoint of mount %d to fdstore\n", mi->mnt_id);
		return -1;
	}

	pr_info("Move mount %d from %s to %s\n", mi->mnt_id,
		mi->plain_mountpoint, mi->mountpoint);
	if (mount(mi->plain_mountpoint, mi->mountpoint, NULL, MS_MOVE, NULL)) {
		pr_perror("Failed to move mount %d from %s to %s", mi->mnt_id,
			  mi->plain_mountpoint, mi->mountpoint);
		return -1;
	}

	fd = open(mi->mountpoint, O_PATH);
	if (fd < 0) {
		pr_perror("Failed to open real mountpoint of %d", mi->mnt_id);
		return -1;
	}

	mi->rmi->mnt_fd_id = fdstore_add(fd);
	close(fd);
	if (mi->rmi->mnt_fd_id < 0) {
		pr_err("Can't add mount %d fd to fdstore\n", mi->mnt_id);
		return -1;
	}

	return 0;
}

static int assemble_tree_from_plain_mounts(struct ns_id *nsid)
{
	return mnt_tree_for_each(nsid->mnt.mntinfo_tree, move_mount_to_tree);
}

static int restore_one_sharing_group(struct sharing_group *sg)
{
	struct mount_info *first, *other;
	char first_path[PATH_MAX];
	int first_fd;

	first = list_first_entry(&sg->mnt_list,
			    struct mount_info, mnt_sharing);
	first_fd = fdstore_get(first->rmi->mnt_fd_id);
	BUG_ON(first_fd < 0);
	snprintf(first_path, sizeof(first_path),
		 "/proc/self/fd/%d", first_fd);

	/* Restore first's master_id from shared_id of the source */
	if (sg->master_id) {
		char *source, _source[PATH_MAX];
		int sfd = -1;

		if (sg->parent) {
			struct mount_info *p;

			p = list_first_entry(&sg->parent->mnt_list,
					     struct mount_info, mnt_sharing);
			sfd = fdstore_get(p->rmi->mnt_fd_id);
			BUG_ON(sfd < 0);
			snprintf(_source, sizeof(_source),
				 "/proc/self/fd/%d", sfd);
			source = _source;
			pr_debug("Copy slavery from %d to %d\n",
				 p->mnt_id, first->mnt_id);
		} else {
			/*
			 * External slavery. We rely on the user to give us the
			 * right source for external mount with all proper
			 * sharing optioins setup (it should be either shared
			 * or non-shared slave). If source is a private mount
			 * we would restore mounts wrong.
			 */
			BUG_ON(!sg->source);
			source = sg->source;
			pr_debug("Copy slavery from external %s to %d\n",
				 source, first->mnt_id);
		}

		/* Copy shared_id of the source */
		if (mount(source, first_path, NULL, MS_SET_GROUP, NULL)) {
			pr_perror("Failed to copy sharing from %s to %d",
				  source, first->mnt_id);
			close(first_fd);
			if (sfd >= 0)
				close(sfd);
			return -1;
		}

		/* Convert shared_id to master_id */
		if (mount(NULL, first_path, NULL, MS_SLAVE, NULL)) {
			pr_perror("Failed to make mount %d slave",
				  first->mnt_id);
			close(first_fd);
			if (sfd >= 0)
				close(sfd);
			return -1;
		}

		if (sfd >= 0)
			close(sfd);
	}

	/* Restore first's shared_id */
	if (sg->shared_id) {
		pr_debug("Create new shared group for %d\n",
			 first->mnt_id);
		if (mount(NULL, first_path, NULL, MS_SHARED, NULL)) {
			pr_perror("Failed to make mount %d shared",
				  first->mnt_id);
			close(first_fd);
			return -1;
		}
	}

	/* Restore sharing for other mounts from the sharing group */
	list_for_each_entry(other, &sg->mnt_list, mnt_sharing) {
		char mntfd_path[PATH_MAX];
		int mntfd;

		if (other == first)
			continue;

		mntfd = fdstore_get(other->rmi->mnt_fd_id);
		BUG_ON(mntfd < 0);
		snprintf(mntfd_path, sizeof(mntfd_path),
			 "/proc/self/fd/%d", mntfd);

		pr_debug("Copy sharing group from %d to %d\n",
			 first->mnt_id, other->mnt_id);
		if (mount(first_path, mntfd_path, NULL, MS_SET_GROUP, NULL)) {
			pr_perror("Failed to copy sharing from %d to %d",
				  first->mnt_id, other->mnt_id);
			close(mntfd);
			close(first_fd);
			return -1;
		}

		close(mntfd);
	}

	close(first_fd);
	return 0;
}

static struct sharing_group *sharing_group_next(struct sharing_group *sg)
{
	if (!list_empty(&sg->children))
		return list_entry(sg->children.next, struct sharing_group, siblings);

	while (sg->parent) {
		if (sg->siblings.next == &sg->parent->children)
			sg = sg->parent;
		else
			return list_entry(sg->siblings.next, struct sharing_group, siblings);
	}

	return NULL;
}

static int restore_mount_sharing_options(void)
{
	struct sharing_group *sg;

	list_for_each_entry(sg, &sharing_groups, list) {
		struct sharing_group *t;

		if (sg->parent)
			continue;

		/* Handle dependant sharing groups in tree order */
		for (t = sg; t != NULL; t = sharing_group_next(t)) {
			if (restore_one_sharing_group(t))
				return -1;
		}
	}

	return 0;
}

static int remove_source_of_deleted_mount(struct mount_info *mi)
{
	char *cut_root, path[PATH_MAX], *root;

	BUG_ON(!mi->deleted || !mi->bind);

	cut_root = get_relative_path(mi->root, mi->bind->root);
	if (!cut_root) {
		pr_err("Failed to find root for %d in our supposed bind %d\n",
				mi->mnt_id, mi->bind->mnt_id);
		return -1;
	}

	if (cut_root[0]) {
		snprintf(path, sizeof(path), "%s/%s",
			 mi->bind->plain_mountpoint, cut_root);
		root = path;
	} else {
		root = mi->bind->plain_mountpoint;
	}

	if (mi->is_dir) {
		if (rmdir(root)) {
			pr_perror("Can't remove deleted directory %s", root);
			return -1;
		}
	} else {
		if (unlink(root)) {
			pr_perror("Can't unlink deleted file %s", root);
			return -1;
		}
	}

	if (mi->deleted_level && rm_parent_dirs(-1, root, mi->deleted_level))
		return -1;

	return 0;
}

static int remove_sources_of_deleted_mounts(void)
{
	struct mount_info *mi;
	int ret = 0;

	list_for_each_entry(mi, &deleted_mounts, deleted_list) {
		if (remove_source_of_deleted_mount(mi))
			ret = -1;
	}

	return ret;
}

int prepare_mnt_ns_v2(void)
{
	int ret = -1, rst = -1, fd;
	struct ns_id *nsid;

	if (!(root_ns_mask & CLONE_NEWNS))
		return 0;

	ret = populate_mnt_ns_v2();
	if (ret)
		return -1;

	rst = open_proc(PROC_SELF, "ns/mnt");
	if (rst < 0)
		return -1;

	/* restore non-root namespaces */
	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		char path[PATH_MAX];

		if (nsid->nd != &mnt_ns_desc)
			continue;
		/* Create the new mount namespace */
		if (unshare(CLONE_NEWNS)) {
			pr_perror("Unable to create a new mntns");
			goto err;
		}

		fd = open_proc(PROC_SELF, "ns/mnt");
		if (fd < 0)
			goto err;

		if (nsid->type == NS_ROOT) {
			/*
			 * We need to create a mount namespace which will be
			 * used to clean up remap files
			 * (depopulate_roots_yard).  The namespace where mounts
			 * was restored has to be restored as a root mount
			 * namespace, because there are file descriptors
			 * linked with it (e.g. to bind-mount slave pty-s).
			 */
			if (setns(rst, CLONE_NEWNS)) {
				pr_perror("Can't restore mntns back");
				goto err;
			}
			SWAP(rst, fd);
		}

		/* Pin one with a file descriptor */
		nsid->mnt.nsfd_id = fdstore_add(fd);
		close(fd);
		if (nsid->mnt.nsfd_id < 0) {
			pr_err("Can't add ns fd\n");
			goto err;
		}

		if (assemble_tree_from_plain_mounts(nsid))
			goto err;

		/* Set its root */
		print_ns_root(nsid, 0, path, sizeof(path) - 1);
		if (cr_pivot_root(path))
			goto err;

		/* root fd is used to restore file mappings */
		fd = open_proc(PROC_SELF, "root");
		if (fd < 0)
			goto err;
		nsid->mnt.root_fd_id = fdstore_add(fd);
		if (nsid->mnt.root_fd_id < 0) {
			pr_err("Can't add root fd\n");
			close(fd);
			goto err;
		}
		close(fd);

		/* And return back to regain the access to the roots yard */
		if (setns(rst, CLONE_NEWNS)) {
			pr_perror("Can't restore mntns back");
			goto err;
		}
	}
	close(rst);

	extract_internal_yards();

	return remove_sources_of_deleted_mounts();
err:
	if (rst >= 0)
		restore_ns(rst, &mnt_ns_desc);
	return -1;
}

LIST_HEAD(nested_pidns_procs);

static void search_nested_pidns_proc(void) {
	struct mount_info *mi, *t;

	for (mi = mntinfo; mi; mi = mi->next) {
		if (mi->fstype->code != FSTYPE__PROC)
			continue;

		if (mi->nses.pidns_id)
			continue;

		BUG_ON(list_empty(&mi->mnt_bind) && !mi->mnt_no_bind);
		list_for_each_entry(t, &mi->mnt_bind, mnt_bind) {
			if (t->nses.pidns_id) {
				mi->nses.pidns_id = t->nses.pidns_id;
				break;
			}
		}

		if (!mi->nses.pidns_id) {
			pr_warn("Proc %d lacks owner pidns info, assume root pidns\n", mi->mnt_id);
			mi->nses.pidns_id = root_item->ids->pid_ns_id;
		}

		list_for_each_entry(t, &mi->mnt_bind, mnt_bind) {
			BUG_ON(t->nses.pidns_id &&
			       t->nses.pidns_id != mi->nses.pidns_id);
			t->nses.pidns_id = mi->nses.pidns_id;
		}
	}

	for (mi = mntinfo; mi; mi = mi->next) {
		if (mi->fstype->code != FSTYPE__PROC)
			continue;

		if (mi->nses.pidns_id != root_item->ids->pid_ns_id)
			list_add(&mi->mnt_proc, &nested_pidns_procs);
	}
}

static int setup_internal_yards(void)
{
	struct ns_id *ns;

	for (ns = ns_ids; ns != NULL; ns = ns->next) {
		struct mount_info *yard;
		char yard_mp[PATH_MAX], plain[PATH_MAX];
		int len;

		if (ns->nd != &mnt_ns_desc)
			continue;

		yard = mnt_entry_alloc(true);
		if (!yard)
			return -1;

		len = print_ns_root(ns, 0, yard_mp, sizeof(yard_mp));
		snprintf(yard_mp + len, sizeof(yard_mp) - len, "/internal-yard-XXXXXX");
		yard->mountpoint = shmalloc(strlen(yard_mp) + 1);
		if (!yard->mountpoint)
			return -1;
		strcpy(yard->mountpoint, yard_mp);
		yard->ns_mountpoint = yard->mountpoint + len;

		snprintf(plain, sizeof(plain), "%s/internal-yard-%010d", mnt_roots, ns->id);
		yard->plain_mountpoint = xstrdup(plain);
		if (!yard->plain_mountpoint)
			return -1;

		yard->root = xstrdup("/");
		if (!yard->root)
			return -1;

		yard->fstype = find_fstype_by_name("tmpfs");
		yard->is_dir = true;

		yard->nsid = ns;
		yard->rmi->mounted = false;
		yard->mnt_no_bind = true;

		yard->parent = ns->mnt.mntinfo_tree;
		ns->mnt.internal_yard = yard;
	}

	return 0;
}

int print_plain_helper_mountpoint(struct mount_info *mi, char *buf, int bs)
{
	return snprintf(buf, bs, "%s/hlp-%010d", mnt_roots, mi->mnt_id);
}

static int handle_nested_pidns_proc(void)
{
	struct mount_info *mi;

	/**
	 * Temporary remove nested pidns proc mounts from tree, so that it is
	 * easier to do a walk over all their descendants visiting each only
	 * once.
	 */
	list_for_each_entry(mi, &nested_pidns_procs, mnt_proc)
		list_del_init(&mi->siblings);

	list_for_each_entry(mi, &nested_pidns_procs, mnt_proc) {
		struct mount_info *c = mi;
		struct ns_id *nsid = mi->nsid;

		nsid->mnt.enable_internal_yard = true;

		while ((c = mnt_subtree_next(c, mi))) {
			char path[PATH_MAX];
			struct mount_info *h;
			int len;

			/**
			 * Create a helper mount in internal yard for each
			 * mount of second step:
			 *
			 * 1) Will bind real mount from helper later when in
			 * proper mntns;
			 * 2) Helper should effectively be the same as it's
			 * prototype mount, except it's mountpoint is in
			 * internal yard and its root is wider ("/") so that
			 * helpers are not "deleted" or "file" mounts.
			 */
			h = mnt_entry_alloc(true);
			if (!h)
				return -1;

			h->nsid = c->nsid;
			h->mnt_id = c->mnt_id;
			print_plain_helper_mountpoint(h, path, sizeof(path));
			h->plain_mountpoint = xstrdup(path);
			if (!h->plain_mountpoint)
				return -1;
			/* FIXME external mounts sometimes can't have root "/" */
			h->root = xstrdup("/");
			if (!h->root)
				return -1;
			h->deleted = false;
			h->s_dev = c->s_dev;
			h->fstype = c->fstype;
			h->is_dir = true;
			h->external = c->external;
			h->need_plugin = c->need_plugin;
			h->source = c->source;
			h->ns_bind_id = c->ns_bind_id;
			h->ns_bind_desc = c->ns_bind_desc;
			h->private = c->private;

			len = print_ns_root(nsid, 0, path, sizeof(path));
			snprintf(path + len, sizeof(path) - len,
				 "/internal-yard-XXXXXX/hlp-%010d", c->mnt_id);
			h->mountpoint = shmalloc(strlen(path) + 1);
			if (!h->mountpoint)
				return -1;
			strcpy(h->mountpoint, path);
			h->ns_mountpoint = h->mountpoint + len;

			h->parent = nsid->mnt.internal_yard;
			list_add(&h->siblings, &h->parent->children);

			list_add(&h->mnt_bind, &c->mnt_bind);
			c->mnt_no_bind = false;
			c->helper = h;
		}
	}

	/* Put nested pidns proc mounts back to tree */
	list_for_each_entry(mi, &nested_pidns_procs, mnt_proc)
		list_add(&mi->siblings, &mi->parent->children);

	return 0;
}

int read_mnt_ns_img_v2(struct mount_info *info) {
	search_nested_pidns_proc();

	if (resolve_shared_mounts_v2(info))
		return -1;

	if (setup_internal_yards())
		return -1;

	if (handle_nested_pidns_proc())
		return -1;

	return 0;
}

static int __resolve_mnt_path_fd(struct mount_info *mi, char *path, char **rel,
				 struct mount_info *skip)
{
	struct mount_info *t;
	int len, fd_id, fd;
	char *rel_path;

	/* Not yet mounted */
	if (mi->rmi->mnt_fd_id == -1) {
		pr_err("Mount %d is not yet mounted\n", mi->mnt_id);
		return -1;
	}

	rel_path = get_relative_path(path, mi->ns_mountpoint);
	if (!rel_path) {
		pr_err("Failed to find %s in %s\n",
		       path, mi->ns_mountpoint);
		return -1;
	}

	len = strlen(rel_path);
	fd_id = mi->rmi->mnt_fd_id;

	list_for_each_entry(t, &mi->children, siblings) {
		char *tmp_rel_path;
		int tmp_len;

		/* Not yet mounted */
		if (t->rmi->mp_fd_id == -1)
			continue;

		if (skip && t == skip)
			continue;

		tmp_rel_path = get_relative_path(path, t->ns_mountpoint);
		if (!tmp_rel_path)
			continue;
		tmp_len = strlen(tmp_rel_path);

		if (tmp_len < len) {
			rel_path = tmp_rel_path;
			len = tmp_len;
			fd_id = t->rmi->mp_fd_id;
		}
	}

	fd = fdstore_get(fd_id);
	if (fd < 0) {
		pr_err("Can't fdstore_get for %d\n", fd_id);
		return -1;
	}

	*rel = rel_path;
	return fd;
}

/**
 * This function performs a lookup of path in specified mount and opens it.
 *
 * Each mounted mount has mnt_fd_id in fdstore, which is a root dentry of the
 * mount. We can open any path on the mount from it if the path is not covered
 * by children mounts.
 *
 * Each mounted mount has mp_fd_id in fdstore, which is a mountpoint dentry of
 * the mount. We can open any path on the parent mount which is covered by our
 * mount from it.
 */
static int __maybe_unused resolve_mnt_path_fd(struct mount_info *mi, char *path)
{
	char *rel_path;
	int fd;

	fd = __resolve_mnt_path_fd(mi, path, &rel_path, NULL);
	if (fd < 0)
		return -1;

	if (rel_path[0]) {
		int tmp;

		tmp = openat(fd, rel_path, O_PATH);
		if (tmp < 0) {
			pr_err("Can't openat %d:%s\n", fd, rel_path);
			close(fd);
			return -1;
		}
		close(fd);
		fd = tmp;
	}

	return fd;
}

/* Get an fd to the root dentry of the mount which was just mounted */
static int __maybe_unused resolve_mnt_fd(struct mount_info *mi)
{
	struct mount_info *ancestor = mi->parent, *skip = mi;
	char *rel_path = NULL;
	int fd, tmp;

	/*
	 * Don't support overmounted "/". It can be open through setns as it
	 * will get mntns chrooted into overmount, but it can't be open from
	 * where we are right now.
	 */
	BUG_ON(get_relative_path("/", mi->ns_mountpoint));

	/* Find first ancestor with different mountpoint */
	while (ancestor) {
		rel_path = get_relative_path(mi->ns_mountpoint, ancestor->ns_mountpoint);
		if (!rel_path) {
			pr_err("Failed to find %s in %s\n",
			       mi->ns_mountpoint, ancestor->ns_mountpoint);
			return -1;
		}

		if (rel_path[0])
			break;

		skip = ancestor;
		ancestor = ancestor->parent;
	}

	if (!rel_path || !rel_path[0]) {
		pr_err("Failed to find ancestor with diffrent mp for %d\n",
		       mi->mnt_id);
		return -1;
	}

	fd = __resolve_mnt_path_fd(ancestor, mi->ns_mountpoint, &rel_path, skip);
	if (fd < 0)
		return -1;

	BUG_ON(!rel_path[0]);

	tmp = openat(fd, rel_path, O_PATH);
	if (tmp < 0) {
		pr_err("Can't openat %d:%s\n", fd, rel_path);
		close(fd);
		return -1;
	}
	close(fd);
	fd = tmp;

	return fd;
}

static int __fini_restore_mntns_v2(void *arg)
{
	struct ns_id *nsid;
	bool cleanup = (bool)arg;

	if (root_ns_mask & CLONE_NEWUSER) {
		int fd, ret;

		nsid = lookup_ns_by_id(root_item->ids->user_ns_id, &user_ns_desc);
		if (!nsid) {
			pr_err("Can't find root item's userns\n");
			return 1;
		}

		fd = fdstore_get(nsid->user.nsfd_id);
		if (fd < 0) {
			pr_perror("Can't fdstore_get userns fd");
			return 1;
		}

		ret = setns(fd, CLONE_NEWUSER);
		close(fd);
		if (ret) {
			pr_perror("Can't setns to root item's userns");
			return 1;
		}

		if (prepare_userns_creds()) {
			pr_err("Can't set creds\n");
			return 1;
		}
	}

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &mnt_ns_desc)
			continue;

		if (!nsid->mnt.enable_internal_yard)
			continue;

		if (cleanup && nsid->mnt.nsfd_id == -1)
			continue;

		if (do_restore_task_mnt_ns(nsid))
			return 1;

		if (cleanup && !strcmp(nsid->mnt.internal_yard->ns_mountpoint,
				       "/internal-yard-XXXXXX"))
			continue;

		pr_info("Unmounting internal yard\n");
		if (umount2(nsid->mnt.internal_yard->ns_mountpoint,
			    MNT_DETACH)) {
			pr_perror("Failed to unmount internal yard of %d",
				  nsid->id);
			return 1;
		}

		if (rmdir(nsid->mnt.internal_yard->ns_mountpoint) &&
		    errno != ENOENT) {
			pr_perror("Failed to rmdir internal yard of %d",
				  nsid->id);
			return 1;
		}
	}

	return 0;
}

int fini_restore_mntns_v2(void)
{
	if (!(root_ns_mask & CLONE_NEWNS))
		return 0;

	if (call_in_child_process(__fini_restore_mntns_v2, (void*)false))
		return -1;

	return restore_mount_sharing_options();
}

int cleanup_internal_yards(void)
{
	if (!(root_ns_mask & CLONE_NEWNS))
		return 0;

	if (call_in_child_process(__fini_restore_mntns_v2, (void*)true))
		return -1;

	return 0;
}
