#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <ctype.h>
#include <sys/sendfile.h>
#include <sched.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <elf.h>

#ifndef SEEK_DATA
#define SEEK_DATA	3
#define SEEK_HOLE	4
#endif

/* Stolen from kernel/fs/nfs/unlink.c */
#define SILLYNAME_PREF ".nfs"
#define SILLYNAME_SUFF_LEN (((unsigned)sizeof(u64) << 1) + ((unsigned)sizeof(unsigned int) << 1))

/*
 * If the build-id exists, then it will most likely be present in the
 * beginning of the file. Therefore only the first 1MB will be mapped
 * and checked.
 */
#define BUILD_ID_MAP_SIZE 1048576

#include "cr_options.h"
#include "imgset.h"
#include "file-ids.h"
#include "mount.h"
#include "files.h"
#include "common/list.h"
#include "rst-malloc.h"
#include "fs-magic.h"
#include "namespaces.h"
#include "proc_parse.h"
#include "path.h"
#include "pstree.h"
#include "string.h"
#include "fault-injection.h"
#include "external.h"
#include "memfd.h"
#include "spfs.h"
#include "filesystems.h"
#include "fdstore.h"

#include "protobuf.h"
#include "util.h"
#include "images/mnt.pb-c.h"
#include "images/regfile.pb-c.h"
#include "images/remap-file-path.pb-c.h"

#include "files-reg.h"
#include "plugin.h"
#include "criu-log.h"
#include "string.h"

#define ATOP_ACCT_FILE "tmp/atop.d/atop.acct"
#define PROCFS_SYSDIR	"proc/sys/"
#define CGROUP_SYSDIR	"sys/fs/cgroup/"

int setfsuid(uid_t fsuid);
int setfsgid(gid_t fsuid);

/*
 * Ghost files are those not visible from the FS. Dumping them is
 * nasty and the only way we have -- just carry its contents with
 * us. Any brave soul to implement link unlinked file back?
 */
struct ghost_file {
	struct list_head	list;
	u32			id;

	u32			dev;
	u32			ino;

	struct file_remap	remap;
};

static u32 ghost_file_ids = 1;
static LIST_HEAD(ghost_files);
static LIST_HEAD(spfs_files);

/*
 * When opening remaps we first create a link on the remap
 * target, then open one, then unlink. In case the remap
 * source has more than one instance, these tree steps
 * should be serialized with each other.
 */
static mutex_t *remap_open_lock;

static inline int init_remap_lock(void)
{
	remap_open_lock = shmalloc(sizeof(*remap_open_lock));
	if (!remap_open_lock)
		return -1;

	mutex_init(remap_open_lock);
	return 0;
}

static LIST_HEAD(dmp_remaps);
static struct list_head *rst_remaps;

/*
 * Remember the name to delete it if needed on error or
 * rollback action. Note we don't expect that there will
 * be a HUGE number of link remaps, so in a sake of speed
 * we keep all data in memory.
 */
struct link_remap_rlb {
	struct list_head	list;
	struct mount_info	*mi;
	char			*path;
	char			*orig;
	u32			id;
};

static int note_link_remap(char *path, char *orig, struct mount_info *mi, u32 id)
{
	struct link_remap_rlb *rlb;

	rlb = xmalloc(sizeof(*rlb));
	if (!rlb)
		goto err;

	rlb->path = xstrdup(path);
	if (!rlb->path)
		goto err2;

	rlb->orig = strdup(orig);
	if (!rlb->orig)
		goto err3;

	rlb->mi = mi;
	rlb->id = id;
	list_add(&rlb->list, &dmp_remaps);

	return 0;

err3:
	xfree(rlb->path);
err2:
	xfree(rlb);
err:
	pr_err("Can't note link remap for %s\n", path);
	return -1;
}

static int find_link_remap(char *path, struct mount_info *mi, u32 *id)
{
	struct link_remap_rlb *rlb;

	list_for_each_entry(rlb, &dmp_remaps, list) {
		if (rlb->mi != mi)
			continue;
		if (strcmp(rlb->orig, path))
			continue;

		*id = rlb->id;
		return 0;
	}
	return -ENOENT;
}

/* Trim "a/b/c/d" to "a/b/d" */
static int trim_last_parent(char *path)
{
	char *fname, *p;

	p = strrchr(path, '/');
	fname = p + 1;
	if (!p || *fname == '\0')
		return -1;

	while (p >= path && *p == '/')
		p--;

	if (p < path)
		return -1;

	while (p >= path && *p != '/')
		p--;
	p++;

	while (*fname != '\0')
		*p++ = *fname++;
	*p = '\0';

	return 0;
}

#define BUFSIZE	(4096)

static int copy_chunk_from_file(int fd, int img, off_t off, size_t len)
{
	int ret;

	while (len > 0) {
		ret = sendfile(img, fd, &off, len);
		if (ret <= 0) {
			pr_perror("Can't send ghost to image");
			return -1;
		}

		len -= ret;
	}

	return 0;
}

static int copy_file_to_chunks(int fd, struct cr_img *img, size_t file_size)
{
	GhostChunkEntry ce = GHOST_CHUNK_ENTRY__INIT;
	off_t data, hole = 0;

	while (hole < file_size) {
		data = lseek(fd, hole, SEEK_DATA);
		if (data < 0) {
			if (errno == ENXIO)
				/* No data */
				break;
			else if (hole == 0) {
				/* No SEEK_HOLE/DATA by FS */
				data = 0;
				hole = file_size;
			} else {
				pr_perror("Can't seek file data");
				return -1;
			}
		} else {
			hole = lseek(fd, data, SEEK_HOLE);
			if (hole < 0) {
				pr_perror("Can't seek file hole");
				return -1;
			}
		}

		ce.len = hole - data;
		ce.off = data;

		if (pb_write_one(img, &ce, PB_GHOST_CHUNK))
			return -1;

		if (copy_chunk_from_file(fd, img_raw_fd(img), ce.off, ce.len))
			return -1;
	}

	return 0;
}

static int copy_chunk_to_file(int img, int fd, off_t off, size_t len)
{
	int ret;

	while (len > 0) {
		if (lseek(fd, off, SEEK_SET) < 0) {
			pr_perror("Can't seek file");
			return -1;
		}

		if (opts.stream)
			ret = splice(img, NULL, fd, NULL, len, SPLICE_F_MOVE);
		else
			ret = sendfile(fd, img, NULL, len);
		if (ret < 0) {
			pr_perror("Can't send data");
			return -1;
		}

		off += ret;
		len -= ret;
	}

	return 0;
}

static int copy_file_from_chunks(struct cr_img *img, int fd, size_t file_size)
{
	if (ftruncate(fd, file_size) < 0) {
		pr_perror("Can't make file size");
		return -1;
	}

	while (1) {
		int ret;
		GhostChunkEntry *ce;

		ret = pb_read_one_eof(img, &ce, PB_GHOST_CHUNK);
		if (ret <= 0)
			return ret;

		if (copy_chunk_to_file(img_raw_fd(img), fd, ce->off, ce->len))
			return -1;

		ghost_chunk_entry__free_unpacked(ce, NULL);
	}
}

static int mkreg_ghost(char *path, GhostFileEntry *gfe, struct cr_img *img)
{
	int gfd, ret;

	gfd = open(path, O_WRONLY | O_CREAT | O_EXCL, gfe->mode);
	if (gfd < 0)
		return -1;

	if (gfe->chunks) {
		if (!gfe->has_size) {
			pr_err("Corrupted ghost image -> no size\n");
			close(gfd);
			return -1;
		}

		ret = copy_file_from_chunks(img, gfd, gfe->size);
	} else
		ret = copy_file(img_raw_fd(img), gfd, 0);
	if (ret < 0)
		unlink(path);
	close(gfd);

	return ret;
}

static int mklnk_ghost(char *path, GhostFileEntry *gfe)
{
	if (!gfe->symlnk_target) {
		pr_err("Ghost symlink target is NULL for %s. Image from old CRIU?\n", path);
		return -1;
	}

	if (symlink(gfe->symlnk_target, path) < 0) {
		/*
		 * ENOENT case is OK
		 * Take a look closer on create_ghost() function
		 */
		if (errno != ENOENT)
			pr_perror("symlink(%s, %s) failed", gfe->symlnk_target, path);
		return -1;
	}

	return 0;
}

static int ghost_apply_metadata(const char *path, GhostFileEntry *gfe)
{
	struct timeval tv[2];
	int ret = -1;

	if (S_ISLNK(gfe->mode)) {
		if (lchown(path, gfe->uid, gfe->gid) < 0) {
			pr_perror("Can't reset user/group on ghost %s", path);
			goto err;
		}

		/*
		 * We have no lchmod() function, and fchmod() will fail on
		 * O_PATH | O_NOFOLLOW fd. Yes, we have fchmodat()
		 * function and flag AT_SYMLINK_NOFOLLOW described in
		 * man 2 fchmodat, but it is not currently implemented. %)
		 */
	} else {
		if (chown(path, gfe->uid, gfe->gid) < 0) {
			pr_perror("Can't reset user/group on ghost %s", path);
			goto err;
		}

		if (chmod(path, gfe->mode)) {
			pr_perror("Can't set perms %o on ghost %s", gfe->mode, path);
			goto err;
		}
	}

	if (gfe->atim) {
		tv[0].tv_sec = gfe->atim->tv_sec;
		tv[0].tv_usec = gfe->atim->tv_usec;
		tv[1].tv_sec = gfe->mtim->tv_sec;
		tv[1].tv_usec = gfe->mtim->tv_usec;
		if (lutimes(path, tv)) {
			pr_perror("Can't set access and modification times on ghost %s", path);
			goto err;
		}
	}

	ret = 0;
err:
	return ret;
}

static int create_ghost_dentry(char *path, GhostFileEntry *gfe, struct cr_img *img)
{
	int ret = -1;
	char *msg = "";

again:
	if (S_ISFIFO(gfe->mode)) {
		if ((ret = mknod(path, gfe->mode, 0)) < 0)
			msg = "Can't create node for ghost file";
	} else if (S_ISCHR(gfe->mode) || S_ISBLK(gfe->mode)) {
		if (!gfe->has_rdev) {
			pr_err("No rdev for ghost device\n");
			goto err;
		}
		if ((ret = mknod(path, gfe->mode, gfe->rdev)) < 0)
			msg = "Can't create node for ghost dev";
	} else if (S_ISDIR(gfe->mode)) {
		if ((ret = mkdirpat(AT_FDCWD, path, gfe->mode)) < 0)
			msg = "Can't make ghost dir";
	} else if (S_ISLNK(gfe->mode)) {
		if ((ret = mklnk_ghost(path, gfe)) < 0)
			msg = "Can't create ghost symlink";
	} else {
		if ((ret = mkreg_ghost(path, gfe, img)) < 0)
			msg = "Can't create ghost regfile";
	}

	if (ret < 0) {
		/* Use grand parent, if parent directory does not exist */
		if (errno == ENOENT) {
			if (trim_last_parent(path) < 0) {
				pr_err("trim failed: @%s@\n", path);
				goto err;
			}
			goto again;
		}

		pr_perror("%s %s", msg, path);
		goto err;
	}

	ret = 0;
err:
	return ret;
}

static int nomntns_create_ghost(struct ghost_file *gf, GhostFileEntry *gfe,
				struct cr_img *img)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/%s", gf->remap.rpath);

	if (create_ghost_dentry(path, gfe, img))
		return -1;

	if (ghost_apply_metadata(path, gfe))
		return -1;

	strlcpy(gf->remap.rpath, path + 1, PATH_MAX);
	pr_debug("Remap rpath is %s\n", gf->remap.rpath);
	return 0;
}

static int create_ghost(struct ghost_file *gf, GhostFileEntry *gfe, struct cr_img *img)
{
	struct mount_info *mi;
	char path[PATH_MAX], *rel_path;

	if (!(root_ns_mask & CLONE_NEWNS))
		return nomntns_create_ghost(gf, gfe, img);

	mi = lookup_mnt_id(gf->remap.rmnt_id);
	if (!mi) {
		pr_err("The %d mount is not found for ghost\n", gf->remap.rmnt_id);
		return -1;
	}

	/*
	 * The path gf->remap.rpath is relative to mntns root, but we need a
	 * path relative to mountpoint as mountpoints are mounted plain without
	 * tree.
	 */
	rel_path = get_relative_path(gf->remap.rpath, mi->ns_mountpoint);
	if (!rel_path) {
		pr_err("Can't get path %s relative to %s\n",
		       gf->remap.rpath, mi->ns_mountpoint);
		return -1;
	}

	snprintf(path, sizeof(path), "%s%s%s",
		 service_mountpoint(mi), rel_path[0] ? "/" : "", rel_path);
	pr_debug("Trying to create ghost on plain path %s\n", path);

	/* We get here while in service mntns */
	if (try_remount_writable(mi, REMOUNT_IN_SERVICE_MNTNS))
		return -1;

	if (create_ghost_dentry(path, gfe, img))
		return -1;

	if (ghost_apply_metadata(path, gfe))
		return -1;

	/*
	 * Convert the path back to mntns relative, as create_ghost_dentry
	 * might have changed it.
	 */
	rel_path = get_relative_path(path, service_mountpoint(mi));
	if (!rel_path) {
		pr_err("Can't get path %s relative to %s\n",
		       path, mi->mountpoint);
		return -1;
	}

	snprintf(gf->remap.rpath, PATH_MAX, "%s%s%s",
		mi->ns_mountpoint + 1, rel_path[0] ? "/" : "", rel_path);
	pr_debug("Remap rpath is %s\n", gf->remap.rpath);
	return 0;
}

static inline void ghost_path(char *path, int plen,
		struct reg_file_info *rfi, RemapFilePathEntry *rpe)
{
	snprintf(path, plen, "%s.cr.%x.ghost", rfi->path, rpe->remap_id);
}

static int collect_remap_ghost(struct reg_file_info *rfi,
		RemapFilePathEntry *rpe)
{
	struct ghost_file *gf;

	list_for_each_entry(gf, &ghost_files, list)
		if (gf->id == rpe->remap_id)
			goto gf_found;

	/*
	 * Ghost not found. We will create one in the same dir
	 * as the very first client of it thus resolving any
	 * issues with cross-device links.
	 */

	pr_info("Opening ghost file %#x for %s\n", rpe->remap_id, rfi->path);

	gf = shmalloc(sizeof(*gf));
	if (!gf)
		return -1;
	file_remap_init(&gf->remap);

	/*
	 * The rpath is shmalloc-ed because we create the ghost
	 * file in root task context and generate its path there.
	 * However the path should be visible by the criu task
	 * in order to remove the ghost files from root FS (see
	 * try_clean_remaps()).
	 */
	gf->remap.rpath = shmalloc(PATH_MAX);
	if (!gf->remap.rpath)
		return -1;
	gf->remap.rpath[0] = 0;
	gf->id = rpe->remap_id;
	list_add_tail(&gf->list, &ghost_files);

gf_found:
	rfi->is_dir = gf->remap.is_dir;
	rfi->remap = &gf->remap;
	return 0;
}

static int open_remap_ghost(struct reg_file_info *rfi,
					RemapFilePathEntry *rpe)
{
	struct ghost_file *gf = container_of(rfi->remap, struct ghost_file, remap);
	GhostFileEntry *gfe = NULL;
	struct cr_img *img;

	if (rfi->remap->rpath[0])
		return 0;

	img = open_image(CR_FD_GHOST_FILE, O_RSTR, rpe->remap_id);
	if (!img)
		goto err;

	if (pb_read_one(img, &gfe, PB_GHOST_FILE) < 0)
		goto close_ifd;

	/*
	 * For old formats where optional has_[dev|ino] is
	 * not present we will have zeros here which is quite
	 * a sign for "absent" fields.
	 */
	gf->dev = gfe->dev;
	gf->ino = gfe->ino;
	gf->remap.rmnt_id = rfi->rfe->mnt_id;

	if (S_ISDIR(gfe->mode))
		strlcpy(gf->remap.rpath, rfi->path, PATH_MAX);
	else
		ghost_path(gf->remap.rpath, PATH_MAX, rfi, rpe);

	if (create_ghost(gf, gfe, img))
		goto close_ifd;

	close_image(img);

	gf->remap.is_dir = S_ISDIR(gfe->mode);
	gf->remap.uid = gfe->uid;
	gf->remap.gid = gfe->gid;
	ghost_file_entry__free_unpacked(gfe, NULL);

	return 0;

close_ifd:
	close_image(img);
err:
	if (gfe)
		ghost_file_entry__free_unpacked(gfe, NULL);
	return -1;
}

static int collect_remap_linked(struct reg_file_info *rfi,
		RemapFilePathEntry *rpe)
{
	struct file_remap *rm;
	struct file_desc *rdesc;
	struct reg_file_info *rrfi;

	rdesc = find_file_desc_raw(FD_TYPES__REG, rpe->remap_id);
	if (!rdesc) {
		pr_err("Can't find target file %x\n", rpe->remap_id);
		return -1;
	}

	rm = xmalloc(sizeof(*rm));
	if (!rm)
		return -1;
	file_remap_init(rm);

	rrfi = container_of(rdesc, struct reg_file_info, d);
	pr_info("Remapped %s -> %s\n", rfi->path, rrfi->path);

	rm->rpath = rrfi->path;
	rm->rmnt_id = rfi->rfe->mnt_id;
	rfi->remap = rm;
	return 0;
}

static int open_remap_linked(struct reg_file_info *rfi)
{
	if (root_ns_mask & CLONE_NEWUSER) {
		char *rpath, path[PATH_MAX];
		struct mount_info *mi;
		struct stat st;

		mi = lookup_mnt_id(rfi->remap->rmnt_id);
		if (!mi) {
			pr_err("The %d mount is not found for remap\n", rfi->remap->rmnt_id);
			return -1;
		}

		rpath = get_relative_path(rfi->remap->rpath, mi->ns_mountpoint);
		if (!rpath) {
			pr_err("Can't get path %s relative to %s\n", rfi->remap->rpath, mi->ns_mountpoint);
			return -1;
		}

		snprintf(path, sizeof(path), "%s%s%s", service_mountpoint(mi), rpath[0] ? "/" : "", rpath);

		if (lstat(path, &st)) {
			pr_perror("Can't get owner of link remap %s (-> %s)", rfi->remap->rpath, rpath);
			return -1;
		}

		rfi->remap->uid = st.st_uid;
		rfi->remap->gid = st.st_gid;
	}

	return 0;
}

static int collect_remap_dead_process(struct reg_file_info *rfi,
		RemapFilePathEntry *rfe)
{
	struct pstree_item *helper;

	helper = lookup_create_item((pid_t *)&rfe->remap_id, 1, root_item->ids->pid_ns_id);
	if (!helper)
		return -1;

	if (helper->pid->state != TASK_UNDEF) {
		pr_info("Skipping helper for restoring /proc/%d; pid exists\n", rfe->remap_id);
		return 0;
	}


	vsid(helper) = vsid(root_item);
	vpgid(helper) = vpgid(root_item);
	vpid(helper) = rfe->remap_id;
	helper->parent = root_item;

	helper->ids = dup_helper_ids(root_item->ids);
	if (!helper->ids)
		return -1;

	if (init_pstree_helper(helper)) {
		pr_err("Can't init helper\n");
		return -1;
	}
	add_child_task(helper, root_item);

	pr_info("Added a helper for restoring /proc/%d\n", vpid(helper));

	return 0;
}

struct remap_info {
	struct list_head list;
	RemapFilePathEntry *rpe;
	struct reg_file_info *rfi;
};

static int collect_one_remap(void *obj, ProtobufCMessage *msg, struct cr_img *i)
{
	struct remap_info *ri = obj;
	RemapFilePathEntry *rpe;
	struct file_desc *fdesc;

	ri->rpe = rpe = pb_msg(msg, RemapFilePathEntry);

	if (!rpe->has_remap_type) {
		rpe->has_remap_type = true;
		/* backward compatibility with images */
		if (rpe->remap_id & REMAP_GHOST) {
			rpe->remap_id &= ~REMAP_GHOST;
			rpe->remap_type = REMAP_TYPE__GHOST;
		} else
			rpe->remap_type = REMAP_TYPE__LINKED;
	}

	fdesc = find_file_desc_raw(FD_TYPES__REG, rpe->orig_id);
	if (fdesc == NULL) {
		pr_err("Remap for non existing file %#x\n", rpe->orig_id);
		return -1;
	}

	ri->rfi = container_of(fdesc, struct reg_file_info, d);

	switch (rpe->remap_type) {
	case REMAP_TYPE__GHOST:
		if (collect_remap_ghost(ri->rfi, ri->rpe))
			return -1;
		break;
	case REMAP_TYPE__LINKED:
		if (collect_remap_linked(ri->rfi, ri->rpe))
			return -1;
		break;
	case REMAP_TYPE__PROCFS:
		if (collect_remap_dead_process(ri->rfi, rpe) < 0)
			return -1;
		break;
	default:
		break;
	}

	list_add_tail(&ri->list, rst_remaps);

	return 0;
}

static int create_spfs(int mnt_id, char *rpath, size_t size, GhostFileEntry *gfe, struct cr_img *img)
{
	struct mount_info *mi;
	char path[PATH_MAX], *rel_path;
	int ret;
	struct stat st;

	if (!(root_ns_mask & CLONE_NEWNS)) {
		snprintf(path, sizeof(path), "/%s", rpath);
		goto nomntns;
	}

	mi = lookup_mnt_id(mnt_id);
	if (!mi) {
		pr_err("The %d mount is not found for ghost\n", mnt_id);
		return -1;
	}

	rel_path = get_relative_path(rpath, mi->ns_mountpoint);
	if (!rel_path) {
		pr_err("Can't get path %s relative to %s\n",
		       rpath, mi->ns_mountpoint);
		return -1;
	}

	snprintf(path, sizeof(path), "%s%s%s", service_mountpoint(mi),
		 strlen(rel_path) ? "/" : "", rel_path);

nomntns:
	if (lstat(path, &st) == 0) {
		pr_debug("%s exists\n", path);

		/* Path exists: lets check file type */
		if ((st.st_mode & S_IFMT) != (gfe->mode & S_IFMT)) {
			pr_err("path has wrong mode: %#o != %#o\n",
					st.st_mode & S_IFMT, gfe->mode & S_IFMT);
			return -1;
		}
		if (ghost_apply_metadata(path, gfe))
			return -1;

		return 0;
	}

	if (mkdirname(path, 0755))
		return -1;

	if (S_ISLNK(gfe->mode) && !gfe->symlnk_target) {
		/*
		 * Backward compatibility. Old images (vz7-u15) may have spfs
		 * files without symlnk_target, but mklnk_ghost requires it.
		 */
		gfe->symlnk_target = "CRIU_SPFS_SYMLINK_PLACEHOLDER";
	}

	ret = create_ghost_dentry(path, gfe, img);
	if (ret)
		return -1;

	if (size && truncate(path, size)) {
		pr_perror("failed to truncate %s", path);
		return -1;
	}

	if (ghost_apply_metadata(path, gfe))
		return -1;

	return 0;
}

static int open_remap_spfs(struct reg_file_info *rfi,
		RemapFilePathEntry *rfe)
{
	struct ghost_file *gf;
	GhostFileEntry *gfe = NULL;
	struct cr_img *img;

	/*
	 * Ghost not found. We will create one in the same dir
	 * as the very first client of it thus resolving any
	 * issues with cross-device links.
	 */

	pr_info("Creating spfs file %#x for %s\n", rfe->remap_id, rfi->path);

	gf = xmalloc(sizeof(*gf));
	if (!gf)
		return -1;

	img = open_image(CR_FD_GHOST_FILE, O_RSTR, rfe->remap_id);
	if (!img)
		goto err;

	if (pb_read_one(img, &gfe, PB_GHOST_FILE) < 0)
		goto close_ifd;

	if (create_spfs(rfi->rfe->mnt_id, rfi->path, rfi->rfe->size, gfe, img))
		goto close_ifd;

	ghost_file_entry__free_unpacked(gfe, NULL);
	close_image(img);

	gf->id = rfe->remap_id;
	list_add_tail(&gf->list, &spfs_files);
	return 0;

close_ifd:
	close_image(img);
err:
	if (gfe)
		ghost_file_entry__free_unpacked(gfe, NULL);
	xfree(gf);
	return -1;
}

static int open_remap_spfs_linked(struct reg_file_info *rfi,
		RemapFilePathEntry *rfe)
{
	int err;
	struct mount_info *mi;
	struct file_desc *rdesc;
	struct reg_file_info *rrfi;
	char *rel_path, *rrel_path;
	char path[PATH_MAX], link_remap[PATH_MAX];

	rdesc = find_file_desc_raw(FD_TYPES__REG, rfe->remap_id);
	if (!rdesc) {
		pr_err("Can't find target file %x\n", rfe->remap_id);
		return -1;
	}
	rrfi = container_of(rdesc, struct reg_file_info, d);

	mi = lookup_mnt_id(rfi->rfe->mnt_id);
	if (!mi) {
		pr_err("The %d mount is not found for ghost\n", rfi->rfe->mnt_id);
		return -1;
	}

	rel_path = get_relative_path(rfi->path, mi->ns_mountpoint);
	if (!rel_path) {
		pr_err("Can't get path %s relative to %s\n",
		       rfi->path, mi->ns_mountpoint);
		return -1;
	}

	rrel_path = get_relative_path(rrfi->path, mi->ns_mountpoint);
	if (!rel_path) {
		pr_err("Can't get path %s relative to %s\n",
		       rrfi->path, mi->ns_mountpoint);
		return -1;
	}

	snprintf(path, sizeof(path), "%s%s%s",
		 service_mountpoint(mi), rel_path[0] ? "/" : "", rel_path);
	snprintf(link_remap, sizeof(link_remap), "%s%s%s",
		 service_mountpoint(mi), rrel_path[0] ? "/" : "", rrel_path);
	pr_info("Creating spfs link %s for %s\n", link_remap, path);

	err = link(path, link_remap);
	if (err) {
		pr_perror("failed to create link %s", link_remap);
		return -1;
	}

	snprintf(path, sizeof(path), "/%s", rfi->path);
	snprintf(link_remap, sizeof(link_remap), "/%s", rrel_path);

	err = spfs_remap_path(mi->nsid, path, link_remap);
	if (err) {
		pr_err("failed to remap SPFS %s to %s\n", path, link_remap);
		return -errno;
	}

	pr_info("Remapped %s -> %s\n", rfi->path, rrfi->path);

	return 0;
}

static int prepare_one_remap(struct remap_info *ri)
{
	int ret = -1;
	RemapFilePathEntry *rpe = ri->rpe;
	struct reg_file_info *rfi = ri->rfi;

	pr_info("Configuring remap %#x -> %#x\n", rfi->rfe->id, rpe->remap_id);

	switch (rpe->remap_type) {
	case REMAP_TYPE__LINKED:
		ret = open_remap_linked(rfi);
		break;
	case REMAP_TYPE__GHOST:
		ret = open_remap_ghost(rfi, rpe);
		break;
	case REMAP_TYPE__PROCFS:
		/* handled earlier by collect_remap_dead_process */
		ret = 0;
		break;
	case REMAP_TYPE__SPFS:
		ret = open_remap_spfs(rfi, rpe);
		break;
	case REMAP_TYPE__SPFS_LINKED:
		ret = open_remap_spfs_linked(rfi, rpe);
		break;
	default:
		pr_err("unknown remap type %u\n", rpe->remap_type);
		goto out;
	}

out:
	return ret;
}

static int remap_info_cmp(const void *_a, const void *_b)
{
	struct remap_info *a = ((struct remap_info **)_a)[0];
	struct remap_info *b = ((struct remap_info **)_b)[0];
	int32_t mnt_id_a = a->rfi->rfe->mnt_id;
	int32_t mnt_id_b = b->rfi->rfe->mnt_id;

	/*
	 * If entries are laying on same mount, which is
	 * a common case, we can safely use paths comparision.
	 */
	if (mnt_id_a == mnt_id_b)
		return -strcmp(a->rfi->path, b->rfi->path);

	/*
	 * Otherwise simply order by mnt_id order for
	 * simplicity case, in future we might need to
	 * make more complex full path comparision.
	 */
	return mnt_id_a > mnt_id_b ? 1 : -1;
}

/*
 * Ghost directories may carry ghost files but file descriptors
 * are unordered in compare with this ghost paths, thus on cleanup
 * we might try to remove the directory itself without waiting
 * all files (and subdirectories) are cleaned up first.
 *
 * What we do here is we're move all ghost dirs into own list,
 * sort them (to address subdirectories order) and move back
 * to the end of the remap list.
 */
static int order_remap_dirs(void)
{
	struct remap_info *ri, *tmp;
	struct remap_info **p, **t;
	size_t nr_remaps = 0, i;
	LIST_HEAD(ghost_dirs);

	list_for_each_entry_safe(ri, tmp, rst_remaps, list) {
		if (ri->rpe->remap_type != REMAP_TYPE__GHOST)
			continue;
		if (!ri->rfi->remap->is_dir)
			continue;
		list_move_tail(&ri->list, &ghost_dirs);
		nr_remaps++;
	}

	if (list_empty(&ghost_dirs))
		return 0;

	p = t = xmalloc(sizeof(*p) * nr_remaps);
	if (!p) {
		list_splice_tail_init(&ghost_dirs, rst_remaps);
		return -ENOMEM;
	}

	list_for_each_entry_safe(ri, tmp, &ghost_dirs, list) {
		list_del_init(&ri->list);
		p[0] = ri, p++;
	}

	qsort(t, nr_remaps, sizeof(t[0]), remap_info_cmp);

	for (i = 0; i < nr_remaps; i++) {
		list_add_tail(&t[i]->list, rst_remaps);
		pr_debug("remap: ghost mov dir %s\n", t[i]->rfi->path);
	}

	if (!pr_quelled(LOG_DEBUG)) {
		list_for_each_entry_safe(ri, tmp, rst_remaps, list) {
			if (ri->rpe->remap_type != REMAP_TYPE__GHOST)
				continue;
			pr_debug("remap: ghost ord %3s %s\n",
				 ri->rfi->remap->is_dir ? "dir" : "fil",
				 ri->rfi->path);
		}
	}

	xfree(t);
	return 0;
}

int prepare_remaps(void)
{
	struct remap_info *ri;
	int ret = 0;

	ret = init_remap_lock();
	if (ret)
		return ret;

	list_for_each_entry(ri, rst_remaps, list) {
		ret = prepare_one_remap(ri);
		if (ret)
			break;
	}

	return ret ? : order_remap_dirs();
}

static int clean_ghost_dir(char *rpath)
{
	int ret = rmdir(rpath);
	/*
	 * When deleting ghost directories here is an issue:
	 * - names might duplicate, so we may receive ENOENT
	 *   and should not treat it as an error
	 */
	if (!ret || errno == ENOENT)
		return 0;

	/* Lets see what is inside for PSBM-101145 */
	if (errno == ENOTEMPTY) {
		int dfd, errno_saved = errno;

		dfd = open(rpath, O_DIRECTORY);
		if (dfd >= 0) {
			ret = is_empty_dir(dfd);
			if (ret == 1)
				pr_err("Got ENOTEMPTY on empty dir?\n");
		} else {
			pr_perror("Failed to open %s", rpath);
		}

		errno = errno_saved;
	}

	return -1;
}

static int clean_one_remap(struct remap_info *ri)
{
	struct file_remap *remap = ri->rfi->remap;
	int mnt_id, ret;
	struct mount_info *mi;
	char path[PATH_MAX], *rel_path;

	if (remap->rpath[0] == 0)
		return 0;

	if (!(root_ns_mask & CLONE_NEWNS)) {
		snprintf(path, sizeof(path), "/%s", remap->rpath);
		goto nomntns;
	}

	mnt_id = ri->rfi->rfe->mnt_id; /* rirfirfe %) */
	mi = lookup_mnt_id(mnt_id);
	if (!mi) {
		pr_err("The %d mount is not found for ghost\n", mnt_id);
		return -1;
	}

	rel_path = get_relative_path(remap->rpath, mi->ns_mountpoint);
	if (!rel_path) {
		pr_err("Can't get path %s relative to %s\n",
		       remap->rpath, mi->ns_mountpoint);
		return -1;
	}

	snprintf(path, sizeof(path), "%s%s%s", service_mountpoint(mi),
		 strlen(rel_path) ? "/" : "", rel_path);

	/* We get here while in service mntns */
	if (try_remount_writable(mi, REMOUNT_IN_SERVICE_MNTNS))
		return -1;

nomntns:
	pr_info("Unlink remap %s\n", path);

	if (remap->is_dir)
		ret = clean_ghost_dir(path);
	else
		ret = unlink(path);

	if (ret) {
		pr_perror("Couldn't unlink remap %s", path);
		return -1;
	}

	remap->rpath[0] = 0;
	return 0;
}

int try_clean_remaps(bool only_ghosts)
{
	struct remap_info *ri;
	int ret = 0;

	list_for_each_entry(ri, rst_remaps, list) {
		if (ri->rpe->remap_type == REMAP_TYPE__GHOST)
			ret |= clean_one_remap(ri);
		else if (only_ghosts)
			continue;
		else if (ri->rpe->remap_type == REMAP_TYPE__LINKED)
			ret |= clean_one_remap(ri);
	}

	return ret;
}

static struct collect_image_info remap_cinfo = {
	.fd_type = CR_FD_REMAP_FPATH,
	.pb_type = PB_REMAP_FPATH,
	.priv_size = sizeof(struct remap_info),
	.collect = collect_one_remap,
	.flags = COLLECT_SHARED,
};

/* Tiny files don't need to generate chunks in ghost image. */
#define GHOST_CHUNKS_THRESH	(3 * 4096)

static int dump_ghost_file(int _fd, u32 id, const struct stat *st,
			   dev_t phys_dev, bool dump_content)
{
	struct cr_img *img;
	int exit_code = -1;
	GhostFileEntry gfe = GHOST_FILE_ENTRY__INIT;
	Timeval atim = TIMEVAL__INIT, mtim = TIMEVAL__INIT;
	char pathbuf[PATH_MAX];

	pr_info("Dumping ghost file contents (id %#x)\n", id);

	img = open_image(CR_FD_GHOST_FILE, O_DUMP, id);
	if (!img)
		return -1;

	gfe.uid = userns_uid(st->st_uid);
	gfe.gid = userns_gid(st->st_gid);
	gfe.mode = st->st_mode;

	gfe.atim = &atim;
	gfe.mtim = &mtim;
	gfe.atim->tv_sec = st->st_atim.tv_sec;
	gfe.atim->tv_usec = st->st_atim.tv_nsec / 1000;
	gfe.mtim->tv_sec = st->st_mtim.tv_sec;
	gfe.mtim->tv_usec = st->st_mtim.tv_nsec / 1000;

	gfe.has_dev = gfe.has_ino = true;
	gfe.dev = phys_dev;
	gfe.ino = st->st_ino;

	if (S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode)) {
		gfe.has_rdev = true;
		gfe.rdev = st->st_rdev;
	}

	if (S_ISREG(st->st_mode) && (st->st_size >= GHOST_CHUNKS_THRESH)) {
		gfe.has_chunks = gfe.chunks = true;
		gfe.has_size = true;
		gfe.size = st->st_size;
	}

	/*
	 * We set gfe.symlnk_target only if we need to dump
	 * symlink content, otherwise we leave it NULL.
	 * It will be taken into account on restore in mklnk_ghost function.
	 */
	if (S_ISLNK(st->st_mode)) {
		ssize_t ret;

		/*
		 * We assume that _fd opened with O_PATH | O_NOFOLLOW
		 * flags because S_ISLNK(st->st_mode). With current kernel version,
		 * it's looks like correct assumption in any case.
		 */
		ret = readlinkat(_fd, "", pathbuf, sizeof(pathbuf) - 1);
		if (ret < 0) {
			pr_perror("Can't readlinkat");
			goto err_out;
		}

		pathbuf[ret] = 0;

		if (ret != st->st_size) {
			pr_err("Buffer for readlinkat is too small: ret %zd, st_size %"PRId64", buf %u %s\n",
					ret, st->st_size, PATH_MAX, pathbuf);
			goto err_out;
		}

		gfe.symlnk_target = pathbuf;
	}

	if (pb_write_one(img, &gfe, PB_GHOST_FILE))
		goto err_out;

	if (S_ISREG(st->st_mode) && dump_content) {
		int fd, ret;

		/*
		 * Reopen file locally since it may have no read
		 * permissions when drained
		 */
		fd = open_proc(PROC_SELF, "fd/%d", _fd);
		if (fd < 0) {
			pr_perror("Can't open ghost original file");
			goto err_out;
		}

		if (gfe.chunks)
			ret = copy_file_to_chunks(fd, img, st->st_size);
		else
			ret = copy_file(fd, img_raw_fd(img), st->st_size);
		close(fd);
		if (ret)
			goto err_out;
	}

	exit_code = 0;
err_out:
	close_image(img);
	return exit_code;
}

struct file_remap *lookup_ghost_remap(u32 dev, u32 ino)
{
	struct ghost_file *gf;

	list_for_each_entry(gf, &ghost_files, list) {
		if (gf->ino == ino && (gf->dev == dev)) {
			return &gf->remap;
		}
	}

	return NULL;
}

static int dump_ghost_remap_type(char *path, const struct stat *st,
				 int lfd, u32 id, struct ns_id *nsid,
				 RemapType remap_type, bool dump_content)
{
	struct ghost_file *gf;
	RemapFilePathEntry rpe = REMAP_FILE_PATH_ENTRY__INIT;
	dev_t phys_dev;

	phys_dev = phys_stat_resolve_dev(nsid, st->st_dev, path);
	list_for_each_entry(gf, &ghost_files, list)
		if ((gf->dev == phys_dev) && (gf->ino == st->st_ino))
			goto dump_entry;

	gf = xmalloc(sizeof(*gf));
	if (gf == NULL)
		return -1;

	gf->dev = phys_dev;
	gf->ino = st->st_ino;
	gf->id = ghost_file_ids++;

	if (dump_ghost_file(lfd, gf->id, st, phys_dev, dump_content)) {
		xfree(gf);
		return -1;
	}

	list_add_tail(&gf->list, &ghost_files);

dump_entry:
	rpe.orig_id = id;
	rpe.remap_id = gf->id;
	rpe.has_remap_type = true;
	rpe.remap_type = remap_type;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_REMAP_FPATH),
			&rpe, PB_REMAP_FPATH);
}

static int dump_ghost_remap(char *path, const struct stat *st,
			    int lfd, u32 id, struct ns_id *nsid)
{
	pr_info("Dumping ghost file for fd %d id %#x\n", lfd, id);

	if (st->st_size > (10 << 20)) {
		pr_syslog("Dumping the ghost file %s (%"PRIu64" bytes)\n", path, st->st_size);
	}

	if (st->st_size > opts.ghost_limit) {
		pr_err("Can't dump ghost file %s of %"PRIu64" size, increase limit\n",
				path, st->st_size);
		return -1;
	}

	return dump_ghost_remap_type(path, st, lfd, id, nsid, REMAP_TYPE__GHOST, true);
}

static void __rollback_link_remaps(bool do_unlink)
{
	struct link_remap_rlb *rlb, *tmp;
	int path_root = -1;
	char *path;
	bool ovm;

	list_for_each_entry_safe(rlb, tmp, &dmp_remaps, list) {
		if (do_unlink) {
			ovm = path_is_overmounted(rlb->path, rlb->mi);
			if (ovm) {
				resolve_mntfd_and_rpath(rlb->mi->mnt_id, rlb->path, false, &path_root, &path);
			} else {
				path_root = mntns_get_root_fd(rlb->mi->nsid);
				path = rlb->path;
			}

			if (path_root >= 0) {
				if (unlinkat(path_root, path, 0))
					pr_err("Failed to cleanup %s link remap\n", rlb->path);
				if (ovm)
					close(path_root);
			} else {
				pr_err("Failed to cleanup %s link remap\n", rlb->path);
			}
		}

		list_del(&rlb->list);
		xfree(rlb->orig);
		xfree(rlb->path);
		xfree(rlb);
	}
}

void delete_link_remaps(void) { __rollback_link_remaps(true); }
void free_link_remaps(void) { __rollback_link_remaps(false); }
static int linkat_hard(int odir, char *opath, int ndir, char *npath, uid_t uid, gid_t gid, int flags);

static int create_link_remap(char *path, int len, int lfd,
				u32 *idp, struct mount_info *mi,
				const struct stat *st)
{
	char link_name[PATH_MAX], *tmp, *rpath;
	FileEntry fe = FILE_ENTRY__INIT;
	RegFileEntry rfe = REG_FILE_ENTRY__INIT;
	FownEntry fwn = FOWN_ENTRY__INIT;
	int path_root, ret, fd = -1;
	bool overmounted;

	if (!opts.link_remap_ok) {
		pr_err("Can't create link remap for %s. "
				"Use " LREMAP_PARAM " option.\n", path);
		return -1;
	}

	/*
	 * Linked remapping -- we create a hard link on a removed file
	 * in the directory original file used to sit.
	 *
	 * Bad news is than we can't easily open lfd's parent dir. Thus
	 * we have to just generate an absolute path and use it. The linkat
	 * will fail if we chose the bad one.
	 */

	link_name[0] = '.';
	memcpy(link_name + 1, path, len);
	tmp = link_name + len;
	while (*tmp != '/') {
		BUG_ON(tmp == link_name);
		tmp--;
	}

	fd_id_generate_special(NULL, idp);
	rfe.id		= *idp;
	rfe.flags	= 0;
	rfe.pos		= 0;
	rfe.fown	= &fwn;
	rfe.name	= link_name + 1;

	/* Any 'unique' name works here actually. Remap works by reg-file ids. */
	snprintf(tmp + 1, sizeof(link_name) - (size_t)(tmp - link_name - 1), "link_remap.%d", rfe.id);

	overmounted = path_is_overmounted(link_name, mi);
	if (overmounted) {
		if (resolve_mntfd_and_rpath(mi->mnt_id, link_name, false, &path_root, &rpath)) {
			pr_err("Unable to resolve mntfd and rpath\n");
			return -1;
		}

		fd = open_opath_at_mount(lfd, path_root);
		if (fd < 0) {
			pr_perror("failed to reopen lfd %d at mount %d", lfd, mi->mnt_id);
			goto out;
		}
	} else {
		path_root = mntns_get_root_fd(mi->nsid);
		rpath = link_name;
		fd = lfd;
	}

again:
	ret = linkat_hard(fd, "", path_root, rpath,
				st->st_uid, st->st_gid, AT_EMPTY_PATH);
	if (ret < 0 && errno == ENOENT) {
		/* Use grand parent, if parent directory does not exist. */
		if (trim_last_parent(link_name) < 0) {
			pr_err("trim failed: @%s@\n", link_name);
			goto out;
		}
		goto again;
	} else if (ret < 0) {
		pr_perror("Can't link remap to %s", path);
		goto out;
	}

	if (note_link_remap(link_name, path, mi, *idp))
		goto out;

	fe.type = FD_TYPES__REG;
	fe.id = rfe.id;
	fe.reg = &rfe;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);

out:
	if (overmounted) {
		close(path_root);
		close(fd);
	}
	return -1;
}

static int dump_linked_remap_type(char *path, int len, const struct stat *ost,
				  int lfd, u32 id, struct mount_info *mi,
				  RemapType remap_type)
{
	u32 lid;
	RemapFilePathEntry rpe = REMAP_FILE_PATH_ENTRY__INIT;

	if (!find_link_remap(path, mi, &lid)) {
		pr_debug("Link remap for %s already exists with id %x\n",
				path, lid);
		/* Link-remap files in case of SPFS are created by criu on
		 * restore. Dump it only once to avoid collision */
		if (remap_type == REMAP_TYPE__SPFS_LINKED)
			return 0;
	} else if (create_link_remap(path, len, lfd, &lid, mi, ost))
			return -1;

	rpe.orig_id = id;
	rpe.remap_id = lid;
	rpe.has_remap_type = true;
	rpe.remap_type = remap_type;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_REMAP_FPATH),
			&rpe, PB_REMAP_FPATH);
}

static inline bool spfs_file(const struct fd_parms *parms, struct ns_id *nsid)
{
	struct mount_info *mi;

	if (parms->fs_type != NFS_SUPER_MAGIC)
		return false;

	if (!(root_ns_mask & CLONE_NEWNS))
		return false;

	mi = lookup_mnt_id(parms->mnt_id);
	if (!mi)
		return false;

	if (is_root_mount(mi))
		return false;

	if (mnt_is_external(mi))
		return false;

	return true;
}

static int dump_linked_remap(char *path, int len, const struct stat *ost,
				int lfd, u32 id, struct mount_info *mi,
				const struct fd_parms *parms)
{
	RemapType remap_type = REMAP_TYPE__LINKED;

	if (spfs_file(parms, mi->nsid))
		remap_type = REMAP_TYPE__SPFS_LINKED;

	return dump_linked_remap_type(path, len, ost, lfd, id, mi, remap_type);
}

static int dump_spfs_remap(char *path, const struct stat *st,
				int lfd, u32 id, struct ns_id *nsid)
{
	pr_info("Dumping SPFS path for fd %d id %#x [%s]\n", lfd, id, path);
	return dump_ghost_remap_type(path, st, lfd, id, nsid, REMAP_TYPE__SPFS, false);
}

static pid_t *dead_pids;
static int n_dead_pids;

int dead_pid_conflict(void)
{
	int i;

	for (i = 0; i < n_dead_pids; i++) {
		struct pid *node;
		pid_t pid = dead_pids[i];

		node = pstree_pid_by_virt(pid);
		if (!node)
			continue;

		/* Main thread */
		if (node->state != TASK_THREAD)
			continue;

		pr_err("Conflict with a dead task with the same PID as of this thread (virt %d, real %d).\n",
			node->ns[0].virt, node->real);
		return -1;
	}

	return 0;
}

static int have_seen_dead_pid(pid_t pid)
{
	int i;

	for (i = 0; i < n_dead_pids; i++) {
		if (dead_pids[i] == pid)
			return 1;
	}

	if (xrealloc_safe(&dead_pids, sizeof(*dead_pids) * (n_dead_pids + 1)))
		return -1;
	dead_pids[n_dead_pids++] = pid;

	return 0;
}

static int dump_dead_process_remap(pid_t pid, u32 id)
{
	RemapFilePathEntry rpe = REMAP_FILE_PATH_ENTRY__INIT;
	int ret;

	ret = have_seen_dead_pid(pid);
	if (ret < 0)
		return -1;
	if (ret) {
		pr_info("Found dead pid %d already, skipping remap\n", pid);
		return 0;
	}

	rpe.orig_id = id;
	rpe.remap_id = pid;
	rpe.has_remap_type = true;
	rpe.remap_type = REMAP_TYPE__PROCFS;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_REMAP_FPATH),
			&rpe, PB_REMAP_FPATH);
}

static bool is_sillyrename_name(char *name)
{
	int i;

	name = strrchr(name, '/');
	BUG_ON(name == NULL); /* see check in dump_one_reg_file */
	name++;

	/*
	 * Strictly speaking this check is not bullet-proof. User
	 * can create file with this name by hands and we have no
	 * API to distinguish really-silly-renamed files from those
	 * fake names :(
	 *
	 * But since NFS people expect .nfsXXX files to be unstable,
	 * we treat them as such too.
	 */

	if (strncmp(name, SILLYNAME_PREF, sizeof(SILLYNAME_PREF) - 1))
		return false;

	name += sizeof(SILLYNAME_PREF) - 1;
	for (i = 0; i < SILLYNAME_SUFF_LEN; i++)
		if (!isxdigit(name[i]))
			return false;

	return true;
}

static inline bool nfs_silly_rename(char *rpath, const struct fd_parms *parms)
{
	return (parms->fs_type == NFS_SUPER_MAGIC) && is_sillyrename_name(rpath);
}

static int check_path_remap(struct fd_link *link, const struct fd_parms *parms,
				int lfd, u32 id, struct mount_info *mi, int is_overmounted)
{
	char *rpath = link->name;
	int plen = link->len;
	int ret, rf_mnt_root = -1;
	struct stat pst;
	const struct stat *ost = &parms->stat;
	int flags = 0;

	if (parms->fs_type == PROC_SUPER_MAGIC) {
		/* The file points to /proc/pid/<foo> where pid is a dead
		 * process. We remap this file by adding this pid to be
		 * fork()ed into a TASK_HELPER state so that we can point to it
		 * on restore.
		 */
		pid_t pid;
		char *pid_str, *end;

		pid_str = get_relative_path(rpath, mi->ns_mountpoint);
		if (!pid_str) {
			pr_err("Can't resolve rpath (%s, %s)\n", rpath, mi->ns_mountpoint);
			return -1;
		}

		if (*pid_str == '\0') /* it's /proc */
			return 0;

		pid = strtol(pid_str, &end, 10);

		/* If strtol didn't convert anything, then we are looking at
		 * something like /proc/kmsg, which we shouldn't mess with.
		 * Anything under /proc/<pid> (including that directory itself)
		 * can be c/r'd with a dead pid remap, so let's allow all such
		 * cases.
		 */
		if (pid != 0) {
			bool is_dead = link_strip_deleted(link);

			if (is_overmounted) {
				rf_mnt_root = open_mountpoint(mi);
				rpath = pid_str;
			} else {
				rf_mnt_root = mntns_get_root_fd(mi->nsid);
			}
			if (rf_mnt_root < 0)
				return -1;

			/* /proc/<pid> will be "/proc/1 (deleted)" when it is
			 * dead, but a path like /proc/1/mountinfo won't have
			 * the suffix, since it isn't actually deleted (still
			 * exists, but the parent dir is deleted). So, if we
			 * have a path like /proc/1/mountinfo, test if /proc/1
			 * exists instead, since this is what CRIU will need to
			 * open on restore.
			 */
			if (!is_dead) {
				*end = 0;
				is_dead = faccessat(rf_mnt_root, rpath, F_OK, 0);
				*end = '/';
			}

			if (is_overmounted)
				close(rf_mnt_root);

			if (is_dead) {
				pr_info("Dumping dead process remap of %d\n", pid);
				return dump_dead_process_remap(pid, id);
			}
		}

		return 0;
	} else if (parms->fs_type == DEVPTS_SUPER_MAGIC) {
		/*
		 * It's safe to call stripping here because
		 * file paths are having predefined format for
		 * this FS and can't have a valid " (deleted)"
		 * postfix as a part of not deleted filename.
		 */
		link_strip_deleted(link);
		/*
		 * Devpts devices/files are generated by the
		 * kernel itself so we should not try to generate
		 * any kind of ghost files here even if file is
		 * no longer exist.
		 */
		return 0;
	}

	if (ost->st_nlink == 0) {
		if (spfs_file(parms, mi->nsid)) {
			pr_err("Ghost files on NFS are not supported\n");
			return -1;
		}

		/*
		 * Unpleasant, but easy case. File is completely invisible
		 * from the FS. Just dump its contents and that's it. But
		 * be careful whether anybody still has any of its hardlinks
		 * also open.
		 */

		link_strip_deleted(link);
		return dump_ghost_remap(rpath + 1, ost, lfd, id, mi->nsid);
	}

	if (spfs_file(parms, mi->nsid)) {
		if (dump_spfs_remap(rpath + 1, ost, lfd, id, mi->nsid))
			return -1;
	}

	if (nfs_silly_rename(rpath, parms)) {
		/*
		 * If this is NFS silly-rename file the path we have at hands
		 * will be accessible by fstat(), but once we kill the dumping
		 * tasks it will disappear. So we just go ahead an dump it as
		 * linked-remap file (NFS will allow us to create more hard
		 * links on it) to have some persistent name at hands.
		 */

		pr_debug("Dump silly-rename linked remap for %x [%s]\n", id, rpath + 1);
		return dump_linked_remap(rpath + 1, plen - 1, ost, lfd, id, mi, parms);
	}

	if (is_overmounted)
		resolve_mntfd_and_rpath(mi->mnt_id, link->name, false, &rf_mnt_root, &rpath);
	else
		rf_mnt_root = mntns_get_root_fd(mi->nsid);

	if (rf_mnt_root < 0) {
		pr_err("Unable to open mount to dump file\n");
		return -1;
	}

	if (S_ISLNK(parms->stat.st_mode))
		flags = AT_SYMLINK_NOFOLLOW;

	ret = fstatat(rf_mnt_root, rpath, &pst, flags);

	if (is_overmounted) {
		int errno_save = errno;

		close(rf_mnt_root);
		errno = errno_save;
	}

	if (ret < 0) {
		/*
		 * Linked file, but path is not accessible (unless any
		 * other error occurred). We can create a temporary link to it
		 * using linkat with AT_EMPTY_PATH flag and remap it to this
		 * name.
		 */

		if (errno == ENOENT) {
			link_strip_deleted(link);
			return dump_linked_remap(link->name + 1, plen - 1,
							ost, lfd, id, mi, parms);
		}

		pr_perror("Can't stat path");
		return -1;
	}

	if ((pst.st_ino != ost->st_ino) || (pst.st_dev != ost->st_dev)) {
		if (opts.evasive_devices &&
		    (S_ISCHR(ost->st_mode) || S_ISBLK(ost->st_mode)) &&
		    pst.st_rdev == ost->st_rdev)
			return 0;
		/*
		 * FIXME linked file, but the name we see it by is reused
		 * by somebody else. We can dump it with linked remaps, but
		 * we'll have difficulties on restore -- we will have to
		 * move the existing file aside, then restore this one,
		 * unlink, then move the original file back. It's fairly
		 * easy to do, but we don't do it now, since unlinked files
		 * have the "(deleted)" suffix in proc and name conflict
		 * is unlikely :)
		 */
		pr_err("Unaccessible path opened %u:%u, need %u:%u\n",
				(int)pst.st_dev, (int)pst.st_ino,
				(int)ost->st_dev, (int)ost->st_ino);
		return -1;
	}

	/*
	 * File is linked and visible by the name it is opened by
	 * this task. Go ahead and dump it.
	 */
	return 0;
}

static bool should_check_size(int flags)
{
	/* Skip size if file has O_APPEND and O_WRONLY flags (e.g. log file). */
	if (((flags & O_ACCMODE) == O_WRONLY) &&
			(flags & O_APPEND))
		return false;

	return true;
}

/*
 * Gets the build-id (If it exists) from 32-bit ELF files.
 * Returns the number of bytes of the build-id if it could
 * be obtained, else -1.
 */
static int get_build_id_32(Elf32_Ehdr *file_header, unsigned char **build_id,
				const int fd, size_t mapped_size)
{
	int size, num_iterations;
	size_t file_header_end;
	Elf32_Phdr *program_header, *program_header_end;
	Elf32_Nhdr *note_header_end, *note_header = NULL;

	file_header_end = (size_t) file_header + mapped_size;
	if (sizeof(Elf32_Ehdr) > mapped_size)
		return -1;

	/*
	 * If the file doesn't have atleast 1 program header entry, it definitely can't
	 * have a build-id.
	 */
	if (!file_header->e_phnum) {
		pr_warn("Couldn't find any program headers for file with fd %d\n", fd);
		return -1;
	}

	program_header = (Elf32_Phdr *) (file_header->e_phoff + (char *) file_header);
	if (program_header <= (Elf32_Phdr *) file_header)
		return -1;

	program_header_end = (Elf32_Phdr *) (file_header_end - sizeof(Elf32_Phdr));

	/*
	 * If the file has a build-id, it will be in the PT_NOTE program header
	 * entry AKA the note sections.
	 */
	for (num_iterations = 0; num_iterations < file_header->e_phnum; num_iterations++, program_header++) {
		if (program_header > program_header_end)
			break;
		if (program_header->p_type != PT_NOTE)
			continue;

		note_header = (Elf32_Nhdr *) (program_header->p_offset + (char *) file_header);
		if (note_header <= (Elf32_Nhdr *) file_header) {
			note_header = NULL;
			continue;
		}

		note_header_end = (Elf32_Nhdr *) min_t(char*,
						(char *) note_header + program_header->p_filesz,
						(char *) (file_header_end - sizeof(Elf32_Nhdr)));

		/* The note type for the build-id is NT_GNU_BUILD_ID. */
		while (note_header <= note_header_end && note_header->n_type != NT_GNU_BUILD_ID)
			note_header = (Elf32_Nhdr *) ((char *) note_header + sizeof(Elf32_Nhdr) +
							ALIGN(note_header->n_namesz, 4) +
							ALIGN(note_header->n_descsz, 4));

		if (note_header > note_header_end) {
			note_header = NULL;
			continue;
		}
		break;
	}

	if (!note_header) {
		pr_warn("Couldn't find the build-id note for file with fd %d\n", fd);
		return -1;
	}

	/*
	 * If the size of the notes description is too large or is invalid
	 * then the build-id could not be obtained.
	 */
	if (note_header->n_descsz <= 0 || note_header->n_descsz > 512) {
		pr_warn("Invalid description size for build-id note for file with fd %d\n", fd);
		return -1;
	}

	size = note_header->n_descsz;
	note_header = (Elf32_Nhdr *) ((char *) note_header + sizeof(Elf32_Nhdr) +
					ALIGN(note_header->n_namesz, 4));
	note_header_end = (Elf32_Nhdr *) (file_header_end - size);
	if (note_header <= (Elf32_Nhdr *) file_header || note_header > note_header_end)
		return -1;

	*build_id = (unsigned char *) xmalloc(size);
	if (!*build_id)
		return -1;

	memcpy(*build_id, (void *) note_header, size);
	return size;
}

/*
 * Gets the build-id (If it exists) from 64-bit ELF files.
 * Returns the number of bytes of the build-id if it could
 * be obtained, else -1.
 */
static int get_build_id_64(Elf64_Ehdr *file_header, unsigned char **build_id,
				const int fd, size_t mapped_size)
{
	int size, num_iterations;
	size_t file_header_end;
	Elf64_Phdr *program_header, *program_header_end;
	Elf64_Nhdr *note_header_end, *note_header = NULL;

	file_header_end = (size_t) file_header + mapped_size;
	if (sizeof(Elf64_Ehdr) > mapped_size)
		return -1;

	/*
	 * If the file doesn't have atleast 1 program header entry, it definitely can't
	 * have a build-id.
	 */
	if (!file_header->e_phnum) {
		pr_warn("Couldn't find any program headers for file with fd %d\n", fd);
		return -1;
	}

	program_header = (Elf64_Phdr *) (file_header->e_phoff + (char *) file_header);
	if (program_header <= (Elf64_Phdr *) file_header)
		return -1;

	program_header_end = (Elf64_Phdr *) (file_header_end - sizeof(Elf64_Phdr));

	/*
	 * If the file has a build-id, it will be in the PT_NOTE program header
	 * entry AKA the note sections.
	 */
	for (num_iterations = 0; num_iterations < file_header->e_phnum; num_iterations++, program_header++) {
		if (program_header > program_header_end)
			break;
		if (program_header->p_type != PT_NOTE)
			continue;

		note_header = (Elf64_Nhdr *) (program_header->p_offset + (char *) file_header);
		if (note_header <= (Elf64_Nhdr *) file_header) {
			note_header = NULL;
			continue;
		}

		note_header_end = (Elf64_Nhdr *) min_t(char*,
						(char *) note_header + program_header->p_filesz,
						(char *) (file_header_end - sizeof(Elf64_Nhdr)));

		/* The note type for the build-id is NT_GNU_BUILD_ID. */
		while (note_header <= note_header_end && note_header->n_type != NT_GNU_BUILD_ID)
			note_header = (Elf64_Nhdr *) ((char *) note_header + sizeof(Elf64_Nhdr) +
							ALIGN(note_header->n_namesz, 4) +
							ALIGN(note_header->n_descsz, 4));

		if (note_header > note_header_end) {
			note_header = NULL;
			continue;
		}
		break;
	}

	if (!note_header) {
		pr_warn("Couldn't find the build-id note for file with fd %d\n", fd);
		return -1;
	}

	/*
	 * If the size of the notes description is too large or is invalid
	 * then the build-id could not be obtained.
	 */
	if (note_header->n_descsz <= 0 || note_header->n_descsz > 512) {
		pr_warn("Invalid description size for build-id note for file with fd %d\n", fd);
		return -1;
	}

	size = note_header->n_descsz;
	note_header = (Elf64_Nhdr *) ((char *) note_header + sizeof(Elf64_Nhdr) +
					ALIGN(note_header->n_namesz, 4));
	note_header_end = (Elf64_Nhdr *) (file_header_end - size);
	if (note_header <= (Elf64_Nhdr *) file_header || note_header > note_header_end)
		return -1;

	*build_id = (unsigned char *) xmalloc(size);
	if (!*build_id)
		return -1;

	memcpy(*build_id, (void *) note_header, size);
	return size;
}

/*
 * Finds the build-id of the file by checking if the file is an ELF file
 * and then calling either the 32-bit or the 64-bit function as necessary.
 * Returns the number of bytes of the build-id if it could be
 * obtained, else -1.
 */
static int get_build_id(const int fd, const struct stat *fd_status,
				unsigned char **build_id)
{
	char buf[SELFMAG+1];
	void *start_addr;
	size_t mapped_size;
	int ret = -1;

	if (read(fd, buf, SELFMAG+1) != SELFMAG+1)
		return -1;

	/*
	 * The first 4 bytes contain a magic number identifying the file as an
	 * ELF file. They should contain the characters ‘\x7f’, ‘E’, ‘L’, and
	 * ‘F’, respectively. These characters are together defined as ELFMAG.
	 */
	if (strncmp(buf, ELFMAG, SELFMAG))
		return -1;

	/*
	 * If the build-id exists, then it will most likely be present in the
	 * beginning of the file. Therefore at most only the first 1 MB of the
	 * file is mapped.
	 */
	mapped_size = min_t(size_t, fd_status->st_size, BUILD_ID_MAP_SIZE);
	start_addr = mmap(0, mapped_size, PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (start_addr == MAP_FAILED) {
		pr_warn("Couldn't mmap file with fd %d", fd);
		return -1;
	}

	if (buf[EI_CLASS] == ELFCLASS32)
		ret = get_build_id_32(start_addr, build_id, fd, mapped_size);
	if (buf[EI_CLASS] == ELFCLASS64)
		ret = get_build_id_64(start_addr, build_id, fd, mapped_size);
	
	munmap(start_addr, mapped_size);
	return ret;
}

/*
 * Finds and stores the build-id of a file, if it exists, so that it can be validated
 * while restoring.
 * Returns 1 if the build-id of the file could be stored, -1 if there was an error
 * or 0 if the build-id could not be obtained.
 */
static int store_validation_data_build_id(RegFileEntry *rfe, int lfd,
						const struct fd_parms *p)
{
	unsigned char *build_id = NULL;
	int build_id_size, allocated_size;
	int fd;

	/*
	 * Checks whether the file is atleast big enough to try and read the first
	 * four (SELFMAG) bytes which should correspond to the ELF magic number
	 * and the next byte which indicates whether the file is 32-bit or 64-bit.
	 */
	if (p->stat.st_size < SELFMAG+1)
		return 0;

	fd = open_proc(PROC_SELF, "fd/%d", lfd);
	if (fd < 0) {
		pr_err("Build-ID (For validation) could not be obtained for file %s because can't open the file\n",
				rfe->name);
		return -1;
	}

	build_id_size = get_build_id(fd, &(p->stat), &build_id);
	close(fd);
	if (!build_id || build_id_size == -1)
		return 0;

	allocated_size = round_up(build_id_size, sizeof(uint32_t));
	rfe->build_id = xzalloc(allocated_size);
	if (!rfe->build_id) {
		pr_warn("Build-ID (For validation) could not be set for file %s\n",
				rfe->name);
		xfree(build_id);
		return -1;
	}

	rfe->n_build_id = allocated_size / sizeof(uint32_t);
	memcpy(rfe->build_id, (void *) build_id, build_id_size);

	xfree(build_id);
	return 1;
}

/*
 * This routine stores metadata about the open file (File size, build-id, CRC32C checksum)
 * so that validation can be done while restoring to make sure that the right file is
 * being restored.
 * Returns true if atleast some metadata was stored, if there was an error it returns false.
 */
static bool store_validation_data(RegFileEntry *rfe,
					const struct fd_parms *p, int lfd)
{
	int result = 1;

	rfe->has_size = true;
	rfe->size = p->stat.st_size;

	/*
	 * FIXME: A temp solution until we can
	 * detect tasks which has called acct()
	 * where file get filled after container
	 * stop. In particular atop utility setups
	 * statistics file into a known place.
	 */
	if (!strcmp(rfe->name, "/"ATOP_ACCT_FILE)) {
		pr_warn("Zap size check for %s\n", &rfe->name[1]);
		rfe->has_size = false;
		rfe->size = 0;
	}

	if (opts.file_validation_method == FILE_VALIDATION_BUILD_ID)
		result = store_validation_data_build_id(rfe, lfd, p);

	if (result == -1)
		return false;

	if (!result)
		pr_info("Only file size could be stored for validation for file %s\n",
				rfe->name);
	return true;
}

static bool unsupported_nfs_file(const struct fd_link *link,
				 const struct fd_parms *parms)
{
	if (parms->fs_type != NFS_SUPER_MAGIC)
		return false;

	if (S_ISCHR(parms->stat.st_mode)) {
		pr_err("Character devices ([%s]) migration on NFS are not supported\n", &link->name[1]);
		return true;
	}

	if (S_ISBLK(parms->stat.st_mode)) {
		pr_err("Block devices ([%s]) migration on NFS are not supported\n", &link->name[1]);
		return true;
	}

	return false;
}

int dump_one_reg_file(int lfd, u32 id, const struct fd_parms *p)
{
	struct fd_link _link, *link;
	struct mount_info *mi;
	struct cr_img *rimg;
	char ext_id[64];
	int ret;
	FileEntry fe = FILE_ENTRY__INIT;
	RegFileEntry rfe = REG_FILE_ENTRY__INIT;

	if (!p->link) {
		if (fill_fdlink(lfd, p, &_link))
			return -1;
		link = &_link;
	} else
		link = p->link;

	snprintf(ext_id, sizeof(ext_id), "file[%x:%"PRIx64"]", p->mnt_id, p->stat.st_ino);
	if (external_lookup_id(ext_id)) {
		/* the first symbol will be cut on restore to get an relative path*/
		rfe.name = xstrdup(ext_id);
		rfe.ext = true;
		rfe.has_ext = true;
		goto ext;
	}

	mi = lookup_mnt_id(p->mnt_id);
	if (mi == NULL) {
		struct mount_info *m;

		pr_err("Can't lookup mount=%d sdev=%ld for fd=%d path=%s\n",
			p->mnt_id, p->stat.st_dev, p->fd, link->name + 1);

		m = lookup_mnt_sdev_on_root(p->stat.st_dev);
		if (m)
			pr_err("Hint: Other mount %d with same sdev\n",
			       m->mnt_id);
		return -1;
	}

	if (mi->fstype->code == FSTYPE__VZ_NFSD) {
		pr_err("Open files on nfsd(%d) are not supported\n", mi->mnt_id);
		return -1;
	}

	if (path_is_overmounted(link->name, mi)) {
		if (!(root_ns_mask & CLONE_NEWNS)) {
			pr_err("Unable to dump overmouned file %s. Processes need to be in dedicated mount namespace\n", link->name);
			return -1;
		}
		BUG_ON(p->mnt_id < 0);

		rfe.has_vz_use_relative_path = true;
		rfe.vz_use_relative_path = true;

		pr_info("Dumping file %s on overmounted mount %d: will use relative path on restore\n", link->name, mi->mnt_id);
		if (!kdat.has_mount_set_group)
			pr_warn("Mounts-v2 is required to restore such image, but current kernel does not support this\n");
	}

	if (p->mnt_id >= 0 && (root_ns_mask & CLONE_NEWNS)) {
		rfe.mnt_id = p->mnt_id;
		rfe.has_mnt_id = true;
	}

	pr_info("Dumping path for %d fd via self %d [%s]\n",
			p->fd, lfd, &link->name[1]);

	/*
	 * The regular path we can handle should start with slash.
	 */
	if (link->name[1] != '/') {
		pr_err("The path [%s] is not supported\n", &link->name[1]);
		return -1;
	}

	if (unsupported_nfs_file(link, p)) {
		pr_err("The path [%s] is not supported\n", &link->name[1]);
		return -1;
	}

	if (check_path_remap(link, p, lfd, id, mi, rfe.vz_use_relative_path))
		return -1;
	rfe.name	= &link->name[1];
ext:
	rfe.id		= id;
	rfe.flags	= p->flags;
	rfe.pos		= p->pos;
	rfe.fown	= (FownEntry *)&p->fown;
	rfe.has_mode	= true;
	rfe.mode	= p->stat.st_mode;

	if (S_ISREG(p->stat.st_mode) && should_check_size(rfe.flags) &&
		!store_validation_data(&rfe, p, lfd))
		return -1;

	fe.type = FD_TYPES__REG;
	fe.id = rfe.id;
	fe.reg = &rfe;

	rimg = img_from_set(glob_imgset, CR_FD_FILES);
	ret = pb_write_one(rimg, &fe, PB_FILE);

	if (rfe.build_id)
		xfree(rfe.build_id);

	return ret;
}

const struct fdtype_ops regfile_dump_ops = {
	.type		= FD_TYPES__REG,
	.dump		= dump_one_reg_file,
};

static void convert_path_from_another_mp(char *src, char *dst, int dlen,
					struct mount_info *smi,
					struct mount_info *dmi)
{
	int off;

	/*
	 * mi->mountpoint	./foo/bar
	 * mi->ns_mountpoint	/foo/bar
	 * rfi->path		foo/bar/baz
	 */
	off = strlen(smi->ns_mountpoint + 1);
	BUG_ON(strlen(smi->root) < strlen(dmi->root));

	/*
	 * Create paths relative to this mount.
	 * Absolute path to the mount point + difference between source
	 * and destination roots + path relative to the mountpoint.
	 */
	snprintf(dst, dlen, "./%s/%s/%s",
				dmi->ns_mountpoint + 1,
				smi->root + strlen(dmi->root),
				src + off);
}

static int linkat_hard(int odir, char *opath, int ndir, char *npath, uid_t uid, gid_t gid, int flags)
{
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
	struct __user_cap_header_struct hdr;
	int ret, old_fsuid = -1, old_fsgid = -1;
	int errno_save;

	ret = linkat(odir, opath, ndir, npath, flags);
	if (ret == 0)
		return 0;

	if (!( (errno == EPERM || errno == EOVERFLOW) && (root_ns_mask & CLONE_NEWUSER) )) {
		errno_save = errno;
		pr_warn("Can't link %s -> %s\n", opath, npath);
		errno = errno_save;
		return ret;
	}

	/*
	 * Kernel before 4.3 has strange security restrictions about
	 * linkat. If the fsuid of the caller doesn't equals
	 * the uid of the file and the file is not "safe"
	 * one, then only global CAP_CHOWN will be allowed
	 * to link().
	 *
	 * Next, when we're in user namespace we're ns root,
	 * but not global CAP_CHOWN. Thus, even though we
	 * ARE ns root, we will not be allowed to link() at
	 * files that belong to regular users %)
	 *
	 * Fortunately, the setfsuid() requires ns-level
	 * CAP_SETUID which we have.
	 *
	 * Starting with 4.8 the kernel doesn't allow to create inodes
	 * with a uid or gid unknown to an user namespace.
	 * 036d523641c66 ("vfs: Don't create inodes with a uid or gid unknown to the vfs")
	 */

	old_fsuid = setfsuid(uid);
	old_fsgid = setfsgid(gid);

	/* AT_EMPTY_PATH requires CAP_DAC_READ_SEARCH */
	if (flags & AT_EMPTY_PATH) {
		hdr.version = _LINUX_CAPABILITY_VERSION_3;
		hdr.pid = 0;

		if (capget(&hdr, data) < 0) {
			errno_save = errno;
			pr_perror("capget");
			goto out;
		}
		data[0].effective = data[0].permitted;
		data[1].effective = data[1].permitted;
		if (capset(&hdr, data) < 0) {
			errno_save = errno;
			pr_perror("capset");
			goto out;
		}
	}

	ret = linkat(odir, opath, ndir, npath, flags);
	errno_save = errno;
	if (ret < 0)
		pr_perror("Can't link %s -> %s", opath, npath);

out:
	setfsuid(old_fsuid);
	setfsgid(old_fsgid);
	if (setfsuid(-1) != old_fsuid) {
		pr_warn("Failed to restore old fsuid!\n");
		/*
		 * Don't fail here. We still have chances to run till
		 * the pie/restorer, and if _this_ guy fails to set
		 * the proper fsuid, then we'll abort the restore.
		 */
	}

	/*
	 * Restoring PR_SET_DUMPABLE flag is required after setfsuid,
	 * as if it not set, proc inode will be created with root cred
	 * (see proc_pid_make_inode), which will result in permission
	 * check fail when trying to access files in /proc/self/
	 */
	prctl(PR_SET_DUMPABLE, 1, 0);

	errno = errno_save;

	return ret;
}

/*
 * FIXME these function changes path string in place, if this string is used
 * simultaneousely in multiple processes we can have a race. Do we need strdup?
 */
int rm_parent_dirs(int mntns_root, char *path, int count)
{
	char *p, *prev = NULL;
	int ret = -1;

	if (!count)
		return 0;

	while (count > 0) {
		count -= 1;
		p = strrchr(path, '/');
		if (p) {
			/* We don't won't a "//" in path */
			BUG_ON(prev && (prev - p == 1));
			*p = '\0';
		} else {
			/* Inconsistent path and count */
			pr_perror("Can't strrchr \"/\" in \"%s\"/\"%s\"]"
				  " left count=%d\n",
				  path, prev ? prev + 1 : "", count + 1);
			goto err;
		}

		if (prev)
			*prev = '/';
		prev = p;

		if (unlinkat(mntns_root, path, AT_REMOVEDIR)) {
			pr_perror("Can't remove %s AT %d", path, mntns_root);
			goto err;
		}
		pr_debug("Unlinked parent dir: %s AT %d\n", path, mntns_root);
	}

	ret = 0;
err:
	if (prev)
		*prev = '/';

	return ret;
}

/* Construct parent dir name and mkdir parent/grandparents if they're not exist */
int make_parent_dirs_if_need(int mntns_root, char *path)
{
	char *p, *last_delim;
	int err, count = 0;
	struct stat st;

	p = last_delim = strrchr(path, '/');
	if (!p)
		return 0;
	*p = '\0';

	if (fstatat(mntns_root, path, &st, AT_EMPTY_PATH) == 0)
		goto out;
	if (errno != ENOENT) {
		pr_perror("Can't stat %s", path);
		count = -1;
		goto out;
	}

	p = path;

	/* when used for absolute paths we need to skip 1-st '/' */
	if (p[0] == '/')
		p++;

	do {
		p = strchr(p, '/');
		if (p)
			*p = '\0';

		err = mkdirat(mntns_root, path, 0777);
		if (err && errno != EEXIST) {
			pr_perror("Can't create dir: %s AT %d", path, mntns_root);
			/* Failing anyway -> no retcode check */
			rm_parent_dirs(mntns_root, path, count);
			count = -1;
			goto out;
		} else if (!err) {
			pr_debug("Created parent dir: %s AT %d\n", path, mntns_root);
			count++;
		}

		if (p)
			*p++ = '/';
	} while (p);
out:
	*last_delim = '/';
	return count;
}

/*
 * This routine properly resolves d's path handling ghost/link-remaps.
 * The open_cb is a routine that does actual open, it differs for
 * files, directories, fifos, etc.
 *
 * Return 0 on success, -1 on error and 1 to indicate soft error, which can be
 * retried.
 */

static int rfi_remap(struct reg_file_info *rfi, int *level)
{
	struct mount_info *mi, *rmi, *tmi;
	char _path[PATH_MAX], *path = _path;
	char _rpath[PATH_MAX], *rpath = _rpath;
	int path_root, remap_root, ret = -1;
	bool close_pr = false, close_rr = false;

	if (rfi->rfe->mnt_id == -1) {
		/* Know nothing about mountpoints */
		path_root = remap_root = mntns_get_root_by_mnt_id(-1);
		path = rfi->path;
		rpath = rfi->remap->rpath;
		goto out_root;
	}

	mi = lookup_mnt_id(rfi->rfe->mnt_id);
	if (mi == NULL)
		return -1;

	if (rfi->rfe->mnt_id == rfi->remap->rmnt_id) {
		/* Both links on the same mount point */
		tmi = mi;
		path = rfi->path;
		rpath = rfi->remap->rpath;
		goto out;
	}

	rmi = lookup_mnt_id(rfi->remap->rmnt_id);
	if (rmi == NULL)
		return -1;

	/*
	 * Find the common bind-mount. We know that one mount point was
	 * really mounted and all other were bind-mounted from it, so the
	 * lowest mount must contains all bind-mounts.
	 */
	for (tmi = mi; tmi->bind; tmi = tmi->bind)
		;

	BUG_ON(tmi->s_dev != rmi->s_dev);
	BUG_ON(tmi->s_dev != mi->s_dev);

	/* Calculate paths on the device (root mount) */
	convert_path_from_another_mp(rfi->path, path, sizeof(_path), mi, tmi);
	convert_path_from_another_mp(rfi->remap->rpath, rpath, sizeof(_rpath), rmi, tmi);

out:
	if (path_is_overmounted(path, tmi)) {
		if (resolve_mntfd_and_rpath(tmi->mnt_id, path, true, &path_root, &path)) {
			pr_err("Unable to resolve mntfd and rpath for overmounted file\n");
			return -1;
		}
		close_pr = true;
	} else {
		path_root = mntns_get_root_fd(tmi->nsid);
	}

	if (path_is_overmounted(rpath, tmi)) {
		if (resolve_mntfd_and_rpath(tmi->mnt_id, rpath, true, &remap_root, &rpath)) {
			pr_err("Unable to resolve mntfd and rpath for overmounted remap\n");
			goto err;
		}
		close_rr = true;
	} else {
		remap_root = mntns_get_root_fd(tmi->nsid);
	}

	/* We get here while in task's mntns */
	if (try_remount_writable(tmi, REMOUNT_IN_REAL_MNTNS))
		goto err;

	pr_debug("%d: Link %s -> %s\n", tmi->mnt_id, rpath, path);
out_root:
	*level = make_parent_dirs_if_need(path_root, path);
	if (*level < 0)
		goto err;

	if (linkat_hard(remap_root, rpath, path_root, path,
			rfi->remap->uid, rfi->remap->gid, 0) < 0) {
		int errno_saved = errno;

		if (!rm_parent_dirs(path_root, path, *level) &&
		    errno_saved == EEXIST) {
			errno = errno_saved;
			ret = 1;
			goto err;
		}
		goto err;
	}

	ret = 0;
err:
	if (close_pr)
		close(path_root);
	if (close_rr)
		close(remap_root);
	return ret;
}

/*
 * Compares the file's build-id with the stored value.
 * Returns 1 if the build-id of the file matches the build-id that was stored
 * while dumping, -1 if there is a mismatch or 0 if the build-id has not been
 * stored or could not be obtained.
 */
static int validate_with_build_id(const int fd, const struct stat *fd_status,
					const struct reg_file_info *rfi)
{
	unsigned char *build_id;
	int build_id_size;

	if (!rfi->rfe->has_size)
		return 1;

	if (!rfi->rfe->n_build_id)
		return 0;

	build_id = NULL;
	build_id_size = get_build_id(fd, fd_status, &build_id);
	if (!build_id || build_id_size == -1)
		return 0;

	if (round_up(build_id_size, sizeof(uint32_t)) != rfi->rfe->n_build_id * sizeof(uint32_t)) {
		pr_err("File %s has bad build-ID length %d (expect %d)\n", rfi->path,
				round_up(build_id_size, sizeof(uint32_t)),
				(int) (rfi->rfe->n_build_id * sizeof(uint32_t)));
		xfree(build_id);
		return -1;
	}

	if (memcmp(build_id, rfi->rfe->build_id, build_id_size)) {
		pr_err("File %s has bad build-ID\n", rfi->path);
		xfree(build_id);
		return -1;
	}

	xfree(build_id);
	return 1;
}

/*
 * This function determines whether it was the same file that was open during dump
 * by checking the file's size, build-id and/or checksum with the same metadata
 * that was stored before dumping.
 * Checksum is calculated with CRC32C.
 * Returns true if the metadata of the file matches the metadata stored while
 * dumping else returns false.
 */
static bool validate_file(const int fd, const struct stat *fd_status,
					const struct reg_file_info *rfi)
{
	int result = 1;

	if (rfi->rfe->has_size && (fd_status->st_size != rfi->rfe->size)) {
		pr_err("File %s has bad size %"PRIu64" (expect %"PRIu64")\n",
				rfi->path, fd_status->st_size, rfi->rfe->size);
		if (strcmp(rfi->path, ATOP_ACCT_FILE))
			return false;
		else
			pr_warn("Skip size test on %s\n", ATOP_ACCT_FILE);
	}

	if (opts.file_validation_method == FILE_VALIDATION_BUILD_ID)
		result = validate_with_build_id(fd, fd_status, rfi);

	if (result == -1)
		return false;

	if (!result)
		pr_info("File %s could only be validated with file size\n",
				rfi->path);
	return true;
}

int open_path(struct file_desc *d,
		int(*open_cb)(int mntns_root, struct reg_file_info *, void *), void *arg)
{
	int tmp = -1, rf_path_root = -1, level = 0;
	struct reg_file_info *rfi;
	char path[PATH_MAX], *rpath;
	char *orig_path;
	int inh_fd = -1;
	bool use_rpath;
	int ret;

	if (inherited_fd(d, &tmp))
		return tmp;

	rfi = container_of(d, struct reg_file_info, d);
	orig_path = rfi->path;

	use_rpath = rfi->rfe->has_vz_use_relative_path && rfi->rfe->vz_use_relative_path;
	if (use_rpath) {
		if (!use_mounts_v2()) {
			pr_err("Unable to restore file %s. Mounts-v2 is needed to restore files with relative path\n", rfi->path);
			goto err;
		}
	}

	if (rfi->rfe->ext) {
		tmp = inherit_fd_lookup_id(rfi->rfe->name);
		if (tmp >= 0) {
			inh_fd = tmp;
			/* 
			 * PROC_SELF isn't used, because only service
			 * descriptors can be used here.
			 */
			rf_path_root = open_pid_proc(getpid());
			snprintf(path, sizeof(path), "fd/%d", tmp);
			rfi->path = path;
			goto ext;
		}
	}

	if (rfi->remap) {
		if (fault_injected(FI_RESTORE_OPEN_LINK_REMAP)) {
			pr_info("fault: Open link-remap failure!\n");
			kill(getpid(), SIGKILL);
		}

		mutex_lock(remap_open_lock);
		if (rfi->remap->is_dir) {
			/*
			 * FIXME Can't make directory under new name.
			 * Will have to open it under the ghost one :(
			 */
			rfi->path = rfi->remap->rpath;
		} else if ((ret = rfi_remap(rfi, &level)) == 1) {
			static char tmp_path[PATH_MAX];

			/*
			 * The file whose name we're trying to create
			 * exists. Need to pick some other one, we're
			 * going to remove it anyway.
			 *
			 * Strictly speaking, this is cheating, file
			 * name shouldn't change. But since NFS with
			 * its silly-rename doesn't care, why should we?
			 */

			rfi->path = tmp_path;
			snprintf(tmp_path, sizeof(tmp_path), "%s.cr_link", orig_path);
			pr_debug("Fake %s -> %s link\n", rfi->path, rfi->remap->rpath);

			if (rfi_remap(rfi, &level)) {
				pr_perror("Can't create even fake link!");
				goto err;
			}
		} else if (ret < 0) {
			pr_perror("Can't link %s -> %s",
				  rfi->remap->rpath, rfi->path);
			goto err;
		}
	}

	if (use_rpath) {
		if (resolve_mntfd_and_rpath(rfi->rfe->mnt_id, rfi->path, true, &rf_path_root, &rpath)) {
			pr_err("Unable to get rpath or open mount\n");
			goto err;
		}

		rfi->path = rpath;
	} else {
		rf_path_root = mntns_get_root_by_mnt_id(rfi->rfe->mnt_id);
	}

	if (rf_path_root < 0) {
		pr_err("Unable to get mount fd\n");
		goto err;
	}

ext:
	tmp = open_cb(rf_path_root, rfi, arg);
	if (tmp < 0) {
		pr_perror("Can't open file %s", rfi->path);
		close_safe(&inh_fd);
		goto err;
	}
	close_safe(&inh_fd);

	if ((rfi->rfe->has_size || rfi->rfe->has_mode) &&
	    !rfi->size_mode_checked) {
		struct stat st;

		if (fstat(tmp, &st) < 0) {
			pr_perror("Can't fstat opened file");
			goto err;
		}

		if (!validate_file(tmp, &st, rfi))
			goto err;

		if (rfi->rfe->has_mode && (st.st_mode != rfi->rfe->mode)) {
			pr_err("File %s has bad mode 0%o (expect 0%o)\n",
			       rfi->path, (int)st.st_mode,
			       rfi->rfe->mode);
			/*
			 * When we're restoring proc/sysfs entry the
			 * file modes are virtualized by kernel and
			 * 'write' bit is dropped when opening inside
			 * veX. So don't fail in such case.
			 *
			 * FIXME if someone bind-mounts proc to some other
			 * place this check will not work, moreover if someone
			 * puts some regular file in /proc/sys path we would still
			 * ignore mode missmatch for this non-proc-sys file.
			 */
			if (!strncmp(rfi->path, PROCFS_SYSDIR, strlen(PROCFS_SYSDIR)))
				pr_warn("\tExpecting in VE environment. Ignore.\n");
			else if (!strncmp(rfi->path, CGROUP_SYSDIR, strlen(CGROUP_SYSDIR)))
				pr_warn("\tCgroup dirs might be modifed outside. Ignore.\n");
			else
				goto err;
		}

		/*
		 * This is only visible in the current process, so
		 * change w/o locks. Other tasks sharing the same
		 * file will get one via unix sockets.
		 */
		rfi->size_mode_checked = true;
	}

	if (rfi->remap) {
		if (!rfi->remap->is_dir) {
			struct mount_info *mi = lookup_mnt_id(rfi->rfe->mnt_id);

			if (try_remount_writable(mi, REMOUNT_IN_REAL_MNTNS))
				goto err;

			pr_debug("%d: Unlink: %s\n", rfi->rfe->mnt_id, rfi->path);
			if (unlinkat(rf_path_root, rfi->path, 0)) {
				pr_perror("Failed to unlink the remap file");
				goto err;
			}
			if (rm_parent_dirs(rf_path_root, rfi->path, level))
				goto err;
		}

		mutex_unlock(remap_open_lock);
	}

	rfi->path = orig_path;

	if (restore_fown(tmp, rfi->rfe->fown)) {
		close(tmp);
		return -1;
	}

	if (use_rpath)
		close_safe(&rf_path_root);

	return tmp;
err:
	if (use_rpath && rf_path_root > -1)
		close_safe(&rf_path_root);
	if (rfi->remap)
		mutex_unlock(remap_open_lock);
	if (tmp >= 0)
		close(tmp);
	return -1;
}

int do_open_reg_noseek_flags(int ns_root_fd, struct reg_file_info *rfi, void *arg)
{
	u32 flags = *(u32 *)arg;
	int fd;

	/* unnamed temporary files are restored as ghost files */
	flags &= ~O_TMPFILE;

	fd = openat(ns_root_fd, rfi->path, flags);
	if (fd < 0) {
		pr_perror("Can't open file %s on restore", rfi->path);
		return fd;
	}

	return fd;
}

static int do_open_reg_noseek(int ns_root_fd, struct reg_file_info *rfi, void *arg)
{
	return do_open_reg_noseek_flags(ns_root_fd, rfi, &rfi->rfe->flags);
}

static int do_open_reg(int ns_root_fd, struct reg_file_info *rfi, void *arg)
{
	int fd;

	fd = do_open_reg_noseek(ns_root_fd, rfi, arg);
	if (fd < 0)
		return fd;

	/*
	 * O_PATH opened files carry empty fops in kernel,
	 * just ignore positioning at all.
	 */
	if (!(rfi->rfe->flags & O_PATH)) {
		if (rfi->rfe->pos != -1ULL &&
		    lseek(fd, rfi->rfe->pos, SEEK_SET) < 0) {
			pr_perror("Can't restore file pos");
			close(fd);
			return -1;
		}
	}

	return fd;
}

int open_reg_fd(struct file_desc *fd)
{
	return open_path(fd, do_open_reg_noseek, NULL);
}

int open_reg_by_id(u32 id)
{
	struct file_desc *fd;

	/*
	 * This one gets called by exe link, chroot and cwd
	 * restoring code. No need in calling lseek on either
	 * of them.
	 */

	fd = find_file_desc_raw(FD_TYPES__REG, id);
	if (fd == NULL) {
		pr_err("Can't find regfile for %#x\n", id);
		return -1;
	}

	return open_reg_fd(fd);
}

struct filemap_ctx {
	u32 flags;
	struct file_desc *desc;
	int fd;
	/*
	 * Whether or not to close the fd when we're about to
	 * put a new one into ctx.
	 *
	 * True is used by premap, so that it just calls vm_open
	 * in sequence, immediately mmap()s the file, then it
	 * can be closed.
	 *
	 * False is used by open_vmas() which pre-opens the files
	 * for restorer, and the latter mmap()s them and closes.
	 *
	 * ...
	 */
	bool close;
	/* ...
	 *
	 * but closing all vmas won't work, as some of them share
	 * the descriptor, so only the ones that terminate the
	 * fd-sharing chain are marked with VMA_CLOSE flag, saying
	 * restorer to close the vma's fd.
	 *
	 * Said that, this vma pointer references the previously
	 * seen vma, so that once fd changes, this one gets the
	 * closing flag.
	 */
	struct vma_area *vma;
};

static struct filemap_ctx ctx;

void filemap_ctx_init(bool auto_close)
{
	ctx.desc = NULL;	/* to fail the first comparison in open_ */
	ctx.fd = -1;		/* not to close random fd in _fini */
	ctx.vma = NULL;		/* not to put spurious VMA_CLOSE in _fini */
				/* flags may remain any */
	ctx.close = auto_close;
}

void filemap_ctx_fini(void)
{
	if (ctx.close) {
		if (ctx.fd >= 0)
			close(ctx.fd);
	} else {
		if (ctx.vma)
			ctx.vma->e->status |= VMA_CLOSE;
	}
}

static int open_filemap(int pid, struct vma_area *vma)
{
	u32 flags;
	int ret;

	/*
	 * The vma->fd should have been assigned in collect_filemap
	 *
	 * We open file w/o lseek, as mappings don't care about it
	 */

	BUG_ON((vma->vmfd == NULL) || !vma->e->has_fdflags);
	flags = vma->e->fdflags;

	if (ctx.flags != flags || ctx.desc != vma->vmfd) {
		if (vma->e->status & VMA_AREA_MEMFD)
			ret = memfd_open(vma->vmfd, &flags);
		else
			ret = open_path(vma->vmfd, do_open_reg_noseek_flags, &flags);
		if (ret < 0)
			return ret;

		filemap_ctx_fini();

		ctx.flags = flags;
		ctx.desc = vma->vmfd;
		ctx.fd = ret;
	}

	ctx.vma = vma;
	vma->e->fd = ctx.fd;
	return 0;
}

int collect_filemap(struct vma_area *vma)
{
	struct file_desc *fd;

	if (!vma->e->has_fdflags) {
		/* Make a wild guess for the fdflags */
		vma->e->has_fdflags = true;
		if ((vma->e->prot & PROT_WRITE) &&
				vma_area_is(vma, VMA_FILE_SHARED))
			vma->e->fdflags = O_RDWR;
		else
			vma->e->fdflags = O_RDONLY;
	}

	if (vma->e->status & VMA_AREA_MEMFD)
		fd = collect_memfd(vma->e->shmid);
	else
		fd = collect_special_file(vma->e->shmid);
	if (!fd)
		return -1;

	vma->vmfd = fd;
	vma->vm_open = open_filemap;
	return 0;
}

static int open_fe_fd(struct file_desc *fd, int *new_fd)
{
	int tmp;

	tmp = open_path(fd, do_open_reg, NULL);
	if (tmp < 0)
		return -1;
	*new_fd = tmp;
	return 0;
}

static char *reg_file_path(struct file_desc *d, char *buf, size_t s)
{
	struct reg_file_info *rfi;

	rfi = container_of(d, struct reg_file_info, d);
	return rfi->path;
}

static struct file_desc_ops reg_desc_ops = {
	.type = FD_TYPES__REG,
	.open = open_fe_fd,
	.name = reg_file_path,
};

struct file_desc *try_collect_special_file(u32 id, int optional)
{
	struct file_desc *fdesc;

	/*
	 * Files dumped for vmas/exe links can have remaps
	 * configured. Need to bump-up users for them, otherwise
	 * the open_path() would unlink the remap file after
	 * the very first open.
	 */

	fdesc = find_file_desc_raw(FD_TYPES__REG, id);
	if (fdesc == NULL) {
		if (!optional)
			pr_err("No entry for reg-file-ID %#x\n", id);
		return NULL;
	}

	return fdesc;
}

static int collect_one_regfile(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct reg_file_info *rfi = o;
	static char dot[] = ".";

	rfi->rfe = pb_msg(base, RegFileEntry);
	/* change "/foo" into "foo" and "/" into "." */
	if (rfi->rfe->name[1] == '\0')
		rfi->path = dot;
	else
		rfi->path = rfi->rfe->name + 1;
	rfi->remap = NULL;
	rfi->size_mode_checked = false;

	pr_info("Collected [%s] ID %#x\n", rfi->path, rfi->rfe->id);
	return file_desc_add(&rfi->d, rfi->rfe->id, &reg_desc_ops);
}

struct collect_image_info reg_file_cinfo = {
	.fd_type = CR_FD_REG_FILES,
	.pb_type = PB_REG_FILE,
	.priv_size = sizeof(struct reg_file_info),
	.collect = collect_one_regfile,
	.flags = COLLECT_SHARED,
};

int collect_remaps_and_regfiles(void)
{
	rst_remaps = shmalloc(sizeof(*rst_remaps));
	if (!rst_remaps)
		return -1;
	INIT_LIST_HEAD(rst_remaps);

	if (!files_collected() && collect_image(&reg_file_cinfo))
		return -1;

	if (collect_image(&remap_cinfo))
		return -1;

	return 0;
}
