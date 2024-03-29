#ifndef ZDTM_FS_H_
#define ZDTM_FS_H_

#ifndef _BSD_SOURCE
# define _BSD_SOURCE
#endif

#include <sys/types.h>
#include <sys/sysmacros.h>

#include <limits.h>

#define KDEV_MINORBITS	20
#define KDEV_MINORMASK	((1UL << KDEV_MINORBITS) - 1)
#define MKKDEV(ma, mi)	(((ma) << KDEV_MINORBITS) | (mi))

static inline unsigned int kdev_major(unsigned int kdev)
{
	return kdev >> KDEV_MINORBITS;
}

static inline unsigned int kdev_minor(unsigned int kdev)
{
	return kdev & KDEV_MINORMASK;
}

static inline dev_t kdev_to_odev(unsigned int kdev)
{
	/*
	 * New kernels encode devices in a new form.
	 * See kernel's fs/stat.c for details, there
	 * choose_32_64 helpers which are the key.
	 */
	unsigned major = kdev_major(kdev);
	unsigned minor = kdev_minor(kdev);

	return makedev(major, minor);
}

typedef struct {
	int			mnt_id;
	int			parent_mnt_id;
	unsigned int		s_dev;
	char			root[PATH_MAX];
	char			mountpoint[PATH_MAX];
	char			fsname[64];
} mnt_info_t;

extern mnt_info_t *mnt_info_alloc(void);
extern void mnt_info_free(mnt_info_t **m);
extern mnt_info_t *get_cwd_mnt_info(void);
int mkdirp(const char *pathname, mode_t mode);

/*
 * Setup filesystem layout ready for overlayfs testing.
 * all directories
 * parentdir - location, where all needed dirs will be created.
 * lower     - a list of lowerdir names, terminated by NULL. All these
 *             dirs will be created.
 * upper     - upperdir with this name will be created.
 * work      - name for workdir that will be created for internal
 *             needs of overlayfs
 * mountdir  - name of resulting mountpoint directory and mount name
 *             of overlayfs mount.
 */
int overlayfs_setup(const char *parentdir, const char **lower,
		    const char *upper, const char *work, const char *mountdir);

int prepare_dirname(char *dirname);

/*
 * get_path_check_perm is called to check that path is actually usable for a calling
 * process.
 *
 * Example output of a stat command on a '/root' path shows file access bits:
 * > stat /root
 * File: ‘/root’
 *   ...
 *   Access: (0550/dr-xr-x---) Uid: (  0/root)   Gid: (  0/root)
 *                          ^- no 'x' bit for other
 *
 * Here we can see that '/root' dir (that can be part of path) does not
 * allow non-root user and non-root group to list contents of this directory.
 * Calling process matching 'other' access category may succeed getting path, but will
 * fail performing further filesystem operations based on this path with confusing errors.
 *
 * This function checks that bit 'x' is enabled for a calling process and logs the error.
 *
 * If check passes, returns 0
 * If check fails, returns -1
 */
extern int get_path_check_perm(const char *path);

/*
 * This function calls get_current_dir_name and checks bit 'x' by get_path_check_perm.
 *
 * If check passes, stores get_current_dir's result in *result and returns 0
 * If check fails, stores 0 in *result and returns -1
 */
extern int get_cwd_check_perm(char **result);

#endif /* ZDTM_FS_H_ */
