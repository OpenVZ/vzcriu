#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "zdtmtst.h"
#include "fs.h"

mnt_info_t *mnt_info_alloc(void)
{
	mnt_info_t *m = malloc(sizeof(*m));
	if (m)
		memset(m, 0, sizeof(*m));
	return m;
}

void mnt_info_free(mnt_info_t **m)
{
	if (m && *m) {
		free(*m);
		*m = NULL;
	}
}

mnt_info_t *get_cwd_mnt_info(void)
{
	int mnt_id, parent_mnt_id;
	unsigned int kmaj, kmin;
	char str[1024], *cwd;
	int ret;
	FILE *f;

	mnt_info_t *m = NULL;

	char mountpoint[PATH_MAX];
	char root[PATH_MAX];

	char *fsname = NULL;
	size_t len = 0, best_len = 0;

	f = fopen("/proc/self/mountinfo", "r");
	if (!f)
		return NULL;

	cwd = get_current_dir_name();
	if (!cwd)
		goto err;

	m = mnt_info_alloc();
	if (!m)
		goto err;

	while (fgets(str, sizeof(str), f)) {
		char *hyphen = strchr(str, '-');
		ret = sscanf(str, "%i %i %u:%u %s %s", &mnt_id, &parent_mnt_id, &kmaj, &kmin, root, mountpoint);
		if (ret != 6 || !hyphen)
			goto err;
		ret = sscanf(hyphen + 1, " %ms", &fsname);
		if (ret != 1)
			goto err;

		len = strlen(mountpoint);
		if (!strncmp(mountpoint, cwd, len)) {
			if (len > best_len) {
				best_len = len;

				m->mnt_id = mnt_id;
				m->parent_mnt_id = parent_mnt_id;
				m->s_dev = MKKDEV(kmaj, kmin);

				strncpy(m->root, root, sizeof(m->root));
				strncpy(m->mountpoint, mountpoint, sizeof(m->mountpoint));
				strncpy(m->fsname, fsname, sizeof(m->fsname) - 1);
				m->fsname[sizeof(m->fsname) - 1] = 0;
			}
		}

		free(fsname);
		fsname = NULL;
	}

out:
	free(cwd);
	fclose(f);

	return m;

err:
	mnt_info_free(&m);
	goto out;
}

int get_cwd_check_perm(char **result)
{
	char *cwd;
	*result = 0;
	cwd = get_current_dir_name();
	if (!cwd) {
		pr_perror("failed to get current directory");
		return -1;
	}

	if (access(cwd, X_OK)) {
		pr_err("access check for bit X for current dir path '%s' "
		       "failed for uid:%d,gid:%d, error: %d(%s). "
		       "Bit 'x' should be set in all path components of "
		       "this directory\n",
		       cwd, getuid(), getgid(), errno, strerror(errno));
		free(cwd);
		return -1;
	}

	*result = cwd;
	return 0;
}

int mkdirp(const char *pathname, mode_t mode)
{
	char tmp[PATH_MAX];
	int len;
	char c;
	const char *path_end = pathname;

	if (strlen(pathname) >= PATH_MAX) {
		pr_err("path %s is longer than PATH_MAX\n", pathname);
		return -1;
	}

	do {
		c = *path_end;
		if (c == '/' || !c) {
			len = path_end - pathname;
			memcpy(tmp, pathname, len);
			tmp[len] = 0;
			if (mkdir(tmp, mode) && errno != EEXIST) {
				pr_perror("mkdir failed for path %s", tmp);
				return -1;
			}
		}
		path_end++;
	} while (c);

	return 0;
}

#define OPT_PRINT(fmt, ...)\
	do {\
		mntopt_n += snprintf(mntopt + mntopt_n,\
			sizeof(mntopt) - mntopt_n,\
			fmt, ## __VA_ARGS__);\
	} while(0)

#define SETUP_DIR(__parent, __name)\
	do {\
		snprintf(path, sizeof(path), "%s/%s", __parent, __name);\
		if (mkdirp(path, 0700)) {\
			pr_perror("mkdir failed, path: %s", path);\
			return 1;\
		}\
	} while(0)

int overlayfs_setup(const char *parentdir, const char **lower,
		    const char *upper, const char *work, const char *mountdir)
{
	int mntopt_n = 0;
	char mntopt[PATH_MAX];
	char path[PATH_MAX];

	const char **current_lower = lower;
	if (*lower == NULL) {
		pr_err("overlayfs_setup error: should be at least one lower dir\n");
		return 1;
	}

	OPT_PRINT("nfs_export=on,index=on,lowerdir=");

	while (*current_lower) {
		SETUP_DIR(parentdir, *current_lower);
		OPT_PRINT("%s%s", current_lower > lower ? ":" : "", path);
		current_lower++;
	}

	if (upper) {
		SETUP_DIR(parentdir, upper);
		OPT_PRINT(",upperdir=%s,", path);
	}

	if (work) {
		SETUP_DIR(parentdir, work);
		OPT_PRINT(",workdir=%s", path);
	}

	SETUP_DIR(parentdir, mountdir);

	if (mount("none", path, "overlay", 0, mntopt)) {
		pr_perror("Failed to mount overlayfs on %s with opts: %s", path, mntopt);
		return 1;
	}
	return 0;
}
