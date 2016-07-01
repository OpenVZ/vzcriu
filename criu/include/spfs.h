#ifndef __CR_SPFS_H__
#define __CR_SPFS_H__

int spfs_set_env(void);

struct mount_info;
int spfs_mount(struct mount_info *mi, const char *source,
	      const char *filesystemtype, unsigned long mountflags);

int spfs_create_file(int ns_root_fd, const char *path, unsigned mode, size_t size);

#endif
