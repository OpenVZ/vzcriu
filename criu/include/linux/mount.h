#ifndef _CRIU_LINUX_MOUNT_H
#define _CRIU_LINUX_MOUNT_H

#include <linux/types.h>

#include "common/config.h"
#include "compel/plugins/std/syscall-codes.h"

/* Copied from /usr/include/sys/mount.h */

#ifndef FSOPEN_CLOEXEC
/* The type of fsconfig call made.   */
enum fsconfig_command {
	FSCONFIG_SET_FLAG = 0, /* Set parameter, supplying no value */
#define FSCONFIG_SET_FLAG FSCONFIG_SET_FLAG
	FSCONFIG_SET_STRING = 1, /* Set parameter, supplying a string value */
#define FSCONFIG_SET_STRING FSCONFIG_SET_STRING
	FSCONFIG_SET_BINARY = 2, /* Set parameter, supplying a binary blob value */
#define FSCONFIG_SET_BINARY FSCONFIG_SET_BINARY
	FSCONFIG_SET_PATH = 3, /* Set parameter, supplying an object by path */
#define FSCONFIG_SET_PATH FSCONFIG_SET_PATH
	FSCONFIG_SET_PATH_EMPTY = 4, /* Set parameter, supplying an object by (empty) path */
#define FSCONFIG_SET_PATH_EMPTY FSCONFIG_SET_PATH_EMPTY
	FSCONFIG_SET_FD = 5, /* Set parameter, supplying an object by fd */
#define FSCONFIG_SET_FD FSCONFIG_SET_FD
	FSCONFIG_CMD_CREATE = 6, /* Invoke superblock creation */
#define FSCONFIG_CMD_CREATE FSCONFIG_CMD_CREATE
	FSCONFIG_CMD_RECONFIGURE = 7, /* Invoke superblock reconfiguration */
#define FSCONFIG_CMD_RECONFIGURE FSCONFIG_CMD_RECONFIGURE
};

#endif // FSOPEN_CLOEXEC

/* fsopen flags. With the redundant definition, we check if the kernel,
 * glibc value and our value still match.
 */
#define FSOPEN_CLOEXEC 0x00000001

#ifndef MS_MGC_VAL
/* Magic mount flag number. Has to be or-ed to the flag values.  */
#define MS_MGC_VAL 0xc0ed0000 /* Magic flag number to indicate "new" flags */
#define MS_MGC_MSK 0xffff0000 /* Magic flag number mask */
#endif

#ifndef MOUNT_ATTR_SIZE_VER0
#define MOUNT_ATTR_SIZE_VER0    32

#define MOUNT_ATTR_RDONLY      0x00000001 /* Mount read-only */
#define MOUNT_ATTR_NOSUID      0x00000002 /* Ignore suid and sgid bits */
#define MOUNT_ATTR_NODEV       0x00000004 /* Disallow access to device special files */
#define MOUNT_ATTR_NOEXEC      0x00000008 /* Disallow program execution */
#define MOUNT_ATTR__ATIME      0x00000070 /* Setting on how atime should be updated */
#define MOUNT_ATTR_RELATIME    0x00000000 /* - Update atime relative to mtime/ctime. */
#define MOUNT_ATTR_NOATIME     0x00000010 /* - Do not update access times. */
#define MOUNT_ATTR_STRICTATIME 0x00000020 /* - Always perform atime updates */
#define MOUNT_ATTR_NODIRATIME  0x00000080 /* Do not update directory access times */
#define MOUNT_ATTR_IDMAP       0x00100000 /* Idmap mount to @userns_fd in struct mount_attr. */
#define MOUNT_ATTR_NOSYMFOLLOW 0x00200000 /* Do not follow symlinks */

/*
 * mount_setattr()
 */
struct mount_attr {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
	__u64 userns_fd;
};
#endif

#endif
