#pragma once

struct fanotify_mark_inode {
	unsigned long		i_ino;
	unsigned int		s_dev;
	unsigned int		mflags;
	unsigned int		mask;
	unsigned int		ignored_mask;
	unsigned int		fhandle_bytes;
	unsigned int		fhandle_type;
	unsigned char		fhandle[512];
};

struct fanotify_mark_mount {
	unsigned int		mnt_id;
	unsigned int		mflags;
	unsigned int		mask;
	unsigned int		ignored_mask;
};

struct fanotify_glob {
	unsigned int		faflags;
	unsigned int		evflags;
};

struct fanotify_obj {
	struct fanotify_glob		glob;
	struct fanotify_mark_inode	inode;
	struct fanotify_mark_mount	mount;
};

int fanotify_init(unsigned int flags, unsigned int event_f_flags);

int fanotify_mark(int fanotify_fd, unsigned int flags, unsigned long mask,
			 int dfd, const char *pathname);

void fanotify_obj_show(struct fanotify_obj *obj);

int fanotify_obj_cmp(struct fanotify_obj *old, struct fanotify_obj *new);

int fanotify_obj_parse(int fd, struct fanotify_obj *obj, unsigned int expected_to_meet);
