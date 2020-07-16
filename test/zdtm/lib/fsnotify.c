#include "fsnotify.h"
#include "zdtmtst.h"

#ifdef __x86_64__
#define __NR_fanotify_init 300
#define __NR_fanotify_mark 301
#elif defined(__PPC64__)
#define __NR_fanotify_init 323
#define __NR_fanotify_mark 324
#elif __aarch64__
#define __NR_fanotify_init 262
#define __NR_fanotify_mark 263
#elif __s390x__
#define __NR_fanotify_init 332
#define __NR_fanotify_mark 333
#else
#define __NR_fanotify_init 338
#define __NR_fanotify_mark 339
#endif

static void fanotify_copy_handle(char *tok, struct fanotify_mark_inode *inode)
{
	int off = 0;

	while (*tok && (*tok > '0' || *tok < 'f')) {
		inode->fhandle[off++] = *tok++;
		if (off >= sizeof(inode->fhandle) - 1)
			break;
	}
	inode->fhandle[off] = '\0';
}

int fanotify_init(unsigned int flags, unsigned int event_f_flags)
{
	return syscall(__NR_fanotify_init, flags, event_f_flags);
}

int fanotify_mark(int fanotify_fd, unsigned int flags, unsigned long mask, int dfd, const char *pathname)
{
#ifdef __i386__
	return syscall(__NR_fanotify_mark, fanotify_fd, flags, mask, 0, dfd, pathname);
#else
	return syscall(__NR_fanotify_mark, fanotify_fd, flags, mask, dfd, pathname);
#endif
}

void fanotify_obj_show(struct fanotify_obj *obj)
{
	test_msg("fanotify obj at %p\n", obj);

	test_msg(" glob\n");
	test_msg("  faflags: %x evflags: %x\n", obj->glob.faflags, obj->glob.evflags);

	test_msg(" inode\n");
	test_msg("  i_ino: %lx s_dev: %x mflags: %x "
		 "mask: %x ignored_mask: %x "
		 "fhandle_bytes: %x fhandle_type: %x "
		 "fhandle: %s",
		 obj->inode.i_ino, obj->inode.s_dev, obj->inode.mflags, obj->inode.mask, obj->inode.ignored_mask,
		 obj->inode.fhandle_bytes, obj->inode.fhandle_type, obj->inode.fhandle);

	test_msg(" mount\n");
	test_msg("  mnt_id: %x mflags: %x mask: %x ignored_mask: %x\n", obj->mount.mnt_id, obj->mount.mflags,
		 obj->mount.mask, obj->mount.ignored_mask);
}

int fanotify_obj_cmp(struct fanotify_obj *old, struct fanotify_obj *new)
{
	/*
	 * mnt_id and s_dev may change during container migration,
	 * moreover the backend (say PLOOP) may be re-mounted during
	 * c/r, so exclude them.
	 */
	if ((old->glob.faflags != new->glob.faflags) ||
	    (old->glob.evflags != new->glob.evflags) ||
	    (old->inode.i_ino != new->inode.i_ino) ||
	    (old->inode.mflags != new->inode.mflags) ||
	    (old->inode.mask != new->inode.mask) ||
	    (old->inode.ignored_mask != new->inode.ignored_mask))
		return -1;

	if (memcmp(old->inode.fhandle, new->inode.fhandle, sizeof(new->inode.fhandle)))
		return -2;

	if ((old->mount.mflags != new->mount.mflags) || (old->mount.mask != new->mount.mask) ||
	    (old->mount.ignored_mask != new->mount.ignored_mask))
		return -3;

	return 0;
}

#define fdinfo_field(str, field) !strncmp(str, field ":", sizeof(field))

int fanotify_obj_parse(int fd, struct fanotify_obj *obj, unsigned int expected_to_meet)
{
	unsigned int met = 0;
	char str[512];
	FILE *f;
	int ret;

	sprintf(str, "/proc/self/fdinfo/%d", fd);
	f = fopen(str, "r");
	if (!f) {
		pr_perror("Can't open fdinfo to parse");
		return -1;
	}

	while (fgets(str, sizeof(str), f)) {
		if (fdinfo_field(str, "fanotify flags")) {
			ret = sscanf(str, "fanotify flags:%x event-flags:%x", &obj->glob.faflags, &obj->glob.evflags);
			if (ret != 2)
				goto parse_err;
			met++;
			continue;
		}
		if (fdinfo_field(str, "fanotify mnt_id")) {
			ret = sscanf(str, "fanotify mnt_id:%x mflags:%x mask:%x ignored_mask:%x", &obj->mount.mnt_id,
				     &obj->mount.mflags, &obj->mount.mask, &obj->mount.ignored_mask);
			if (ret != 4)
				goto parse_err;
			met++;
			continue;
		}
		if (fdinfo_field(str, "fanotify ino")) {
			int hoff;
			ret = sscanf(str,
				     "fanotify ino:%lx sdev:%x mflags:%x mask:%x ignored_mask:%x "
				     "fhandle-bytes:%x fhandle-type:%x f_handle: %n",
				     &obj->inode.i_ino, &obj->inode.s_dev, &obj->inode.mflags, &obj->inode.mask,
				     &obj->inode.ignored_mask, &obj->inode.fhandle_bytes, &obj->inode.fhandle_type,
				     &hoff);
			if (ret != 7)
				goto parse_err;
			fanotify_copy_handle(&str[hoff], &obj->inode);
			met++;
			continue;
		}
	}

	if (expected_to_meet != met) {
		pr_perror("Expected to meet %d entries but got %d", expected_to_meet, met);
		return -1;
	}

	return 0;

parse_err:
	pr_perror("Can't parse '%s'", str);
	return -1;
}
