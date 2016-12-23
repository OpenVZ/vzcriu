#ifndef __CR_CRTOOLS_H__
#define __CR_CRTOOLS_H__

#include <sys/types.h>

#include "common/list.h"
#include "servicefd.h"

#include "images/inventory.pb-c.h"

#define CR_FD_PERM (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

extern int check_img_inventory(bool restore);
extern int write_img_inventory(InventoryEntry *he);
extern int inventory_save_uptime(InventoryEntry *he);
extern InventoryEntry *get_parent_inventory(void);
extern int prepare_inventory(InventoryEntry *he);
struct pprep_head {
	int (*actor)(struct pprep_head *);
	struct pprep_head *next;
};
extern void add_post_prepare_cb(struct pprep_head *);
extern bool deprecated_ok(char *what);
extern int cr_dump_tasks(pid_t pid);
extern int cr_pre_dump_tasks(pid_t pid);
extern int cr_restore_tasks(void);
extern int convert_to_elf(char *elf_path, int fd_core);
extern int cr_check(void);
extern int cr_dedup(void);
extern int cr_lazy_pages(bool daemon);

extern int check_add_feature(char *arg);
extern void pr_check_features(const char *offset, const char *sep, int width);

#define PPREP_HEAD_INACTIVE ((struct pprep_head *)-1)

#define add_post_prepare_cb_once(phead)                   \
	do {                                              \
		if ((phead)->next == PPREP_HEAD_INACTIVE) \
			add_post_prepare_cb(phead);       \
	} while (0)

#define MAKE_PPREP_HEAD(name)                \
	struct pprep_head name = {           \
		.next = PPREP_HEAD_INACTIVE, \
		.actor = name##_cb,          \
	}

int join_ve(bool veX);
#define join_veX() join_ve(true)
/*
 * Use join_ve0 very carefully! We have checks in kernel to prohibit execution
 * of files on CT mounts for security. All mounts created after join_veX are
 * marked as CT mounts, including all mounts of the root_yard temporary mntns.
 * So if you do join_ve0 you can be blocked from executing anything.
 *
 * https://jira.sw.ru/browse/PSBM-98702
 *
 * note: If for some reason we will desperately need to execute binaries from
 * mounts in the root_yard temporary mntns from VE0 we have an option:
 *
 * In restore_root_task before calling join_veX we can clone a helper process
 * which will create CT userns and mntns first (all mounts are marked as host
 * mounts), next after join_veX in restore_root_task we create another helper
 * process which setns'es to these user and mnt namespaces, and from these
 * helper we can clone CT init process obviousely without CLONE_NEWNS and
 * CLONE_NEWUSER. These way userns, mntns, ve will be preserved for all tasks
 * but all mounts cloned from host will be marked as host mounts, and execution
 * on them will be allowed even from VE0.
 */
#define join_ve0() join_ve(false)

#endif /* __CR_CRTOOLS_H__ */
