#ifndef __CR_SECCOMP_H__
#define __CR_SECCOMP_H__

#include <linux/seccomp.h>
#include <linux/filter.h>

#include "images/seccomp.pb-c.h"
#include "images/core.pb-c.h"

#ifndef SECCOMP_MODE_DISABLED
#define SECCOMP_MODE_DISABLED 0
#endif

#ifndef SECCOMP_MODE_STRICT
#define SECCOMP_MODE_STRICT 1
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif

struct pstree_item;
struct rb_node;

struct seccomp_entry {
	struct rb_node		node;
	pid_t			tid_real;
	size_t			last_filter;
	unsigned int		mode;
};

extern struct seccomp_entry *seccomp_lookup(pid_t tid_real, bool create, bool mandatory);
#define seccomp_find_entry(tid_real) seccomp_lookup(tid_real, false, true)
extern int seccomp_collect_entry(pid_t tid_real, unsigned int mode);
extern void seccomp_free_entries(void);

struct seccomp_info {
	struct seccomp_info	*prev;
	int			id;
	SeccompFilter		filter;
};

extern int collect_seccomp_filters(void);
extern int prepare_seccomp_filters(void);
struct task_restore_args;
extern int seccomp_filters_get_rst_pos(CoreEntry *item, struct task_restore_args *);
#endif
