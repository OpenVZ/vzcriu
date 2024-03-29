#ifndef __CR_PID_H__
#define __CR_PID_H__

#include <compel/task-state.h>
#include "stdbool.h"
#include "rbtree.h"
#include "log.h"

/*
 * Task states, used in e.g. struct pid's state.
 */
enum __criu_task_state
{
	/* Values shared with compel */
	TASK_ALIVE		= COMPEL_TASK_ALIVE,
	TASK_DEAD		= COMPEL_TASK_DEAD,
	TASK_STOPPED		= COMPEL_TASK_STOPPED,
	TASK_ZOMBIE		= COMPEL_TASK_ZOMBIE,
	/* Own internal states */
	TASK_HELPER		= COMPEL_TASK_MAX + 1,
	TASK_THREAD,
	/* new values are to be added before this line */
	TASK_UNDEF		= 0xff
};

struct pid {
	struct pstree_item *item;
	/*
	 * The @real pid is used to fetch tasks during dumping stage,
	 * This is a global pid seen from the context where the dumping
	 * is running.
	 */
	pid_t real;
	/*
	 * These entries are collected on dump to be able to resolve
	 * tty inheritance.
	 */
	pid_t real_ppid;
	pid_t real_pgid;
	pid_t real_sid;

	int state;	/* TASK_XXX constants */

	/*
	 * The @virt pid is one which used in the image itself and keeps
	 * the pid value to be restored. This pid fetched from the
	 * dumpee context, because the dumpee might have own pid namespace.
	 */
	int level;
	struct {
		pid_t virt;
		struct rb_node node;
	} ns[1]; /* Must be at the end of struct pid */
};

static inline bool equal_pid(struct pid *a, struct pid *b)
{
	struct pid *t;
	int i;

	if (a->level > b->level) {
		t = a;
		a = b;
		b = t;
	}

	for(i = 0; i < b->level; i++) {
		if (i < a->level) {
			if (a->ns[i].virt != b->ns[i].virt)
				return false;
		} else if (b->ns[i].virt != 0)
			return false;
	}

	return true;
}

static inline pid_t last_level_pid(struct pid *pid)
{
	return pid->ns[pid->level-1].virt;
}

/*
 * When we have to restore a shared resource, we mush select which
 * task should do it, and make other(s) wait for it. In order to
 * avoid deadlocks, always make task with lower pid be the restorer.
 */
static inline bool pid_rst_prio(unsigned pid_a, unsigned pid_b)
{
	return pid_a < pid_b;
}

static inline bool pid_rst_prio_eq(unsigned pid_a, unsigned pid_b)
{
	return pid_a <= pid_b;
}

#endif /* __CR_PID_H__ */
