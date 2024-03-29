#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>

#include "types.h"
#include "cr_options.h"
#include "pstree.h"
#include "rst-malloc.h"
#include "common/lock.h"
#include "namespaces.h"
#include "cgroup.h"
#include "ipc_ns.h"
#include "uts_ns.h"
#include "files.h"
#include "tty.h"
#include "mount.h"
#include "dump.h"
#include "util.h"
#include "net.h"

#include "protobuf.h"
#include "images/pstree.pb-c.h"
#include "crtools.h"

struct pstree_item *root_item;

void core_entry_free(CoreEntry *core)
{
	if (core->tc && core->tc->timers)
		xfree(core->tc->timers->posix);
	if (core->thread_core)
		xfree(core->thread_core->creds->groups);
	arch_free_thread_info(core);
	xfree(core);
}

#ifndef RLIM_NLIMITS
# define RLIM_NLIMITS 16
#endif

CoreEntry *core_entry_alloc(int th, int tsk)
{
	size_t sz;
	CoreEntry *core = NULL;
	void *m;

	sz = sizeof(CoreEntry);
	if (tsk) {
		sz += sizeof(TaskCoreEntry) + TASK_COMM_LEN;
		if (th) {
			sz += sizeof(TaskRlimitsEntry);
			sz += RLIM_NLIMITS * sizeof(RlimitEntry *);
			sz += RLIM_NLIMITS * sizeof(RlimitEntry);
			sz += sizeof(TaskTimersEntry);
			sz += 3 * sizeof(ItimerEntry); /* 3 for real, virt and prof */
		}
	}
	if (th) {
		CredsEntry *ce = NULL;

		sz += sizeof(ThreadCoreEntry) + sizeof(ThreadSasEntry) + sizeof(CredsEntry);

		sz += CR_CAP_SIZE * sizeof(ce->cap_inh[0]);
		sz += CR_CAP_SIZE * sizeof(ce->cap_prm[0]);
		sz += CR_CAP_SIZE * sizeof(ce->cap_eff[0]);
		sz += CR_CAP_SIZE * sizeof(ce->cap_bnd[0]);
		/*
		 * @groups are dynamic and allocated
		 * on demand.
		 */
	}

	m = xmalloc(sz);
	if (m) {
		core = xptr_pull(&m, CoreEntry);
		core_entry__init(core);
		core->mtype = CORE_ENTRY__MARCH;

		if (tsk) {
			core->tc = xptr_pull(&m, TaskCoreEntry);
			task_core_entry__init(core->tc);
			core->tc->comm = xptr_pull_s(&m, TASK_COMM_LEN);
			memzero(core->tc->comm, TASK_COMM_LEN);

			if (th) {
				TaskRlimitsEntry *rls;
				TaskTimersEntry *tte;
				int i;

				rls = core->tc->rlimits = xptr_pull(&m, TaskRlimitsEntry);
				task_rlimits_entry__init(rls);

				rls->n_rlimits = RLIM_NLIMITS;
				rls->rlimits = xptr_pull_s(&m, sizeof(RlimitEntry *) * RLIM_NLIMITS);

				for (i = 0; i < RLIM_NLIMITS; i++) {
					rls->rlimits[i] = xptr_pull(&m, RlimitEntry);
					rlimit_entry__init(rls->rlimits[i]);
				}

				tte = core->tc->timers = xptr_pull(&m, TaskTimersEntry);
				task_timers_entry__init(tte);
				tte->real = xptr_pull(&m, ItimerEntry);
				itimer_entry__init(tte->real);
				tte->virt = xptr_pull(&m, ItimerEntry);
				itimer_entry__init(tte->virt);
				tte->prof = xptr_pull(&m, ItimerEntry);
				itimer_entry__init(tte->prof);
			}
		}

		if (th) {
			CredsEntry *ce;

			core->thread_core = xptr_pull(&m, ThreadCoreEntry);
			thread_core_entry__init(core->thread_core);
			core->thread_core->sas = xptr_pull(&m, ThreadSasEntry);
			thread_sas_entry__init(core->thread_core->sas);
			ce = core->thread_core->creds = xptr_pull(&m, CredsEntry);
			creds_entry__init(ce);

			ce->n_cap_inh	= CR_CAP_SIZE;
			ce->n_cap_prm	= CR_CAP_SIZE;
			ce->n_cap_eff	= CR_CAP_SIZE;
			ce->n_cap_bnd	= CR_CAP_SIZE;
			ce->cap_inh	= xptr_pull_s(&m, CR_CAP_SIZE * sizeof(ce->cap_inh[0]));
			ce->cap_prm	= xptr_pull_s(&m, CR_CAP_SIZE * sizeof(ce->cap_prm[0]));
			ce->cap_eff	= xptr_pull_s(&m, CR_CAP_SIZE * sizeof(ce->cap_eff[0]));
			ce->cap_bnd	= xptr_pull_s(&m, CR_CAP_SIZE * sizeof(ce->cap_bnd[0]));

			if (arch_alloc_thread_info(core)) {
				xfree(core);
				core = NULL;
			}
		}
	}

	return core;
}

int pstree_alloc_cores(struct pstree_item *item)
{
	unsigned int i;

	item->core = xzalloc(sizeof(*item->core) * item->nr_threads);
	if (!item->core)
		return -1;

	for (i = 0; i < item->nr_threads; i++) {
		if (item->threads[i]->real == item->pid->real)
			item->core[i] = core_entry_alloc(1, 1);
		else
			item->core[i] = core_entry_alloc(1, 0);

		if (!item->core[i])
			goto err;
	}

	return 0;
err:
	pstree_free_cores(item);
	return -1;
}

void pstree_free_cores(struct pstree_item *item)
{
	unsigned int i;

	if (item->core) {
		for (i = 1; i < item->nr_threads; i++)
			if (item->core[i])
				core_entry_free(item->core[i]);
		xfree(item->core);
		item->core = NULL;
	}
}

void free_pstree_item(struct pstree_item *item)
{
	pstree_free_cores(item);
	if (item->shmalloced)
		return;
	xfree(item->threads);
	xfree(item->pid);
	xfree(item->pgid);
	xfree(item->sid);
	xfree(item);
}

void free_pstree(struct pstree_item *root_item)
{
	struct pstree_item *item = root_item, *parent;

	while (item) {
		if (!list_empty(&item->children)) {
			item = list_first_entry(&item->children, struct pstree_item, sibling);
			continue;
		}

		parent = item->parent;
		list_del(&item->sibling);
		free_pstree_item(item);
		item = parent;
	}
}

struct pstree_item *__alloc_pstree_item(bool rst, int level)
{
	struct pstree_item *item;
	int sz, p_sz, i;

	p_sz = PID_SIZE(level);
	if (!rst) {
		sz = sizeof(*item) + sizeof(struct dmp_info);
		item = xzalloc(sz);
		if (!item)
			return NULL;
		item->pid = xmalloc(p_sz);
		item->pgid = xmalloc(p_sz);
		item->sid = xmalloc(p_sz);
		if (!item->pid || !item->pgid || !item->sid) {
			free_pstree_item(item);
			return NULL;
		}
	} else {
		sz = sizeof(*item) + sizeof(struct rst_info);
		item = shmalloc(sz);
		if (!item)
			return NULL;
		memset(item, 0, sz);
		item->shmalloced = true;

		vm_area_list_init(&rsti(item)->vmas);
		INIT_LIST_HEAD(&rsti(item)->vma_io);
		mutex_init(&rsti(item)->fds_mutex);

		/*
		 * On restore we never expand pid level,
		 * so allocate them all at once.
		 */
		item->pid = shmalloc(3 * p_sz);
		if (!item->pid) {
			shfree_last(item);
			return NULL;
		}
		item->pgid = (void *)item->pid + p_sz;
		item->sid = (void *)item->pgid + p_sz;
	}

	INIT_LIST_HEAD(&item->children);
	INIT_LIST_HEAD(&item->sibling);

	vpid(item) = -1;
	item->pid->real = -1;
	item->pid->real_ppid = -1;
	item->pid->real_pgid = -1;
	item->pid->real_sid = -1;
	item->pid->state = TASK_UNDEF;
	item->born_sid = -1;
	item->tty_pgrp = -1;
	item->pid->item = item;
	futex_init(&item->task_st);
	item->pid->level = item->sid->level = item->pgid->level = level;
	for (i = 0; i < item->pid->level; i++) {
		rb_init_node(&item->pid->ns[i].node);
		rb_init_node(&item->sid->ns[i].node);
		rb_init_node(&item->pgid->ns[i].node);
	}

	return item;
}

void add_child_task(struct pstree_item *child, struct pstree_item *parent)
{
	struct pstree_item *item;

	if (vpid(child) != INIT_PID)
		list_add_tail(&child->sibling, &parent->children);
	else {
		list_for_each_entry(item, &parent->children, sibling)
			if (vpid(item) != INIT_PID ||
			    item->pid->level >= child->pid->level)
				break;
		/* Add child before item */
		list_add_tail(&child->sibling, &item->sibling);
	}
}

void move_child_task(struct pstree_item *child, struct pstree_item *new_parent)
{
	list_del(&child->sibling);
	add_child_task(child, new_parent);
}

int init_pstree_helper(struct pstree_item *ret)
{
	BUG_ON(!ret->parent);
	ret->pid->state = TASK_HELPER;
	rsti(ret)->clone_flags = CLONE_FILES | CLONE_FS;
	if (shared_fdt_prepare(ret) < 0)
		return -1;
	task_entries->nr_helpers++;
	return 0;
}

/* Search only root's subtree, possibly skipping descendants */
struct pstree_item *pssubtree_item_next(struct pstree_item *item,
		struct pstree_item *root, bool skip_descendants)
{
	if (!skip_descendants && !list_empty(&item->children))
		return list_first_entry(&item->children, struct pstree_item, sibling);

	while (item->parent && item != root) {
		if (item->sibling.next != &item->parent->children)
			return list_entry(item->sibling.next, struct pstree_item, sibling);
		item = item->parent;
	}

	return NULL;
}

/* Deep first search on children */
struct pstree_item *pstree_item_next(struct pstree_item *item)
{
	return pssubtree_item_next(item, NULL, false);
}

/* Preorder traversal of pstree item */
int preorder_pstree_traversal(struct pstree_item *item, int (*f)(struct pstree_item *))
{
	struct pstree_item *cursor;

	if (f(item) < 0)
		return -1;

	list_for_each_entry(cursor, &item->children, sibling) {
		if (preorder_pstree_traversal(cursor, f) < 0)
			return -1;
	}

	return 0;
}

static void free_pstree_entry(PstreeEntry *e)
{
	int i;

	xfree(e->vz_ns_pid);
	xfree(e->vz_ns_pgid);
	xfree(e->vz_ns_sid);

	if (e->vz_tids) {
		for (i = 0; i < e->n_vz_tids; i++) {
			if (e->vz_tids[i]) {
				xfree(e->vz_tids[i]->tid);
				xfree(e->vz_tids[i]);
			}
		}
		xfree(e->vz_tids);
	}
}

static int plant_ns_xid(uint32_t **ns_xid, size_t *n_ns_xid, int level, struct pid *xid)
{
	int i;

	*ns_xid = xmalloc(level * sizeof(uint32_t));
	if (!*ns_xid)
		return -1;
	for (i = 0; i < level; i++)
		(*ns_xid)[i] = xid->ns[i].virt;
	*n_ns_xid = level;
	return 0;
}

int is_session_leader(struct pstree_item *item)
{
	if (vsid(item) == vpid(item)) {
		BUG_ON(!equal_pid(item->pid, item->sid));
		return 1;
	}
	return 0;
}

int dump_pstree(struct pstree_item *root_item)
{
	struct pstree_item *item = root_item;
	PstreeEntry e = PSTREE_ENTRY__INIT;
	int ret = -1, i, level;
	struct cr_img *img;

	pr_info("\n");
	pr_info("Dumping pstree (pid: %d)\n", root_item->pid->real);
	pr_info("----------------------------------------\n");

	/*
	 * Make sure we're dumping session leader, if not an
	 * appropriate option must be passed.
	 *
	 * Also note that if we're not a session leader we
	 * can't get the situation where the leader sits somewhere
	 * deeper in process tree, thus top-level checking for
	 * leader is enough.
	 */
	if (!is_session_leader(root_item)) {
		if (!opts.shell_job) {
			pr_err("The root process %d is not a session leader. "
			       "Consider using --" OPT_SHELL_JOB " option\n", vpid(item));
			return -1;
		}
	}

	img = open_image(CR_FD_PSTREE, O_DUMP);
	if (!img)
		return -1;

	for_each_pstree_item(item) {
		pr_info("Process: %d(%d)\n", vpid(item), item->pid->real);
		level = item->pid->level;

		e.ppid		= item->parent ? vpid(item->parent) : 0;

		if (plant_ns_xid(&e.vz_ns_pid,  &e.n_vz_ns_pid,  level, item->pid)  < 0 ||
		    plant_ns_xid(&e.vz_ns_pgid, &e.n_vz_ns_pgid, level, item->pgid) < 0 ||
		    plant_ns_xid(&e.vz_ns_sid,  &e.n_vz_ns_sid,  level, item->sid)  < 0)
			goto err;
		e.n_vz_tids	= item->nr_threads;
		if (e.n_vz_tids) {
			e.vz_tids = xzalloc(e.n_vz_tids * sizeof(NsTid *));
			if (!e.vz_tids)
				goto err;
			for (i = 0; i < e.n_vz_tids; i++) {
				e.vz_tids[i] = xzalloc(sizeof(NsTid));
				if (!e.vz_tids[i])
					goto err;
				ns_tid__init(e.vz_tids[i]);
				if (plant_ns_xid(&e.vz_tids[i]->tid, &e.vz_tids[i]->n_tid,
						 level, item->threads[i])  < 0)
					goto err;
			}
		}

		e.has_vz_child_subreaper = true;
		e.vz_child_subreaper = item->child_subreaper;

		ret = pb_write_one(img, &e, PB_PSTREE);
		if (ret)
			goto err;
		free_pstree_entry(&e);
		pstree_entry__init(&e);
	}
	ret = 0;

err:
	pr_info("----------------------------------------\n");
	free_pstree_entry(&e);
	close_image(img);
	return ret;
}

static int prepare_pstree_for_shell_job(pid_t pid)
{
	pid_t current_sid = getsid(pid);
	pid_t current_gid = getpgid(pid);

	struct pstree_item *pi;

	pid_t old_sid;
	pid_t old_gid;

	if (!opts.shell_job)
		return 0;

	if (is_session_leader(root_item))
		return 0;

	/*
	 * Migration of a root task group leader is a bit tricky.
	 * When a task yields SIGSTOP, the kernel notifies the parent
	 * with SIGCHLD. This means when task is running in a
	 * shell, the shell obtains SIGCHLD and sends a task to
	 * the background.
	 *
	 * The situation gets changed once we restore the
	 * program -- our tool become an additional stub between
	 * the restored program and the shell. So to be able to
	 * notify the shell with SIGCHLD from our restored
	 * program -- we make the root task to inherit the
	 * process group from us.
	 *
	 * Not that clever solution but at least it works.
	 */

	old_sid = vsid(root_item);

	pr_info("Migrating process tree (SID %d->%d)\n",
		old_sid, current_sid);

	for_each_pstree_item(pi) {
		BUG_ON(vsid(pi) == current_sid);
		if (vsid(pi) == old_sid)
			vsid(pi) = current_sid;
	}

	old_gid = vpgid(root_item);
	if (old_gid != vpid(root_item)) {
		if (lookup_create_item(&current_sid, 1, root_item->ids->pid_ns_id) == NULL)
			return -1;

		pr_info("Migrating process tree (GID %d->%d)\n",
			old_gid, current_gid);

		for_each_pstree_item(pi) {
			BUG_ON(vpgid(pi) == current_gid);
			if (vpgid(pi) == old_gid)
				vpgid(pi) = current_gid;
		}

		if (lookup_create_item(&current_gid, 1, root_item->ids->pid_ns_id) == NULL)
			return -1;
	}

	return 0;
}

static struct pid *find_pid_or_place_in_hier(struct rb_node **root, pid_t pid, int level,
					     struct rb_node **ret_parent, struct rb_node ***ret_place)
{
	struct rb_node *node = *root;
	struct rb_node **new = root;
	struct rb_node *parent = NULL;

	while (node) {
		struct pid *this = rb_entry(node, struct pid, ns[level].node);

		parent = *new;
		if (pid < this->ns[level].virt)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (pid > this->ns[level].virt)
			node = node->rb_right, new = &((*new)->rb_right);
		else
			return this;
	}
	*ret_parent = parent;
	*ret_place = new;
	return NULL;
}

/*
 * Try to find a pid node in the tree and insert a new one,
 * it is not there yet. If pid_node isn't set, pstree_item
 * is inserted.
 */
static struct pid *__lookup_create_pid(pid_t *pid, int level, struct pid
				       *pid_node, int ns_id, bool replaceable)
{
	struct rb_node **new = NULL, *parent = NULL;
	struct pid *found;
	struct ns_id *ns;
	int i;

	ns = lookup_ns_by_id(ns_id, &pid_ns_desc);

	while (level > 0 && ns && !pid[level-1]) {
		level--;
		ns = ns->parent;
	}
	if (!level || !ns) {
		pr_err("Can't skip zero pids levels (%d) or find {parent,} ns (%d)\n", level, ns_id);
		return NULL;
	}

	found = find_pid_or_place_in_hier(&ns->pid.rb_root.rb_node, pid[level-1], level-1, &parent, &new);
	if (found) {
		for (i = level - 2; i >= 0; i--)
			if (pid[i] != found->ns[i].virt || RB_EMPTY_NODE(&found->ns[i].node)) {
				pr_err("Wrong pid\n");
				return NULL;
			}
		return found;
	}

	if (!pid_node) {
		struct pstree_item *item;

		item = __alloc_pstree_item(true, level);
		if (item == NULL)
			return NULL;

		if (replaceable)
			item->replaceable = true;

		for (i = 0; i < level; i++)
			item->pid->ns[i].virt = pid[i];
		pid_node = item->pid;
	}

	for (i = level-1; i >= 0; i--) {

again:
		found = find_pid_or_place_in_hier(&ns->pid.rb_root.rb_node, pid[i], i, &parent, &new);
		if (found) {
			if (found->item->replaceable) {
				int j;
				struct ns_id *tmp = ns;

				pr_info("%d: Removing old (short cut) pid on all lower levels", found->ns[0].virt);
				for (j = i; j >= 0; j--) {
					BUG_ON(pid_node->ns[j].virt != found->ns[j].virt);
					rb_erase(&found->ns[j].node, &tmp->pid.rb_root);
					tmp = tmp->parent;
					if (!tmp && j) {
						pr_err("tmp ns has no parent\n");
						return NULL;
					}
				}
				/*
				 * Just leave these pid and found item unlinked and unused,
				 * it seems that we can't do anything with it here.
				 */
				goto again;
			} else {
				pr_err("pid is already linked\n");
				return NULL;
			}
		}
		if (!pid[i]) {
			pr_err("Zero pid level\n");
			return NULL;
		}
		rb_link_and_balance(&ns->pid.rb_root, &pid_node->ns[i].node, parent, new);
		ns = ns->parent;
		if (!ns && i) {
			pr_err("ns has no parent\n");
			return NULL;
		}
	}
	return pid_node;
}

static struct pid *lookup_create_pid(pid_t *pid, int level, struct pid *pid_node, int ns_id)
{
	return __lookup_create_pid(pid, level, pid_node, ns_id, false);
}

void pstree_insert_pid(struct pid *pid_node, uint32_t ns_id)
{
	struct pid* n;
	pid_t pid[MAX_NS_NESTING];
	int i;

	BUG_ON(pid_node->level > MAX_NS_NESTING);
	for (i = 0; i < pid_node->level; i++)
		pid[i] = pid_node->ns[i].virt;

	n = lookup_create_pid(pid, pid_node->level, pid_node, ns_id);

	BUG_ON(n != pid_node);
}

struct pstree_item *__lookup_create_item(pid_t *pid, int level, uint32_t ns_id, int replaceable)
{
	struct pid *node;

	node = __lookup_create_pid(pid, level, NULL, ns_id, replaceable);
	if (!node)
		return NULL;

	if (node->state == TASK_THREAD) {
		pr_err("The %d node is used for a thread\n", pid[0]);
		return NULL;
	}

	return node->item;
}

struct pstree_item *lookup_create_item(pid_t *pid, int level, uint32_t ns_id)
{
	return __lookup_create_item(pid, level, ns_id, false);
}

struct pstree_item *lookup_replaceable_item(pid_t *pid, int level, uint32_t ns_id)
{
	return __lookup_create_item(pid, level, ns_id, true);
}

struct pid *__pstree_pid_by_virt(struct ns_id *ns, pid_t pid)
{
	struct rb_node *node = ns->pid.rb_root.rb_node;
	struct ns_id *i = ns;
	int level = 0;

	while ((i = i->parent) != NULL)
		level++;

	while (node) {
		struct pid *this = rb_entry(node, struct pid, ns[level].node);

		if (pid < this->ns[level].virt)
			node = node->rb_left;
		else if (pid > this->ns[level].virt)
			node = node->rb_right;
		else
			return this;
	}
	return NULL;
}

/*
 *  0 -- pids are the same
 *  1 -- @a is a parent of @b
 *  2 -- @b is a parent of @a
 *  3 -- pids are not connected
 *  -1 -- pid not found
 */
int pstree_pid_cmp(pid_t a, pid_t b)
{
	struct pstree_item *pstree_a, *pstree_b, *t;

	if (a == b)
		return 0;

	pstree_a = pstree_item_by_virt(a);
	pstree_b = pstree_item_by_virt(b);
	if (!pstree_a || !pstree_b)
		return -1;

	for (t = pstree_b; t; t = t->parent) {
		if (t == pstree_a)
			return 1;
	}

	for (t = pstree_a; t; t = t->parent) {
		if (t == pstree_b)
			return 2;
	}

	return 3;
}

int fixup_pid_for_children_ns(TaskKobjIdsEntry *ids)
{
	if (!ids->has_vz_pid_for_children_ns_id) {
		ids->has_vz_pid_for_children_ns_id = true;
		ids->vz_pid_for_children_ns_id = ids->pid_ns_id;
	} else if (!lookup_ns_by_id(ids->vz_pid_for_children_ns_id, &pid_ns_desc)) {
		pr_err("Can't find pid_for_children ns linked\n");
		return -1;
	}
	return 0;
}

static int read_pstree_ids(pid_t pid, TaskKobjIdsEntry **ids)
{
	struct cr_img *img;
	int ret;

	img = open_image(CR_FD_IDS, O_RSTR, pid);
	if (!img)
		return -1;

	ret = pb_read_one_eof(img, ids, PB_IDS);
	close_image(img);

	if (ret <= 0)
		return ret;
	ret = 0;
#define ADD_OR_COPY_ID(ids, name)								\
	if (!ret) {										\
		if ((*ids)->has_##name##_ns_id)							\
			ret = rst_add_ns_id((*ids)->name##_ns_id, pid, &name##_ns_desc);	\
		else if (root_item && root_item->ids && root_item->ids->has_##name##_ns_id) {	\
			(*ids)->has_##name##_ns_id = true;					\
			(*ids)->name##_ns_id = root_item->ids->name##_ns_id;			\
		}										\
	}
	ADD_OR_COPY_ID(ids, mnt);
	ADD_OR_COPY_ID(ids, net);
	ADD_OR_COPY_ID(ids, user);
	ADD_OR_COPY_ID(ids, pid);
	ADD_OR_COPY_ID(ids, ipc);
	ADD_OR_COPY_ID(ids, uts);
	ADD_OR_COPY_ID(ids, cgroup);
	ADD_OR_COPY_ID(ids, time);
#undef ADD_OR_COPY_ID

	if (!ret && (!(*ids)->has_pid_ns_id || !(*ids)->has_net_ns_id ||
		     !(*ids)->ipc_ns_id || !(*ids)->uts_ns_id || !(*ids)->mnt_ns_id)) {
			/*
			 * At least root_item must have the fields,
			 * implemented before the img format became
			 * stable (commit 2105e18eee70).
			 */
			pr_err("No task ids or always dumped ns ids\n");
			ret = -1;
	}

	if (!ret)
		ret = fixup_pid_for_children_ns(*ids);

	if (!ret && !top_pid_ns) {
		/*
		 * If top_pid_ns is not set, this means that here is old dump,
		 * which does not contain ns.img. It can have only one pid_ns,
		 * so we set it here.
		 */
		top_pid_ns = lookup_ns_by_id((*ids)->pid_ns_id, &pid_ns_desc);
	}

	return ret;
}

static TaskKobjIdsEntry *dup_zombie_ids(TaskKobjIdsEntry *ids)
{
	TaskKobjIdsEntry *copy;

	copy = xmalloc(sizeof(*copy));
	if (!copy) {
		pr_err("Can't allocate ids copy\n");
		return NULL;
	}
	task_kobj_ids_entry__init(copy);

#define COPY_NS_ID(copy, name)				\
	if (ids->has_##name##_ns_id) {			\
		copy->has_##name##_ns_id = true;	\
		copy->name##_ns_id = ids->name##_ns_id;	\
	}
	/*
	 * Zombies only have pid and user ns ids
	 * but on restore stage we also need to set
	 * mount ns, cgroup ns before task will
	 * become zombie
	 */
	COPY_NS_ID(copy, mnt);
	COPY_NS_ID(copy, user);
	COPY_NS_ID(copy, pid);
	COPY_NS_ID(copy, cgroup);
#undef COPY_NS_ID

	return copy;
}

static int read_one_pstree(struct cr_img *img, PstreeEntry **ret_e)
{
	PstreeEntry *e;
	int i, ret;

	ret = pb_read_one_eof(img, ret_e, PB_PSTREE);
	if (ret <= 0)
		return ret;
	e = *ret_e;
	if ((!e->has_pid && !e->n_vz_ns_pid) || (!e->has_pgid && !e->n_vz_ns_pgid) ||
	    (!e->has_sid && !e->n_vz_ns_sid) || (!e->n_threads && !e->n_vz_tids))
		goto err;
	/* Assign vz_ns_pid, vz_ns_pgid and vz_ns_sid if here is old format image */
#define ASSIGN_NSXID_IF_NEED(name, source)		\
	if (!e->n_##name) {				\
		e->n_##name = 1;			\
		e->name = xmalloc(sizeof(uint32_t));	\
		if (!e->name)				\
			goto err;			\
		e->name[0] = e->source;			\
	}
	ASSIGN_NSXID_IF_NEED(vz_ns_pid, pid);
	ASSIGN_NSXID_IF_NEED(vz_ns_pgid, pgid);
	ASSIGN_NSXID_IF_NEED(vz_ns_sid, sid);
#undef ASSIGN_NSXID_IF_NEED

	/* Assign vz_tids if here is old format image */
	if (!e->n_vz_tids) {
		e->n_vz_tids = e->n_threads;
		e->vz_tids = xzalloc(e->n_vz_tids * sizeof(NsTid *));
		if (!e->vz_tids)
			goto err;
		for (i = 0; i < e->n_vz_tids; i++) {
			e->vz_tids[i] = xzalloc(sizeof(NsTid));
			if (!e->vz_tids[i])
				goto err;
			ns_tid__init(e->vz_tids[i]);
			e->vz_tids[i]->n_tid = 1;
			e->vz_tids[i]->tid = xmalloc(sizeof(uint32_t));
			if (!e->vz_tids[i]->tid)
				goto err;
			e->vz_tids[i]->tid[0] = e->threads[i];
		}
	}

	return 1;
err:
	pr_err("Error of reading pstree\n");
	return -1;
}

/*
 * Returns <0 on error, 0 on eof and >0 on successful read
 */
static int read_one_pstree_item(struct cr_img *img, pid_t *pid_max)
{
	struct pstree_item *pi, *parent;
	TaskKobjIdsEntry *ids;
	PstreeEntry *e;
	int ret, i, k;

	ret = read_one_pstree(img, &e);
	if (ret <= 0)
		return ret;

	/* note: we don't fail if we have empty ids */
	ret = read_pstree_ids(e->vz_ns_pid[0], &ids);
	if (ret < 0)
		goto err;

	ret = -1;
	parent = NULL;
	if (e->ppid) {
		struct pid *pid;

		pid = pstree_pid_by_virt(e->ppid);
		if (!pid || pid->state == TASK_UNDEF || pid->state == TASK_THREAD) {
			pr_err("Can't find a parent for %d\n", e->vz_ns_pid[0]);
			task_kobj_ids_entry__free_unpacked(ids, NULL);
			goto err;
		}
		parent = pid->item;
	}

	if (!ids) {
		/* In not corrupted old image, only dead tasks don't have ids */
		if (!parent || !parent->ids) {
			pr_err("Parent or root_item has no ids\n");
			goto err;
		}

		ids = dup_zombie_ids(parent->ids);
		if (!ids)
			goto err;
	}

	pi = lookup_create_item((pid_t *)e->vz_ns_pid, e->n_vz_ns_pid, ids->pid_ns_id);
	if (pi == NULL)
		goto err;
	BUG_ON(pi->pid->state != TASK_UNDEF);

	pi->ids = ids;

	/*
	 * All pids should be added in the tree to be able to find
	 * free pid-s for helpers. pstree_item for these pid-s will
	 * be initialized when we meet PstreeEntry with this pid or
	 * we will create helpers for them.
	 */
	if (lookup_create_item((pid_t *)e->vz_ns_sid, e->n_vz_ns_sid, ids->pid_ns_id) == NULL)
		goto err;
	/*
	 * Pgid can be cut by level of current task
	 * when process group leader is in several
	 * nested pidns'es so mark it as replaceable.
	 */
	if (lookup_replaceable_item((pid_t *)e->vz_ns_pgid, e->n_vz_ns_pgid, ids->pid_ns_id) == NULL)
		goto err;

	BUG_ON(vpid(pi) != e->vz_ns_pid[0]);
	if (e->vz_ns_pid[0] > *pid_max)
		*pid_max = e->vz_ns_pid[0];
	for (i = 0; i < pi->pgid->level; i++)
		pi->pgid->ns[i].virt = e->vz_ns_pgid[i];
	if (e->vz_ns_pgid[0] > *pid_max)
		*pid_max = e->vz_ns_pgid[0];
	for (i = 0; i < pi->sid->level; i++)
		pi->sid->ns[i].virt = e->vz_ns_sid[i];
	if (e->vz_ns_sid[0] > *pid_max)
		*pid_max = e->vz_ns_sid[0];
	pi->pid->state = TASK_ALIVE;

	if (!parent) {
		if (root_item) {
			pr_err("Parent missed on non-root task "
			       "with pid %d, image corruption!\n", e->vz_ns_pid[0]);
			goto err;
		}
		root_item = pi;
		pi->parent = NULL;
	} else {
		pi->parent = parent;
		add_child_task(pi, parent);
	}

	pi->nr_threads = e->n_vz_tids;
	pi->threads = xzalloc(e->n_vz_tids * sizeof(struct pid *));
	if (!pi->threads)
		goto err;

	for (i = 0; i < e->n_vz_tids; i++) {
		struct pid *node;
		pi->threads[i] = xmalloc(PID_SIZE(pi->pid->level));
		if (!pi->threads)
			goto err;
		pi->threads[i]->real = -1;
		pi->threads[i]->level = pi->pid->level;
		for (k = 0; k < pi->pid->level; k++) {
			pi->threads[i]->ns[k].virt = e->vz_tids[i]->tid[k];
			rb_init_node(&pi->threads[i]->ns[k].node);
		}
		pi->threads[i]->state = TASK_THREAD;
		pi->threads[i]->item = NULL;
		if (i == 0)
			continue; /* A thread leader is in a tree already */
		node = lookup_create_pid((pid_t *)e->vz_tids[i]->tid, e->vz_tids[i]->n_tid, pi->threads[i], ids->pid_ns_id);

		BUG_ON(node == NULL);
		if (node != pi->threads[i]) {
			pr_err("Unexpected task %d in a tree %d\n", e->vz_tids[i]->tid[0], i);
			goto err;
		}
	}

	pi->child_subreaper = e->has_vz_child_subreaper ? e->vz_child_subreaper : false;

	task_entries->nr_threads += e->n_vz_tids;
	task_entries->nr_tasks++;


	ret = 1;
err:
	pstree_entry__free_unpacked(e, NULL);
	return ret;
}

static int read_pstree_image(pid_t *pid_max)
{
	struct cr_img *img;
	int ret;

	pr_info("Reading image tree\n");

	img = open_image(CR_FD_PSTREE, O_RSTR);
	if (!img)
		return -1;

	do {
		ret = read_one_pstree_item(img, pid_max);
	} while (ret > 0);

	if (ret == 0)
		ret = set_ns_roots();
	close_image(img);
	return ret;
}

#define RESERVED_PIDS		300
static int get_free_pid(struct ns_id *ns)
{
	struct pid *prev, *next;
	struct ns_id *i = ns;
	int level = 0;

	while ((i = i->parent) != NULL)
		level++;

	prev = rb_entry(rb_first(&ns->pid.rb_root), struct pid, ns[level].node);

	while (1) {
		struct rb_node *node;
		pid_t pid;

		pid = prev->ns[level].virt + 1;
		pid = pid < RESERVED_PIDS ? RESERVED_PIDS + 1 : pid;

		node = rb_next(&prev->ns[level].node);
		if (node == NULL)
			return pid;
		next = rb_entry(node, struct pid, ns[level].node);
		if (next->ns[level].virt > pid)
			return pid;
		prev = next;
	}

	return -1;
}

pid_t *get_free_pids(struct ns_id *ns, pid_t *pids, int *level)
{
	int i;

	for (i = MAX_NS_NESTING-1; ns && i >= 0; i--, ns = ns->parent) {
		pids[i] = get_free_pid(ns);
		if (pids[i] < 0) {
			pr_err("Can't find free pid\n");
			return NULL;
		}
	}

	if (ns) {
		pr_err("Too many pid levels\n");
		return NULL;
	}

	*level = MAX_NS_NESTING - (++i);
	if (*level == 0)
		return NULL;

	return &pids[i];
}

TaskKobjIdsEntry *__dup_helper_ids(TaskKobjIdsEntry *ns_ids, TaskKobjIdsEntry *pidns_ids)
{
	TaskKobjIdsEntry *copy;

	copy = xmalloc(sizeof(*copy));
	if (!copy) {
		pr_err("Can't allocate ids copy\n");
		return NULL;
	}
	task_kobj_ids_entry__init(copy);

#define COPY_NS_ID(ids, copy, name)				\
	if (ids->has_##name##_ns_id) {			\
		copy->has_##name##_ns_id = true;	\
		copy->name##_ns_id = ids->name##_ns_id;	\
	}
	/* Helpers inherit all namespaces */
	COPY_NS_ID(ns_ids, copy, mnt);
	COPY_NS_ID(ns_ids, copy, net);
	COPY_NS_ID(ns_ids, copy, user);
	COPY_NS_ID(ns_ids, copy, pid);
	COPY_NS_ID(ns_ids, copy, ipc);
	COPY_NS_ID(ns_ids, copy, uts);
	COPY_NS_ID(ns_ids, copy, cgroup);
	COPY_NS_ID(pidns_ids, copy, pid);
#undef COPY_NS_ID

	return copy;
}

TaskKobjIdsEntry *dup_helper_ids(TaskKobjIdsEntry *ids)
{
	return __dup_helper_ids(ids, ids);
}

TaskKobjIdsEntry *dup_helper_ids_other_pidns(TaskKobjIdsEntry *ids, TaskKobjIdsEntry *pidns_ids)
{
	return __dup_helper_ids(ids, pidns_ids);
}

int is_group_leader(struct pstree_item *item)
{
	if (vpid(item) == vpgid(item)) {
		BUG_ON(!equal_pid(item->pid, item->pgid));
		return 1;
	}
	return 0;
}

/* Add session and process group leader helpers to proper namespaces */
static int prepare_pstree_leaders(void) {
	struct pstree_item *item;

	for_each_pstree_item(item) {
		struct pstree_item *session_leader = NULL, *group_leader;

		if (item->pid->state == TASK_UNDEF)
			continue;
		/* item->sid item->pgid should be allocated/initialized here */

		if (is_session_leader(item))
			continue;

		/* inheriting external session */
		if (opts.shell_job && !is_session_leader(root_item) &&
		    vsid(root_item) == vsid(item))
			goto skip_sessions;

		session_leader = pstree_item_by_virt(vsid(item));
		BUG_ON(session_leader == NULL);

		if (session_leader->pid->state == TASK_UNDEF) {
			struct ns_id *pidns;
			struct pstree_item *init;

			/* Pidns is required to create session leader helper */
			BUG_ON(!(root_ns_mask & CLONE_NEWPID));

			pidns = get_pidns_on_level(item, session_leader->pid->level);
			BUG_ON(!pidns);
			init = __pstree_item_by_virt(pidns, INIT_PID);
			BUG_ON(!init);

			/*
			 * Session leader has pid==sid==pgid==item->sid with
			 * ending zeroes cut, and corresponding shift in pidnses
			 * is needed, put the leader in init's children.
			 */
			memcpy(session_leader->sid, item->sid, PID_SIZE(session_leader->sid->level));
			memcpy(session_leader->pgid, item->sid, PID_SIZE(session_leader->pgid->level));
			session_leader->ids = dup_helper_ids(init->ids);
			if (!session_leader->ids)
				return -1;
			session_leader->parent = init;
			add_child_task(session_leader, session_leader->parent);
			init_pstree_helper(session_leader);

			pr_info("Add a helper %d for restoring SID %d\n",
					vpid(session_leader), vsid(session_leader));
		}

skip_sessions:
		if (is_group_leader(item))
			continue;

		/* inheriting external process group */
		if (opts.shell_job && !is_session_leader(root_item) &&
		    !is_group_leader(root_item) &&
		    vpgid(root_item) == vpgid(item))
			continue;

		group_leader = pstree_item_by_virt(vpgid(item));
		BUG_ON(group_leader == NULL);

		if (!is_session_leader(group_leader))
			futex_inc(&rsti(group_leader)->pgrp_member_cnt);

		/* Only the item with full pgid has full info of leader's pidns */
		if (!equal_pid(item->pgid, group_leader->pid))
			continue;

		if (group_leader->pid->state == TASK_UNDEF) {
			struct pstree_item *init, *parent;

			/* Fast path put group leader to our children in same pidns */
			if (item->pid->level == group_leader->pid->level) {
				init = item;
				parent = item;
			} else {
				struct ns_id *pidns;

				/* Multiple pidns-es case */
				BUG_ON(!(root_ns_mask & CLONE_NEWPID));

				pidns = get_pidns_on_level(item, group_leader->pid->level);
				BUG_ON(!pidns);
				init = __pstree_item_by_virt(pidns, INIT_PID);
				BUG_ON(!init);

				/* inheriting external session */
				if (opts.shell_job && !is_session_leader(root_item) &&
				    vsid(root_item) == vsid(item)) {
					parent = root_item;
				} else {
					BUG_ON(!session_leader);
					parent = session_leader;
				}
			}

			/*
			 * Process group leader has pid==pgid==item->pgid and
			 * sid==item->sid with ending zeroes cut, and corresponding
			 * shift in pidnses is needed, put the leader in session
			 * leader's children to have sid inherited.
			 */
			memcpy(group_leader->sid, item->sid, PID_SIZE(group_leader->sid->level));
			memcpy(group_leader->pgid, item->pgid, PID_SIZE(group_leader->pgid->level));
			group_leader->ids = dup_helper_ids_other_pidns(parent->ids, init->ids);
			if (!group_leader->ids)
				return -1;
			group_leader->parent = parent;
			add_child_task(group_leader, group_leader->parent);
			init_pstree_helper(group_leader);

			pr_info("Add a helper %d for restoring PGID %d\n",
					vpid(group_leader), vpgid(group_leader));
		}
	}

	return 0;
}

static int set_born_sid(struct pstree_item *item, int born_sid)
{
	if (item->born_sid != -1 && item->born_sid != born_sid) {
		pr_err("Can't figure out which sid (%d or %d)"
		       "the process %d was born with\n",
		       item->born_sid, born_sid, vpid(item));
		return -1;
	}

	item->born_sid = born_sid;
	pr_info("%d was born with sid %d\n", vpid(item), born_sid);
	return 0;
}

static int __can_inherit_sid(struct pstree_item *item, int set)
{
	struct pstree_item *parent;

	parent = item->parent;
	while (parent) {
		/* parent will give the right sid to item */
		if (vsid(item) == vsid(parent))
			return 1;
		/* non-leader can't give children sid different from it's own */
		if (!is_session_leader(parent))
			break;
		/* parent should have had sid == born_sid before setsid */
		if (set && set_born_sid(parent, vsid(item)))
			return 0;
		/* some other ancestor can have the right pid for item */
		parent = parent->parent;
	}
	return 0;
}

static int can_inherit_sid(struct pstree_item *item)
{
	return __can_inherit_sid(item, 0);
}

/*
 * Get pid of process item in pidns of process base,
 * base and item should have ->ids initialized.
 */
static pid_t get_relative_pid(struct pstree_item *base,
			      struct pstree_item *item)
{
	/* Same level fast path */
	if (item->pid->level == base->pid->level) {
		if (base->ids->pid_ns_id == item->ids->pid_ns_id)
			return last_level_pid(item->pid);
		else
			return 0;
	}

	if (have_nested_pidns(base, item))
		return item->pid->ns[base->pid->level-1].virt;
	return 0;
}

static int can_receive_pgid(struct pstree_item *item)
{
	struct pstree_item *leader;
	pid_t pgid = vpgid(item);

	/* inheriting external process group */
	if (opts.shell_job && !is_session_leader(root_item) &&
	    !is_group_leader(root_item) &&
	    vpgid(root_item) == vpgid(item))
		return 1;

	BUG_ON(pgid == 0);

	leader = pstree_item_by_virt(pgid);
	BUG_ON(!leader || leader->pid->state == TASK_UNDEF);

	/* item inherited pgid with session */
	if (is_session_leader(leader))
		return 1;

	/* item can see it's leader */
	if (get_relative_pid(item, leader))
		return 1;

	return 0;
}

static int check_set_pgid(struct pstree_item *curr, struct pstree_item *item,
		pid_t pgid, pid_t *pitem_pid, pid_t *pnew_pgid)
{
	struct pstree_item *leader;
	pid_t item_pid, new_pgid;

	/* Invalid pgid */
	if (pgid <= 0) {
		pr_err("Can't setpgid %d: bad pgid %d\n", vpid(item), pgid);
		return 1;
	}

	/* Pgid is already set */
	if (pgid == rsti(item)->curr_pgid) {
		pr_err("Can't setpgid %d: pgid %d is already set\n", vpid(item), pgid);
		return 1;
	}

	leader = pstree_item_by_virt(pgid);
	BUG_ON(!leader || leader->pid->state == TASK_UNDEF);

	/* We must be item or parent of item */
	if (item != curr && item->parent != curr) {
		pr_err("Can't setpgid %d: item is not %d and not it's child\n", vpid(item), vpid(curr));
		return 1;
	}

	item_pid = get_relative_pid(curr, item);
	/* We always see item's pid from curr thanks to previous check */
	BUG_ON(!item_pid);

	/* We must see the leader in our pidns to setpgid to it's group */
	new_pgid = get_relative_pid(curr, leader);
	if (!new_pgid) {
		pr_err("Can't setpgid %d: %d is not visible from %d\n", vpid(item), vpid(leader), vpid(curr));
		return 1;
	}

	/* Item should not be session leader */
	if (rsti(item)->curr_sid == vpid(item)) {
		pr_err("Can't setpgid %d: item is session leader\n", vpid(item));
		return 1;
	}

	/**
	 * FIXME: checks below are racy as we access ->forked
	 * ->curr_pgid and ->curr_sid of other tasks, and this needs
	 *  some syncronization. But we can still use them as a hint
	 *  for investigation if setpgid will evenutially fail.
	 */
	/* Everybody should be already forked */
	if (!rsti(item)->forked || !rsti(leader)->forked) {
		pr_warn("Can't setpgid %d: item or leader is not alive\n", vpid(item));
	}

	/* Leader should be the group leader already */
	if (item != leader && rsti(leader)->curr_pgid != pgid) {
		pr_warn("Can't setpgid %d: leader does not have the right pgid %d/%d\n",
			vpid(item), rsti(leader)->curr_pgid, pgid);
	}

	/* Everybody should be in a same session */
	if (rsti(curr)->curr_sid != rsti(item)->curr_sid || rsti(item)->curr_sid != rsti(leader)->curr_sid) {
		pr_warn("Can't setpgid %d: sessions does not match %d/%d/%d\n", vpid(item),
			rsti(item)->curr_sid, rsti(leader)->curr_sid, rsti(curr)->curr_sid);
	}

	if (pitem_pid)
		*pitem_pid = item_pid;
	if (pnew_pgid)
		*pnew_pgid = new_pgid;
	return 0;
}

/* From current task try to setpgid task item to pgid */
int set_pgid(struct pstree_item *item, pid_t pgid)
{
	pid_t item_pid, new_pgid, old_pgid;

	BUG_ON(pgid == 0);

	if (check_set_pgid(current, item, pgid, &item_pid, &new_pgid))
		return 1;

	old_pgid = getpgid(item_pid);
	pr_info("\twill call setpgid for %d, old pgid is %d, new pgid is %d\n", vpid(item), old_pgid, new_pgid);
	if (setpgid(item_pid, new_pgid) != 0) {
		pr_perror("Can't restore pgid (%d/%d->%d)", vpid(item), rsti(item)->curr_pgid, vpgid(current));
		return 1;
	}
	rsti(item)->curr_pgid = pgid;
	return 0;
}

static struct pstree_item *get_helper(int sid, unsigned int id, struct list_head *helpers)
{
	struct pstree_item *helper;
	list_for_each_entry(helper, helpers, sibling)
		if (vsid(helper) == sid && helper->ids->pid_ns_id == id)
			return helper;
	return NULL;
}

struct pstree_item *has_subreaper(struct pstree_item *item)
{
	return item->my_child_subreaper;
}

static int handle_init_reparent(struct ns_id *ns)
{
	struct pstree_item *init, *item, *helper, *branch, *tmp;
	LIST_HEAD(helpers);

	init = __pstree_item_by_virt(ns, INIT_PID);

	pr_info("Handle init reparent to %d\n", vpid(init));

	for_each_pssubtree_item(item, init) {
skip:
		if (!item)
			break;

		/* Skip pidns's reaper */
		if (item == init)
			continue;

		/* Session leaders do setsid() */
		if (is_session_leader(item)) {
			/*
			 * Stop on pidns init, it's descendants
			 * will be handled from it's pidns.
			 */
			if (last_level_pid(item->pid) == INIT_PID)
				goto skip_descendants;
			continue;
		}

		if (can_inherit_sid(item))
			goto skip_descendants;

		helper = get_helper(vsid(item), ns->id, &helpers);
		if (!helper) {
			struct pstree_item *leader;
			pid_t pid[MAX_NS_NESTING], *p;
			int level;

			leader = pstree_item_by_virt(vsid(item));
			BUG_ON(leader == NULL || leader->pid->state == TASK_UNDEF);
			BUG_ON(!is_session_leader(leader));

			if (has_subreaper(leader) || leader->child_subreaper) {
				pr_warn("Can't reparent %d from leader %d as it has subreaper\n",
					vpid(item), vpid(leader));
				goto skip_descendants;
			}

			if (leader->pid->level > init->pid->level)
				/*
				 * If leader is in lower pidns, then item's branch
				 * couldn't have been reparented to init from leader
				 * - will manage item in other pidns
				 *
				 * FIXME One tricky case which does not fit these rule
				 * is doing CLONE_PARENT after entering pidns and setsid.
				 */
				goto skip_descendants;

			p = get_free_pids(ns, pid, &level);
			if (!p)
				return -1;

			helper = lookup_create_item(p, level, ns->id);
			if (helper == NULL)
				return -1;

			memcpy(helper->sid, item->sid, PID_SIZE(helper->sid->level));
			memcpy(helper->pgid, item->sid, PID_SIZE(helper->pgid->level));
			helper->ids = dup_helper_ids_other_pidns(leader->ids, init->ids);
			if (!helper->ids)
				return -1;
			helper->parent = leader;

			list_add_tail(&helper->sibling, &helpers);
			init_pstree_helper(helper);

			pr_info("Add a helper %d for restoring SID %d\n", vpid(helper), vsid(helper));
		}

		branch = item;
		while (branch->parent && branch->parent != init)
			branch = branch->parent;
		pr_info("Attach %d to the temporary task %d\n", vpid(branch), vpid(helper));

		if (branch->sibling.next == &init->children)
			/* Last child of init */
			item = NULL;
		else
			/* Skip the subtree that we're reparenting to helper */
			item = list_entry(branch->sibling.next, struct pstree_item, sibling);

		/* Re-reparent branch */
		branch->parent = helper;
		move_child_task(branch, helper);
		goto skip;
skip_descendants:
		/* Descendants of non-leader should be fine, skip them */
		item = pssubtree_item_next(item, init, true);
		goto skip;
	}

	list_for_each_entry_safe(helper, tmp, &helpers, sibling) {
		move_child_task(helper, helper->parent);
		pr_info("Attach helper %d to the task %d\n", vpid(helper), vpid(helper->parent));
	}
	return 0;
}

static int handle_subreaper_reparent(struct pstree_item *subreaper)
{
	struct pstree_item *item, *helper, *branch, *leader, *tmp;
	LIST_HEAD(helpers);
	struct ns_id *ns;

	pr_info("Handle subreaper reparent to %d\n", vpid(subreaper));

	for_each_pssubtree_item(item, subreaper) {
skip:
		if (!item)
			break;

		/* Skip sub-reaper */
		if (item == subreaper)
			continue;

		/* Session leaders do setsid() */
		if (is_session_leader(item)) {
			/*
			 * Stop on pidns init, it's descendants
			 * will be handled from it's pidns.
			 */
			if (last_level_pid(item->pid) == INIT_PID)
				goto skip_descendants;
			continue;
		}

		if (can_inherit_sid(item))
			goto skip_descendants;

		branch = item;
		while (branch->parent && branch->parent != subreaper)
			branch = branch->parent;

		leader = pstree_item_by_virt(vsid(item));
		BUG_ON(leader == NULL || leader->pid->state == TASK_UNDEF);
		BUG_ON(!is_session_leader(leader));

		tmp = has_subreaper(leader);
		if (tmp != subreaper || leader->child_subreaper) {
			pr_warn("Can't reparent %d from leader %d subreaper mismatch\n",
				vpid(item), vpid(leader));
			goto skip_descendants;
		}

		ns = lookup_ns_by_id(leader->ids->pid_ns_id, &pid_ns_desc);
		BUG_ON(!ns);

		helper = get_helper(vsid(item), ns->id, &helpers);
		if (!helper) {
			pid_t pid[MAX_NS_NESTING], *p;
			int level;

			p = get_free_pids(ns, pid, &level);
			if (!p)
				return -1;

			helper = lookup_create_item(p, level, ns->id);
			if (helper == NULL)
				return -1;

			memcpy(helper->sid, item->sid, PID_SIZE(helper->sid->level));
			memcpy(helper->pgid, item->sid, PID_SIZE(helper->pgid->level));
			helper->ids = dup_helper_ids(leader->ids);
			if (!helper->ids)
				return -1;
			helper->parent = leader;

			list_add_tail(&helper->sibling, &helpers);
			init_pstree_helper(helper);

			pr_info("Add a helper %d for restoring SID %d\n", vpid(helper), vsid(helper));
		}

		pr_info("Attach %d to the temporary task %d\n", vpid(branch), vpid(helper));

		item = pssubtree_item_next(branch, subreaper, true);

		/* Re-re-parent branch */
		branch->parent = helper;
		move_child_task(branch, helper);
		goto skip;
skip_descendants:
		/* Descendants of non-leader should be fine, skip them */
		item = pssubtree_item_next(item, subreaper, true);
		goto skip;
	}

	list_for_each_entry_safe(helper, tmp, &helpers, sibling) {
		move_child_task(helper, helper->parent);
		pr_info("Attach helper %d to the task %d\n", vpid(helper), vpid(helper->parent));
	}

	return 0;
}

static int handle_subreapers_reparent(struct ns_id *ns)
{
	struct pstree_item *init, *item, *subreaper;
	LIST_HEAD(subreapers);

	init = __pstree_item_by_virt(ns, INIT_PID);
	if (!init) {
		pr_err("No init for pidns %d\n", ns->id);
		return -1;
	}

	for_each_pssubtree_item(item, init) {
skip:
		if (!item)
			break;

		if (item == init)
			continue;

		if (last_level_pid(item->pid) == INIT_PID) {
			item = pssubtree_item_next(item, init, true);
			goto skip;
		}

		if (item->child_subreaper)
			list_add(&item->child_subreaper_list, &subreapers);
	}

	list_for_each_entry(subreaper, &subreapers, child_subreaper_list) {
		if (handle_subreaper_reparent(subreaper))
			return -1;
	}

	return 0;
}

static int handle_reparenting(struct ns_id *ns, void *unused)
{
	int ret;

	ret = handle_init_reparent(ns);
	if (ret)
		return -1;

	return handle_subreapers_reparent(ns);
}

static void prepare_pstree_my_child_subreaper(void)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		struct pstree_item *parent = item->parent;

		if (!parent)
			continue;

		if (last_level_pid(item->pid) == INIT_PID)
			continue;

		if (parent->child_subreaper) {
			pr_debug("Parent %d is my(%d) child subreaper\n",
					vpid(parent), vpid(item));
			item->my_child_subreaper = parent;
		} else if (parent->my_child_subreaper) {
			pr_debug("Ancestor %d is my(%d) child subreaper "
					"copy from %d\n",
					vpid(parent->my_child_subreaper), vpid(item),
					vpid(parent));
			item->my_child_subreaper = parent->my_child_subreaper;
		}
	}
}

static int prepare_pstree_ids(void)
{
	struct pstree_item *item;

	if (prepare_pstree_leaders())
		return -1;

	prepare_pstree_my_child_subreaper();

	/*
	 * Some task can be reparented to init. A helper task should be added
	 * for restoring sid of such tasks. The helper tasks will be exited
	 * immediately after forking children and all children will be
	 * reparented to init.
	 */
	if (root_ns_mask & CLONE_NEWPID &&
	    walk_namespaces(&pid_ns_desc, handle_reparenting, NULL))
		return -1;

	for_each_pstree_item(item) {
		if (!item->parent) /* skip the root task */
			continue;

		if (item->pid->state == TASK_HELPER)
			continue;

		if (!is_session_leader(item)) {
			if (!__can_inherit_sid(item, 1)) {
				pr_err("Can't find a session leader for %d\n", vsid(item));
				return -1;
			}
		}

		if (!is_group_leader(item)) {
			if (!can_receive_pgid(item)) {
				pr_err("Can't find a group leader for %d\n", vsid(item));
				return -1;
			}
		}
	}

	return 0;
}

static unsigned long get_clone_mask(TaskKobjIdsEntry *i,
		TaskKobjIdsEntry *p)
{
	unsigned long mask = 0;

	if (i->files_id && i->files_id == p->files_id)
		mask |= CLONE_FILES;
	if (i->pid_ns_id && i->pid_ns_id != p->pid_ns_id)
		mask |= CLONE_NEWPID;
	if (i->net_ns_id && i->net_ns_id != p->net_ns_id)
		mask |= CLONE_NEWNET;
	if (i->ipc_ns_id && i->ipc_ns_id != p->ipc_ns_id)
		mask |= CLONE_NEWIPC;
	if (i->uts_ns_id && i->uts_ns_id != p->uts_ns_id)
		mask |= CLONE_NEWUTS;
	if (i->time_ns_id && i->time_ns_id != p->time_ns_id)
		mask |= CLONE_NEWTIME;
	if (i->mnt_ns_id && i->mnt_ns_id != p->mnt_ns_id)
		mask |= CLONE_NEWNS;
	if (i->user_ns_id && i->user_ns_id != p->user_ns_id)
		mask |= CLONE_NEWUSER;

	return mask;
}

static int prepare_pstree_kobj_ids(void)
{
	struct pstree_item *item;

	/* Find a process with minimal pid for shared fd tables */
	for_each_pstree_item(item) {
		struct pstree_item *parent = item->parent;
		TaskKobjIdsEntry *ids;
		unsigned long cflags;

		if (parent)
			ids = parent->ids;
		else
			ids = root_ids;

		/*
		 * Add some sanity check on image data.
		 */
		if (unlikely(!ids)) {
			pr_err("No kIDs provided, image corruption\n");
			return -1;
		}

		cflags = get_clone_mask(item->ids, ids);

		if (cflags & CLONE_FILES) {
			int ret;

			/*
			 * There might be a case when kIDs for
			 * root task are the same as in root_ids,
			 * thus it's image corruption and we should
			 * exit out.
			 */
			if (unlikely(!item->parent)) {
				pr_err("Image corruption on kIDs data\n");
				return -1;
			}

			ret = shared_fdt_prepare(item);
			if (ret)
				return ret;
		}

		rsti(item)->clone_flags = cflags;
		if (parent)
			/*
			 * Mount namespaces are setns()-ed at
			 * restore_task_mnt_ns() explicitly,
			 * no need in creating it with its own
			 * temporary namespace.
			 *
			 * Root task is exceptional -- it will
			 * be born in a fresh new mount namespace
			 * which will be populated with all other
			 * namespaces' entries.
			 *
			 * User namespaces are created in create_ns_hierarhy()
			 * before the tasks, as their hierarhy does not correlated
			 * with tasks hierarhy in any way.
			 */
			rsti(item)->clone_flags &= ~(CLONE_NEWNS | CLONE_NEWUSER);

		/*
		 * Net namespaces also do not correlated with task hierarhy,
		 * so we create them manually in prepare_net_namespaces().
		 * The second reason is that some kernel modules, such as network
		 * packet generator, run kernel thread upon net-namespace creattion
		 * taking the pid we've been requeting via LAST_PID_PATH interface
		 * in fork_with_pid(), so that we can't restore a take with pid needed.
		 *
		 * The cgroup namespace is also unshared explicitly in the
		 * move_in_cgroup(), so drop this flag here as well. And same
		 * for time namespace.
		 *
		 * UTS, IPC namespaces also don't correlate with task hierarhy and
		 * we create them in prepare_namespaces(...)
		 */
		rsti(item)->clone_flags &= ~(CLONE_NEWNET | CLONE_NEWCGROUP |
					     CLONE_NEWTIME | CLONE_NEWUTS |
					     CLONE_NEWIPC);

		/**
		 * Only child reaper can clone with CLONE_NEWPID
		 */
		if (last_level_pid(item->pid) != INIT_PID)
			rsti(item)->clone_flags &= ~CLONE_NEWPID;

		cflags &= CLONE_ALLNS;

		if (item == root_item) {
			pr_info("Will restore in %lx namespaces\n", cflags);
			root_ns_mask = cflags;
		} else if (cflags & ~(root_ns_mask & CLONE_SUBNS)) {
			/*
			 * Namespaces from CLONE_SUBNS can be nested, but in
			 * this case nobody can't share external namespaces of
			 * these types.
			 *
			 * Workaround for all other namespaces --
			 * all tasks should be in one namespace. And
			 * this namespace is either inherited from the
			 * criu or is created for the init task (only)
			 */
			pr_err("Can't restore sub-task in NS\n");
			return -1;
		}
	}

	pr_debug("NS mask to use %lx\n", root_ns_mask);
	return 0;
}

int prepare_pstree(void)
{
	int ret;
	pid_t pid_max = 0, kpid_max = 0, pid;
	int fd;
	char buf[21];

	fd = open_proc(PROC_GEN, PID_MAX_PATH);
	if (fd >= 0) {
		ret = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (ret > 0) {
			buf[ret] = 0;
			kpid_max = strtoul(buf, NULL, 10);
			pr_debug("kernel pid_max=%d\n", kpid_max);
		}
	}

	ret = read_pstree_image(&pid_max);
	pr_debug("pstree pid_max=%d\n", pid_max);

	if (!ret && kpid_max && pid_max > kpid_max) {
		/* Try to set kernel pid_max */
		fd = open_proc_rw(PROC_GEN, PID_MAX_PATH);
		if (fd == -1)
			ret = -1;
		else {
			snprintf(buf, sizeof(buf), "%u", pid_max+1);
			if (write(fd, buf, strlen(buf)) < 0) {
				pr_perror("Can't set kernel pid_max=%s", buf);
				ret = -1;
			}
			else
				pr_info("kernel pid_max pushed to %s\n", buf);
			close(fd);
		}
	}

	pid = getpid();

	if (!ret)
		/*
		 * Shell job may inherit sid/pgid from the current
		 * shell, not from image. Set things up for this.
		 */
		ret = prepare_pstree_for_shell_job(pid);
	if (!ret)
		/*
		 * Walk the collected tree and prepare for restoring
		 * of shared objects at clone time
		 */
		ret = prepare_pstree_kobj_ids();
	if (!ret)
		/*
		 * Session/Group leaders might be dead. Need to fix
		 * pstree with properly injected helper tasks.
		 */
		ret = prepare_pstree_ids();
	if (!ret)
		ret = reserve_pid_ns_helpers();

	return ret;
}

int prepare_dummy_pstree(void)
{
	pid_t dummy = 0;

	if (check_img_inventory(/* restore = */ false) == -1)
		return -1;

	if (prepare_task_entries() == -1)
		return -1;

	if (read_ns_with_hookups())
		return -1;

	if (read_pstree_image(&dummy) == -1)
		return -1;

	return 0;
}

bool restore_before_setsid(struct pstree_item *child)
{
	int csid = child->born_sid == -1 ? vsid(child) : child->born_sid;

	if (child->parent->born_sid == csid)
		return true;

	return false;
}

struct pstree_item *__pstree_item_by_virt(struct ns_id *ns, pid_t virt)
{
	struct pid *pid;

	pid = __pstree_pid_by_virt(ns, virt);
	if (pid == NULL)
		return NULL;
	BUG_ON(pid->state == TASK_THREAD);

	return pid->item;
}

struct pstree_item *pstree_item_by_real(pid_t real)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		if (item->pid->real == real)
			return item;
	}
	return NULL;
}

int pid_to_virt(pid_t real)
{
	struct pstree_item *item;

	item = pstree_item_by_real(real);
	if (item)
		return vpid(item);
	return 0;
}

static int handle_init_sessions(struct ns_id *ns)
{
	struct pstree_item *init, *item;

	init = __pstree_item_by_virt(ns, INIT_PID);
	if (!init) {
		pr_err("No init for pidns %d\n", ns->id);
		return -1;
	}

	pr_info("Handle init sessions to %d\n", vpid(init));

	for_each_pssubtree_item(item, init) {
		struct pstree_item *leader;

skip:
		if (!item)
			break;

		if (item == init)
			continue;

		if (is_session_leader(item)) {
			/*
			 * Stop on pidns init, it's descendants
			 * will be handled from it's pidns.
			 */
			if (last_level_pid(item->pid) == INIT_PID)
				goto skip_descendants;
			continue;
		}

		if (can_inherit_sid(item))
			goto skip_descendants;

		/* No leader case can't be checked on dump easily */
		leader = pstree_item_by_virt(vsid(item));
		if (leader) {
			if (leader->child_subreaper) {
				pr_err("Can't init-reparent %d from leader %d as leader is subreaper\n", vpid(item), vpid(leader));
				return -1;
			}

			if (has_subreaper(leader)) {
				pr_warn("Can't init-reparent %d from leader %d as leader has subreaper\n", vpid(item), vpid(leader));
				set_inherit_sid(item, false);
			} else {
				set_inherit_sid(item, true);
			}
		}
skip_descendants:
		/* Descendants of non-leader should be fine, skip them */
		item = pssubtree_item_next(item, init, true);
		goto skip;
	}

	return 0;
}

static int handle_subreaper_sessions(struct pstree_item *subreaper)
{
	struct pstree_item *item, *leader;

	pr_info("Handle subreaper sessions to %d\n", vpid(subreaper));

	for_each_pssubtree_item(item, subreaper) {
skip:
		if (!item)
			break;

		/* Skip sub-reaper */
		if (item == subreaper)
			continue;

		/* Session leaders do setsid() */
		if (is_session_leader(item)) {
			/*
			 * Stop on pidns init, it's descendants
			 * will be handled from it's pidns.
			 */
			if (last_level_pid(item->pid) == INIT_PID)
				goto skip_descendants;
			continue;
		}

		if (can_inherit_sid(item))
			goto skip_descendants;

		/* No leader case can't be checked on dump easily */
		leader = pstree_item_by_virt(vsid(item));
		if (leader) {
			if (leader->child_subreaper) {
				pr_err("Can't subpreaper-reparent %d from leader %d as leader is subreaper\n", vpid(item), vpid(leader));
				return -1;
			}

			if (has_subreaper(leader) != subreaper) {
				pr_warn("Can't subreaper-reparent %d from leader %d as leader has different subreaper\n", vpid(item), vpid(leader));
				set_inherit_sid(item, false);
			} else {
				set_inherit_sid(item, true);
			}
		}
skip_descendants:
		/* Descendants of non-leader should be fine, skip them */
		item = pssubtree_item_next(item, subreaper, true);
		goto skip;
	}

	return 0;
}

static int handle_subreapers_sessions(struct ns_id *ns)
{
	struct pstree_item *init, *item, *subreaper;
	LIST_HEAD(subreapers);

	init = __pstree_item_by_virt(ns, INIT_PID);
	if (!init) {
		pr_err("No init for pidns %d\n", ns->id);
		return -1;
	}

	for_each_pssubtree_item(item, init) {
skip:
		if (!item)
			break;

		if (item == init)
			continue;

		if (last_level_pid(item->pid) == INIT_PID) {
			item = pssubtree_item_next(item, init, true);
			goto skip;
		}

		if (item->child_subreaper)
			list_add(&item->child_subreaper_list, &subreapers);
	}

	list_for_each_entry(subreaper, &subreapers, child_subreaper_list) {
		if (handle_subreaper_sessions(subreaper))
			return -1;
	}

	return 0;

}

static int handle_sessions(struct ns_id *ns, void *unused)
{
	if (handle_init_sessions(ns))
		return -1;

	if (handle_subreapers_sessions(ns))
		return -1;

	return 0;
}

int handle_pstree_sessions(void)
{
	struct pstree_item *item;

	prepare_pstree_my_child_subreaper();

	if (root_ns_mask & CLONE_NEWPID &&
	    walk_namespaces(&pid_ns_desc, handle_sessions, NULL))
		return -1;

	/*
	 * If at least one process of the tree can not inherit sid,
	 * we can not restore this pstree in future and shouldn't dump it.
	 */
	for_each_pstree_item(item) {
		if (item->can_inherit_sid == -1) {
			pr_err("Can't inherit sid for %d\n", vpid(item));
			return -1;
		}
	}

	return 0;
}
