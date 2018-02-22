#include <linux/filter.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "imgset.h"
#include "kcmp.h"
#include "pstree.h"
#include <compel/ptrace.h>
#include "proc_parse.h"
#include "restorer.h"
#include "seccomp.h"
#include "servicefd.h"
#include "util.h"
#include "rst-malloc.h"

#include "protobuf.h"
#include "images/seccomp.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "seccomp: "

static struct rb_root seccomp_tid_rb_root = RB_ROOT;

struct seccomp_entry *seccomp_lookup(pid_t tid_real, bool create, bool mandatory)
{
	struct seccomp_entry *entry = NULL;

	struct rb_node *node = seccomp_tid_rb_root.rb_node;
	struct rb_node **new = &seccomp_tid_rb_root.rb_node;
	struct rb_node *parent = NULL;

	while (node) {
		struct seccomp_entry *this = rb_entry(node, struct seccomp_entry, node);

		parent = *new;
		if (tid_real < this->tid_real)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (tid_real > this->tid_real)
			node = node->rb_right, new = &((*new)->rb_right);
		else
			return this;
	}

	if (create) {
		entry = xzalloc(sizeof(*entry));
		if (!entry)
			return NULL;
		rb_init_node(&entry->node);
		entry->tid_real	= tid_real;

		rb_link_and_balance(&seccomp_tid_rb_root, &entry->node, parent, new);
	} else {
		if (mandatory)
			pr_err("Can't find entry on tid_real %d\n", tid_real);
	}

	return entry;
}

int seccomp_collect_entry(pid_t tid_real, unsigned int mode)
{
	struct seccomp_entry *entry;

	entry = seccomp_lookup(tid_real, true, false);
	if (!entry) {
		pr_err("Can't create entry on tid_real %d\n", tid_real);
		return -1;
	}

	entry->mode = mode;

	pr_debug("Collected tid_real %d mode %#x\n", tid_real, mode);
	return 0;
}

void seccomp_free_entries(void)
{
	struct seccomp_entry *entry;
	struct rb_node *node;

	while ((node = rb_first(&seccomp_tid_rb_root))) {
		rb_erase(node, &seccomp_tid_rb_root);
		entry = rb_entry(node, struct seccomp_entry, node);
		xfree(entry);
	}
}

int seccomp_dump_thread(pid_t tid_real, ThreadCoreEntry *thread_core)
{
	struct seccomp_entry *entry = seccomp_find_entry(tid_real);
	if (!entry) {
		pr_err("Can't dump thread core on tid_real %d\n", tid_real);
		return -1;
	}

	if (entry->mode != SECCOMP_MODE_DISABLED) {
		thread_core->has_seccomp_mode = true;
		thread_core->seccomp_mode = entry->mode;

		if (entry->mode == SECCOMP_MODE_FILTER) {
			thread_core->has_seccomp_filter = true;
			thread_core->seccomp_filter = entry->last_filter;
		}
	}

	return 0;
}

/* populated on dump during collect_seccomp_filters() */
static int next_filter_id = 0;
static struct seccomp_info **filters = NULL;

static struct seccomp_info *find_inherited(int last_filter, struct sock_filter *filter,
					   int len, struct seccomp_metadata *meta)
{
	struct seccomp_info *info;

	/* if we have no filters yet, this one has no parent */
	if (!filters)
		return NULL;

	for (info = filters[last_filter]; info; info = info->prev) {

		if (len != info->filter.filter.len)
			continue;
		if (!!meta ^ !!info->filter.has_flags)
			continue;
		if (info->filter.has_flags && meta) {
			if (info->filter.flags != meta->flags)
				continue;
		}
		if (!memcmp(filter, info->filter.filter.data, len))
			return info;
	}

	return NULL;
}

static int collect_filter_for_pstree(struct pstree_item *item)
{
	struct seccomp_metadata meta_buf, *meta = &meta_buf;
	struct seccomp_info *infos = NULL, *cursor;
	struct seccomp_entry *entry, *entry_parent;
	int info_count, i, ret = -1;
	struct sock_filter buf[BPF_MAXINSNS];
	void *m;

	if (item->pid->state == TASK_DEAD)
		return 0;

	entry = seccomp_find_entry(item->pid->real);
	if (!entry)
		return -1;
	if (entry->mode != SECCOMP_MODE_FILTER)
		return 0;

	for (i = 0; true; i++) {
		int len;
		struct seccomp_info *info, *inherited = NULL;

		len = ptrace(PTRACE_SECCOMP_GET_FILTER, item->pid->real, i, buf);
		if (len < 0) {
			if (errno == ENOENT) {
				/* end of the search */
				BUG_ON(i == 0);
				goto save_infos;
			} else if (errno == EINVAL) {
				pr_err("dumping seccomp infos not supported\n");
				goto out;
			} else {
				pr_perror("couldn't dump seccomp filter");
				goto out;
			}
		}

		if (!meta)
			meta = &meta_buf;

		if (ptrace(PTRACE_SECCOMP_GET_METADATA, item->pid->real, i, meta) < 0) {
			if (errno == EIO) {
				meta = NULL;
			} else {
				pr_perror("couldn't fetch seccomp metadata: pid %d pos %d",
					  item->pid->real, i);
				goto out;
			}
		}

		entry_parent = seccomp_find_entry(item->parent->pid->real);
		if (!entry_parent)
			goto out;
		inherited = find_inherited(entry_parent->last_filter, buf, len, meta);
		if (inherited) {
			bool found = false;

			/* Small sanity check: if infos is already populated,
			 * we should have inherited that filter too. */
			for (cursor = infos; cursor; cursor = cursor->prev) {
				if (inherited->prev== cursor) {
					found = true;
					break;
				}
			}

			BUG_ON(!found);

			infos = inherited;
			continue;
		}

		info = xmalloc(sizeof(*info));
		if (!info)
			goto out;
		seccomp_filter__init(&info->filter);

		if (meta) {
			info->filter.has_flags = true;
			info->filter.flags = meta->flags;
		}

		info->filter.filter.len = len * sizeof(struct sock_filter);
		info->filter.filter.data = xmalloc(info->filter.filter.len);
		if (!info->filter.filter.data) {
			xfree(info);
			goto out;
		}

		memcpy(info->filter.filter.data, buf, info->filter.filter.len);

		info->prev = infos;
		infos = info;
	}

save_infos:
	info_count = i;

	m = xrealloc(filters, sizeof(*filters) * (next_filter_id + info_count));
	if (!m)
		goto out;
	filters = m;

	for (cursor = infos, i = info_count + next_filter_id - 1;
	     i >= next_filter_id; i--) {
		BUG_ON(!cursor);
		cursor->id = i;
		filters[i] = cursor;
		cursor = cursor->prev;
	}

	next_filter_id += info_count;

	entry->last_filter = infos->id;

	/* Don't free the part of the tree we just successfully acquired */
	infos = NULL;
	ret = 0;
out:
	while (infos) {
		struct seccomp_info *freeme = infos;
		infos = infos->prev;
		xfree(freeme->filter.filter.data);
		xfree(freeme);
	}

	return ret;
}

static int dump_seccomp_filters(void)
{
	SeccompEntry se = SECCOMP_ENTRY__INIT;
	int ret = -1, i;

	/* If we didn't collect any filters, don't create a seccomp image at all. */
	if (next_filter_id == 0)
		return 0;

	se.seccomp_filters = xzalloc(sizeof(*se.seccomp_filters) * next_filter_id);
	if (!se.seccomp_filters)
		return -1;

	se.n_seccomp_filters = next_filter_id;

	for (i = 0; i < next_filter_id; i++) {
		SeccompFilter *sf;
		struct seccomp_info *cur = filters[i];

		sf = se.seccomp_filters[cur->id] = &cur->filter;
		if (cur->prev) {
			sf->has_prev = true;
			sf->prev = cur->prev->id;
		}
	}

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_SECCOMP), &se, PB_SECCOMP);

	xfree(se.seccomp_filters);

	for (i = 0; i < next_filter_id; i++) {
		struct seccomp_info *freeme = filters[i];

		xfree(freeme->filter.filter.data);
		xfree(freeme);
	}
	xfree(filters);

	return ret;
}

int collect_seccomp_filters(void)
{
	if (preorder_pstree_traversal(root_item, collect_filter_for_pstree) < 0)
		return -1;

	if (dump_seccomp_filters())
		return -1;

	return 0;
}

/* Populated on restore by prepare_seccomp_filters */
static SeccompEntry *se;

int prepare_seccomp_filters(void)
{
	struct cr_img *img;
	int ret;

	img = open_image(CR_FD_SECCOMP, O_RSTR);
	if (!img)
		return -1;

	ret = pb_read_one_eof(img, &se, PB_SECCOMP);
	close_image(img);
	if (ret <= 0)
		return 0; /* there were no filters */

	BUG_ON(!se);

	return 0;
}

int seccomp_filters_get_rst_pos(CoreEntry *core, struct task_restore_args *ta)
{
	SeccompFilter *sf = NULL;
	struct sock_fprog *arr = NULL;
	void *filter_data = NULL;
	int ret = -1, i, n_filters;
	size_t filter_size = 0;

	ta->seccomp_filters_n = 0;

	if (!core->thread_core->has_seccomp_filter)
		return 0;

	ta->seccomp_filters = (struct sock_fprog *)rst_mem_align_cpos(RM_PRIVATE);

	BUG_ON(core->thread_core->seccomp_filter > se->n_seccomp_filters);
	sf = se->seccomp_filters[core->thread_core->seccomp_filter];

	while (1) {
		ta->seccomp_filters_n++;
		filter_size += sf->filter.len;

		if (!sf->has_prev)
			break;

		sf = se->seccomp_filters[sf->prev];
	}

	n_filters = ta->seccomp_filters_n;
	arr = rst_mem_alloc(sizeof(struct sock_fprog) * n_filters + filter_size, RM_PRIVATE);
	if (!arr)
		goto out;

	filter_data = &arr[n_filters];
	sf = se->seccomp_filters[core->thread_core->seccomp_filter];
	for (i = 0; i < n_filters; i++) {
		struct sock_fprog *fprog = &arr[i];

		BUG_ON(sf->filter.len % sizeof(struct sock_filter));
		fprog->len = sf->filter.len / sizeof(struct sock_filter);

		memcpy(filter_data, sf->filter.data, sf->filter.len);

		filter_data += sf->filter.len;
		sf = se->seccomp_filters[sf->prev];
	}

	ret = 0;

out:
	seccomp_entry__free_unpacked(se, NULL);
	return ret;
}
