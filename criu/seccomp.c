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
static struct seccomp_entry *seccomp_tid_entry_root;

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

		entry->next = seccomp_tid_entry_root, seccomp_tid_entry_root = entry;
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

static void seccomp_free_chain(struct seccomp_entry *entry)
{
	struct seccomp_filter_chain *chain, *prev;

	for (chain = entry->chain; chain; chain = prev) {
		prev = chain->prev;

		xfree(chain->filter.filter.data);
		xfree(chain);
	}

	entry->nr_chains = 0;
	entry->chain = NULL;
}

void seccomp_free_entries(void)
{
	struct seccomp_entry *entry, *next;

	for (entry = seccomp_tid_entry_root; entry; entry = next) {
		next = entry->next;
		seccomp_free_chain(entry);
		xfree(entry);
	}

	seccomp_tid_rb_root = RB_ROOT;
	seccomp_tid_entry_root = NULL;
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
			thread_core->seccomp_filter = entry->img_filter_pos;
		}
	}

	return 0;
}

static int collect_filter(struct seccomp_entry *entry)
{
	struct seccomp_metadata meta_buf, *meta = &meta_buf;
	struct seccomp_filter_chain *chain, *prev;
	struct sock_filter buf[BPF_MAXINSNS];
	size_t pos;
	int len;

	if (entry->mode != SECCOMP_MODE_FILTER)
		return 0;

	for (pos = 0; true; pos++) {
		len = ptrace(PTRACE_SECCOMP_GET_FILTER, entry->tid_real, pos, buf);
		if (len < 0) {
			if (errno == ENOENT) {
				break;
			} else {
				pr_perror("Can't fetch filter on tid_real %d pos %zu",
					  entry->tid_real, pos);
				return -1;
			}
		}

		if (!meta)
			meta = &meta_buf;

		if (ptrace(PTRACE_SECCOMP_GET_METADATA, entry->tid_real, pos, meta) < 0) {
			if (errno == EIO) {
				meta = NULL;
			} else {
				pr_perror("Can't fetch seccomp metadataon tid_real %d pos %zu",
					  entry->tid_real, pos);
				return -1;
			}
		}

		chain = xzalloc(sizeof(*chain));
		if (!chain)
			return -1;

		seccomp_filter__init(&chain->filter);

		chain->filter.filter.len = len * sizeof(struct sock_filter);
		chain->filter.filter.data = xmalloc(chain->filter.filter.len);
		if (!chain->filter.filter.data) {
			xfree(chain);
			return -1;
		}

		memcpy(chain->filter.filter.data, buf, chain->filter.filter.len);

		if (meta) {
			chain->filter.has_flags = true;
			chain->filter.flags = meta->flags;
		}

		prev = entry->chain, entry->chain = chain, chain->prev = prev;
		entry->nr_chains++;
	}

	return 0;
}

static int collect_filters(struct pstree_item *item)
{
	struct seccomp_entry *parent, *leader, *entry;
	size_t i;

	if (item->pid->state == TASK_DEAD)
		return 0;

	parent = item->parent ? seccomp_find_entry(item->parent->pid->real) : NULL;
	if (!parent && item->parent) {
		pr_err("Can't collect filter on parent tid_real %d\n",
		       item->parent->pid->real);
		return -1;
	}
	leader = seccomp_find_entry(item->pid->real);
	if (!leader) {
		pr_err("Can't collect filter on leader tid_real %d\n",
		       item->pid->real);
		return -1;
	}

	for (i = 0; i < item->nr_threads; i++) {
		entry = seccomp_find_entry(item->threads[i].real);
		if (!leader) {
			pr_err("Can't collect filter on tid_real %d\n",
			       item->pid->real);
			return -1;
		}

		if (collect_filter(entry))
			return -1;
	}

	return 0;
}

static int dump_seccomp_filters(void)
{
	SeccompEntry se = SECCOMP_ENTRY__INIT;
	struct seccomp_filter_chain *chain;
	struct seccomp_entry *entry;
	size_t img_filter_pos = 0, nr_chains = 0;
	struct rb_node *node;
	int ret;

	for (node = rb_first(&seccomp_tid_rb_root); node; node = rb_next(node)) {
		entry = rb_entry(node, struct seccomp_entry, node);
		nr_chains += entry->nr_chains;
	}

	se.n_seccomp_filters = nr_chains;
	se.seccomp_filters = xmalloc(sizeof(*se.seccomp_filters) * nr_chains);
	if (!se.seccomp_filters)
		return -1;

	for (node = rb_first(&seccomp_tid_rb_root); node; node = rb_next(node)) {
		entry = rb_entry(node, struct seccomp_entry, node);

		if (!entry->nr_chains)
			continue;

		for (chain = entry->chain; chain; chain = chain->prev) {
			BUG_ON(img_filter_pos >= nr_chains);

			se.seccomp_filters[img_filter_pos] = &chain->filter;
			if (chain != entry->chain) {
				chain->filter.has_prev = true;
				chain->filter.prev = img_filter_pos - 1;
			}
			img_filter_pos++;
		}

		entry->img_filter_pos = img_filter_pos - 1;
	}

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_SECCOMP), &se, PB_SECCOMP);

	xfree(se.seccomp_filters);

	for (node = rb_first(&seccomp_tid_rb_root); node; node = rb_next(node)) {
		entry = rb_entry(node, struct seccomp_entry, node);
		seccomp_free_chain(entry);
	}

	return ret;
}

int seccomp_collect_dump_filters(void)
{
	if (preorder_pstree_traversal(root_item, collect_filters) < 0)
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
