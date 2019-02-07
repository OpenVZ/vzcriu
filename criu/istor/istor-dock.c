#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "common/lock.h"
#include "common/err.h"
#include "criu-log.h"
#include "bitops.h"
#include "log.h"

#include "istor/istor-dock.h"
#include "istor/istor-rwlock.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif

#define LOG_PREFIX "istor-dock: "

#define ISTOR_MAX_DOCKS	1024

static struct {
	istor_rbtree_t	tree;
	size_t		nr_docks;
	istor_rwlock_t	lock;
	unsigned long	free_mark[BITS_TO_LONGS(ISTOR_MAX_DOCKS)];
	istor_dock_t	docks[ISTOR_MAX_DOCKS];
} *shared;

static int oidcmp(const struct istor_rbnode_s * const e, const void * const param)
{
	istor_dock_t *dock = container_of(e, istor_dock_t, node);
	return memcmp(param, dock->oid, sizeof(uuid_t));
}

const char *istor_dock_stage_repr(uint32_t stage)
{
	static const char *stages[DOCK_STAGE_MAX] = {
		[DOCK_STAGE_NONE]	= "NONE",
		[DOCK_STAGE_CREATED]	= "CREATED",
		[DOCK_STAGE_READY]	= "READY",
		[DOCK_STAGE_NOTIFY]	= "NOTIFY",
	};

	if (stage < ARRAY_SIZE(stages)) {
		const char *s = stages[stage];
		if (s) {
			return s;
		}
	}

	return stage & FUTEX_ABORT_FLAG ? "ABORTED" : "UNKNOWN";
}

void istor_fill_stat(istor_stat_t *st)
{
	memset(st, 0, sizeof(*st));
	st->nr_docks = shared->nr_docks;
}

static istor_dock_t *istor_alloc_locked(void)
{
	unsigned long pos = 0;
	istor_dock_t *dock;

	if (shared->nr_docks >= ISTOR_MAX_DOCKS)
		return ERR_PTR(-ENOSPC);

	pos = find_next_bit(shared->free_mark, ISTOR_MAX_DOCKS, 0);
	if (pos >= ISTOR_MAX_DOCKS) {
		pr_err("Internal error: free_mark is full but has space: %lu %lu\n",
		       pos, (unsigned long)ISTOR_MAX_DOCKS);
		return ERR_PTR(-ENOSPC);
	}
	clear_bit(pos, shared->free_mark);
	dock = &shared->docks[pos];
	shared->nr_docks++;

	memset(dock, 0, sizeof(*dock));

	uuid_generate(dock->oid);
	istor_dock_stage_init(dock);
	dock->owner_pid = -1;
	dock->unix_sk = -1;
	dock->data_sk = -1;

	istor_rbnode_init(&dock->node);
	istor_rbtree_insert(&shared->tree, &dock->node);

	pr_debug("alloc: dock %p oid %s pos %4lu\n",
		 dock, ___istor_repr_id(dock->oid), pos);
	istor_dock_stage_set(dock, DOCK_STAGE_CREATED);
	return dock;
}

static istor_dock_t *istor_lookup_locked(const uuid_t oid)
{
	istor_rbnode_t *e = istor_rbtree_lookup(&shared->tree, oid);
	return e ? container_of(e, istor_dock_t, node) : NULL;
}

static void istor_delete_locked(istor_dock_t *dock)
{
	unsigned long pos = (dock - shared->docks) / sizeof(shared->docks[0]);
	pr_debug("free : dock %p oid %s pos %4lu\n",
		 dock, ___istor_repr_id(dock->oid), pos);
	if (dock->unix_sk >= 0)
		close(dock->unix_sk);
	if (dock->data_sk >= 0)
		close(dock->data_sk);
	shared->nr_docks--;
	set_bit(pos, shared->free_mark);
	istor_rbnode_delete(&shared->tree, &dock->node);
}

int istor_delete(const uuid_t oid)
{
	istor_dock_t *dock = NULL;
	int ret = -ENOENT;

	if (!istor_oid_is_zero(oid)) {
		istor_write_lock(&shared->lock);
		dock = istor_lookup_locked(oid);
		if (dock) {
			istor_delete_locked(dock);
			ret = 0;
		}
		istor_write_unlock(&shared->lock);
	}
	return ret;
}

static size_t mk_unix_path(pid_t pid, char *path, size_t size)
{
	 size_t len = snprintf(path, size, "X/criu-dock-%d", pid);
	 path[0] = '\0';
	 return len;
}

static void gen_transport_addr(istor_dock_t *dock,
			       struct sockaddr_un *addr,
			       unsigned int *addrlen)
{
	addr->sun_family = AF_UNIX;
	*addrlen = mk_unix_path(dock->owner_pid, addr->sun_path,
				sizeof(addr->sun_path));
	*addrlen += sizeof(addr->sun_family);
}

void istor_dock_fill_stat(const istor_dock_t *dock, istor_dock_stat_t *st)
{
	memset(st, 0, sizeof(*st));

	st->pid		= dock->owner_pid;
	st->unix_sk	= dock->unix_sk;
	st->data_sk	= dock->data_sk;

	mk_unix_path(dock->owner_pid, (void *)st->transport,
		     sizeof(st->transport));
}

static int istor_boot_dock(istor_dock_t *dock, pid_t owner_pid)
{
	istor_uuid_str_t oidbuf;
	struct sockaddr_un addr;
	unsigned int addrlen;

	log_init_by_pid(getpid());
	pr_debug("booting dock %s\n", __istor_repr_id(dock->oid, oidbuf));

	dock->owner_pid = owner_pid;

	dock->unix_sk = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (dock->unix_sk < 0) {
		int _errno = errno;
		pr_perror("Unable to create a socket for %s",
			  __istor_repr_id(dock->oid, oidbuf));
		istor_dock_stage_abort(dock);
		return -_errno;
	}

	gen_transport_addr(dock, &addr, &addrlen);

	if (bind(dock->unix_sk, (struct sockaddr *)&addr, addrlen)) {
		int _errno = errno;
		pr_perror("Unable to bind a socket for %s",
			  __istor_repr_id(dock->oid, oidbuf));
		istor_dock_stage_abort(dock);
		return -_errno;
	}

	pr_debug("booted  dock %s\n", __istor_repr_id(dock->oid, oidbuf));
	istor_dock_stage_set(dock, DOCK_STAGE_READY);
	return 0;
}

static int istor_serve_dock(istor_dock_t *dock)
{
	int ret;

	for (;;) {
		ret = istor_dock_stage_wait(dock, DOCK_STAGE_NOTIFY);
		if (ret < 0) {
			pr_err("Abort processing on %s\n",
			       ___istor_repr_id(dock->oid));
			return -1;
		}
	}

	return 0;
}

static void istor_dock_clean_on_fork(clean_on_fork_t *args)
{
	if (args) {
		size_t i;

		for (i = 0; i < args->nr_fds; i++)
			close(args->fds[i]);
	}
}

static istor_dock_t *istor_new_dock_locked(clean_on_fork_t *args)
{
	istor_dock_t *dock;
	pid_t pid;

	dock = istor_alloc_locked();
	if (IS_ERR(dock))
		return dock;

	pid = fork();
	if (pid == 0) {
		int ret;

		istor_dock_clean_on_fork(args);
		ret = istor_boot_dock(dock, getpid());
		if (ret)
			exit(ret);
		exit(istor_serve_dock(dock));
	} else if (pid < 0) {
		int _errno = errno;
		pr_perror("Can't allocate new dock handler\n");
		istor_delete_locked(dock);
		return ERR_PTR(-_errno);
	}

	/*
	 * A child should notify us about error and
	 * it is up to us to cleanup resources.
	 */
	if (istor_dock_stage_wait(dock, DOCK_STAGE_READY)) {
		pr_err("Failed to wait booting on %s\n",
		       ___istor_repr_id(dock->oid));
		istor_delete_locked(dock);
		return ERR_PTR(-EINVAL);
	}

	return dock;
}

istor_dock_t *istor_lookup_alloc(const uuid_t oid, bool alloc, clean_on_fork_t *args)
{
	istor_dock_t *dock;
	if (alloc) {
		istor_write_lock(&shared->lock);
		dock = istor_lookup_locked(oid);
		if (!dock)
			dock = istor_new_dock_locked(args);
		istor_write_unlock(&shared->lock);
	} else {
		istor_read_lock(&shared->lock);
		dock = istor_lookup_locked(oid);
		istor_read_unlock(&shared->lock);
	}
	return dock;
}

struct iter_entry_params {
	iter_t	iter;
	void	*args;
};

static int iter_entry(const struct istor_rbnode_s * const e, void *param)
{
	istor_dock_t *dock = rb_entry(e, istor_dock_t, node);
	struct iter_entry_params *p = param;
	return p->iter(dock, p->args);
}

int istor_iterate(iter_t iter, void *args)
{
	struct iter_entry_params params = {
		.iter	= iter,
		.args	= args,
	};
	int ret;

	istor_read_lock(&shared->lock);
	ret = istor_rbtree_iterate(&shared->tree, iter_entry, &params);
	istor_read_unlock(&shared->lock);
	return ret;
}

int istor_init_shared(void)
{
	shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
		      MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if ((void *)shared == MAP_FAILED) {
		pr_perror("Can't allocate root resource");
		return -ENOMEM;
	}

	istor_rbtree_init(&shared->tree, oidcmp);
	memset(shared->free_mark, 0xff, sizeof(shared->free_mark));
	istor_rwlock_init(&shared->lock);

	pr_debug("shared data at %p took %zd bytes\n", shared, sizeof(*shared));

//	{
//		atomic_t raw = ATOMIC_INIT(0);
//		pr_debug("atomic_add_return(1, &raw)    %d\n", atomic_add_return(1, &raw));
//		pr_debug("atomic_read(&raw)             %d\n", atomic_read(&raw));
//		pr_debug("atomic_sub_return(1, &raw)    %d\n", atomic_sub_return(1, &raw));
//		pr_debug("atomic_read(&raw)             %d\n", atomic_read(&raw));
//		pr_debug("atomic_cmpxchg(&raw, 0 , 1)   %d\n", atomic_cmpxchg(&raw, 0 , 1));
//		pr_debug("atomic_read(&raw)             %d\n", atomic_read(&raw));
//		pr_debug("atomic_cmpxchg(&raw, 0 , 1)   %d\n", atomic_cmpxchg(&raw, 0 , 1));
//		pr_debug("atomic_read(&raw)             %d\n", atomic_read(&raw));
//		pr_debug("atomic_cmpxchg(&raw, 0 , 1)   %d\n", atomic_cmpxchg(&raw, 1 , 0));
//		pr_debug("atomic_read(&raw)             %d\n", atomic_read(&raw));
//	}

	return 0;
}
