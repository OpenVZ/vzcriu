#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <syscall.h>
#include <linux/kcmp.h>

#include "criu-log.h"

#include "common/lock.h"
#include "common/err.h"
#include "common/bug.h"
#include "common/scm.h"
#include "common/xmalloc.h"

#include "setproctitle.h"

#include "bitops.h"
#include "log.h"

#include "istor/istor-dock.h"
#include "istor/istor-net.h"
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
		[DOCK_STAGE_COMPLETE]	= "COMPLETE",
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
	mutex_init(&dock->notify_mutex);
	atomic_set(&dock->ref, 1);
	dock->owner_pid = -1;
	dock->unix_sk = -1;
	dock->data_sk = -1;

	istor_rbnode_init(&dock->node);
	istor_rbtree_insert_new(&shared->tree, &dock->node, dock->oid);

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

static int istor_delete_locked(istor_dock_t *dock)
{
	unsigned long pos;

	if (istor_dock_put_locked(dock)) {
		istor_dock_get_locked(dock);
		return -EBUSY;
	}

	pos = (dock - shared->docks) / sizeof(shared->docks[0]);
	pr_debug("free : dock %p oid %s pos %4lu\n",
		 dock, ___istor_repr_id(dock->oid), pos);

	if (dock->unix_sk >= 0)
		close(dock->unix_sk);
	if (dock->data_sk >= 0)
		close(dock->data_sk);
	shared->nr_docks--;
	set_bit(pos, shared->free_mark);
	istor_rbnode_delete(&shared->tree, &dock->node);
	return 0;
}

int istor_delete(const uuid_t oid)
{
	istor_dock_t *dock = NULL;
	int ret = -ENOENT;

	if (!istor_oid_is_zero(oid)) {
		istor_write_lock(&shared->lock);
		dock = istor_lookup_locked(oid);
		if (dock)
			ret = istor_delete_locked(dock);
		istor_write_unlock(&shared->lock);
	}
	return ret;
}

static size_t mk_unix_path(pid_t pid, char *path, size_t size)
{
	 size_t len = snprintf(path, size, "X/istor-dock-%d", pid);
	 path[0] = '\0';

	 BUG_ON(len >= ISTOR_DOCK_MAX_TRANSPORT_LEN);

	 return len;
}

static void gen_transport_addr(const istor_dock_t *dock,
			       struct sockaddr_un *addr,
			       unsigned int *addrlen)
{
	addr->sun_family = AF_UNIX;
	*addrlen = mk_unix_path(dock->owner_pid, addr->sun_path,
				sizeof(addr->sun_path));
	*addrlen += sizeof(addr->sun_family);
}

void istor_dock_close_data_sk(istor_dock_t *dock)
{
	if (dock->data_sk < 0)
		return;

	pr_debug("%s: remove data_sk %d\n", dock->oidbuf, dock->data_sk);
	close(dock->data_sk);
	dock->data_sk = -1;
}

int istor_dock_send_data_sk(const istor_dock_t *dock, int usk, int data_sk)
{
	struct sockaddr_un addr;
	unsigned int addrlen;
	int ret;

	if (dock->data_sk > -1) {
		ret = syscall(SYS_kcmp, getpid(), dock->owner_pid,
			      KCMP_FILE, data_sk, dock->data_sk);
		if (!ret) {
			pr_debug("%s: reuse data_sk %d\n", dock->oidbuf, data_sk);
			return 0;
		}
	}

	gen_transport_addr(dock, &addr, &addrlen);
	ret = send_fds(usk, &addr, addrlen, &data_sk, 1, NULL, 0);
	if (ret) {
		errno = -ret;
		pr_perror("%s: can't send fd", dock->oidbuf);
		return -EIO;
	}
	pr_debug("%s: sent data_sk %d\n", dock->oidbuf, data_sk);
	return 1;
}

int istor_dock_recv_data_sk(istor_dock_t *dock)
{
	int sk = -1, ret;

	if (dock->unix_sk < 0) {
		pr_err("%s: no transport socket opened\n", dock->oidbuf);
		return -EIO;
	}

	ret = recv_fds(dock->unix_sk, &sk, 1, NULL, 0);
	if (ret < 0) {
		errno = -ret;
		pr_perror("%s: can't receive data socket", dock->oidbuf);
		return -EIO;
	}

	if (dock->data_sk > -1)
		close(dock->data_sk);

	dock->data_sk = sk;
	pr_debug("%s: install data_sk %d\n", dock->oidbuf, sk);
	return 0;
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
	struct sockaddr_un addr;
	unsigned int addrlen;

	log_init_by_pid(getpid());

	__istor_repr_short_id(dock->oid, dock->oidbuf);
	pr_debug("%s: booting\n", dock->oidbuf);

	dock->owner_pid = owner_pid;

	dock->unix_sk = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (dock->unix_sk < 0) {
		int _errno = errno;
		pr_perror("%s: Unable to create a socket", dock->oidbuf);
		istor_dock_stage_abort(dock);
		return -_errno;
	}

	gen_transport_addr(dock, &addr, &addrlen);

	if (bind(dock->unix_sk, (struct sockaddr *)&addr, addrlen)) {
		int _errno = errno;
		pr_perror("%s: Unable to bind a socket", dock->oidbuf);
		istor_dock_stage_abort(dock);
		return -_errno;
	}

	pr_debug("%s: booted\n", dock->oidbuf);
	istor_dock_stage_set(dock, DOCK_STAGE_READY);
	return 0;
}

static int istor_serve_dock_img_write(istor_dock_t *dock)
{
	istor_msg_img_write_t *mwrite = (void *)(dock->notify.data);
	istor_imgset_t *iset = dock->owner_iset;
	istor_img_t *img;
	size_t new_size;
	ssize_t len;
	void *where;
	int ret;

	if (dock->notify.flags & DOCK_NOTIFY_F_DATA_SK) {
		ret = istor_dock_recv_data_sk(dock);
		if (ret)
			return ret;
	}

	img = istor_img_lookup(iset, NULL, mwrite->idx);
	if (!img) {
		pr_debug("%s: iwrite: idx %d doesn't exist\n",
			 dock->oidbuf, mwrite->idx);
		return -ENOENT;
	}

	new_size = img->off + mwrite->data_size;
	if (new_size > img->size) {
		if (xrealloc_safe(&img->data, new_size)) {
			pr_err("%s: iwrite no %zu bytes for idx %d\n",
			       dock->oidbuf, new_size, mwrite->idx);
			return -ENOMEM;
		}
	}

	where = img->data + img->off;
	len = istor_recv(dock->data_sk, where, mwrite->data_size);
	if (len < 0) {
		pr_err("%s: iwrite network error\n", dock->oidbuf);
		return len;
	}

	pr_debug("%s: iwrite wrote %zu bytes idx %d\n",
		 dock->oidbuf, len, mwrite->idx);

	img->off += len;
	return 0;
}

static int istor_serve_dock_img_open(istor_dock_t *dock)
{
	istor_msg_img_open_t *mopen = (void *)dock->notify.data;
	istor_imgset_t *iset = dock->owner_iset;
	istor_img_t *img;
	size_t path_size;

	path_size = istor_msg_t_psize(mopen);

	if (path_size > ISTOR_IMG_NAME_LEN) {
		pr_debug("%s: iopen: path %s is too long\n",
			 dock->oidbuf, mopen->path);
		return -ENAMETOOLONG;
	}

	img = istor_img_lookup(iset, mopen->path, -1);
	if (img) {
		if (!(mopen->flags & (O_TRUNC))) {
			pr_debug("%s: iopen: path %s is busy\n",
				 dock->oidbuf, mopen->path);
			return -EBUSY;
		}
		/*
		 * FIXME reset image data!
		 */
	} else if (!(mopen->flags & (O_CREAT))) {
		pr_debug("%s: iopen: path %s doesn't exist\n",
			 dock->oidbuf, mopen->path);
		return -ENOENT;
	}

	img = istor_img_alloc(iset, mopen->path);
	if (IS_ERR(img)) {
		pr_err("%s: iopen: can't allocate %s: %ld\n",
		       dock->oidbuf, mopen->path, PTR_ERR(img));
		return PTR_ERR(img);
	}

	img->flags	= mopen->flags;
	img->mode	= mopen->mode;

	pr_debug("%s: iopen: name %s idx %ld flags %0o mode %#x\n",
		 dock->oidbuf, img->name, img->idx, img->flags, img->mode);

	return img->idx;
}

static int istor_serve_dock(istor_dock_t *dock)
{
	int ret;

	setproctitle("istor dock %s",  dock->oidbuf);

	dock->owner_iset = istor_imgset_alloc();
	if (IS_ERR(dock->owner_iset)) {
		errno = -PTR_ERR(dock->owner_iset);
		pr_err("%s: Can't allocate image set", dock->oidbuf);
		dock->owner_iset = NULL;
		exit(1);
	}

	for (;;) {
		ret = istor_dock_stage_wait(dock, DOCK_STAGE_NOTIFY);
		if (ret < 0) {
			pr_err("%s: Abort on stage\n", dock->oidbuf);
			return -EINTR;
		}

		pr_debug("%s: notify %s\n", dock->oidbuf,
			 cmd_repr(dock->notify.cmd));

		switch (dock->notify.cmd) {
		case ISTOR_CMD_IMG_OPEN:
			dock->notify.ret = istor_serve_dock_img_open(dock);
			break;
		case ISTOR_CMD_IMG_STAT:
			dock->notify.ret = -EINVAL;
			break;
		case ISTOR_CMD_IMG_WRITE:
			dock->notify.ret = istor_serve_dock_img_write(dock);
			break;
		case ISTOR_CMD_IMG_READ:
			dock->notify.ret = -EINVAL;
			break;
		case ISTOR_CMD_IMG_CLOSE:
			dock->notify.ret = -EINVAL;
			break;
		default:
			break;
		}
		istor_dock_stage_set(dock, DOCK_STAGE_COMPLETE);
	}

	return 0;
}

int istor_dock_serve_cmd_locked(istor_dock_t *dock)
{
	istor_dock_stage_set(dock, DOCK_STAGE_NOTIFY);
	return istor_dock_stage_wait(dock, DOCK_STAGE_COMPLETE);
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
		if (!istor_oid_is_zero(oid))
			dock = ERR_PTR(-EINVAL);
		else
			dock = istor_new_dock_locked(args);
		istor_write_unlock(&shared->lock);
	} else {
		istor_read_lock(&shared->lock);
		if (!istor_oid_is_zero(oid)) {
			dock = istor_lookup_locked(oid);
			if (dock)
				istor_dock_get_locked(dock);
			else
				dock = ERR_PTR(-ENOENT);
		} else
			dock = ERR_PTR(-ENOENT);
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
