#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <syscall.h>

#include "criu-log.h"

#include "common/lock.h"
#include "common/err.h"
#include "common/bug.h"
#include "common/scm.h"
#include "common/xmalloc.h"

#include "setproctitle.h"

#include "bitops.h"
#include "kcmp.h"
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

static istor_dock_t *istor_lookup_locked(const uuid_t oid)
{
	istor_rbnode_t *e = istor_rbtree_lookup(&shared->tree, oid);
	return e ? container_of(e, istor_dock_t, node) : NULL;
}

static istor_dock_t *istor_alloc_locked(const uuid_t oid)
{
	bool oid_is_zero = istor_oid_is_zero(oid);
	unsigned long pos = 0;
	istor_dock_t *dock;

	if (!oid_is_zero) {
		dock = istor_lookup_locked(oid);
		if (dock)
			return ERR_PTR(-EBUSY);
	}

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

	if (oid_is_zero)
		uuid_generate(dock->oid);
	else
		memcpy(dock->oid, oid, sizeof(dock->oid));

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

static int __istor_delete_locked(istor_dock_t *dock)
{
	unsigned long pos;

	pos = (dock - shared->docks) / sizeof(shared->docks[0]);
	pr_debug("free : dock %p oid %s pos %4lu\n",
		 dock, ___istor_repr_id(dock->oid), pos);

	istor_imgset_free(dock->owner_iset);
	dock->owner_iset = NULL;

	if (dock->unix_sk >= 0)
		close(dock->unix_sk);
	if (dock->data_sk >= 0)
		close(dock->data_sk);
	shared->nr_docks--;
	set_bit(pos, shared->free_mark);
	istor_rbnode_delete(&shared->tree, &dock->node);
	return 0;
}

static int istor_delete_locked(istor_dock_t *dock)
{
	if (istor_dock_put_locked(dock)) {
		istor_dock_get_locked(dock);
		return -EBUSY;
	}

	return __istor_delete_locked(dock);
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
	istor_msghdr_t *msgh = (void *)(dock->notify.data);
	istor_msg_img_rdwr_t *mwrite = ISTOR_MSG_DATA(msgh);
	istor_imgset_t *iset = dock->owner_iset;
	istor_img_t *img;
	size_t new_size;
	ssize_t len;
	void *where;
	int ret;

	pr_debug("%s: iwrite: params idx %u off %lu data_size %u\n",
		 dock->oidbuf, mwrite->idx, mwrite->off, mwrite->data_size);

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

	if (img->state & IMG_STATE_CLOSED) {
		pr_debug("%s: iwrite: idx %d is closed\n",
			 dock->oidbuf, mwrite->idx);
		return -EIO;
	}

	if (mwrite->data_size == 0) {
		len = 0;
		goto out;
	}

	new_size = mwrite->off + mwrite->data_size;
	if (new_size > img->size) {
		if (xrealloc_safe(&img->data, new_size)) {
			pr_err("%s: iwrite: nomem %zu bytes %u for idx %d\n",
			       dock->oidbuf, new_size,
			       mwrite->data_size, mwrite->idx);
			return -ENOMEM;
		}
	}

	/*
	 * FIXME: Need to shrink back on error.
	 */
	img->size = new_size;

	where = img->data + mwrite->off;
	len = istor_recv(dock->data_sk, where, mwrite->data_size);
	if (len < 0) {
		pr_err("%s: iwrite: network error\n", dock->oidbuf);
		return len;
	}

out:
	pr_debug("%s: iwrite: wrote %zu bytes off %zu idx %d size %zu (%s)\n",
		 dock->oidbuf, len, (size_t)mwrite->off, mwrite->idx,
		 img->size, img->name);
	return 0;
}

static int istor_serve_dock_img_read(istor_dock_t *dock)
{
	istor_msghdr_t *msgh = (void *)(dock->notify.data);
	istor_msg_img_rdwr_t *mread = ISTOR_MSG_DATA(msgh);
	istor_imgset_t *iset = dock->owner_iset;
	istor_msghdr_t reply;
	istor_img_t *img;
	ssize_t len;
	void *where;
	int ret;

	pr_debug("%s: iclose: params idx %u off %lu data_size %u\n",
		 dock->oidbuf, mread->idx, mread->off, mread->data_size);

	if (dock->notify.flags & DOCK_NOTIFY_F_DATA_SK) {
		ret = istor_dock_recv_data_sk(dock);
		if (ret)
			return ret;
	}

	img = istor_img_lookup(iset, NULL, mread->idx);
	if (!img) {
		pr_debug("%s: iread: idx %d doesn't exist\n",
			 dock->oidbuf, mread->idx);
		return -ENOENT;
	}

	/*
	 * Once we start replying data we should not
	 * return errors to the callers so no additional
	 * packets would be sent to a client.
	 */

	where = img->data + mread->off + mread->data_size;
	if (where <= img->data + img->size) {
		/*
		 * We have data left to read.
		 */

		istor_enc_ok(&reply, dock->oid);
		reply.msghdr_len = ISTOR_MSG_LENGTH(mread->data_size);

		len = istor_send_msghdr(dock->data_sk, &reply);
		if (len < 0) {
			pr_err("%s: iread: header sending net error %zd\n",
			       dock->oidbuf, len);
			return 0;
		}

		where = img->data + mread->off;
		len = istor_send_msgpayload(dock->data_sk, &reply, where);
		if (len < 0) {
			pr_err("%s: iread: payload sending net error %zd\n",
			       dock->oidbuf, len);
			return 0;
		}
	} else if (where >= img->data + img->size) {
		/*
		 * Nothing left to read, thus return zero.
		 */
		istor_enc_ok(&reply, dock->oid);
		reply.msghdr_len = ISTOR_MSG_LENGTH(0);

		len = istor_send_msg(dock->data_sk, &reply);
		if (len < 0) {
			pr_err("%s: iread: header sending net error %zd\n",
			       dock->oidbuf, len);
			return 0;
		}
	}

	pr_debug("%s: iread: read %zu bytes off %zu idx %d\n",
		 dock->oidbuf, len, (size_t)mread->off, mread->idx);

	return 0;
}

static int istor_serve_dock_img_close(istor_dock_t *dock)
{
	istor_msghdr_t *msgh = (void *)dock->notify.data;
	istor_msg_img_close_t *mclose = ISTOR_MSG_DATA(msgh);
	istor_imgset_t *iset = dock->owner_iset;
	istor_img_t *img;

	pr_debug("%s: iclose: params idx %d\n", dock->oidbuf, mclose->idx);

	img = istor_img_lookup(iset, NULL, mclose->idx);
	if (!img) {
		pr_debug("%s: iclose: idx %d doesn't exist\n",
			 dock->oidbuf, mclose->idx);
		return -ENOENT;
	}

	img->state |= IMG_STATE_CLOSED;

	pr_debug("%s: iclose: closed name %s idx %ld flags %06o mode %#x\n",
		 dock->oidbuf, img->name, img->idx, img->flags, img->mode);

	return 0;
}

static int istor_serve_dock_img_open(istor_dock_t *dock)
{
	istor_msghdr_t *msgh = (void *)dock->notify.data;
	istor_msg_img_open_t *mopen = ISTOR_MSG_DATA(msgh);
	istor_imgset_t *iset = dock->owner_iset;
	istor_img_t *img;

	pr_debug("%s: iopen: params path %s flags %06o mode %#x\n",
		 dock->oidbuf, mopen->path, mopen->flags, mopen->mode);

	if (mopen->path_size > ISTOR_IMG_NAME_LEN) {
		pr_debug("%s: iopen: path %s is too long\n",
			 dock->oidbuf, mopen->path);
		return -ENAMETOOLONG;
	}

	img = istor_img_lookup(iset, mopen->path, -1);
	if (img) {
		if (mopen->flags == O_RDONLY)
			goto open_existing;
		else if (!(mopen->flags & (O_TRUNC))) {
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

open_existing:
	pr_debug("%s: iopen: opened name %s idx %ld flags %06o mode %#x\n",
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
			dock->notify.ret = istor_serve_dock_img_read(dock);
			break;
		case ISTOR_CMD_IMG_CLOSE:
			dock->notify.ret = istor_serve_dock_img_close(dock);
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

static istor_dock_t *istor_new_dock_locked(const uuid_t oid, clean_on_fork_t *args)
{
	istor_dock_t *dock;
	pid_t pid;

	dock = istor_alloc_locked(oid);
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
		dock = istor_new_dock_locked(oid, args);
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
