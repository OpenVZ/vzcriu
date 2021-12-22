#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <libnl3/netlink/msg.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/un.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <libgen.h>
#include <sched.h>

#include "libnetlink.h"
#include "cr_options.h"
#include "imgset.h"
#include "unix_diag.h"
#include "files.h"
#include "file-ids.h"
#include "log.h"
#include "util.h"
#include "util-pie.h"
#include "sockets.h"
#include "sk-queue.h"
#include "mount.h"
#include "cr-service.h"
#include "plugin.h"
#include "namespaces.h"
#include "pstree.h"
#include "external.h"
#include "crtools.h"
#include "fdstore.h"
#include "fdinfo.h"
#include "kerndat.h"
#include "rst-malloc.h"
#include "sysctl.h"

#include "protobuf.h"
#include "images/sk-unix.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "unix: "

/*
 * By-default, when dumping a unix socket, we should dump its peer
 * as well. Which in turn means, we should dump the task(s) that have
 * this peer opened.
 *
 * Sometimes, we can break this rule and dump only one end of the
 * unix sockets pair, and on restore time connect() this end back to
 * its peer.
 *
 * So, to resolve this situation we mark the peers we don't dump
 * as "external" and require the --ext-unix-sk option.
 */

#define FAKE_INO	0

struct unix_sk_desc {
	struct socket_desc	sd;
	unsigned int		type;
	unsigned int		state;
	unsigned int		peer_ino;
	unsigned int		rqlen;
	unsigned int		wqlen;
	unsigned int		namelen;
	char			*name;
	unsigned int		nr_icons;
	unsigned int		*icons;

	unsigned int		vfs_dev;
	unsigned int		vfs_ino;

	unsigned char		shutdown;
	bool			deleted;

	bool			bindmount;
	size_t			mnt_usk_bind_list_size;
	struct list_head	mnt_usk_bind_list;	/* bindmounts of unix sk list */

	mode_t			mode;
	uid_t			uid;
	gid_t			gid;

	struct list_head	list;

	int			fd;
	struct list_head	peer_list;
	struct list_head	peer_node;

	UnixSkEntry		*ue;
};

/*
 * The mutex_ghost is accessed from different tasks,
 * so make sure it is in shared memory.
 */
static mutex_t *mutex_ghost;

static LIST_HEAD(unix_sockets);
static LIST_HEAD(unix_ghost_addr);
static LIST_HEAD(unix_mnt_sockets);
static LIST_HEAD(unix_overmounted_sockets);

static int unix_resolve_name(int lfd, uint32_t id, struct unix_sk_desc *d,
			     UnixSkEntry *ue, const struct fd_parms *p);

struct unix_sk_info;
static int unlink_sk(struct unix_sk_info *ui);

struct unix_sk_listen_icon {
	unsigned int			peer_ino;
	struct unix_sk_desc		*sk_desc;
	struct unix_sk_listen_icon	*next;
};

#define SK_HASH_SIZE		32

static struct unix_sk_listen_icon *unix_listen_icons[SK_HASH_SIZE];

static struct unix_sk_listen_icon *lookup_unix_listen_icons(unsigned int peer_ino)
{
	struct unix_sk_listen_icon *ic;

	for (ic = unix_listen_icons[peer_ino % SK_HASH_SIZE];
			ic; ic = ic->next)
		if (ic->peer_ino == peer_ino)
			return ic;
	return NULL;
}

static void show_one_unix(char *act, const struct unix_sk_desc *sk)
{
	pr_debug("\t%s: ino %u peer_ino %u family %4d type %4d state %2d name %s\n",
		act, sk->sd.ino, sk->peer_ino, sk->sd.family, sk->type, sk->state, sk->name);

	if (sk->nr_icons) {
		int i;

		for (i = 0; i < sk->nr_icons; i++)
			pr_debug("\t\ticon: %d\n", sk->icons[i]);
	}
}

static void show_one_unix_img(const char *act, const UnixSkEntry *e)
{
	pr_info("\t%s: id %#x ino %u peer %u type %d state %d name %d bytes\n",
		act, e->id, e->ino, e->peer, e->type, e->state, (int)e->name.len);
}

static int can_dump_unix_sk(const struct unix_sk_desc *sk)
{
	/*
	 * The last case in this "if" is seqpacket socket,
	 * that is connected to cr_service. We will dump
	 * it properly below.
	 */
	if (sk->type != SOCK_STREAM &&
	    sk->type != SOCK_DGRAM &&
	    sk->type != SOCK_SEQPACKET) {
		pr_err("Unsupported type (%d) on socket %d.\n"
				"Only stream/dgram/seqpacket are supported.\n",
				sk->type, sk->sd.ino);
		return 0;
	}

	switch (sk->state) {
	case TCP_LISTEN:
	case TCP_ESTABLISHED:
	case TCP_CLOSE:
		break;
	default:
		pr_err("Unknown state %d for unix socket %d\n",
				sk->state, sk->sd.ino);
		return 0;
	}

	return 1;
}

static bool unix_sk_exception_lookup_id(unsigned int ino)
{
	char id[20];

	snprintf(id, sizeof(id), "unix[%u]", ino);
	if (external_lookup_id(id)) {
		pr_debug("Found ino %u in exception unix sk list\n", (unsigned int)ino);
		return true;
	}

	return false;
}

static int write_unix_entry(struct unix_sk_desc *sk)
{
	int ret;
	FileEntry fe = FILE_ENTRY__INIT;

	fe.type = FD_TYPES__UNIXSK;
	fe.id = sk->ue->id;
	fe.usk = sk->ue;

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);

	show_one_unix_img("Dumped", sk->ue);

	release_skopts(sk->ue->opts);
	xfree(sk->ue);

	sk->ue = NULL;

	return ret;
}

#ifndef SIOCUNIXFILE
#define SIOCUNIXFILE (SIOCPROTOPRIVATE + 0) /* open a socket file with O_PATH */
#endif

int kerndat_socket_unix_file(void)
{
	int sk, fd;

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("Unable to create socket");
		return -1;
	}
	fd = ioctl(sk, SIOCUNIXFILE);
	if (fd < 0 && errno != ENOENT) {
		pr_warn("Unable to open a socket file: %m\n");
		kdat.sk_unix_file = false;
		close(sk);
		return 0;
	}
	close(sk);
	close_safe(&fd);

	kdat.sk_unix_file = true;

	return 0;
}

static int get_mnt_id(int lfd, int *mnt_id)
{
	struct fdinfo_common fdinfo = { .mnt_id = -1 };
	int ret, fd;

	fd = ioctl(lfd, SIOCUNIXFILE);
	if (fd < 0) {
		pr_perror("Unable to get a socket file descriptor");
		return -1;
	}

	ret = parse_fdinfo(fd, FD_TYPES__UND, &fdinfo);
	close(fd);
	if (ret < 0)
		return -1;

	*mnt_id = fdinfo.mnt_id;

	return 0;
}

static int dump_one_unix_fd(int lfd, uint32_t id, const struct fd_parms *p)
{
	struct unix_sk_desc *sk, *peer;
	UnixSkEntry *ue;
	SkOptsEntry *skopts;
	FilePermsEntry *perms;
	FownEntry *fown;
	void *m;

	m = xmalloc(sizeof(UnixSkEntry) +
		    sizeof(SkOptsEntry) +
		    sizeof(FilePermsEntry) +
		    sizeof(FownEntry));
	if (!m)
		return -ENOMEM;
	ue	= xptr_pull(&m, UnixSkEntry);
	skopts	= xptr_pull(&m, SkOptsEntry);
	perms	= xptr_pull(&m, FilePermsEntry);
	fown	= xptr_pull(&m, FownEntry);

	unix_sk_entry__init(ue);
	sk_opts_entry__init(skopts);
	file_perms_entry__init(perms);

	*fown = p->fown;

	sk = (struct unix_sk_desc *)lookup_socket(p->stat.st_ino, PF_UNIX, 0);
	if (IS_ERR_OR_NULL(sk)) {
		pr_err("Unix socket %d not found\n", (int)p->stat.st_ino);
		goto err;
	}

	if (!can_dump_unix_sk(sk))
		goto err;

	BUG_ON(sk->sd.already_dumped);

	ue->name.len	= (size_t)sk->namelen;
	ue->name.data	= (void *)sk->name;

	ue->id		= id;
	ue->ino		= sk->sd.ino;
	ue->ns_id	= sk->sd.sk_ns->id;
	ue->has_ns_id	= true;
	ue->type	= sk->type;
	ue->state	= sk->state;
	ue->flags	= p->flags;
	ue->backlog	= sk->wqlen;
	ue->peer	= sk->peer_ino;
	ue->fown	= fown;
	ue->opts	= skopts;
	ue->uflags	= 0;

	if (unix_resolve_name(lfd, id, sk, ue, p))
		goto err;

	if (sk->namelen && *sk->name) {
		char _abspath[PATH_MAX], *abspath = _abspath;
		struct mount_info *mi;

		if (!ue->has_mnt_id) {
			pr_warn("Can't check if unix socket #%d is overmounted: mnt_id is absent\n", ue->id);
			goto skip_overmount_check;
		}

		mi = lookup_mnt_id(ue->mnt_id);
		if (!mi) {
			pr_err("Can't find mnt_id %d\n", ue->mnt_id);
			return -1;
		}

		if (sk->name[0] == '/')
			abspath = sk->name;
		else
			snprintf(abspath, PATH_MAX, "%s/%s", ue->name_dir, sk->name);

		if (path_is_overmounted(abspath, mi))
			ue->uflags |= UNIX_UFLAGS__VZ_OVERMOUNTED;
	}

skip_overmount_check:
	if (sk->bindmount) {
		struct mount_info *mi;
		int i = 0;

		if (!ue->has_mnt_id) {
			pr_err("Can't dump bindmounted unix socket #%d: mnt_id is absent\n", ue->id);
			return -1;
		}

		ue->uflags |= UNIX_UFLAGS__BINDMOUNT;

		ue->n_vz_bind_mnt_ids = sk->mnt_usk_bind_list_size;
		ue->vz_bind_mnt_ids = xzalloc(ue->n_vz_bind_mnt_ids * sizeof(uint32_t));

		list_for_each_entry(mi, &sk->mnt_usk_bind_list, mnt_usk_bind)
			ue->vz_bind_mnt_ids[i++] = mi->mnt_id;
	}

	/*
	 * Check if this socket is connected to criu service.
	 * Dump it like closed one and mark it for restore.
	 */
	if (unlikely(ue->peer == service_sk_ino)) {
		ue->state = TCP_CLOSE;
		ue->peer = 0;
		ue->uflags |= UNIX_UFLAGS__SERVICE;
	}

	if (sk->namelen && *sk->name) {
		ue->file_perms = perms;

		perms->mode	= sk->mode;
		perms->uid	= userns_uid(sk->uid);
		perms->gid	= userns_gid(sk->gid);
	}

	if (sk->deleted) {
		ue->has_deleted = true;
		ue->deleted	= sk->deleted;
	}

	sk_encode_shutdown(ue, sk->shutdown);

	/*
	 * If a stream listening socket has non-zero rqueue, this
	 * means there are in-flight connections waiting to get
	 * accept()-ed. We handle them separately with the "icons"
	 * (i stands for in-flight, cons -- for connections) things.
	 */
	if (sk->rqlen != 0 && !(sk->type == SOCK_STREAM &&
				sk->state == TCP_LISTEN)) {
		if (dump_sk_queue(lfd, id, SK_QUEUE_REAL_PID, NULL))
			goto err;
	}

	if (ue->peer) {
		peer = (struct unix_sk_desc *)lookup_socket(ue->peer, PF_UNIX, 0);
		if (IS_ERR_OR_NULL(peer)) {
			pr_err("Unix socket %u without peer %u\n",
					ue->ino, ue->peer);
			goto err;
		}

		/*
		 * Peer should have us as peer or have a name by which
		 * we can access one.
		 */
		if (peer->peer_ino != ue->ino) {
			if (!peer->name) {
				pr_err("Unix socket %u with unreachable peer %u (%u)\n",
				       ue->ino, ue->peer, peer->peer_ino);
				goto err;
			}
		}

		/*
		 * It can be external socket, so we defer dumping
		 * until all sockets the program owns are processed.
		 */
		if (!peer->sd.already_dumped) {
			show_one_unix("Add a peer", peer);
			list_add(&sk->peer_node, &peer->peer_list);
			sk->fd = dup(lfd);
			if (sk->fd < 0) {
				pr_perror("Unable to dup(%d)", lfd);
				goto err;
			}
		}

		if ((ue->type != SOCK_DGRAM) && (
				((ue->shutdown == SK_SHUTDOWN__READ)  &&
				 (peer->shutdown != SK_SHUTDOWN__WRITE)) ||
				((ue->shutdown == SK_SHUTDOWN__WRITE) &&
				 (peer->shutdown != SK_SHUTDOWN__READ))  ||
				((ue->shutdown == SK_SHUTDOWN__BOTH)  &&
				 (peer->shutdown != SK_SHUTDOWN__BOTH)) )) {
			/*
			 * Usually this doesn't happen, however it's possible if
			 * socket was shut down before connect() (see sockets03.c test).
			 * On restore we will shutdown both end (iow sockets will be in
			 * matched state). This shouldn't be a problem, since kernel seems
			 * to check both ends on read()/write(). Thus mismatched sockets behave
			 * the same way as matched.
			 */
			pr_warn("Shutdown mismatch %u:%d -> %u:%d\n",
					ue->ino, ue->shutdown, peer->sd.ino, peer->shutdown);
		}
	} else if (ue->state == TCP_ESTABLISHED) {
		const struct unix_sk_listen_icon *e;

		e = lookup_unix_listen_icons(ue->ino);
		if (!e) {
			/*
			 * ESTABLISHED socket without peer and without
			 * anyone waiting for it should be semi-closed
			 * connection.
			 */

			if (ue->shutdown == SK_SHUTDOWN__BOTH) {
				pr_info("Dumping semi-closed connection\n");
				goto dump;
			}

			pr_err("Dangling connection %d\n", ue->ino);
			goto err;
		}

		/*
		 * If this is in-flight connection we need to figure
		 * out where to connect it on restore. Thus, tune up peer
		 * id by searching an existing listening socket.
		 *
		 * Note the socket name will be found at restore stage,
		 * not now, just to reduce size of dump files.
		 */

		/* e->sk_desc is _never_ NULL */
		if (e->sk_desc->state != TCP_LISTEN) {
			pr_err("In-flight connection on "
				"non-listening socket %d\n", ue->ino);
			goto err;
		}

		ue->peer = e->sk_desc->sd.ino;

		pr_debug("\t\tFixed inflight socket %u peer %u)\n",
				ue->ino, ue->peer);
	}
dump:
	if (dump_socket_opts(lfd, skopts))
		goto err;

	pr_info("Dumping unix socket at %d\n", p->fd);
	show_one_unix("Dumping", sk);

	sk->ue = ue;
	/*
	 *  Postpone writing the entry if a peer isn't found yet.
	 *  It's required, because we may need to modify the entry.
	 *  For example, if a socket is external and is dumped by
	 *  a callback, the UNIX_UFLAGS__CALLBACK flag must be set.
	 */
	if (list_empty(&sk->peer_node) && write_unix_entry(sk))
		return -1;

	sk->sd.already_dumped = 1;

	while (!list_empty(&sk->peer_list)) {
		struct unix_sk_desc *psk;
		psk = list_first_entry(&sk->peer_list, struct unix_sk_desc, peer_node);
		close_safe(&psk->fd);
		list_del_init(&psk->peer_node);

		if (write_unix_entry(psk))
			return -1;
		psk->sd.already_dumped = 1;
	}

	return 0;

err:
	release_skopts(skopts);
	xfree(ue);
	return -1;
}

const struct fdtype_ops unix_dump_ops = {
	.type		= FD_TYPES__UNIXSK,
	.dump		= dump_one_unix_fd,
};

static int unix_resolve_name(int lfd, uint32_t id, struct unix_sk_desc *d,
				UnixSkEntry *ue, const struct fd_parms *p)
{
	char *name = d->name;
	char path[PATH_MAX], tmp[PATH_MAX];
	struct stat st;
	int fd, proc_fd, ret, mnt_id;

	if (d->namelen == 0 || name[0] == '\0')
		return 0;

	if (kdat.sk_unix_file && (root_ns_mask & CLONE_NEWNS)) {
		if (get_mnt_id(lfd, &mnt_id))
			return -1;
		ue->mnt_id = mnt_id;
		ue->has_mnt_id = true;
	}

	fd = ioctl(lfd, SIOCUNIXFILE);
	if (fd < 0) {
		pr_perror("Unable to get a socket file descriptor");
		return -1;
	}

	ret = fstat(fd, &st);
	if (ret) {
		pr_perror("Unable to fstat socker fd");
		return -1;
	}
	d->mode = st.st_mode;
	d->uid	= st.st_uid;
	d->gid	= st.st_gid;

	proc_fd = get_service_fd(PROC_FD_OFF);
	if (proc_fd < 0) {
		pr_err("Unable to get service fd for proc\n");
		return -1;
	}

	snprintf(tmp, sizeof(tmp), "self/fd/%d", fd);
	ret = readlinkat(proc_fd, tmp, path, PATH_MAX);
	if (ret < 0 && ret >= PATH_MAX) {
		pr_perror("Unable to readlink %s", tmp);
		goto out;
	}
	path[ret] = 0;

	d->deleted = strip_deleted(path, ret);

	if (name[0] != '/') {
		ret = cut_path_ending(path, name);
		if (ret) {
			pr_err("Unable too resolve %s from %s\n", name, path);
			goto out;
		}

		ue->name_dir = xstrdup(path);
		if (!ue->name_dir) {
			ret = -ENOMEM;
			goto out;
		}

		pr_debug("Resolved socket relative name %s to %s/%s\n", name, ue->name_dir, name);
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

/*
 * Returns: < 0 on error, 0 if OK, 1 to skip the socket
 */
static int unix_process_name(struct unix_sk_desc *d, const struct unix_diag_msg *m, struct nlattr **tb)
{
	int len;
	char *name;

	len = nla_len(tb[UNIX_DIAG_NAME]);
	name = xmalloc(len + 1);
	if (!name)
		return -ENOMEM;

	memcpy(name, nla_data(tb[UNIX_DIAG_NAME]), len);
	name[len] = '\0';

	if (name[0]) {
		struct unix_diag_vfs *uv;

		if (!tb[UNIX_DIAG_VFS]) {
			pr_err("Bound socket w/o inode %d\n", m->udiag_ino);
			goto skip;
		}

		uv = RTA_DATA(tb[UNIX_DIAG_VFS]);
		d->vfs_dev = uv->udiag_vfs_dev;
		d->vfs_ino = uv->udiag_vfs_ino;
	}

	d->namelen = len;
	d->name = name;
	return 0;
skip:
	xfree(name);
	return 1;
}

static int unix_collect_one(const struct unix_diag_msg *m,
			    struct nlattr **tb, struct ns_id *ns)
{
	struct unix_sk_desc *d;
	int ret = 0;

	d = xzalloc(sizeof(*d));
	if (!d)
		return -1;

	d->type	 = m->udiag_type;
	d->state = m->udiag_state;
	INIT_LIST_HEAD(&d->list);

	INIT_LIST_HEAD(&d->peer_list);
	INIT_LIST_HEAD(&d->peer_node);
	d->fd = -1;

	INIT_LIST_HEAD(&d->mnt_usk_bind_list);

	if (tb[UNIX_DIAG_SHUTDOWN])
		d->shutdown = nla_get_u8(tb[UNIX_DIAG_SHUTDOWN]);
	else
		pr_err_once("No socket shutdown info\n");

	if (tb[UNIX_DIAG_PEER])
		d->peer_ino = nla_get_u32(tb[UNIX_DIAG_PEER]);

	if (tb[UNIX_DIAG_NAME]) {
		ret = unix_process_name(d, m, tb);
		if (ret < 0)
			goto err;
		else if (ret == 1)
			goto skip;
		BUG_ON(ret != 0);
	}

	if (tb[UNIX_DIAG_ICONS]) {
		unsigned int len = nla_len(tb[UNIX_DIAG_ICONS]);
		unsigned int i;

		d->icons = xmalloc(len);
		if (!d->icons)
			goto err;

		memcpy(d->icons, nla_data(tb[UNIX_DIAG_ICONS]), len);
		d->nr_icons = len / sizeof(uint32_t);

		/*
		 * Remember these sockets, we will need them
		 * to fix up in-flight sockets peers.
		 */
		for (i = 0; i < d->nr_icons; i++) {
			struct unix_sk_listen_icon *e, **chain;
			unsigned int n;

			e = xzalloc(sizeof(*e));
			if (!e)
				goto err;

			n = d->icons[i];
			chain = &unix_listen_icons[n % SK_HASH_SIZE];
			e->next = *chain;
			*chain = e;

			pr_debug("\t\tCollected icon %d\n", d->icons[i]);

			e->peer_ino	= n;
			e->sk_desc	= d;
		}
	}

	if (tb[UNIX_DIAG_RQLEN]) {
		struct unix_diag_rqlen *rq;

		rq = (struct unix_diag_rqlen *)RTA_DATA(tb[UNIX_DIAG_RQLEN]);
		d->rqlen = rq->udiag_rqueue;
		d->wqlen = rq->udiag_wqueue;
	}

	sk_collect_one(m->udiag_ino, AF_UNIX, &d->sd, ns);
	list_add_tail(&d->list, &unix_sockets);
	show_one_unix("Collected", d);

	return 0;
err:
	ret = -1;
skip:
	xfree(d->icons);
	xfree(d->name);
	xfree(d);
	return ret;
}

int unix_receive_one(struct nlmsghdr *h, struct ns_id *ns, void *arg)
{
	struct unix_diag_msg *m = NLMSG_DATA(h);
	struct nlattr *tb[UNIX_DIAG_MAX+1];

	nlmsg_parse(h, sizeof(struct unix_diag_msg), tb, UNIX_DIAG_MAX, NULL);

	return unix_collect_one(m, tb, ns);
}

static int __dump_external_socket(struct unix_sk_desc *sk,
					struct unix_sk_desc *peer)
{
	int ret;

	ret = run_plugins(DUMP_UNIX_SK, sk->fd, sk->sd.ino);
	if (ret < 0 && ret != -ENOTSUP)
		return -1;

	if (ret == 0) {
		sk->ue->uflags |= UNIX_UFLAGS__CALLBACK;
		return 0;
	}

	if (unix_sk_exception_lookup_id(sk->sd.ino)) {
		pr_debug("found exception for unix name-less external socket.\n");
		return 0;
	}

	/* Legacy -x|--ext-unix-sk option handling */
	if (!opts.ext_unix_sk) {
		show_one_unix("Runaway socket", peer);
		pr_err("External socket is used. "
		       "Consider using --" USK_EXT_PARAM " option.\n");
		return -1;
	}

	if (peer->type != SOCK_DGRAM) {
		show_one_unix("Ext stream not supported", peer);
		pr_err("Can't dump half of stream unix connection.\n");
		return -1;
	}

	if (!peer->name) {
		show_one_unix("Ext dgram w/o name", peer);
		pr_err("Can't dump name-less external socket.\n");
		pr_err("%d\n", sk->fd);
		return -1;
	}

	return 0;
}

static int dump_external_sockets(struct unix_sk_desc *peer)
{
	struct unix_sk_desc *sk;

	while (!list_empty(&peer->peer_list)) {
		sk = list_first_entry(&peer->peer_list, struct unix_sk_desc, peer_node);

		if (__dump_external_socket(sk, peer))
			return -1;

		if (write_unix_entry(sk))
			return -1;
		close_safe(&sk->fd);

		list_del_init(&sk->peer_node);
	}

	return 0;
}

int fix_external_unix_sockets(void)
{
	struct unix_sk_desc *sk;

	pr_debug("Dumping external sockets\n");

	list_for_each_entry(sk, &unix_sockets, list) {
		FileEntry fe = FILE_ENTRY__INIT;
		UnixSkEntry e = UNIX_SK_ENTRY__INIT;
		FownEntry fown = FOWN_ENTRY__INIT;
		SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;

		if (sk->sd.already_dumped ||
		    list_empty(&sk->peer_list))
			continue;

		show_one_unix("Dumping extern", sk);

		fd_id_generate_special(NULL, &e.id);
		e.ino		= sk->sd.ino;
		e.type		= SOCK_DGRAM;
		e.state		= TCP_LISTEN;
		e.name.data	= (void *)sk->name;
		e.name.len	= (size_t)sk->namelen;
		e.uflags	= UNIX_UFLAGS__EXTERN;
		e.peer		= 0;
		e.fown		= &fown;
		e.opts		= &skopts;

		fe.type = FD_TYPES__UNIXSK;
		fe.id = e.id;
		fe.usk = &e;

		if (pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE))
			goto err;

		show_one_unix_img("Dumped extern", &e);

		if (dump_external_sockets(sk))
			goto err;
	}

	return 0;
err:
	return -1;
}

int sk_bindmount_supported(unsigned int type, unsigned int state)
{
	if (type == SOCK_DGRAM && state == TCP_CLOSE)
		return 1;

	if ((type == SOCK_STREAM || type == SOCK_SEQPACKET) &&
	    (state == TCP_CLOSE || state == TCP_LISTEN))
		return 1;

	return 0;
}

int collect_unix_bindmounts(void)
{
	struct mount_info *mi;
	struct stat st = {};
	int ret = 0;

	pr_debug("Collecting unix bindmounts\n");

	for (mi = mntinfo; mi; mi = mi->next) {
		struct unix_sk_desc *sk, *unsupported = NULL;
		int path_root, flags = AT_SYMLINK_NOFOLLOW;
		char *path;
		bool ovm;

		if (list_empty(&mi->mnt_bind))
			continue;

		ovm = mnt_is_overmounted(mi);
		if (ovm) {
			path_root = open_mountpoint_with_flags(mi, O_PATH | O_NOFOLLOW);
			if (path_root < 0) {
				pr_err("Unable to open mounpotint mnt_id %d\n", mi->mnt_id);
				return -1;
			}
			path = "";
			flags |= AT_EMPTY_PATH;
		} else {
			path_root = mntns_get_root_fd(mi->nsid);
			if (path_root < 0)
				return -1;
			path = mi->ns_mountpoint;
		}

		if (fstatat(path_root, path, &st, flags)) {
			pr_warn("Can't stat on %s(is overmount: %d): %m\n", mi->ns_mountpoint, ovm);
			if (ovm)
				close(path_root);
			continue;
		}
		if (ovm)
			close(path_root);

		if (!S_ISSOCK(st.st_mode))
			continue;

		list_for_each_entry(sk, &unix_sockets, list) {
			if (sk->vfs_ino == (int)st.st_ino &&
			    __phys_stat_dev_match(st.st_dev, sk->vfs_dev, NULL, NULL, mi)) {
				if (!sk_bindmount_supported(sk->type, sk->state)) {
					unsupported = sk;
					continue;
				}

				pr_debug("Found sock s_dev %#x ino %d (%u) bindmounted mnt_id %d %s\n",
					 (int)st.st_dev, (int)st.st_ino, sk->sd.ino, mi->mnt_id, mi->ns_mountpoint);

				sk->bindmount = true;
				sk->mnt_usk_bind_list_size++;
				list_add_tail(&mi->mnt_usk_bind, &sk->mnt_usk_bind_list);

				unsupported = NULL;
				break;
			}
		}

		if (unsupported) {
			pr_err("Unsupported bindmounted socket ino %d (%u) at %s\n",
			       (int)st.st_ino, unsupported->sd.ino, mi->ns_mountpoint);
			return -1;
		}
	}

	return ret;
}

struct unix_sk_info {
	UnixSkEntry		*ue;
	struct list_head	list;
	/* To link in unix_overmounted_sockets OR unix_mnt_sockets */
	struct list_head	early_list;
	char			*name;
	char			*name_dir;
	unsigned		flags;
	int			early_bind_id[2];
	int			ghost_id;
	struct unix_sk_info	*peer;
	struct pprep_head	peer_resolve; /* XXX : union with the above? */
	struct file_desc	d;
	struct hlist_node	hash; /* To lookup socket by ino */
	struct list_head	connected; /* List of sockets, connected to me */
	struct list_head	node; /* To link in peer's connected list  */
	struct list_head	scm_fles;
	struct list_head	ghost_node;
	size_t			ghost_dir_pos;

	/*
	 * For DGRAM sockets with queues, we should only restore the queue
	 * once although it may be open by more than one tid. This is the peer
	 * that should do the queueing.
	 */
	struct unix_sk_info	*queuer;
	/*
	 * These bits are set by task-owner of this unix_sk_info.
	 * Another tasks can only read them.
	 */
	uint8_t			bound:1;
	uint8_t			listen:1;
	uint8_t			is_connected:1;
	uint8_t			peer_queue_restored:1; /* Set in 1 after we restore peer's queue */
};

struct scm_fle {
	struct list_head l;
	struct fdinfo_list_entry *fle;
};

#define USK_PAIR_MASTER		0x1
#define USK_PAIR_SLAVE		0x2
#define USK_GHOST_FDSTORE	0x4	/* bound but removed address */
#define USK_EARLY_BIND		0x8	/* socket is pre-openeded for bindmount or overmount */
#define USK_NOCWD		0x10	/* no cwd switch */

#define SK_INFO_HASH_SIZE	32

static struct hlist_head sk_info_hash[SK_INFO_HASH_SIZE];

void init_sk_info_hash(void)
{
	int i;

	for (i = 0; i < SK_INFO_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&sk_info_hash[i]);
}

static struct unix_sk_info *find_unix_sk_by_ino(unsigned int ino)
{
	struct unix_sk_info *ui;
	struct hlist_head *chain;

	chain = &sk_info_hash[ino % SK_INFO_HASH_SIZE];
	hlist_for_each_entry(ui, chain, hash) {
		if (ui->ue->ino == ino)
			return ui;
	}

	return NULL;
}

static struct unix_sk_info *find_queuer_for(int id)
{
	struct unix_sk_info *ui;

	list_for_each_entry(ui, &unix_sockets, list) {
		if (ui->queuer && ui->queuer->ue->id == id)
			return ui;
	}

	return NULL;
}

static int sk_to_mnt_id(struct unix_sk_info *ui)
{
	struct mount_info *mi;

	if (!ui->ue->has_mnt_id)
		return -1;

	if (!(ui->ue->uflags & UNIX_UFLAGS__BINDMOUNT))
		return ui->ue->mnt_id;

	if (ui->ue->n_vz_bind_mnt_ids)
		return ui->ue->mnt_id;

	pr_warn_once("Processing old criu image with bindmount mnt_id stored instead of unix socket mnt_id\n");

	mi = lookup_mnt_id(ui->ue->mnt_id);
	BUG_ON(mi);
	BUG_ON(mi->bind);

	return mi->bind->mnt_id;
}

static struct fdinfo_list_entry *get_fle_for_task(struct file_desc *tgt,
		struct pstree_item *owner, bool force_master)
{
	struct fdinfo_list_entry *fle;
	FdinfoEntry *e = NULL;
	int fd;

	list_for_each_entry(fle, &tgt->fd_info_head, desc_list) {
		if (fle->task == owner)
			/*
			 * Owner already has this file in its fdtable.
			 * Just use one.
			 */
			return fle;

		e = fle->fe; /* keep any for further reference */
	}

	/*
	 * Some other task restores this file. Pretend that
	 * we're another user of it.
	 */
	fd = find_unused_fd(owner, -1);
	pr_info("`- will add fake %d fd\n", fd);

	if (e != NULL) {
		e = dup_fdinfo(e, fd, 0);
		if (!e) {
			pr_err("Can't duplicate fdinfo for scm\n");
			return NULL;
		}
	} else {
		/*
		 * This can happen if the file in question is
		 * sent over the socket and closed. In this case
		 * we need to ... invent a new one!
		 */

		e = xmalloc(sizeof(*e));
		if (!e)
			return NULL;

		fdinfo_entry__init(e);
		e->id = tgt->id;
		e->type = tgt->ops->type;
		e->fd = fd;
		e->flags = 0;
	}

	/*
	 * Make this fle fake, so that files collecting engine
	 * closes them at the end.
	 */
	return collect_fd_to(vpid(owner), e, rsti(owner), tgt, true, force_master);
}

int unix_note_scm_rights(int id_for, uint32_t *file_ids, int *fds, int n_ids)
{
	struct unix_sk_info *ui;
	struct pstree_item *owner;
	int i;

	ui = find_queuer_for(id_for);
	if (!ui) {
		pr_err("Can't find sender for %#x\n", id_for);
		return -1;
	}

	pr_info("Found queuer for %#x -> %#x\n", id_for, ui->ue->id);
	/*
	 * This is the task that will restore this socket
	 */
	owner = file_master(&ui->d)->task;

	pr_info("-> will set up deps\n");
	/*
	 * The ui will send data to the rights receiver. Add a fake fle
	 * for the file and a dependency.
	 */
	for (i = 0; i < n_ids; i++) {
		struct file_desc *tgt;
		struct scm_fle *sfle;

		tgt = find_file_desc_raw(FD_TYPES__UND, file_ids[i]);
		if (!tgt) {
			pr_err("Can't find fdesc to send\n");
			return -1;
		}

		pr_info("scm: add file %#x -> %d\n", tgt->id, vpid(owner));
		sfle = xmalloc(sizeof(*sfle));
		if (!sfle)
			return -1;

		sfle->fle = get_fle_for_task(tgt, owner, false);
		if (!sfle->fle) {
			pr_err("Can't request new fle for scm\n");
			xfree(sfle);
			return -1;
		}

		list_add_tail(&sfle->l, &ui->scm_fles);
		fds[i] = sfle->fle->fe->fd;
	}

	return 0;
}

static int chk_restored_scms(struct unix_sk_info *ui)
{
	struct scm_fle *sf, *n;

	list_for_each_entry_safe(sf, n, &ui->scm_fles, l) {
		if (sf->fle->stage < FLE_OPEN)
			return 1;

		/* Optimization for the next pass */
		list_del(&sf->l);
		xfree(sf);
	}

	return 0;
}

static int wake_connected_sockets(struct unix_sk_info *ui)
{
	struct fdinfo_list_entry *fle;
	struct unix_sk_info *tmp;

	list_for_each_entry(tmp, &ui->connected, node) {
		fle = file_master(&tmp->d);
		set_fds_event(fle->pid);
	}
	return 0;
}

static bool peer_is_not_prepared(struct unix_sk_info *peer)
{
	if (peer->ue->state != TCP_LISTEN)
		return (!peer->bound);
	else
		return (!peer->listen);
}

static int restore_unix_queue(int fd, SkOptsEntry *soe, struct unix_sk_info *peer)
{
	struct pstree_item *task;

	if (restore_socket_bufsz(fd, soe))
		return -1;

	if (restore_sk_queue(fd, peer->ue->id))
		return -1;
	if (peer->queuer)
		peer->queuer->peer_queue_restored = true;

	task = file_master(&peer->d)->task;
	set_fds_event(vpid(task));
	return 0;
}

static int shutdown_unix_sk(int sk, struct unix_sk_info *ui)
{
	int how;
	UnixSkEntry *ue = ui->ue;

	if (!ue->has_shutdown || ue->shutdown == SK_SHUTDOWN__NONE)
		return 0;

	how = sk_decode_shutdown(ue->shutdown);
	if (shutdown(sk, how)) {
		pr_perror("Can't shutdown unix socket");
		return -1;
	}

	pr_debug("Socket %u is shut down %d\n", ue->ino, how);
	return 0;
}

static int restore_sk_common(int fd, struct unix_sk_info *ui)
{
	if (rst_file_params(fd, ui->ue->fown, ui->ue->flags))
		return -1;

	if (restore_socket_opts(fd, ui->ue->opts))
		return -1;

	if (shutdown_unix_sk(fd, ui))
		return -1;

	return 0;
}

static int revert_unix_sk_cwd(struct unix_sk_info *ui, int *prev_cwd_fd, int *root_fd, int *ns_fd)
{
	int ret = 0;

	if (ui->flags & USK_NOCWD)
		return 0;

	if (*ns_fd >= 0 && restore_ns(*ns_fd, &mnt_ns_desc))
		ret = -1;
	if (*root_fd >= 0) {
		if (fchdir(*root_fd) || chroot("."))
			pr_perror("Can't revert root directory");
		close_safe(root_fd);
		ret = -1;
	}
	if (prev_cwd_fd && *prev_cwd_fd >= 0) {
		if (fchdir(*prev_cwd_fd))
			pr_perror("Can't revert working dir");
		else if (ui->name_dir)
			pr_debug("Reverted working dir\n");
		close(*prev_cwd_fd);
		*prev_cwd_fd = -1;
		ret = -1;
	}

	return ret;
}

static int prep_unix_sk_cwd(struct unix_sk_info *ui, int *prev_cwd_fd,
			    int *prev_root_fd, int *prev_mntns_fd)
{
	static struct ns_id *root = NULL, *ns;
	int fd;

	if (ui->flags & USK_NOCWD)
		return 0;

	/*
	 * To change mount namespace we should have fs->user = 1
	 * (see fs/namespace.c:mntns_install) but this is not
	 * usually possible since main criu process already may
	 * has forked() with CLONE_FS | CLONE_FILES and fs->user
	 * is a way bigger.
	 *
	 * For now simply switch to old scheme where all sockets
	 * are restored in root mount namespace.
	 *
	 * FIXME: Need to revisit later.
	 */
	if (prev_mntns_fd && ui->name[0] && ui->ue->mnt_id >= 0) {
		*prev_mntns_fd = -1;
		prev_mntns_fd = NULL;
	}

	if (prev_mntns_fd && ui->name[0] && ui->ue->mnt_id >= 0) {
		struct ns_id *mntns = lookup_nsid_by_mnt_id(ui->ue->mnt_id);
		int ns_fd;

		if (mntns == NULL) {
			pr_err("Unable to find the %d mount\n", ui->ue->mnt_id);
			return -1;
		}

		ns_fd = fdstore_get(mntns->mnt.nsfd_id);
		if (ns_fd < 0)
			return -1;

		if (switch_ns_by_fd(ns_fd, &mnt_ns_desc, prev_mntns_fd)) {
			close(ns_fd);
			return -1;
		}

		close(ns_fd);
	}

	*prev_cwd_fd = open(".", O_RDONLY);
	if (*prev_cwd_fd < 0) {
		pr_perror("Can't open current dir");
		return -1;
	}

	if (prev_root_fd && (root_ns_mask & CLONE_NEWNS)) {
		if (ui->ue->mnt_id >= 0) {
			ns = lookup_nsid_by_mnt_id(ui->ue->mnt_id);
		} else {
			pr_warn("Assume root mntns for socket id %#x ino %d name %s\n",
				ui->ue->id, ui->ue->ino, ui->name);
			if (root == NULL)
				root = lookup_ns_by_id(root_item->ids->mnt_ns_id,
									&mnt_ns_desc);
			ns = root;
		}
		if (ns == NULL)
			goto err;
		*prev_root_fd = open("/", O_RDONLY);
		if (*prev_root_fd < 0) {
			pr_perror("Can't open current root");
			goto err;
		}

		fd = fdstore_get(ns->mnt.root_fd_id);
		if (fd < 0) {
			pr_err("Can't get root fd\n");
			goto err;
		}
		if (fchdir(fd)) {
			pr_perror("Unable to change current working dir");
			close(fd);
			goto err;
		}
		close(fd);
		if (chroot(".")) {
			pr_perror("Unable to change root directory");
			goto err;
		}
	}

	if (ui->name_dir) {
		if (chdir(ui->name_dir)) {
			pr_perror("Can't change working dir %s",
				  ui->name_dir);
			goto err;
		}
		pr_debug("Change working dir to %s\n", ui->name_dir);
	}

	return 0;
err:
	close_safe(prev_cwd_fd);
	if (prev_root_fd)
		close_safe(prev_root_fd);
	return -1;
}

static int post_open_standalone(struct file_desc *d, int fd)
{
	int fdstore_fd = -1, procfs_self_dir = -1, len;
	struct unix_sk_info *ui;
	struct unix_sk_info *peer;
	struct sockaddr_un addr;
	int cwd_fd = -1, root_fd = -1, ns_fd = -1;

	ui = container_of(d, struct unix_sk_info, d);
	BUG_ON((ui->flags & (USK_PAIR_MASTER | USK_PAIR_SLAVE)) ||
			(ui->ue->uflags & (UNIX_UFLAGS__CALLBACK | UNIX_UFLAGS__INHERIT)));

	if (chk_restored_scms(ui))
		return 1;

	peer = ui->peer;
	if (!peer || ui->is_connected)
		goto restore_sk_common;

	if (ui->ue->ino == FAKE_INO) {
		BUG_ON(ui->queuer);
		goto restore_queue;
	}

	/* Skip external sockets */
	if (!list_empty(&peer->d.fd_info_head))
		if (peer_is_not_prepared(peer))
			return 1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	pr_info("\tConnect %d to %d\n", ui->ue->ino, peer->ue->ino);

	if (prep_unix_sk_cwd(peer, &cwd_fd, &root_fd, &ns_fd))
		return -1;

	if (peer->flags & USK_GHOST_FDSTORE) {
		procfs_self_dir = open_proc(getpid(), "fd");
		fdstore_fd = fdstore_get(peer->ghost_id);

		if (fdstore_fd < 0 || procfs_self_dir < 0)
			goto err_revert_and_exit;

		/*
		 * WARNING: After this call we rely on revert_unix_sk_cwd
		 * to restore the former directories so that connect
		 * will operate inside proc/$pid/fd/X.
		 */
		if (fchdir(procfs_self_dir)) {
			pr_perror("Can't change to procfs");
			goto err_revert_and_exit;
		}
		len = snprintf(addr.sun_path, UNIX_PATH_MAX, "%d", fdstore_fd);
	} else {
		memcpy(&addr.sun_path, peer->name, peer->ue->name.len);
		len = peer->ue->name.len;
	}

	/*
	 * Make sure the target is not being renamed at the moment
	 * while we're connecting in sake of ghost sockets.
	 */
	mutex_lock(mutex_ghost);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr.sun_family) + len) < 0) {
		pr_perror("Can't connect %d socket", ui->ue->ino);
		goto err_revert_and_exit;
	}
	mutex_unlock(mutex_ghost);

	ui->is_connected = true;

	close_safe(&procfs_self_dir);
	close_safe(&fdstore_fd);
	revert_unix_sk_cwd(peer, &cwd_fd, &root_fd, &ns_fd);

restore_queue:
	if (peer->queuer == ui &&
	    !(peer->ue->uflags & UNIX_UFLAGS__EXTERN) &&
	    restore_unix_queue(fd, ui->ue->opts, peer))
		return -1;
restore_sk_common:
	if (ui->queuer && !ui->queuer->peer_queue_restored)
		return 1;
	return restore_sk_common(fd, ui);

err_revert_and_exit:
	close_safe(&procfs_self_dir);
	close_safe(&fdstore_fd);
	revert_unix_sk_cwd(peer, &cwd_fd, &root_fd, &ns_fd);
	return -1;
}

static int restore_file_perms(struct unix_sk_info *ui)
{
	if (ui->ue->file_perms) {
		FilePermsEntry *perms = ui->ue->file_perms;
		char fname[PATH_MAX];

		if (ui->ue->name.len >= sizeof(fname)) {
			pr_err("The file name is too long\n");
			return -E2BIG;
		}

		memcpy(fname, ui->name, ui->ue->name.len);
		fname[ui->ue->name.len] = '\0';

		if (fchownat(AT_FDCWD, fname, perms->uid, perms->gid, 0) < 0) {
			int errno_cpy = errno;
			pr_perror("Unable to change file owner and group");
			return -errno_cpy;
		}

		if (fchmodat(AT_FDCWD, fname, perms->mode, 0) < 0) {
			int errno_cpy = errno;
			pr_perror("Unable to change file mode bits");
			return -errno_cpy;
		}
	}

	return 0;
}

static int keep_deleted(struct unix_sk_info *ui)
{
	int fd = open(ui->name, O_PATH);
	if (fd < 0) {
		pr_perror("ghost: Can't open id %#x ino %u addr %s",
			  ui->ue->id, ui->ue->ino, ui->name);
		return -1;
	}
	ui->ghost_id = fdstore_add(fd);
	pr_debug("ghost: id %#x %d ghost_id %d %s\n",
		 ui->ue->id, ui->ue->ino, ui->ghost_id, ui->name);
	close(fd);
	return ui->ghost_id;
}


#define UNIX_GHOST_FMT "%s.criu-sk-ghost"

/*
 * When path where socket lives is deleted, we need to reconstruct
 * it back up but allow caller to remove it after.
 */
static int bind_on_deleted(int sk, struct unix_sk_info *ui)
{
	char path[PATH_MAX], path_parked[PATH_MAX], *pos;
	struct sockaddr_un addr;
	bool renamed = false;
	int ret;

	if (ui->ue->name.len >= UNIX_PATH_MAX) {
		pr_err("ghost: Too long name for socket id %#x ino %u name %s\n",
		       ui->ue->id, ui->ue->ino, ui->name);
		return -ENOSPC;
	}

	memcpy(path, ui->name, ui->ue->name.len);
	path[ui->ue->name.len] = '\0';

	for (pos = strrchr(path, '/'); pos;
	     pos = strrchr(path, '/')) {
		*pos = '\0';

		ret = access(path, R_OK | W_OK | X_OK);
		if (ret == 0) {
			ui->ghost_dir_pos = pos - path;
			pr_debug("ghost: socket id %#x ino %u name %s detected F_OK %s\n",
				 ui->ue->id, ui->ue->ino, ui->name, path);
			break;
		}

		if (errno != ENOENT) {
			ret = -errno;
			pr_perror("ghost: Can't access %s for socket id %#x ino %u name %s",
				  path, ui->ue->id, ui->ue->ino, ui->name);
			return ret;
		}
	}

	memcpy(path, ui->name, ui->ue->name.len);
	path[ui->ue->name.len] = '\0';

	pos = dirname(path);
	pr_debug("ghost: socket id %#x ino %u name %s creating %s\n",
		 ui->ue->id, ui->ue->ino, ui->name, pos);
	ret = mkdirpat(AT_FDCWD, pos, 0755);
	if (ret) {
		errno = -ret;
		pr_perror("ghost: Can't create %s", pos);
		return ret;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(&addr.sun_path, ui->name, ui->ue->name.len);

	ret = access(ui->name, F_OK);
	if (!ret) {
		snprintf(path_parked, sizeof(path_parked), UNIX_GHOST_FMT, ui->name);
		/*
		 * In case if there exist any file with same name
		 * just move it aside for a while, we will move it back
		 * once ghost socket is processed.
		 */
		if (unlinkat(AT_FDCWD, path_parked, 0) == 0)
			pr_debug("ghost: Unlinked stale socket id %#x ino %d name %s\n",
				 ui->ue->id, ui->ue->ino, path_parked);
		if (rename(ui->name, path_parked)) {
			ret = -errno;
			pr_perror("ghost: Can't rename id %#x ino %u addr %s -> %s",
				  ui->ue->id, ui->ue->ino, ui->name, path_parked);
			return ret;
		}
		pr_debug("ghost: id %#x ino %d renamed %s -> %s\n",
			 ui->ue->id, ui->ue->ino, ui->name, path_parked);
		renamed = true;
	}

	ret = bind(sk, (struct sockaddr *)&addr,
		   sizeof(addr.sun_family) + ui->ue->name.len);
	if (ret < 0) {
		ret = -errno;
		pr_perror("ghost: Can't bind on socket id %#x ino %d addr %s",
			  ui->ue->id, ui->ue->ino, ui->name);
		goto out_rename;
	}

	ret = restore_file_perms(ui);
	if (ret < 0)
		goto out;

	ret = keep_deleted(ui);
	if (ret < 0) {
		pr_err("ghost: Can't save socket %#x ino %u addr %s into fdstore\n",
		       ui->ue->id, ui->ue->ino, ui->name);
		ret = -EIO;
	}

out:
	/*
	 * Once everything is ready, just remove the socket from the
	 * filesystem and rename back the original one if it were here.
	 */
	ret = unlinkat(AT_FDCWD, ui->name, 0);
	if (ret < 0) {
		ret = -errno;
		pr_perror("ghost: Can't unlink socket %#x ino %u addr %s",
			  ui->ue->id, ui->ue->ino, ui->name);
	}

out_rename:
	if (renamed) {
		if (rename(path_parked, ui->name)) {
			ret = -errno;
			pr_perror("ghost: Can't rename id %#x ino %u addr %s -> %s",
				  ui->ue->id, ui->ue->ino, path_parked, ui->name);
		} else {
			pr_debug("ghost: id %#x ino %d renamed %s -> %s\n",
				 ui->ue->id, ui->ue->ino, path_parked,  ui->name);
		}
	}

	/*
	 * Finally remove directories we've created.
	 */
	if (ui->ghost_dir_pos) {
		char *pos;

		memcpy(path, ui->name, ui->ue->name.len);
		path[ui->ue->name.len] = '\0';

		for (pos = strrchr(path, '/');
		     pos && (pos - path) > ui->ghost_dir_pos;
		     pos = strrchr(path, '/')) {
			*pos = '\0';
			if (rmdir(path)) {
				pr_perror("ghost: Can't remove directory %s on id %#x ino %u",
					  path, ui->ue->id, ui->ue->ino);
				return -1;
			}
			pr_debug("ghost: Removed %s on id %#x ino %u\n",
				 path, ui->ue->id, ui->ue->ino);
		}
	}

	return 0;
}

static int bind_unix_sk(int sk, struct unix_sk_info *ui, bool notify)
{
	struct sockaddr_un addr;
	int cwd_fd = -1, root_fd = -1, ns_fd = -1;
	int ret, exit_code = -1;

	if (ui->ue->name.len == 0)
		return 0;

	if ((ui->ue->type == SOCK_STREAM || ui->ue->type == SOCK_SEQPACKET) &&
	    (ui->ue->state == TCP_ESTABLISHED)) {
		/*
		 * FIXME this can be done, but for doing this properly we
		 * need to bind socket to its name, then rename one to
		 * some temporary unique one and after all the sockets are
		 * restored we should walk those temp names and rename
		 * some of them back to real ones.
		 */
		return 0;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(&addr.sun_path, ui->name, ui->ue->name.len);

	if (ui->name[0] && prep_unix_sk_cwd(ui, &cwd_fd, &root_fd, &ns_fd))
		return -1;

	/*
	 * Order binding for sake of ghost sockets. We might rename
	 * existing socket to some temp name, bind ghost, delete it,
	 * and finally move the former back, thus while we're doing
	 * this stuff we should not be interrupted by connection
	 * from another sockets.
	 *
	 * FIXME: Probably wort make it per address rather for
	 * optimization sake.
	 */
	mutex_lock(mutex_ghost);

	if (ui->flags & USK_GHOST_FDSTORE) {
		pr_debug("ghost: bind id %#x ino %u addr %s\n",
			 ui->ue->id, ui->ue->ino, ui->name);
		ret = bind_on_deleted(sk, ui);
		if (ret)
			errno = -ret;
	} else {
		pr_debug("bind id %#x ino %u addr %s\n",
			 ui->ue->id, ui->ue->ino, ui->name);
		ret = bind(sk, (struct sockaddr *)&addr,
			   sizeof(addr.sun_family) + ui->ue->name.len);
		if (ret == 0 && restore_file_perms(ui))
			goto done;
	}
	if (ret < 0) {
		pr_perror("Can't bind id %#x ino %u addr %s",
			  ui->ue->id, ui->ue->ino, ui->name);
		goto done;
	}

	if (notify && ui->ue->state != TCP_LISTEN)
		ui->bound = true;

	exit_code = 0;
done:
	revert_unix_sk_cwd(ui, &cwd_fd, &root_fd, &ns_fd);
	mutex_unlock(mutex_ghost);
	return exit_code;
}

static int post_open_interconnected_master(struct unix_sk_info *ui)
{
	struct fdinfo_list_entry *fle, *fle_peer;
	struct unix_sk_info *peer = ui->peer;

	fle = file_master(&ui->d);
	fle_peer = file_master(&peer->d);
	BUG_ON(fle->task != fle_peer->task); /* See interconnected_pair() */

	if (chk_restored_scms(ui) || chk_restored_scms(peer))
		return 0;

	if (restore_unix_queue(fle->fe->fd, ui->ue->opts, peer))
		return -1;

	if (restore_unix_queue(fle_peer->fe->fd, peer->ue->opts, ui))
		return -1;

	if (restore_sk_common(fle->fe->fd, ui))
		return -1;

	if (restore_sk_common(fle_peer->fe->fd, peer))
		return -1;

	return 0;
}

static void pr_info_opening(const char *prefix, struct unix_sk_info *ui, struct fdinfo_list_entry *fle)
{
	pr_info("Opening %s (stage %d id %#x ino %u peer %u)\n",
		prefix, fle->stage, ui->ue->id, ui->ue->ino, ui->ue->peer);
}

static int open_unixsk_pair_master(struct unix_sk_info *ui, int *new_fd)
{
	struct fdinfo_list_entry *fle, *fle_peer;
	struct unix_sk_info *peer = ui->peer;
	int sk[2], tmp;

	fle = file_master(&ui->d);
	pr_info_opening("master", ui, fle);
	if (fle->stage == FLE_OPEN)
		return post_open_interconnected_master(ui);

	fle_peer = file_master(&peer->d);

	BUG_ON(fle->task != fle_peer->task); /* See interconnected_pair() */

	if (set_netns(ui->ue->ns_id))
		return -1;

	if (socketpair(PF_UNIX, ui->ue->type, 0, sk) < 0) {
		pr_perror("Can't make socketpair");
		return -1;
	}

	if (sk[0] == fle_peer->fe->fd) {
		/*
		 * Below setup_and_serve_out() will reuse this fd,
		 * so this dups it in something else.
		 */
		tmp = dup(sk[0]);
		if (tmp < 0) {
			pr_perror("Can't dup()");
			return -1;
		}
		close(sk[0]);
		sk[0] = tmp;
	}

	if (setup_and_serve_out(fle_peer, sk[1])) {
		pr_err("Can't send pair slave\n");
		return -1;
	}
	sk[1] = fle_peer->fe->fd;

	if (bind_unix_sk(sk[0], ui, true))
		return -1;

	if (bind_unix_sk(sk[1], peer, true))
		return -1;

	*new_fd = sk[0];
	return 1;
}

static int open_unixsk_pair_slave(struct unix_sk_info *ui, int *new_fd)
{
	struct fdinfo_list_entry *fle_peer;

	fle_peer = file_master(&ui->peer->d);
	pr_info_opening("slave", ui, fle_peer);
	/*
	 * All the work is made in master. Slave just says it's restored
	 * after it sees the master is restored.
	 */
	return (fle_peer->stage != FLE_RESTORED);
}

/*
 * When sks[0]'s fle requires to create socketpair, and sks[1] is also
 * somebody's fle, this makes file engine to make note the second_end
 * is also open.
 */
static int setup_second_end(int *sks, struct fdinfo_list_entry *second_end)
{
	int ret;

	if (sks[0] == second_end->fe->fd) {
		/*
		 * Below setup_and_serve_out() will reuse this fd,
		 * so this dups it in something else.
		 */
		ret = dup(sks[0]);
		if (ret < 0) {
			pr_perror("Can't dup()");
			return -1;
		}
		close(sks[0]);
		sks[0] = ret;
	}

	if (setup_and_serve_out(second_end, sks[1])) {
		pr_err("Can't send pair slave\n");
		return -1;
	}
	return 0;
}

static int break_connected(struct unix_sk_info *ui, int sk)
{
	if (ui->ue->type == SOCK_DGRAM) {
		struct sockaddr_un addr = { .sun_family = AF_UNSPEC };
		pr_debug("Break connected id %#x ino %d\n",
			 ui->ue->id, ui->ue->ino);
		/*
		 * socketpair() assigns sks[1] as a peer of sks[0]
		 * (and vice versa). But in this case (not zero peer)
		 * it's impossible for other sockets to connect
		 * to sks[0] (see unix_dgram_connect()->unix_may_send()).
		 * The below is hack: we use that connect with AF_UNSPEC
		 * clears socket's peer.
		 * Note, that connect hack flushes receive queue,
		 * so restore_unix_queue() must be after it.
		 */
		if (connect(sk, (struct sockaddr *)&addr, sizeof(addr.sun_family))) {
			pr_perror("Can't clear socket id %#x peer", ui->ue->id);
			return -1;
		}
	}
	return 0;
}

static int make_socket(struct unix_sk_info *ui, int sks[2], bool pair, bool disjoin_master)
{
	if (unlikely(ui->flags & USK_EARLY_BIND)) {
		sks[0] = fdstore_get(ui->early_bind_id[0]);
		sks[1] = fdstore_get(ui->early_bind_id[1]);
		pr_debug("Fetching early-binded socket pair id %#x ino %d\n",
			 ui->ue->id, ui->ue->ino);
		if (sks[0] < 0 || sks[1] < 0) {
			pr_err("Can't fetch id %#x socketpair from the store\n",
			       ui->ue->id);
			return -1;
		}
	} else {
		int ret;

		sks[0] = sks[1] = -1;
		if (!pair) {
			pr_debug("Create socket id %#x ino %d\n",
				 ui->ue->id, ui->ue->ino);
			ret = socket(PF_UNIX, ui->ue->type, 0);
			sks[0] = ret;
		} else {
			pr_debug("Create socket pair id %#x ino %d\n",
				 ui->ue->id, ui->ue->ino);
			ret = socketpair(PF_UNIX, ui->ue->type, 0, sks);
		}

		if (ret < 0) {
			pr_perror("Can't create %s id %#x\n",
				  pair ? "socketpair" : "socket",
				  ui->ue->id);
			return -1;
		}
	}

	if (disjoin_master)
		return break_connected(ui, sks[0]);

	return 0;
}

static int open_unixsk_standalone(struct unix_sk_info *ui, int *new_fd)
{
	struct unix_sk_info *queuer = ui->queuer;
	struct unix_sk_info *peer = ui->peer;
	struct fdinfo_list_entry *fle, *fle_peer;
	int sks[2];

	fle = file_master(&ui->d);
	pr_info_opening("standalone", ui, fle);

	/*
	 * If we're about to connect to the peer which
	 * has been bound to removed address we should
	 * wait until it is processed and put into fdstore
	 * engine, later we will use the engine to connect
	 * into it in a special way.
	 */
	if (peer && (peer->flags & USK_GHOST_FDSTORE)) {
		fle_peer = file_master(&peer->d);
		if (fle_peer->stage < FLE_OPEN) {
			return 1;
		}
	}

	if (fle->stage == FLE_OPEN)
		return post_open_standalone(&ui->d, fle->fe->fd);

	/* Fake socket will be restored by its peer */
	if (!(ui->ue->uflags & UNIX_UFLAGS__EXTERN) && ui->ue->ino == FAKE_INO)
		return 1;

	if (set_netns(ui->ue->ns_id))
		return -1;

	/*
	 * Check if this socket was connected to criu service.
	 * If so, put response, that dumping and restoring
	 * was successful.
	 */
	if (ui->ue->uflags & UNIX_UFLAGS__SERVICE) {
		if (make_socket(ui, sks, true, false))
			return -1;

		if (send_criu_dump_resp(sks[1], true, true) == -1)
			return -1;

		close(sks[1]);
	} else if (ui->ue->state == TCP_ESTABLISHED && queuer && queuer->ue->ino == FAKE_INO) {
		if (ui->ue->type != SOCK_STREAM) {
			pr_err("Non-stream socket %u in established state\n",
					ui->ue->ino);
			return -1;
		}

		if (ui->ue->shutdown != SK_SHUTDOWN__BOTH) {
			pr_err("Wrong shutdown/peer state for %u\n",
					ui->ue->ino);
			return -1;
		}

		if (make_socket(ui, sks, true, false))
			return -1;

		if (setup_second_end(sks, file_master(&queuer->d)))
			return -1;
	} else if (ui->ue->type == SOCK_DGRAM && queuer && queuer->ue->ino == FAKE_INO) {
		if (make_socket(ui, sks, true, true))
			return -1;

		if (setup_second_end(sks, file_master(&queuer->d)))
			return -1;
	} else {
		if (ui->ue->uflags & UNIX_UFLAGS__CALLBACK) {
			sks[0] = run_plugins(RESTORE_UNIX_SK, ui->ue->ino);
			if (sks[0] >= 0)
				goto out;
		}

		/*
		 * Connect to external sockets requires
		 * special option to be passed.
		 */
		if (ui->peer && (ui->peer->ue->uflags & UNIX_UFLAGS__EXTERN) &&
				!(opts.ext_unix_sk)) {
			pr_err("External socket found in image. "
					"Consider using the --" USK_EXT_PARAM
					" option to allow restoring it.\n");
			return -1;
		}

		pr_debug("socketpair instead of plain socket\n");
		if (make_socket(ui, sks, false, true))
			return -1;
		close_safe(&sks[1]);
	}

	if (!(ui->ue->uflags & (UNIX_UFLAGS__BINDMOUNT | UNIX_UFLAGS__VZ_OVERMOUNTED))) {
		if (bind_unix_sk(sks[0], ui, true)) {
			close(sks[0]);
			return -1;
		}
	} else {
		ui->bound = true;
	}

	if (ui->ue->state == TCP_LISTEN) {
		pr_info("\tPutting %u into listen state\n", ui->ue->ino);
		if (listen(sks[0], ui->ue->backlog) < 0) {
			pr_perror("Can't make usk listen");
			close(sks[0]);
			return -1;
		}
		ui->listen = 1;
	}

	if (ui->peer || ui->queuer) {
		/*
		 * 1)We need to connect() to the peer, but the
		 * guy might have not bind()-ed himself, so
		 * let's postpone this.
		 * 2)Queuer won't be able to connect, if we do
		 * shutdown, so postpone it.
		 */
		*new_fd = sks[0];
		return 1;
	}

out:
	if (restore_sk_common(sks[0], ui))
		return -1;

	*new_fd = sks[0];
	return 0;
}

static int open_unix_sk(struct file_desc *d, int *new_fd)
{
	struct unix_sk_info *ui;
	int ret;

	ui = container_of(d, struct unix_sk_info, d);

	if (inherited_fd(d, new_fd)) {
		ui->ue->uflags |= UNIX_UFLAGS__INHERIT;
		ret = *new_fd >= 0 ? 0 : -1;
	} else if (ui->flags & USK_PAIR_MASTER)
		ret = open_unixsk_pair_master(ui, new_fd);
	else if (ui->flags & USK_PAIR_SLAVE)
		ret = open_unixsk_pair_slave(ui, new_fd);
	else
		ret = open_unixsk_standalone(ui, new_fd);

	return ret;
}

static char *socket_d_name(struct file_desc *d, char *buf, size_t s)
{
	struct unix_sk_info *ui;

	ui = container_of(d, struct unix_sk_info, d);

	if (snprintf(buf, s, "socket:[%u]", ui->ue->ino) >= s) {
		pr_err("Not enough room for unixsk %d identifier string\n",
				ui->ue->ino);
		return NULL;
	}

	return buf;
}

static int on_stage_change(struct file_desc *d, u8 fle_stage)
{
	struct unix_sk_info *ui;

	/*
	 * Our aim:
	 * caught moment when *peer* socket is in fle->stage >= FLE_OPEN
	 * and then wake up all tasks that holds corresponding sockets
	 * that connected to peer socket.
	 */
	ui = container_of(d, struct unix_sk_info, d);

	/*
	 * 1. If socket has peer => this socket is not a peer
	 * 2. If socket has empty name => it was not in listening/bounded state
	 * 3. If socket is SOCK_STREAM and state is TCP_ESTABLISHED
	 * one of the factors means that socket is not a peer socket => let's skip it
	 */
	if (ui->peer || ui->ue->name.len == 0 ||
		(ui->ue->type == SOCK_STREAM && ui->ue->state == TCP_ESTABLISHED))
		return 0;

	/*
	 * So, at the moment, socket *must* be in LISTEN or BOUNDED state.
	 * We inform about possible bug, but not fail restore stage.
	 */
	if (!ui->listen && !ui->bound) {
		pr_err("BUG socket id %#x ino %u peer %u must be in LISTEN or BOUNDED state\n",
			   ui->ue->id, ui->ue->ino, ui->ue->peer);
		return 0;
	}

	wake_connected_sockets(ui);

	return 0;
}

static struct file_desc_ops unix_desc_ops = {
	.type = FD_TYPES__UNIXSK,
	.open = open_unix_sk,
	.name = socket_d_name,
	.on_stage_change = on_stage_change,
};

static void print_sk_full_path(char *buf, size_t bufsize, struct unix_sk_info *ui)
{
	int len;

	len = snprintf(buf, bufsize, "%s%s%s",
		       ui->name_dir ? ui->name_dir : "",
		       ui->name_dir ? "/" : "",
		       ui->name);
	if (len >= bufsize) {
		pr_err("overflow path for socket id %#x ino %u (name %s dir %s)",
		       ui->ue->id, ui->ue->ino,
		       ui->name ? (ui->name[0] ? ui->name : &ui->name[1]) : "-",
		       ui->name_dir ? ui->name_dir : "-");
		BUG_ON(1);
	}
}

/*
 * We need to skip unlinking socket when it's early binded
 * socket (because we create them in unix_early_bind).
 * The problem here is that connection sockets has the same
 * addr as listening socket, so, checking USK_EARLY_BIND flag
 * is not sufficient, we should also check that name is not
 * used in *any* early-binded socket.
 *
 * Analogical problem exists for ghost sockets. Imagine
 * we have ghost socket with some addr and early-binded
 * socket with the same addr -> unix_prepare_root_shared()
 * function is called *after* unix_early_bind()
 * and also calls unlink_sk().
 */
static bool addr_prepared_for_early_bind(struct unix_sk_info *ui)
{
	char path[PATH_MAX], tmp_path[PATH_MAX];
	struct unix_sk_info *tmp;

	if (ui->flags & USK_EARLY_BIND)
		return true;

	print_sk_full_path(path, sizeof(path), ui);

	list_for_each_entry(tmp, &unix_mnt_sockets, early_list) {
		char *rel;

		if (sk_to_mnt_id(ui) != sk_to_mnt_id(tmp))
			continue;

		print_sk_full_path(tmp_path, sizeof(tmp_path), tmp);
		/*
		 * compare tmp_path and path using get_relative_path()
		 * we just need to check that return value is empty
		 * string
		 */
		rel = get_relative_path(tmp_path, path);
		if (rel && !rel[0])
			return true;
	}

	list_for_each_entry(tmp, &unix_overmounted_sockets, early_list) {
		char *rel;

		if (sk_to_mnt_id(ui) != sk_to_mnt_id(tmp))
			continue;

		print_sk_full_path(tmp_path, sizeof(tmp_path), tmp);

		rel = get_relative_path(tmp_path, path);
		if (rel && !rel[0])
			return true;
	}


	return false;
}

/*
 * Make FS clean from sockets we're about to
 * restore. See for how we bind them for details
 */
static int unlink_sk(struct unix_sk_info *ui)
{
	int ret = 0, cwd_fd = -1, root_fd = -1, ns_fd = -1;
	struct stat statbuf;

	if (!ui->name || ui->name[0] == '\0' ||
	    addr_prepared_for_early_bind(ui) ||
	    (ui->ue->uflags & UNIX_UFLAGS__EXTERN))
		return 0;

	if (prep_unix_sk_cwd(ui, &cwd_fd, &root_fd, NULL))
		return -1;

	ret = stat(ui->name, &statbuf);
	if (!ret) {
		/* Do not cleanup non-socket files */
		if (!S_ISSOCK(statbuf.st_mode)) {
			ret = 0;
			goto out;
		}
	}

	ret = unlinkat(AT_FDCWD, ui->name, 0) ? -1 : 0;
	if (ret < 0 && errno != ENOENT) {
		pr_warn("Can't unlink socket %u peer %u (name %s dir %s)\n",
			ui->ue->ino, ui->ue->peer,
			ui->name ? (ui->name[0] ? ui->name : &ui->name[1]) : "-",
			ui->name_dir ? ui->name_dir : "-");
		ret = -errno;
		goto out;
	} else if (ret == 0) {
		pr_debug("Unlinked socket %u peer %u (name %s dir %s)\n",
			 ui->ue->ino, ui->ue->peer,
			 ui->name ? (ui->name[0] ? ui->name : &ui->name[1]) : "-",
			 ui->name_dir ? ui->name_dir : "-");
	}
out:
	revert_unix_sk_cwd(ui, &cwd_fd, &root_fd, &ns_fd);
	return ret;
}

static void try_resolve_unix_peer(struct unix_sk_info *ui);
static int fixup_unix_peer(struct unix_sk_info *ui);

static int post_prepare_unix_sk(struct pprep_head *ph)
{
	struct unix_sk_info *ui;

	ui = container_of(ph, struct unix_sk_info, peer_resolve);
	if (ui->ue->peer && fixup_unix_peer(ui))
		return -1;
	unlink_sk(ui);
	return 0;
}

/*
 * FIXME: Instead of hardcoding the value
 * we should improve dump and carry the settings
 * inside netns image (see prepare_namespace).
 */
static int setup_sysctl_cb(struct pprep_head *ph)
{
	uint32_t value = 0, prev;

	struct sysctl_req req[] = {
		{
			.name	= "net/unix/max_dgram_qlen",
			.arg	= &value,
			.type	= CTL_U32,
		},
	};

	if (sysctl_op(req, ARRAY_SIZE(req), CTL_READ, CLONE_NEWNET))
		pr_warn("Can't fetch %s value, use default\n", req[0].name);

	/*
	 * The limit from systemd source code.
	 */
	prev = value, value = 512;
	pr_debug("Adjust %s: %u -> %u\n", req[0].name, prev, value);

	if (sysctl_op(req, ARRAY_SIZE(req), CTL_WRITE, CLONE_NEWNET))
		pr_warn("Can't adjust %s value, use default\n", req[0].name);

	return 0;
}

static MAKE_PPREP_HEAD(setup_sysctl);

static int init_unix_sk_info(struct unix_sk_info *ui, UnixSkEntry *ue)
{
	ui->ue = ue;
	if (ue->name.len) {
		if (ue->name.len > UNIX_PATH_MAX) {
			pr_err("Bad unix name len %d\n", (int)ue->name.len);
			return -1;
		}

		ui->name = (void *)ue->name.data;
	} else
		ui->name = NULL;
	ui->name_dir = (void *)ue->name_dir;

	ui->flags		= 0;
	ui->early_bind_id[0]	= -1;
	ui->early_bind_id[1]	= -1;
	ui->ghost_id		= -1;
	ui->ghost_dir_pos	= 0;
	ui->peer		= NULL;
	ui->queuer		= NULL;
	ui->bound		= 0;
	ui->listen		= 0;
	ui->is_connected	= 0;
	ui->peer_queue_restored = 0;

	memzero(&ui->peer_resolve, sizeof(ui->peer_resolve));
	memzero(&ui->d, sizeof(ui->d));

	INIT_LIST_HEAD(&ui->list);
	INIT_LIST_HEAD(&ui->early_list);
	INIT_LIST_HEAD(&ui->connected);
	INIT_LIST_HEAD(&ui->node);
	INIT_LIST_HEAD(&ui->scm_fles);
	INIT_LIST_HEAD(&ui->ghost_node);
	INIT_HLIST_NODE(&ui->hash);

	return 0;
}

int unix_prepare_shared(void)
{
	mutex_ghost = shmalloc(sizeof(*mutex_ghost));
	if (!mutex_ghost) {
		pr_err("ghost: Can't allocate mutex\n");
		return -ENOMEM;
	}
	mutex_init(mutex_ghost);
	return 0;
}

int unix_prepare_root_shared(void)
{
	struct unix_sk_info *ui;

	pr_debug("ghost: Resolving addresses\n");

	list_for_each_entry(ui, &unix_ghost_addr, ghost_node) {
		char tp_name[32];
		char st_name[32];

		pr_debug("ghost: id %#x type %s state %s ino %u peer %u address %s\n",
			 ui->ue->id, __socket_type_name(ui->ue->type, tp_name),
			 __tcp_state_name(ui->ue->state, st_name),
			 ui->ue->ino, ui->peer ? ui->peer->ue->ino : 0,
			 ui->name);

		/*
		 * Drop any existing trash on the FS and mark the
		 * peer as a ghost one, so we will put it into
		 * fdstore to be able to connect into it even
		 * when the address is removed from the FS.
		 */
		unlink_sk(ui);
		ui->flags |= USK_GHOST_FDSTORE;
	}

	return 0;
}

static int collect_one_unixsk(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct unix_sk_info *ui = o;
	char *uname, *prefix = "";
	int ulen;

	if (init_unix_sk_info(ui, pb_msg(base, UnixSkEntry)))
		return -1;

	add_post_prepare_cb_once(&setup_sysctl);

	uname = ui->name;
	ulen = ui->ue->name.len;
	if (ulen > 0 && uname[0] == 0) {
		prefix = "@";
		uname++;
		ulen--;
		if (memrchr(uname, 0, ulen)) {
			/* replace zero characters */
			char *s = alloca(ulen + 1);
			int i;

			for (i = 0; i < ulen; i++)
				s[i] = uname[i] ? : '@';
			uname = s;
		}
	} else if (ulen == 0) {
		ulen = 1;
		uname = "-";
	}

	pr_info(" `- Got id %#x ino %u type %s state %s peer %u (name %s%.*s dir %s)\n",
		ui->ue->id, ui->ue->ino, ___socket_type_name(ui->ue->type),
		___tcp_state_name(ui->ue->state), ui->ue->peer, prefix, ulen,
		uname, ui->name_dir ? ui->name_dir : "-");

	if (ui->ue->peer || ui->name) {
		if (ui->ue->peer)
			try_resolve_unix_peer(ui);

		ui->peer_resolve.actor = post_prepare_unix_sk;
		add_post_prepare_cb(&ui->peer_resolve);
	}

	if (ui->ue->deleted) {
		if (!ui->name || !ui->ue->name.len || !ui->name[0]) {
			pr_err("No name present, ino %u\n", ui->ue->ino);
			return -1;
		}

		list_add_tail(&ui->ghost_node, &unix_ghost_addr);
	}

	hlist_add_head(&ui->hash, &sk_info_hash[ui->ue->ino % SK_INFO_HASH_SIZE]);

	if (ui->ue->uflags & UNIX_UFLAGS__VZ_OVERMOUNTED && !use_mounts_v2()) {
		pr_err("Unable to restore overmounted unix socket without mounts-v2\n");
		return -1;
	}

	if (ui->ue->uflags & UNIX_UFLAGS__BINDMOUNT) {
		/*
		 * Make sure it is supported socket!
		 * DGRAM, STREAM, SEQPACKET sockets supported now
		 */
		if ((ui->ue->uflags & ~(UNIX_UFLAGS__BINDMOUNT | UNIX_UFLAGS__VZ_OVERMOUNTED)) ||
		    !sk_bindmount_supported(ui->ue->type, ui->ue->state)) {
			pr_err("bindmount: Unsupported socket id %#x "
			       "(got %x:%s:%s)\n",
			       ui->ue->id, ui->ue->uflags,
			       ___socket_type_name(ui->ue->type),
			       ___tcp_state_name(ui->ue->state));
			return -1;
		}
		list_add_tail(&ui->early_list, &unix_mnt_sockets);
	} else if (ui->ue->uflags & UNIX_UFLAGS__VZ_OVERMOUNTED) {
		list_add_tail(&ui->early_list, &unix_overmounted_sockets);
	}

	list_add_tail(&ui->list, &unix_sockets);
	return file_desc_add(&ui->d, ui->ue->id, &unix_desc_ops);
}

struct collect_image_info unix_sk_cinfo = {
	.fd_type	= CR_FD_UNIXSK,
	.pb_type	= PB_UNIX_SK,
	.priv_size	= sizeof(struct unix_sk_info),
	.collect	= collect_one_unixsk,
	.flags		= COLLECT_SHARED,
};

/*
 * Helper directory where we would construct fake directory structure,
 * to make "plain" mount look like a "mount in tree". (Mounts-v2 only)
 */
static int print_sk_root(struct unix_sk_info *ui, char *buf, int bs)
{
	return snprintf(buf, bs, "%s/sk-unix-%010d", mnt_roots, ui->ue->id);
}

static int sk_has_bindmount(struct unix_sk_info *ui, struct mount_info *mi)
{
	int i;
	for (i = 0; i < ui->ue->n_vz_bind_mnt_ids; i++) {
		if (ui->ue->vz_bind_mnt_ids[i] == mi->mnt_id)
			return 1;
	}

	/* compatibility with old images */
	if (ui->ue->n_vz_bind_mnt_ids == 0 && ui->ue->mnt_id == mi->mnt_id)
		return 1;

	return 0;
}

void unix_note_bindmounts(struct list_head *head)
{
	struct unix_sk_info *ui;
	struct mount_info *mi;
	int i;

	list_for_each_entry(ui, &unix_mnt_sockets, early_list) {
		for (i = 0; i < ui->ue->n_vz_bind_mnt_ids; i++) {
			mi = lookup_mnt_id(ui->ue->vz_bind_mnt_ids[i]);
			BUG_ON(!mi);

			list_add(&mi->mnt_usk_bind, head);
		}

		/*
		 * When n_vz_bind_mount_ids is 0 for UNIX_UFLAGS__BINDMOUNT socket
		 * ui->ue->mnt_id contains bindmount mnt_id
		 */
		if (ui->ue->n_vz_bind_mnt_ids == 0) {
			mi = lookup_mnt_id(ui->ue->mnt_id);
			BUG_ON(!mi);

			list_add(&mi->mnt_usk_bind, head);

			continue;
		}
	}
}

static int unix_early_bind(struct unix_sk_info *ui)
{
	int prev_cwd_fd = -1, prev_root_fd = -1;
	int ret = -1, sks[2] = { -1, -1 };
	char path[PATH_MAX], plain_mount_tmp[PATH_MAX];
	struct mount_info *sk_mi = NULL;
	char type_name[64], state_name[64];

	if (ui->early_bind_id[0] > 0 || ui->early_bind_id[1] > 0)
		return 0;

	pr_info("early bind: id %#x ino %d type %s state %s (queuer id %#x ino %d) peer %d (name %.*s dir %s)\n",
		ui->ue->id, ui->ue->ino,
		__socket_type_name(ui->ue->type, type_name),
		__tcp_state_name(ui->ue->state, state_name),
		ui->queuer ? ui->queuer->ue->id : -1,
		ui->queuer ? ui->queuer->ue->ino : -1,
		ui->ue->peer, (int)ui->ue->name.len,
		ui->ue->name.data, ui->name_dir ? ui->name_dir : "-");

	/*
	 * Mark it as early binded so when need to use we
	 * would fetch it from the fdstore, and point
	 * out that no need to cwd change since we
	 * already opened it in proper place.
	 */
	ui->flags |= USK_EARLY_BIND | USK_NOCWD;

	BUG_ON(!ui->ue->has_mnt_id);
	sk_mi = lookup_mnt_id(sk_to_mnt_id(ui));
	if (!sk_mi) {
		pr_err("Unable to locate mnt_id %d for socket %d\n", sk_to_mnt_id(ui), ui->ue->id);
		return -1;
	}

	/*
	 * This is unix_early_bind() part for mounts-v2 engine.
	 * If you want to get some extra details, please also check and read
	 * test/zdtm/static/bind-mount-unix.c testcases.
	 *
	 * General idea is to reconstruct fake mount namespace root
	 * and move plain mounted mount to this fake tree, then
	 * chroot(fake_mntns_root(=path)) -> chdir(ui->name_dir)
	 * -> bind socket
	 */
	if (use_mounts_v2()) {
		int mntns_fd;

		if (!sk_mi->rmi->mounted) {
			pr_err("early bind: The mount %d is not mounted for unix sk id %#x\n",
			       sk_mi->mnt_id, ui->ue->id);
			return -1;
		}

		mntns_fd = fdstore_get(sk_mi->nsid->mnt.nsfd_id);
		if (mntns_fd < 0) {
			pr_perror("Can't get mntns_fd for nsid %d", sk_mi->nsid->id);
			return -1;
		}

		if (setns(mntns_fd, CLONE_NEWNS) < 0) {
			pr_perror("Can't restore mntns for nsid %d", sk_mi->nsid->id);
			close(mntns_fd);
			return -1;
		}
		close(mntns_fd);

		print_sk_root(ui, path, sizeof(path));
		if (mkdir(path, 0600)) {
			pr_perror("early bind: Unable to create fake nsroot %s", path);
			return -1;
		}

		if (snprintf(plain_mount_tmp, sizeof(plain_mount_tmp), "%s/%s",
			     path, sk_mi->ns_mountpoint) >=
		    sizeof(plain_mount_tmp)) {
			pr_perror("early bind: Unable to create fake nsroot %s", path);
			return -1;
		}

		if (mkdirpat(AT_FDCWD, plain_mount_tmp, 0755)) {
			pr_perror("early bind: Unable to create %s", plain_mount_tmp);
			return -1;
		}

		pr_debug("Move mount %d from %s to %s\n", sk_mi->mnt_id,
			sk_mi->plain_mountpoint, plain_mount_tmp);
		if (mount(sk_mi->plain_mountpoint, plain_mount_tmp, NULL, MS_MOVE, NULL)) {
			pr_perror("early bind: Failed to move mount %d from %s to %s",
				  sk_mi->mnt_id, sk_mi->plain_mountpoint, plain_mount_tmp);
			return -1;
		}
	} else {
		if (rst_get_mnt_root(sk_mi->mnt_id, path, sizeof(path)) < 0) {
			pr_err("early bind: Can't setup mnt_root for %s\n", sk_mi->ns_mountpoint);
			return -1;
		}
	}

	prev_cwd_fd = open(".", O_RDONLY);
	if (prev_cwd_fd < 0) {
		pr_perror("early bind: Can't save current cwd");
		goto out;
	}

	prev_root_fd = open("/", O_RDONLY);
	if (prev_root_fd < 0) {
		pr_perror("early bind: Can't save current root");
		goto out;
	}

	if (chdir(path)) {
		pr_perror("early bind: Can't chdir to %s", path);
		goto out;
	} else if (chroot(".")) {
		pr_perror("early bind: Can't chroot");
		goto out;
	}

	if (ui->name_dir && chdir(ui->name_dir)) {
		pr_perror("early bind: Can't chdir to %s", ui->name_dir);
		goto out;
	}

	if (set_netns(ui->ue->ns_id)) {
		pr_err("Can't set_netns(%u)\n", ui->ue->ns_id);
		goto out;
	}

	/*
	 * Preallocate and bind sockets here and later the
	 * open_unixsk_standalone helper will simply fetch
	 * him from fdstore
	 * Note: TCP_LISTEN socket does not need a peer because
	 * it will never have one - new sockets with pairs are
	 * generated via accept() while this stays alone
	 */

	if (ui->ue->state == TCP_LISTEN) {
		sks[0] = socket(PF_UNIX, ui->ue->type, 0);
		if (sks[0] < 0) {
			pr_perror("early bind: Can't create socket id %#x",
				  ui->ue->id);
			goto out;
		}
	} else {
		if (socketpair(PF_UNIX, ui->ue->type, 0, sks)) {
			pr_perror("early bind: Can't create socketpair id %#x",
				  ui->ue->id);
			goto out;
		}
	}

	/*
	 * We should cleanup FS from leftover socket files.
	 * See also unlink_sk() function.
	 * For mntv2 we already cleaned everything via early_cleanup()
	 */
	if (!use_mounts_v2()) {
		ret = unlinkat(AT_FDCWD, ui->name, 0) ? -1 : 0;
		if (ret < 0 && errno != ENOENT) {
			pr_perror("Can't unlink socket %u peer %u (name %s dir %s)",
				ui->ue->ino, ui->ue->peer,
				ui->name ? (ui->name[0] ? ui->name : &ui->name[1]) : "-",
				ui->name_dir ? ui->name_dir : "-");
			ret = -1;
			goto out;
		} else if (ret == 0) {
			pr_debug("Unlinked socket %u peer %u (name %s dir %s)\n",
				ui->ue->ino, ui->ue->peer,
				ui->name ? (ui->name[0] ? ui->name : &ui->name[1]) : "-",
				ui->name_dir ? ui->name_dir : "-");
		}
	}

	if (bind_unix_sk(sks[0], ui, false))
		goto out;

	ui->early_bind_id[0] = fdstore_add(sks[0]);
	if (ui->ue->state == TCP_LISTEN)
		ui->early_bind_id[1] = -1;
	else
		ui->early_bind_id[1] = fdstore_add(sks[1]);

	if (ui->early_bind_id[0] < 0 || (ui->ue->state != TCP_LISTEN && ui->early_bind_id[1] < 0)) {
		pr_err("early bind: Can't add socketpair id %#x into fdstore\n",
			ui->ue->id);
		goto out;
	}

	if (ui->ue->uflags & UNIX_UFLAGS__VZ_OVERMOUNTED && !(ui->flags & USK_GHOST_FDSTORE)) {
		keep_deleted(ui);
		ui->flags |= USK_GHOST_FDSTORE;
	}

	if (fchdir(prev_root_fd)) {
		pr_perror("early bind: Can't revert root directory");
		goto out;
	} else if (chroot(".")) {
		pr_perror("early bind: Can't revert chroot ");
		goto out;
	} else if (fchdir(prev_cwd_fd)) {
		pr_perror("early bind: Can't revert working dir");
		goto out;
	}

	if (use_mounts_v2()) {
		pr_debug("early bind: Move mount %d back from %s to %s\n", sk_mi->mnt_id,
			plain_mount_tmp, sk_mi->plain_mountpoint);
		if (mount(plain_mount_tmp, sk_mi->plain_mountpoint, NULL, MS_MOVE, NULL)) {
			pr_perror("early bind: Failed to move mount %d back from %s to %s",
				  sk_mi->mnt_id, plain_mount_tmp, sk_mi->plain_mountpoint);
			goto out;
		}
	}

	/*
	 * Once we are pre-created and bounded, clear
	 * the USK_NOCWD flag so other sockets migh connect
	 * to us via relative name.
	 */
	ui->flags &= ~USK_NOCWD;
	ret = 0;
out:
	close_safe(&prev_cwd_fd);
	close_safe(&prev_root_fd);
	close_safe(&sks[0]);
	close_safe(&sks[1]);

	if (ret == 0)
		pr_debug("early bind: Standalone socket moved into fdstore (id %#x ino %d peer %d)\n",
			 ui->ue->id, ui->ue->ino, ui->ue->peer);

	return ret;
}

int mountv1_unix_prepare_bindmount(struct mount_info *mi)
{
	struct unix_sk_info *ui;

	list_for_each_entry(ui, &unix_mnt_sockets, early_list)
		if (sk_has_bindmount(ui, mi))
			break;

	if (&ui->early_list == &unix_mnt_sockets)
		return 0;

	return unix_early_bind(ui);
}

static int early_unlink_sk(struct unix_sk_info *ui)
{
	char ns_abspath[PATH_MAX], abspath[PATH_MAX], *rpath;
	struct mount_info *mi;
	struct stat st;

	if (ui->ue->uflags & UNIX_UFLAGS__EXTERN || (ui->ue->has_deleted && ui->ue->deleted))
		return 0;

	print_sk_full_path(ns_abspath, PATH_MAX, ui);

	BUG_ON(!ui->ue->has_mnt_id);
	mi = lookup_mnt_id(sk_to_mnt_id(ui));
	if (!mi) {
		pr_err("Unable to locate mnt_id %d for socket %d\n", sk_to_mnt_id(ui), ui->ue->id);
		return -1;
	}

	rpath = get_relative_path(ns_abspath, mi->ns_mountpoint);
	if (!rpath) {
		pr_err("Unable to get rpath for (%s, %s)\n", ns_abspath, mi->ns_mountpoint);
		return -1;
	}

	snprintf(abspath, PATH_MAX, "%s/%s", service_mountpoint(mi), rpath);

	/*
	 * Several sockets may have the same name, so we may already cleaned it up
	 */
	if (lstat(abspath, &st))
		return 0;

	if (!S_ISSOCK(st.st_mode)) {
		pr_err("Inconsistent fs and criu image. Non-socket file in place of non-deleted socket\n");
		return -1;
	}

	if (unlink(abspath)) {
		pr_perror("Unable to unlink leftover socket");
		return -1;
	}

	return 0;
}

/*
 * Unlink all sockets we want to bind early
 * Actually we should unlink all sockets right here to not duplicate
 * unlink_sk(), but we still support mntv1 code which do not have
 * access to service mountnamespace
 */
static int early_cleanup(void)
{
	struct unix_sk_info *ui;

	list_for_each_entry(ui, &unix_mnt_sockets, early_list)
		if (early_unlink_sk(ui)) {
			pr_err("Unable to cleanup socket %d\n", ui->ue->id);
			return -1;
		}

	list_for_each_entry(ui, &unix_overmounted_sockets, early_list)
		if (early_unlink_sk(ui)) {
			pr_err("Unable to cleanup socket %d\n", ui->ue->id);
			return -1;
		}

	return 0;
}

int unix_do_early_binds(void)
{
	struct unix_sk_info *ui;
	int service_mntns_fd, ret = -1;

	if (early_cleanup())
		return -1;

	service_mntns_fd = open_proc(PROC_SELF, "ns/mnt");
	if (service_mntns_fd < 0)
		return -1;

	list_for_each_entry(ui, &unix_mnt_sockets, early_list)
		if (unix_early_bind(ui)) {
			pr_err("Unable to bind socket %d\n", ui->ue->id);
			goto out;
		}

	list_for_each_entry(ui, &unix_overmounted_sockets, early_list)
		if (unix_early_bind(ui)) {
			pr_err("Unable to bind socket %d\n", ui->ue->id);
			goto out;
		}

	ret = 0;
out:
	if (restore_ns(service_mntns_fd, &mnt_ns_desc))
		ret = -1;
	return ret;
}

static void set_peer(struct unix_sk_info *ui, struct unix_sk_info *peer)
{
	ui->peer = peer;
	list_add(&ui->node, &peer->connected);
	if (!peer->queuer)
		peer->queuer = ui;
}

static int add_fake_queuer(struct unix_sk_info *ui)
{
	struct unix_sk_info *peer;
	struct pstree_item *task;
	UnixSkEntry *peer_ue;
	SkOptsEntry *skopts;
	FownEntry *fown;

	if (ui->ue->ino == FAKE_INO)
		return 0;

	peer = xzalloc(sizeof(struct unix_sk_info) +
			sizeof(UnixSkEntry) +
			sizeof(SkOptsEntry) +
			sizeof(FownEntry));
	if (peer == NULL)
		return -1;

	peer_ue = (void *) peer + sizeof(struct unix_sk_info);
	skopts = (void *) peer_ue + sizeof(UnixSkEntry);
	fown = (void *) skopts + sizeof(SkOptsEntry);
	memcpy(skopts, ui->ue->opts, sizeof(SkOptsEntry));
	memcpy(fown, ui->ue->fown, sizeof(FownEntry));
	memcpy(peer_ue, ui->ue, sizeof(UnixSkEntry));
	peer_ue->opts = skopts;
	peer_ue->file_perms = NULL;
	peer_ue->fown = fown;
	peer_ue->name.len = 0;
	peer_ue->name_dir = NULL;

	if (init_unix_sk_info(peer, peer_ue))
		return -1;

	peer_ue->id = find_unused_file_desc_id();
	set_peer(peer, ui);

	/* Note, that this fake fdesc has no ino */
	peer->ue->ino = FAKE_INO;
	file_desc_add(&peer->d, peer_ue->id, &unix_desc_ops);
	list_del_init(&peer->d.fake_master_list);
	list_add(&peer->list, &unix_sockets);
	task = file_master(&ui->d)->task;

	return (get_fle_for_task(&peer->d, task, true) == NULL);
}

int add_fake_unix_queuers(void)
{
	struct unix_sk_info *ui;

	list_for_each_entry(ui, &unix_sockets, list) {
		if ((ui->ue->uflags & (UNIX_UFLAGS__EXTERN | UNIX_UFLAGS__CALLBACK)) || ui->queuer)
			continue;
		if (!(ui->ue->type == SOCK_STREAM && ui->ue->state == TCP_ESTABLISHED && !ui->peer) &&
		    !(ui->ue->type == SOCK_DGRAM  && !ui->peer))
			continue;
		if (add_fake_queuer(ui))
			return -1;
	}
	return 0;
}

/* This function is called from post prepare only */
static int interconnected_pair(struct unix_sk_info *ui, struct unix_sk_info *peer)
{
	struct fdinfo_list_entry *fle, *fle_peer;

	ui->flags |= USK_PAIR_MASTER;
	peer->flags |= USK_PAIR_SLAVE;

	fle = file_master(&ui->d);
	fle_peer = file_master(&peer->d);

	/*
	 * Since queue restore is delayed, every socket of the pair
	 * should have another end to send the queue packets.
	 * To fit that, we make the both file_master's to be owned
	 * by the only task.
	 * This function is called from run_post_prepare() and
	 * after add_fake_fds_masters(), so we must not add masters,
	 * which fle->task has no permissions to restore. But
	 * it has permissions on ui, so it has permissions on peer.
	 */
	if (fle->task != fle_peer->task &&
	    !get_fle_for_task(&peer->d, fle->task, true))
		return -1;

	return 0;
}

static int fixup_unix_peer(struct unix_sk_info *ui)
{
	struct unix_sk_info *peer = ui->peer;

	if (!peer) {
		pr_err("FATAL: Peer %u unresolved for %u\n",
				ui->ue->peer, ui->ue->ino);
		return -1;
	}

	if (peer != ui && peer->peer == ui &&
			!(ui->flags & (USK_PAIR_MASTER | USK_PAIR_SLAVE))) {
		pr_info("Connected %d -> %d (%d) flags %#x\n",
				ui->ue->ino, ui->ue->peer, peer->ue->ino, ui->flags);
		/* socketpair or interconnected sockets */
		if (interconnected_pair(ui, peer))
			return -1;
	}

	return 0;
}

static void try_resolve_unix_peer(struct unix_sk_info *ui)
{
	struct unix_sk_info *peer;

	if (ui->peer)
		return;

	BUG_ON(!ui->ue->peer);

	if (ui->ue->peer == ui->ue->ino) {
		/* socket connected to self %) */
		set_peer(ui, ui);
		return;
	}

	peer = find_unix_sk_by_ino(ui->ue->peer);
	if (peer) {
		set_peer(ui, peer);
		if (peer->ue->peer == ui->ue->ino)
			set_peer(peer, ui);
	} /* else -- maybe later */
}

int unix_sk_id_add(unsigned int ino)
{
	char *e_str;

	e_str = xmalloc(20);
	if (!e_str)
		return -1;
	snprintf(e_str, 20, "unix[%u]", ino);
	return add_external(e_str);
}

int unix_sk_ids_parse(char *optarg)
{
	/*
	 * parsing option of the following form: --ext-unix-sk=<inode value>,<inode
	 * value>... or short form -x<inode>,<inode>...
	 */

	char *iter = optarg;

	while (*iter != '\0') {
		if (*iter == ',')
			iter++;
		else {
			unsigned int ino = strtoul(iter, &iter, 10);

			if (0 == ino) {
				pr_err("Can't parse unix socket inode from optarg: %s\n", optarg);
				return -1;
			}
			if (unix_sk_id_add(ino) < 0) {
				pr_err("Can't add unix socket inode in list: %s\n", optarg);
				return -1;
			}
		}
	}

	return 0;
}
