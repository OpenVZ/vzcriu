#include <unistd.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <linux/rtnetlink.h>
#include <libnl3/netlink/msg.h>

#include "imgset.h"
#include "files.h"
#include "sockets.h"
#include "util.h"

#include "protobuf.h"
#include "images/sk-netlink.pb-c.h"
#include "netlink_diag.h"
#include "libnetlink.h"
#include "namespaces.h"
#include "sk-queue.h"
#include "kerndat.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

struct netlink_sk_desc {
	struct socket_desc	sd;
	u32			portid;
	u32			*groups;
	u32			gsize;
	u32			dst_portid;
	u32			dst_group;
	u32			nl_flags;
	u8			state;
	u8			protocol;
};

int netlink_final_check_one(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	struct nlattr *tb[NETLINK_DIAG_MAX+1];
	struct netlink_diag_msg *m;
	unsigned long nl_ino = (unsigned long)arg;
	u64 flags;

	m = NLMSG_DATA(hdr);

	if (m->ndiag_ino == nl_ino)
		return 0;

	nlmsg_parse(hdr, sizeof(struct netlink_diag_msg), tb, NETLINK_DIAG_MAX, NULL);

	flags = NDIAG_FLAG_CB_RUNNING;
	if (tb[NETLINK_DIAG_FLAGS])
		flags = nla_get_u32(tb[NETLINK_DIAG_FLAGS]);

	if (flags & NDIAG_FLAG_CB_RUNNING) {
		pr_err("The netlink socket 0x%x has undumped data\n", m->ndiag_ino);
		return -1;
	}

	return 0;
}

int netlink_receive_one(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	struct nlattr *tb[NETLINK_DIAG_MAX+1];
	struct netlink_diag_msg *m;
	struct netlink_sk_desc *sd;
	unsigned long *groups;

	m = NLMSG_DATA(hdr);
	pr_debug("Collect netlink sock 0x%x\n", m->ndiag_ino);

	sd = xmalloc(sizeof(*sd));
	if (!sd)
		return -1;

	sd->protocol = m->ndiag_protocol;
	sd->portid = m->ndiag_portid;
	sd->dst_portid = m->ndiag_dst_portid;
	sd->dst_group = m->ndiag_dst_group;
	sd->state = m->ndiag_state;

	nlmsg_parse(hdr, sizeof(struct netlink_diag_msg), tb, NETLINK_DIAG_MAX, NULL);

	if (tb[NETLINK_DIAG_GROUPS]) {
		sd->gsize = nla_len(tb[NETLINK_DIAG_GROUPS]);
		groups = nla_data(tb[NETLINK_DIAG_GROUPS]);

		sd->groups = xmalloc(sd->gsize);
		if (!sd->groups) {
			xfree(sd);
			return -1;
		}
		memcpy(sd->groups, groups, sd->gsize);
	} else {
		sd->groups = NULL;
		sd->gsize = 0;
	}

	/*
	 * It's imossible to dump a socket queue if a callback is running now.
	 * We have to set NDIAG_FLAG_CB_RUNNING, if a kernel doesn't report
	 * real flags.
	 */
	sd->nl_flags = NDIAG_FLAG_CB_RUNNING;

	if (tb[NETLINK_DIAG_FLAGS]) {
		u64 flags = nla_get_u32(tb[NETLINK_DIAG_FLAGS]);

		sd->nl_flags = flags;
	}

	return sk_collect_one(m->ndiag_ino, PF_NETLINK, &sd->sd, ns);
}

static bool can_dump_netlink_sk(int lfd, struct netlink_sk_desc *sk)
{
	int ret;

	ret = fd_has_data(lfd);
	if (ret < 0)
		return false;

	return true;
}

static int dump_nl_opts(int sk, NlSkOptsEntry *e)
{
	int ret = 0;
	socklen_t len;

	ret |= dump_opt(sk, SOL_NETLINK, NETLINK_PKTINFO, &e->pktinfo);
	ret |= dump_opt(sk, SOL_NETLINK, NETLINK_BROADCAST_ERROR, &e->broadcast_error);
	ret |= dump_opt(sk, SOL_NETLINK, NETLINK_NO_ENOBUFS, &e->no_enobufs);

	len = sizeof(e->listen_all_nsid);
	if (getsockopt(sk, SOL_NETLINK, NETLINK_LISTEN_ALL_NSID, &e->listen_all_nsid, &len)) {
		if (errno == ENOPROTOOPT) {
			pr_warn("Unable to get NETLINK_LISTEN_ALL_NSID");
		} else {
			pr_perror("Can't get NETLINK_LISTEN_ALL_NSID opt");
			ret = -1;
		}
	}

	len = sizeof(e->cap_ack);
	if (getsockopt(sk, SOL_NETLINK, NETLINK_CAP_ACK, &e->cap_ack, &len) &&
	    errno != ENOPROTOOPT) {
		pr_perror("Can't get NETLINK_CAP_ACK opt");
		ret = -1;
	}

	return ret;
}

static int dump_nl_queue(int sk, int id) {
	int ret, old_val, on = 1;

	if (dump_opt(sk, SOL_NETLINK, NETLINK_NO_ENOBUFS, &old_val))
		return -1;

	if (!old_val && restore_opt(sk, SOL_NETLINK, NETLINK_NO_ENOBUFS, &on))
		return -1;

	ret = dump_sk_queue(sk, id, SK_QUEUE_DUMP_ADDR);

	if (!old_val && restore_opt(sk, SOL_NETLINK, NETLINK_NO_ENOBUFS, &old_val))
		return -1;

	return ret;
}

static int dump_one_netlink_fd(int lfd, u32 id, const struct fd_parms *p)
{
	struct netlink_sk_desc *sk;
	FileEntry fe = FILE_ENTRY__INIT;
	NetlinkSkEntry ne = NETLINK_SK_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	NlSkOptsEntry nlopts = NL_SK_OPTS_ENTRY__INIT;

	sk = (struct netlink_sk_desc *)lookup_socket(p->stat.st_ino, PF_NETLINK, 0);
	if (IS_ERR(sk))
		goto err;

	ne.id = id;
	ne.ino = p->stat.st_ino;

	if (!can_dump_netlink_sk(lfd, sk))
		goto err;

	if (sk) {
		BUG_ON(sk->sd.already_dumped);

		ne.ns_id = sk->sd.sk_ns->id;
		ne.has_ns_id = true;
		ne.protocol = sk->protocol;
		ne.portid = sk->portid;
		ne.groups = sk->groups;


		ne.n_groups = sk->gsize / sizeof(ne.groups[0]);
		/*
		 * On 64-bit sk->gsize is multiple to 8 bytes (sizeof(long)),
		 * so remove the last 4 bytes if they are empty.
		 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		/*
		 * Big endian swap: Ugly hack for zdtm/static/sk-netlink
		 *
		 * For big endian systems:
		 *
		 * - sk->groups[0] are bits 32-64
		 * - sk->groups[1] are bits 0-32
		 */
		if (ne.n_groups == 2) {
			uint32_t tmp = sk->groups[1];

			sk->groups[1] = sk->groups[0];
			sk->groups[0] = tmp;
		}
#endif
		if (ne.n_groups && sk->groups[ne.n_groups - 1] == 0)
			ne.n_groups -= 1;

		if (ne.n_groups > 1) {
			pr_err("The netlink socket 0x%x has more than 32 groups\n", ne.ino);
			return -1;
		}
		if (sk->groups && !sk->portid) {
			pr_err("The netlink socket 0x%x is bound to groups but not to portid\n", ne.ino);
			return -1;
		}
		ne.state = sk->state;
		ne.dst_portid = sk->dst_portid;
		ne.dst_group = sk->dst_group;
	} else { /* unconnected and unbound socket */
		struct ns_id *nsid;
		int val;
		socklen_t aux = sizeof(val);

		if (root_ns_mask & CLONE_NEWNET) {
			nsid = get_socket_ns(lfd);
			if (nsid == NULL)
				return -1;
			ne.ns_id = nsid->id;
			ne.has_ns_id = true;
		}

		if (getsockopt(lfd, SOL_SOCKET, SO_PROTOCOL, &val, &aux) < 0) {
			pr_perror("Unable to get protocol for netlink socket");
			goto err;
		}

		ne.protocol = val;
	}

	ne.fown = (FownEntry *)&p->fown;
	ne.opts	= &skopts;
	ne.nl_opts = &nlopts;

	if (dump_nl_opts(lfd, &nlopts))
		goto err;

	if (dump_socket_opts(lfd, &skopts))
		goto err;

	fe.type = FD_TYPES__NETLINKSK;
	fe.id = ne.id;
	fe.nlsk = &ne;

	if (kdat.has_nl_repair && dump_nl_queue(lfd, id))
		goto err;

	if (pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE))
		goto err;

	return 0;
err:
	return -1;
}

const struct fdtype_ops netlink_dump_ops = {
	.type		= FD_TYPES__NETLINKSK,
	.dump		= dump_one_netlink_fd,
};

struct netlink_sock_info {
	NetlinkSkEntry *nse;
	struct file_desc d;
};

static int restore_netlink_queue(int sk, int id)
{
	int val;

	if (!kdat.has_nl_repair)
		return 0;

	val = 1;
	if (setsockopt(sk, SOL_NETLINK, NETLINK_REPAIR, &val, sizeof(val))) {
		pr_perror("Unable to set NETLINK_REPAIR");
		return -1;
	}

	if (restore_sk_queue(sk, id))
		return -1;

	val = 0;
	if (setsockopt(sk, SOL_NETLINK, NETLINK_REPAIR, &val, sizeof(val)))
		return -1;

	return 0;
}

static int restore_nl_opts(int sk, NlSkOptsEntry *e)
{
	int yes = 1, ret = 0;

	if (e->pktinfo)
		ret |= restore_opt(sk, SOL_NETLINK, NETLINK_PKTINFO, &yes);
	if (e->broadcast_error)
		ret |= restore_opt(sk, SOL_NETLINK, NETLINK_BROADCAST_ERROR, &yes);
	if (e->no_enobufs)
		ret |= restore_opt(sk, SOL_NETLINK, NETLINK_NO_ENOBUFS, &yes);
	if (e->listen_all_nsid)
		ret |= restore_opt(sk, SOL_NETLINK, NETLINK_LISTEN_ALL_NSID, &yes);
	if (e->cap_ack)
		ret |= restore_opt(sk, SOL_NETLINK, NETLINK_CAP_ACK, &yes);

	return ret;
}

static int open_netlink_sk(struct file_desc *d, int *new_fd)
{
	struct netlink_sock_info *nsi;
	NetlinkSkEntry *nse;
	struct sockaddr_nl addr;
	int sk = -1;

	nsi = container_of(d, struct netlink_sock_info, d);
	nse = nsi->nse;

	pr_info("Opening netlink socket id %#x\n", nse->id);

	if (set_netns(nse->ns_id))
		return -1;

	sk = socket(PF_NETLINK, SOCK_RAW, nse->protocol);
	if (sk < 0) {
		pr_perror("Can't create netlink sock");
		goto err;
	}

	if (nse->portid) {
		memset(&addr, 0, sizeof(addr));
		addr.nl_family = AF_NETLINK;
		if (nse->n_groups > 1) {
			pr_err("Groups above 32 are not supported yet\n");
			goto err;
		}
		if (nse->n_groups)
			addr.nl_groups = nse->groups[0];
		addr.nl_pid = nse->portid;

		if (bind(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			pr_perror("Can't bind netlink socket");
			goto err;
		}
	}

	if (nse->state == NETLINK_CONNECTED) {
		addr.nl_family = AF_NETLINK;
		addr.nl_groups = 1 << (nse->dst_group - 1);
		addr.nl_pid = nse->dst_portid;
		if (connect(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			pr_perror("Can't connect netlink socket");
			goto err;
		}
	}

	if (rst_file_params(sk, nse->fown, nse->flags))
		goto err;

	if (restore_netlink_queue(sk, nse->id))
		goto err;

	if (nse->nl_opts && restore_nl_opts(sk, nse->nl_opts))
		goto err;

	if (restore_socket_opts(sk, nse->opts))
		goto err;

	*new_fd = sk;
	return 0;
err:
	close(sk);
	return -1;
}

static struct file_desc_ops netlink_sock_desc_ops = {
	.type = FD_TYPES__NETLINKSK,
	.open = open_netlink_sk,
};

static int collect_one_netlink_sk(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	struct netlink_sock_info *si = o;

	si->nse = pb_msg(base, NetlinkSkEntry);
	return file_desc_add(&si->d, si->nse->id, &netlink_sock_desc_ops);
}

struct collect_image_info netlink_sk_cinfo = {
	.fd_type = CR_FD_NETLINK_SK,
	.pb_type = PB_NETLINK_SK,
	.priv_size = sizeof(struct netlink_sock_info),
	.collect = collect_one_netlink_sk,
};
