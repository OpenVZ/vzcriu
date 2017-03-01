#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <linux/socket.h>
#include <linux/netlink.h>

#include "common/list.h"
#include "imgset.h"
#include "image.h"
#include "servicefd.h"
#include "cr_options.h"
#include "util.h"
#include "util-pie.h"
#include "sockets.h"
#include "namespaces.h"
#include "pstree.h"
#include "util.h"

#include "sk-queue.h"

#include "protobuf.h"
#include "images/sk-packet.pb-c.h"

struct sk_packet {
	struct list_head	list;
	SkPacketEntry		*entry;
	char        		*data;
};

static LIST_HEAD(packets_list);

static int collect_one_packet(void *obj, ProtobufCMessage *msg, struct cr_img *img)
{
	struct sk_packet *pkt = obj;

	pkt->entry = pb_msg(msg, SkPacketEntry);

	pkt->data = xmalloc(pkt->entry->length);
	if (pkt->data ==NULL)
		return -1;

	/*
	 * NOTE: packet must be added to the tail. Otherwise sequence
	 * will be broken.
	 */
	list_add_tail(&pkt->list, &packets_list);

	if (read_img_buf(img, pkt->data, pkt->entry->length) != 1) {
		xfree(pkt->data);
		pr_perror("Unable to read packet data");
		return -1;
	}

	return 0;
}

struct collect_image_info sk_queues_cinfo = {
	.fd_type = CR_FD_SK_QUEUES,
	.pb_type = PB_SK_QUEUES,
	.priv_size = sizeof(struct sk_packet),
	.collect = collect_one_packet,
};

/*
 * Maximum size of the control messages. XXX -- is there any
 * way to get this value out of the kernel?
 * */
#define CMSG_MAX_SIZE	1024

static int dump_sk_creds(struct ucred *ucred, SkPacketEntry *pe, int flags)
{
	SkUcredEntry *ent;

	ent = xmalloc(sizeof(*ent));
	if (!ent)
		return -1;

	sk_ucred_entry__init(ent);
	ent->uid = userns_uid(ucred->uid);
	ent->gid = userns_gid(ucred->gid);
	if (flags & SK_QUEUE_REAL_PID) {
		/*
		 * It is impossible to conver pid from real to virt,
		 * because virt pid-s are known for dumped task only
		 */
		pr_err("ucred-s for unix sockets aren't supported yet");
		goto out;
	} else {
		int pidns = root_ns_mask & CLONE_NEWPID;
		char path[64];
		int ret;

		/* Does a process exist? */
		if (ucred->pid == 0) {
			ret = 0;
		} else if (pidns) {
			snprintf(path, sizeof(path), "%d", ucred->pid);
			ret = faccessat(get_service_fd(CR_PROC_FD_OFF),
							path, R_OK, 0);
		} else {
			snprintf(path, sizeof(path), "/proc/%d", ucred->pid);
			ret = access(path, R_OK);
		}
		if (ret) {
			pr_err("Unable to dump ucred for a dead process %d\n", ucred->pid);
			goto out;
		}
		ent->pid = ucred->pid;
	}

	pe->ucred = ent;

	return 0;
out:
	xfree(ent);
	return -1;
}

static int dump_packet_cmsg(struct msghdr *mh, SkPacketEntry *pe, int flags)
{
	struct cmsghdr *ch;

	for (ch = CMSG_FIRSTHDR(mh); ch; ch = CMSG_NXTHDR(mh, ch)) {
		if (ch->cmsg_level == SOL_SOCKET) {
			if (ch->cmsg_len == CMSG_LEN(sizeof(struct ucred)) &&
			    ch->cmsg_type == SCM_CREDENTIALS) {
				struct ucred *ucred = (struct ucred *)CMSG_DATA(ch);

				if (dump_sk_creds(ucred, pe, flags))
					return -1;
				continue;
			} else if (ch->cmsg_type == SCM_TIMESTAMP ||
				   ch->cmsg_type == SCM_TIMESTAMPNS ||
				   ch->cmsg_type == SCM_TIMESTAMPING) {
				/*
				 * Allow to receive timestamps from the kernel.
				 */
				continue;
			}
		}
		if (ch->cmsg_level == SOL_NETLINK &&
		    ch->cmsg_type == NETLINK_PKTINFO &&
		    ch->cmsg_len == CMSG_LEN(sizeof(struct nl_pktinfo))) {
			struct nl_pktinfo *info = (struct nl_pktinfo *)CMSG_DATA(ch);

			/* Groups less than 32 are returned in msg_address */
			if (info->group < 32)
				continue;

			pr_err("A sender group %d isn't supported\n", info->group);
			return -1;
		}
		pr_err("cmsg: len %ld type %d level %d\n",
			ch->cmsg_len, ch->cmsg_type, ch->cmsg_level);
		pr_err("Control messages in queue, not supported\n");
		return -1;
	}

	return 0;
}

int dump_sk_queue(int sock_fd, int sock_id, int flags)
{
	SkPacketEntry pe = SK_PACKET_ENTRY__INIT;
	int ret, size, orig_peek_off;
	void *data;
	socklen_t tmp;

	/*
	 * Save original peek offset.
	 */
	tmp = sizeof(orig_peek_off);
	orig_peek_off = 0;
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed");
		return ret;
	}
	/*
	 * Discover max DGRAM size
	 */
	tmp = sizeof(size);
	size = 0;
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &size, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed");
		return ret;
	}

	/* Note: 32 bytes will be used by kernel for protocol header. */
	size -= 32;

	/*
	 * Allocate data for a stream.
	 */
	data = xmalloc(size);
	if (!data)
		return -1;

	/*
	 * Enable peek offset incrementation.
	 */
	ret = setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &ret, sizeof(int));
	if (ret < 0) {
		pr_perror("setsockopt fail");
		goto err_brk;
	}

	pe.id_for = sock_id;

	while (1) {
		char cmsg[CMSG_MAX_SIZE];
		unsigned char addr[_K_SS_MAXSIZE];
		struct iovec iov = {
			.iov_base	= data,
			.iov_len	= size,
		};
		struct msghdr msg = {
			.msg_iov	= &iov,
			.msg_iovlen	= 1,
			.msg_control	= &cmsg,
			.msg_controllen	= sizeof(cmsg),
		};

		if (flags & SK_QUEUE_DUMP_ADDR) {
			msg.msg_name	= addr;
			msg.msg_namelen	= _K_SS_MAXSIZE;
		}

		ret = pe.length = recvmsg(sock_fd, &msg, MSG_DONTWAIT | MSG_PEEK);
		if (!ret)
			/*
			 * It means, that peer has performed an
			 * orderly shutdown, so we're done.
			 */
			break;
		else if (ret < 0) {
			if (errno == EAGAIN)
				break; /* we're done */
			pr_perror("recvmsg fail: error");
			goto err_set_sock;
		}
		if (msg.msg_flags & MSG_TRUNC) {
			/*
			 * DGRAM truncated. This should not happen. But we have
			 * to check...
			 */
			pr_err("sys_recvmsg failed: truncated\n");
			ret = -E2BIG;
			goto err_set_sock;
		}

		if (dump_packet_cmsg(&msg, &pe, flags))
			goto err_set_sock;

		if (msg.msg_namelen) {
			pe.has_addr = true;
			pe.addr.data = addr;
			pe.addr.len = msg.msg_namelen;
		}

		ret = pb_write_one(img_from_set(glob_imgset, CR_FD_SK_QUEUES), &pe, PB_SK_QUEUES);
		if (ret < 0) {
			ret = -EIO;
			goto err_set_sock;
		}

		ret = write_img_buf(img_from_set(glob_imgset, CR_FD_SK_QUEUES), data, pe.length);
		if (ret < 0) {
			ret = -EIO;
			goto err_set_sock;
		}
	}
	ret = 0;

err_set_sock:
	/*
	 * Restore original peek offset.
	 */
	if (setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, sizeof(int))) {
		pr_perror("setsockopt failed on restore");
		ret = -1;
	}
err_brk:
	xfree(pe.ucred);
	xfree(data);
	return ret;
}

int restore_sk_queue(int fd, unsigned int peer_id)
{
	struct sk_packet *pkt, *tmp;
	int ret;
	struct cr_img *img;

	pr_info("Trying to restore recv queue for %u\n", peer_id);

	if (restore_prepare_socket(fd))
		return -1;

	img = open_image(CR_FD_SK_QUEUES, O_RSTR);
	if (!img)
		return -1;

	list_for_each_entry_safe(pkt, tmp, &packets_list, list) {
		SkPacketEntry *entry = pkt->entry;
		struct iovec iov = {
			.iov_base	= pkt->data,
			.iov_len	= entry->length,
		};
		struct msghdr msg = {
			.msg_iov	= &iov,
			.msg_iovlen	= 1,
		};
		char cmsg[1024];

		if (entry->id_for != peer_id)
			continue;

		pr_info("\tRestoring %d-bytes skb for %u\n",
			(unsigned int)entry->length, peer_id);

		/*
		 * Don't try to use sendfile here, because it use sendpage() and
		 * all data are split on pages and a new skb is allocated for
		 * each page. It creates a big overhead on SNDBUF.
		 * sendfile() isn't suitable for DGRAM sockets, because message
		 * boundaries messages should be saved.
		 */

		if (entry->has_addr) {
			msg.msg_name = entry->addr.data;
			msg.msg_namelen = entry->addr.len;
		}

		if (entry->ucred && entry->ucred->pid) {
			struct ucred *ucred;
			struct cmsghdr *ch;

			msg.msg_control = cmsg;
			msg.msg_controllen = sizeof(cmsg);

			ch = CMSG_FIRSTHDR(&msg);
			ch->cmsg_len = CMSG_LEN(sizeof(struct ucred));
			ch->cmsg_level = SOL_SOCKET;
			ch->cmsg_type = SCM_CREDENTIALS;
			ucred = (struct ucred *)CMSG_DATA(ch);
			ucred->pid = entry->ucred->pid;
			ucred->uid = entry->ucred->uid;
			ucred->gid = entry->ucred->gid;
			msg.msg_controllen = CMSG_SPACE(sizeof(struct ucred));
		}

		ret = sendmsg(fd, &msg, 0);
		if (ret < 0) {
			pr_perror("Failed to send packet");
			goto err;
		}
		if (ret != entry->length) {
			pr_err("Restored skb trimmed to %d/%d\n",
			       ret, (unsigned int)entry->length);
			goto err;
		}
		list_del(&pkt->list);
		sk_packet_entry__free_unpacked(entry, NULL);
		xfree(pkt);
	}

	close_image(img);
	return 0;
err:
	close_image(img);
	return -1;
}
