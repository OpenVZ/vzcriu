#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <uuid/uuid.h>

#include "cr_options.h"
#include "image.h"
#include "util.h"
#include "log.h"

#include "istor/istor-net.h"
#include "istor/istor-client.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif

#define LOG_PREFIX "istor-client: "

static istor_short_uuid_str_t client_oid_repr;
static uuid_t client_oid;
static int client_sk = -1;

int istor_client_init(struct cr_options *opts)
{
	DECLARE_ISTOR_MSG(m);

	if (!opts->istor_use_server)
		return 0;

	pr_debug("Setting up client\n");

	client_sk = setup_tcp_client(opts->istor_server_ip,
				     opts->istor_server_port);
	if (client_sk < 0) {
		pr_err("Can't connect to server\n");
		return -1;
	}

	m.cmd = ISTOR_CMD_DOCK_INIT;
	if (istor_send_msg(client_sk, &m) < 0 ||
	    istor_recv_msg(client_sk, &m) < 0)
		return -1;

	if (m.cmd == ISTOR_CMD_ACK) {
		memcpy(client_oid, m.oid, sizeof(client_oid));
		__istor_repr_short_id(client_oid, client_oid_repr);
		pr_debug("%s: new dock\n", client_oid_repr);
	} else {
		errno = -m.flags;
		pr_perror("Can't create new dock");
		return m.flags;
	};

	return 0;
}

void istor_client_fini(void)
{
	if (client_sk != -1) {
		close(client_sk);
		client_sk = -1;
	}
}

int istor_client_write_img_buf(struct cr_img *img, const void *ptr, int size)
{
	DECLARE_ISTOR_MSG_T(istor_msg_img_write_t, send);
	DECLARE_ISTOR_MSG(reply);

	memcpy(send.hdr.oid, client_oid, sizeof(client_oid));
	send.hdr.cmd	= ISTOR_CMD_IMG_WRITE;
	send.hdr.size	+= size;
	send.idx	= img->_x.fd;

	if (istor_send_msg(client_sk, (void *)&send) < 0	||
	    istor_send(client_sk, (void *)ptr, size) < size	||
	    istor_recv_msg(client_sk, &reply) < 0 ) {
		pr_err("%s: %s: network failure\n",
		       client_oid_repr, __func__);
		return -1;
	}

	if (reply.cmd == ISTOR_CMD_ACK)
		return 0;

	errno = -reply.flags;
	pr_perror("%s: can't write %zu bytes",
		  client_oid_repr, (size_t)size);

	return -1;
}

int istor_client_read_img_buf_eof(struct cr_img *img, void *ptr, int size)
{
	pr_err("%s: not implemented\n", __func__);
	return -1;
}

off_t istor_client_img_raw_size(struct cr_img *img)
{
	pr_err("Not implemented\n");
	return -1;
}

int istor_client_do_open_image(struct cr_img *img, int dfd, int type,
			       unsigned long oflags, const char *path)
{
	size_t path_size = strlen(path) + 1;
	istor_msg_img_open_t *mopen;
	DECLARE_ISTOR_MSG(reply);
	int ret;

	if (path_size >= PATH_MAX) {
		pr_err("%s: path %s is too long\n",
		       client_oid_repr, path);
		return -ENAMETOOLONG;
	}

	mopen = xmalloc(sizeof(*mopen) + PATH_MAX);
	if (!mopen)
		return -ENOMEM;
	istor_msg_t_init(istor_msg_img_open_t, mopen);

	memcpy(mopen->hdr.oid, client_oid, sizeof(client_oid));
	mopen->hdr.cmd	= ISTOR_CMD_IMG_OPEN;
	mopen->mode	= (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	mopen->flags	= oflags;

	memcpy(mopen->path, path, path_size);
	mopen->hdr.size += path_size;

	if (istor_send_msg(client_sk, &mopen->hdr) < 0 ||
	    istor_recv_msg(client_sk, &reply) < 0) {
		pr_err("%s: %s: network failure\n",
		       client_oid_repr, __func__);
		return -1;
	}

	xfree(mopen);
	mopen = NULL;

	ret = reply.flags;
	if (reply.cmd == ISTOR_CMD_ACK) {
		pr_debug("%s: opened image %s / %d\n",
			 client_oid_repr, path, ret);
	} else
		errno = -ret;

	if (ret < 0) {
		if (!(oflags & O_CREAT) && (errno == ENOENT || ret == -ENOENT)) {
			pr_debug("No %s image\n", path);
			img->_x.fd = EMPTY_IMG_FD;
			goto skip_magic;
		}

		pr_perror("Unable to open %s", path);
		goto err;
	}

	img->_x.fd = ret;

	/*
	 * No buffering we're in memory data.
	 */
	bfd_setraw(&img->_x);

	if (imgset_template[type].magic == RAW_IMAGE_MAGIC)
		return 0;

	if (oflags == O_RDONLY)
		ret = img_check_magic(img, oflags, type, (char *)path);
	else
		ret = img_write_magic(img, oflags, type);
	if (ret)
		goto err;

skip_magic:
	return 0;
err:
	return -1;
}
