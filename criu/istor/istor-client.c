#include <stdlib.h>
#include <unistd.h>

#include <uuid/uuid.h>

#include "cr_options.h"
#include "util.h"
#include "log.h"

#include "istor/istor-client.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif

#define LOG_PREFIX "istor-client: "

static int client_sk = -1;
//static uuid_t oid;

int istor_client_init(struct cr_options *opts)
{
	if (!opts->istor_use_server)
		return 0;

	pr_debug("Setting up client\n");
	
	client_sk = setup_tcp_client(opts->istor_server_ip, opts->istor_server_port);
	if (client_sk < 0) {
		pr_err("Can't connect to server\n");
		return -1;
	}

	exit(1);
	(void)opts->imgs_dir;
	return -1;
}

void istor_client_fini(void)
{
	if (client_sk != -1) {
		close(client_sk);
		client_sk = -1;
	}
}
