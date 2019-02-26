#include <unistd.h>

#include "cr_options.h"
#include "util.h"

#include "istor/istor-client.h"

static int istor_server_sk = -1;

int istor_client_init(struct cr_options *opts)
{
	if (!opts->istor_use_server)
		return 0;

	istor_server_sk = setup_tcp_client(opts->addr, opts->port);
	if (istor_server_sk < 0) {
		pr_err("Can't connect to server\n");
		return -1;
	}

	return 0;
}

void istor_client_fini(void)
{
	if (istor_server_sk != -1)
		close(istor_server_sk);
}
