#include "zdtmtst.h"

const char *test_doc = "Check if {'flavor': 've'} works";
const char *test_author = "Andrey Zhadchenko <andrey.zhadchenko@virtuozzo.com>";

int main(int argc, char **argv)
{
	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
