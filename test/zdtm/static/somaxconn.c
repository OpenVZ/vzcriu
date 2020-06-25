#include <stdio.h>

#include "zdtmtst.h"

#define SOMAXCONN "/proc/sys/net/core/somaxconn"

const char *test_doc	= "Check if /proc/sys/net/core/somaxconn is present and correctly restored";
const char *test_author	= "Andrey Zhadchenko <andrey.zhadchenko@virtuozzo.com>";

int main(int argc, char **argv)
{
	FILE* fp;
	uint val, new_val;

	test_init(argc, argv);

	fp = fopen(SOMAXCONN, "r+");
	if(!fp) {
		pr_perror("Can't open %s\n", SOMAXCONN);
		return 1;
	}

	if(fscanf(fp, "%d", &val) != 1) {
		pr_perror("Can't read %s", SOMAXCONN);
		fclose(fp);
		return 1;
	}
	new_val = val + 1;

	if(fseek(fp, 0, SEEK_SET)) {
		pr_perror("Can't fseek %s", SOMAXCONN);
		fclose(fp);
		return 1;
	}

	if(fprintf(fp, "%d", new_val) < 1) {
		pr_perror("Can't write to %s", SOMAXCONN);
		fclose(fp);
		return 1;
	}

	fclose(fp);

	test_daemon();
	test_waitsig();

	fp = fopen(SOMAXCONN, "r+");
	if(!fp) {
		pr_perror("Can't open %s after c/r", SOMAXCONN);
		return 1;
	}

	if(fscanf(fp, "%d", &val) != 1) {
		pr_perror("Can't read %s ater c/r", SOMAXCONN);
		fclose(fp);
		return 1;
	}

	if(val != new_val) {
		fail("%s has different value after c/r", SOMAXCONN);
		fclose(fp);
		return 1;
	}

	pass();
	fclose(fp);
	return 0;
}
