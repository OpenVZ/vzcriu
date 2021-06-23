#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/vfs.h>
#include <linux/magic.h>

#include "zdtmtst.h"

const char *test_doc = "Open, link, unlink former, change size, migrate, check size";

char *filename;
TEST_OPTION(filename, string, "file name", 1);
static char link_name[1024];

static int is_devicemapper(dev_t st_dev)
{
	int ret;
	unsigned int maj, min;
	char path[1024];
	FILE *fp;

	ret = snprintf(path, sizeof(path), "/sys/block/dm-%u/dev",
		       minor(st_dev));
	if (ret < 0) {
		pr_perror("snprintf");
		return 0;
	}

	ret = access(path, R_OK);
	if (ret < 0)
		return 0;

	fp = fopen(path, "r");
	if (fp == NULL) {
		pr_perror("fopen");
		return 0;
	}

	ret = fscanf(fp, "%u:%u", &maj, &min);
	if (ret != 2) {
		pr_perror("fscanf");
		fclose(fp);
		return 0;
	}

	fclose(fp);

	return maj == major(st_dev) && min == minor(st_dev);
}

int main(int argc, char **argv)
{
	int fd;
	size_t fsize = 1000;
	uint8_t buf[fsize];
	struct stat fst, fst2;
	struct statfs fsst;

	test_init(argc, argv);

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	sprintf(link_name, "%s.link", filename);
	if (link(filename, link_name)) {
		pr_perror("can't link files");
		goto failed0;
	}

	if (fstat(fd, &fst) < 0) {
		pr_perror("can't get file info %s before", filename);
		goto failed;
	}

	if (fst.st_size != 0) {
		pr_perror("%s file size eq %lld", filename, (long long)fst.st_size);
		goto failed;
	}

	if (unlink(filename) < 0) {
		pr_perror("can't unlink %s", filename);
		goto failed;
	}

	memset(buf, '0', sizeof(buf));
	if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("can't write %s", filename);
		goto failed;
	}

	test_daemon();
	test_waitsig();

	if (statfs(link_name, &fsst) < 0) {
		pr_perror("statfs(%s)", link_name);
		goto failed;
	}

	if (fstat(fd, &fst2) < 0) {
		pr_perror("can't get %s file info after", filename);
		goto failed;
	}
	/* An NFS mount is restored with another st_dev
	 * device mapper devices (ploop) will be restored with
	 * different minor (and even major). So we want to check
	 * that restored device is really device mapper device
	 * and skip check in such case.
	 */
	if (fsst.f_type != NFS_SUPER_MAGIC && fst.st_dev != fst2.st_dev &&
	    !is_devicemapper(fst2.st_dev)) {
		fail("files differ after restore");
		goto failed;
	}

	if (fst.st_ino != fst2.st_ino) {
		fail("files differ after restore");
		goto failed;
	}

	if (fst2.st_size != fsize) {
		fail("(via fstat): file size changed to %lld", (long long)fst.st_size);
		goto failed;
	}

	fst2.st_size = lseek(fd, 0, SEEK_END);
	if (fst2.st_size != fsize) {
		fail("(via lseek): file size changed to %lld", (long long)fst.st_size);
		goto failed;
	}

	close(fd);

	pass();
	return 0;

failed:
	unlink(link_name);
failed0:
	unlink(filename);
	close(fd);
	return 1;
}
