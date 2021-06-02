#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc = "Check that we can't migrate with a file open in a "
		       "directory which has been mounted over by another "
		       "filesystem";
const char *test_author = "Roman Kagan <rkagan@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define MNT_ID_PREFIX "mnt_id:"

int get_mnt_id(int target_fd)
{
	char path[256], buf[4096], *ptr = buf;
	int fd, val, mnt_id = -1;

	if (snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", target_fd) >= sizeof(path)) {
		pr_err("Can't sprintf\n");
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	if (read(fd, buf, sizeof(buf)) < 0) {
		pr_perror("Unable to read %s", path);
		goto out;
	}

	while (ptr) {
		if (!strncmp(ptr, MNT_ID_PREFIX, strlen(MNT_ID_PREFIX))) {
			if (sscanf(ptr, "%*s %d", &val) != 1) {
				pr_err("Can't extract mnt_id from %s\n", buf);
				goto out;
			}

			mnt_id = val;
			break;
		}

		ptr = strchr(ptr, '\n') + 1;
	}

out:
	close(fd);
	return mnt_id;
}

int check_mnt_id(int base_fd, int file_fd, int ovm_fd)
{
	int base_mnt_id, file_mnt_id, ovm_mnt_id;

	base_mnt_id = get_mnt_id(base_fd);
	if (base_mnt_id < 0) {
		pr_err("Unable to get base mnt_id\n");
		return -1;
	}

	file_mnt_id = get_mnt_id(file_fd);
	if (file_mnt_id < 0) {
		pr_err("Unable to get file mnt_id\n");
		return -1;
	}

	ovm_mnt_id = get_mnt_id(ovm_fd);
	if (ovm_mnt_id < 0) {
		pr_err("Unable to get overmount mnt_id\n");
		return -1;
	}

	if (file_mnt_id != base_mnt_id) {
		pr_err("overmounted file does not belong to base mount!\n");
		return -1;
	}

	if (file_mnt_id == ovm_mnt_id) {
		pr_err("overmounted file mnt_id is equal to overmount mnt_id!\n");
		return -1;
	}

	test_msg("base_mnt_id = %d, file_mnt_id = %d, ovm_mnt_id = %d\n", base_mnt_id, file_mnt_id, ovm_mnt_id);

	return 0;
}

int main(int argc, char **argv)
{
	int base_fd, file_fd = -1, ovm_fd, ret = -1;
	char ovm_dir[256], path[256];

	test_init(argc, argv);

	if (snprintf(ovm_dir, sizeof(ovm_dir), "%s/ovm", dirname) >= sizeof(path)) {
		pr_perror("directory name \"%s\"is too long", dirname);
		exit(1);
	}

	if (snprintf(path, sizeof(path), "%s/foo", ovm_dir) >= sizeof(path)) {
		pr_perror("directory name \"%s\"is too long", ovm_dir);
		exit(1);
	}

	if (mkdir(dirname, 0700)) {
		pr_perror("can't make directory %s", dirname);
		exit(1);
	}

	if (mount("base", dirname, "tmpfs", 0, 0) < 0) {
		pr_perror("can't mount tmpfs over %s", dirname);
		goto rmdir;
	}

	if (mkdir(ovm_dir, 0700)) {
		pr_perror("can't make directory %s", ovm_dir);
		goto umount_base;
	}

	base_fd = open(dirname, O_RDONLY);
	if (base_fd < 0) {
		pr_perror("can't open base mount");
		goto base_clean;
	}

	file_fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (file_fd < 0) {
		pr_perror("can't open %s", path);
		goto base_clean;
	}

	if (mount("ovm", ovm_dir, "tmpfs", 0, 0) < 0) {
		pr_perror("can't mount tmpfs over %s", ovm_dir);
		goto base_clean;
	}

	ovm_fd = open(ovm_dir, O_RDONLY);
	if (ovm_fd < 0) {
		pr_perror("can't open overmount %s", ovm_dir);
		goto cleanup;
	}

	if (check_mnt_id(base_fd, file_fd, ovm_fd)) {
		pr_err("Incorrect file configuration\n");
		goto cleanup;
	}

	test_daemon();
	test_waitsig();

	if (check_mnt_id(base_fd, file_fd, ovm_fd)) {
		pr_err("Incorrect file configuration after restore\n");
		goto cleanup;
	}

	pass();
	ret = 0;

cleanup:
	close(ovm_fd);
	if (umount(ovm_dir) < 0)
		pr_err("can't umount %s\n", ovm_dir);
base_clean:
	close(file_fd);
	close(base_fd);
	unlink(ovm_dir);
umount_base:
	if (umount(dirname) < 0)
		pr_err("can't umount %s\n", dirname);
rmdir:
	rmdir(dirname);

	return ret;
}
