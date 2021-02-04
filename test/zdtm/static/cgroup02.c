#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include "zdtmtst.h"

const char *test_doc	= "Check that empty cgroups are preserved";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
static const char *cgname = "zdtmtst";
static const char *subname = "oldroot";
static const char *cgname2 = "zdtmtst.defaultroot";

#define BUFSZ 255

int mount_and_add(const char *controller, const char *prefix, const char *path)
{
	char aux[1024], paux[1024], subdir[1024];
	int cgfd, l;

	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir");
		return -1;
	}

	sprintf(subdir, "%s/%s", dirname, controller);
	if (mkdir(subdir, 0700) < 0) {
		pr_perror("Can't make dir");
		return -1;
	}

	sprintf(aux, "none,name=%s", controller);
	if (mount("none", subdir, "cgroup", 0, aux)) {
		pr_perror("Can't mount cgroups");
		goto err_rd;
	}

	ssprintf(paux, "%s/%s", subdir, prefix);
	mkdir(paux, 0600);

	ssprintf(paux, "%s/%s/%s", subdir, prefix, path);
	mkdir(paux, 0600);

	l = sprintf(aux, "%d", getpid());
	ssprintf(paux, "%s/%s/%s/tasks", subdir, prefix, path);

	cgfd = open(paux, O_WRONLY);
	if (cgfd < 0) {
		pr_perror("Can't open tasks");
		goto err_rs;
	}

	l = write(cgfd, aux, l);
	close(cgfd);

	if (l < 0) {
		pr_perror("Can't move self to subcg");
		goto err_rs;
	}

	return 0;
err_rs:
	umount(dirname);
err_rd:
	rmdir(dirname);
	return -1;
}

bool test_exists(char *mountinfo_line, char *path)
{
	char aux[1024], paux[1024];
	struct stat st;

	sscanf(mountinfo_line, "%*d %*d %*d:%*d %*s %s", aux);
	test_msg("found cgroup at %s\n", aux);

	ssprintf(paux, "%s/%s", aux, path);
	if (stat(paux, &st)) {
		return false;
	}

	if (!S_ISDIR(st.st_mode)) {
		return false;
	}

	return true;
}

static int write_positive_int(char *path, int val) {
	char buf[BUFSZ];
	int fd, ret, old, exit_code = -1;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		pr_perror("Unable to open %s", path);
		goto err;
	}

	ret = read(fd, buf, BUFSZ);
	if (ret < 0 && ret == BUFSZ) {
		pr_perror("Unable to read %s", path);
		goto err;
	}

	if (lseek(fd, SEEK_SET, 0)) {
		pr_perror("Unable to lseek to file start");
		goto err;
	}

	if (dprintf(fd, "%d", val) < 0) {
		pr_perror("Unkwon error within dprintf");
		goto err;
	}

	if (sscanf(buf, "%d", &old) != 1) {
		pr_err("Unable to get number from %s\n", buf);
		goto err;
	}

	exit_code = old;
err:
	close(fd);
	return exit_code;
}

int main(int argc, char **argv) {
	FILE *cgf;
	bool found_zdtmtstroot = false, found_newroot = false;
	char paux[1024];
	int ret = -1;
	int fd;
	int cpu_old, mem_old;

	test_init(argc, argv);

	cpu_old = write_positive_int("/sys/fs/cgroup/cpuset/cpuset.cpu_exclusive", 0);
	if (cpu_old < 0)
		return -1;

	mem_old = write_positive_int("/sys/fs/cgroup/cpuset/cpuset.mem_exclusive", 0);
	if (mem_old < 0)
		goto out_cgroup_cpu;

	if (mount_and_add(cgname, "prefix", subname))
		goto out;
	if (mount_and_add(cgname2, "prefix", subname)) {
		sprintf(paux, "%s/%s", dirname, cgname);
		umount(paux);
		rmdir(paux);
		goto out;
	}

	sprintf(paux, "%s/%s/prefix", dirname, cgname);
	fd = open(paux, O_DIRECTORY);
	if (fd < 0)
		goto out_umount;

	if (fchmod(fd, 0777) < 0) {
		fail("fchmod");
		goto out_umount;
	}

	test_daemon();
	test_waitsig();

	if (close(fd) < 0) {
		fail("fd didn't survive");
		goto out_umount;
	}

	cgf = fopen("/proc/self/mountinfo", "r");
	if (cgf == NULL) {
		fail("No mountinfo file");
		goto out_umount;
	}

	while (fgets(paux, sizeof(paux), cgf)) {
		char *s;

		s = strstr(paux, cgname);
		if (s && test_exists(paux, "prefix")) {
			found_zdtmtstroot = true;
		}

		s = strstr(paux, cgname2);
		if (s && test_exists(paux, "newroot")) {
			found_newroot = true;
		}
	}

	if (!found_zdtmtstroot) {
		fail("oldroot not rewritten to zdtmtstroot!\n");
		goto out_close;
	}

	if (!found_newroot) {
		fail("oldroot not rewritten to newroot!\n");
		goto out_close;
	}

	pass();
	ret = 0;


out_close:
	fclose(cgf);
out_umount:
	sprintf(paux, "%s/%s", dirname, cgname);
	umount(paux);
	rmdir(paux);

	sprintf(paux, "%s/%s", dirname, cgname2);
	umount(paux);
	rmdir(paux);
out:
	write_positive_int("/sys/fs/cgroup/cpuset/cpuset.mem_exclusive", mem_old);
out_cgroup_cpu:
	write_positive_int("/sys/fs/cgroup/cpuset/cpuset.cpu_exclusive", cpu_old);

	return ret;
}
