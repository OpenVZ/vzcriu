#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that nested freezer states are restored";
const char *test_author	= "Yuriy Vasiliev <yuriy.vasiliev@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);
char *freezecg;
TEST_OPTION(freezecg, string, "zdtm freezer folder name", 1);
static const char *fzname1 = "cgfz1_test";
static const char *fzname2 = "cgfz2_test";
static const char *nested_fzname1 = "cgfz1_nested_test";
static const char *nested_fzname2 = "cgfz2_nested_test";

static const char frozen[]	= "FROZEN";
static const char thawed[]	= "THAWED";

enum freezer_index {
	FZ1 = 0,
	FZ2
};

struct freezer {
	char dir[128];
	char state_path[128];
	char self_freezing_path[128];
	char tasks_path[128];
	char task[8];
	pid_t pid;
};

static int put_string_to_file(const char *path, const char *str)
{
	int fd, ret;
	size_t size = strlen(str);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open file %s for writing", path);
		return -1;
	}

	ret = write(fd, str, size);
	if (ret < 0)
		pr_perror("Can't write data to the file %s", path);

	close(fd);

	return ret;
}

static int get_string_from_file(const char *path, char *out_str, size_t size)
{
	int fd, ret;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open file %s for reading", path);
		return -1;
	}

	ret = read(fd, out_str, size);
	if (ret < 0)
		pr_perror("Can't read data from file %s", path);
	else
		out_str[ret] = '\0';
	close(fd);

	return ret;
}

static int check_string_value(const char *path, const char *expected)
{
	char read_value[128];

	if (get_string_from_file(path, read_value, strlen(expected)) < 0)
		return -1;

	if (strcmp(read_value, expected) == 0)
		return 0;

	test_msg("File [%s] contain wrong value. Expected: %s Read: %s\n",
		path, expected, read_value);

	return 1;
}

static pid_t create_task_and_add(struct freezer *fz)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't create child process");
		return -1;
	}

	if (pid == 0)
		while (1)
			sleep(1);

	fz->pid = pid;
	if (snprintf(fz->task, sizeof(fz->task), "%d", pid) >= sizeof(fz->task)) {
		pr_perror("Path truncation error");
		return -1;
	}
	if (put_string_to_file(fz->tasks_path, fz->task) < 0)
		return -1;

	return 0;
}

static int create_freezer(struct freezer *fz, const char *path, const char *name)
{
	sprintf(fz->dir, "%s/%s", path, name);
	if (mkdir(fz->dir, 0700) < 0) {
		pr_perror("Can't make freezer dir [%s]", fz->dir);
		return -1;
	}

	if (snprintf(fz->state_path, sizeof(fz->state_path), "%s/freezer.state", fz->dir) >= sizeof(fz->state_path))
		goto err_trunc;

	if (snprintf(fz->self_freezing_path, sizeof(fz->self_freezing_path), "%s/freezer.self_freezing", fz->dir) >= sizeof(fz->self_freezing_path))
		goto err_trunc;

	if (snprintf(fz->tasks_path, sizeof(fz->tasks_path), "%s/tasks", fz->dir) >= sizeof(fz->tasks_path))
		goto err_trunc;

	return 0;

err_trunc:
	pr_perror("Path truncation error");
	return -1;
}

static void delete_freezer(const struct freezer *fz)
{
	if (fz->pid > 0) {
		if (kill(fz->pid, SIGKILL))
			pr_perror("Failed to kill %d", fz->pid);
		if (waitpid(fz->pid, NULL, 0) == -1)
			pr_perror("Failed to collect child %d", fz->pid);
	}
	rmdir(fz->dir);
}

static int create_freezers_and_set(struct freezer *parent,
				   struct freezer *child1,
				   struct freezer *child2,
				   enum freezer_index fz_index)
{
	char parent_path[128];

	sprintf(parent_path, "%s/%s", dirname, freezecg);

	if (create_freezer(parent, parent_path, fz_index == FZ1 ? fzname1 : fzname2) < 0)
		return -1;

	if (create_freezer(child1, parent->dir, nested_fzname1))
		goto out_rm_parent;

	if (create_freezer(child2, parent->dir, nested_fzname2))
		goto out_rm_child1;

	if (put_string_to_file(parent->state_path, fz_index == FZ1 ? thawed : frozen) < 0)
		goto out_rm_child2;

	if (put_string_to_file(child1->state_path, thawed) < 0)
		goto out_rm_child2;

	if (put_string_to_file(child2->state_path, frozen) < 0)
		goto out_rm_child2;

	if (create_task_and_add(parent))
		goto out_rm_child2;

	if (create_task_and_add(child1))
		goto out_rm_child2;

	if (create_task_and_add(child2))
		goto out_rm_child2;

	return 0;

out_rm_child2:
	delete_freezer(child2);
out_rm_child1:
	delete_freezer(child1);
out_rm_parent:
	delete_freezer(parent);
	return -1;
}

static void delete_freezers(const struct freezer *parent,
			   const struct freezer *child1,
			   const struct freezer *child2)
{
	put_string_to_file(parent->state_path, thawed);
	put_string_to_file(child1->state_path, thawed);
	put_string_to_file(child2->state_path, thawed);
	delete_freezer(child2);
	delete_freezer(child1);
	delete_freezer(parent);
}

static int check_freezer_states(const struct freezer *parent,
			   const struct freezer *child1,
			   const struct freezer *child2,
			   enum freezer_index fz_index)
{
	switch (fz_index) {
	case FZ1:
		if (check_string_value(parent[fz_index].state_path, thawed))
			goto out_err;
		if (check_string_value(parent[fz_index].self_freezing_path, "0"))
			goto out_err;

		if (check_string_value(child1[fz_index].state_path, thawed))
			goto out_err;
		if (check_string_value(child1[fz_index].self_freezing_path, "0"))
			goto out_err;

		if (check_string_value(child2[fz_index].state_path, frozen))
			goto out_err;
		if (check_string_value(child2[fz_index].self_freezing_path, "1"))
			goto out_err;
		break;
	case FZ2:
		if (check_string_value(parent[fz_index].state_path, frozen))
			goto out_err;
		if (check_string_value(parent[fz_index].self_freezing_path, "1"))
			goto out_err;

		if (check_string_value(child1[fz_index].state_path, frozen))
			goto out_err;
		if (check_string_value(child1[fz_index].self_freezing_path, "0"))
			goto out_err;

		if (check_string_value(child2[fz_index].state_path, frozen))
			goto out_err;
		if (check_string_value(child2[fz_index].self_freezing_path, "1"))
			goto out_err;
		break;
	}

	if (check_string_value(parent[fz_index].tasks_path, parent[fz_index].task))
		goto out_err;

	if (check_string_value(child1[fz_index].tasks_path, child1[fz_index].task))
		goto out_err;

	if (check_string_value(child2[fz_index].tasks_path, child2[fz_index].task))
		goto out_err;

	return 0;
out_err:
	return 1;
}

int main(int argc, char **argv)
{
	int fd = -1;
	static struct freezer fz[2];
	static struct freezer nested_fz1[2];
	static struct freezer nested_fz2[2];
	int fail = 1;

	test_init(argc, argv);

	if (mkdir(dirname, 0700) < 0) {
		pr_perror("Can't make dir");
		return 1;
	}

	if (mount("none", dirname, "cgroup", 0, "freezer")) {
		pr_perror("Can't mount cgroups");
		goto out_rmdir;
	}

	if (create_freezers_and_set(&fz[FZ1], &nested_fz1[FZ1], &nested_fz2[FZ1], FZ1))
		goto out_umnt;

	if (create_freezers_and_set(&fz[FZ2], &nested_fz1[FZ2], &nested_fz2[FZ2], FZ2))
		goto out_del_fz1;

	test_daemon();
	test_waitsig();

	fail = 0;

	if (check_freezer_states(fz, nested_fz1, nested_fz2, FZ1) != 0)
		fail = 1;

	if (check_freezer_states(fz, nested_fz1, nested_fz2, FZ2) != 0)
		fail = 1;

	if (!fail)
		pass();

	delete_freezers(&fz[FZ2], &nested_fz1[FZ2], &nested_fz2[FZ2]);
out_del_fz1:
	delete_freezers(&fz[FZ1], &nested_fz1[FZ1], &nested_fz2[FZ1]);
out_umnt:
	umount(dirname);
out_rmdir:
	rmdir(dirname);
	close(fd);

	return fail;
}
