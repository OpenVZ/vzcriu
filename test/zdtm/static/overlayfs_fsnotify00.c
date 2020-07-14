#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <sys/fanotify.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include "fs.h"

#include "zdtmtst.h"

const char *test_doc = "Check that fanotify work on overlayfs mounts";
const char *test_author = "Valeriy Vdovin <valeriy.vdovin@virtuozzo.com>";

char *dirname = "overlayfs_fsnotify";
TEST_OPTION(dirname, string, "directory name", 1);

/*
 * Maximum number of seconds to wait for incoming events before
 * failing.
 */
#define TEST_TIMEOUT_SECONDS 12

struct fileobject {
	int fd;
	char *filepath;
};

enum {
	ACTION_TYPE_UNDEFINED = 0,
	ACTION_TYPE_CREATE,
	ACTION_TYPE_OPEN,
	ACTION_TYPE_MODIFY,
	ACTION_TYPE_DELETE,
	ACTION_TYPE_ACCESS,
	ACTION_TYPE_CLOSE
};

const char *action_type_to_string(int type)
{
#define CASE(a) case ACTION_TYPE_ ## a: return #a
	switch (type) {
	CASE(UNDEFINED);
	CASE(CREATE);
	CASE(OPEN);
	CASE(MODIFY);
	CASE(DELETE);
	CASE(ACCESS);
	CASE(CLOSE);
	default: return "UNKNOWN";
	}
#undef CASE
}

struct action {
	/* file op performed on this file object */
	struct fileobject *f;
	/* type of file operation to be performed */
	int type;
	/* file op flags arg if applicable */
	int flags;
	/* file op mode arg if applicable */
	int mode;
	/* expected event_mask for this event */
	int event_mask;
};

struct action_script {
	struct action actions[32];
	int num_actions;
};

struct test_context {
	/*
	 * placeholder for more possible params
	 * to pass around.
	 */
	char *ovl_dir;

	/*
	 * notify_fd - file descriptor, acquired after fsnotify
	 * init function (fanotify_init or inotify_init)
	 */
	int notify_fd;

	/* current working directory queried once */
	char *cwd;
};

struct fsnotify_test_ops {
	int (*setup)(struct test_context *ctx);
	int (*generate_actions)(struct test_context *ctx);
	int (*process_events)(struct test_context *ctx, const char *eventbuf,
			      int eventbuf_sz, struct action **action,
			      struct action *end_action);
};

static struct test_context context;

static struct action_script script;

static bool event_generator_exited;

static void sigchld_handler(int signum)
{
	int status;
	pid_t pid;

	pid = wait(&status);
	event_generator_exited = true;
	test_msg("Process %d exited with status:%d\n", pid, status);
}

static inline bool is_same_filepath(const char *path1, const char *path2)
{
	return !strcmp(path1, path2);
}

static inline int sleep_ms(int msec)
{
	int err;
	struct timespec ts, rm;

	ts.tv_sec = msec / 1000;
	msec -= ts.tv_sec * 1000;
	ts.tv_nsec = msec * 1000000;
	do {
		err = nanosleep(&ts, &rm);
		ts = rm;
	} while (err && errno == EINTR);

	if (err)
		pr_perror("sleep_ms: %d", msec);

	return err;
}

/*
 * Prepare dirname, so that all mounts in it will not propagate and
 * will be destroyed together with our mount namespace. All files
 * created in it will not be visible on host and will remove together
 * with our mountns too.
 */
static int prepare_dirname(void)
{
	if (mkdir(dirname, 0700) && errno != EEXIST) {
		pr_perror("Failed to create %s", dirname);
		return -1;
	}

	if (mount("none", dirname, "tmpfs", 0, NULL)) {
		pr_perror("Failed to mount tmpfs on %s", dirname);
		return -1;
	}

	if (mount(NULL, dirname, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Failed to make mount %s private", dirname);
		return -1;
	}

	return 0;
}

static int setup_overlayfs(struct test_context *ctx)
{
	const char *lower_list[] = { "lower", NULL };
	const char *mountdir = "overlayfs";
	char mountpath[PATH_MAX];

	if (prepare_dirname())
		return 1;

	if (overlayfs_setup(dirname, lower_list, "upper", "work", mountdir)) {
		fail("failed to setup overlayfs for test");
		return 1;
	}

	snprintf(mountpath, sizeof(mountpath), "%s/%s", dirname, mountdir);
	ctx->ovl_dir = strdup(mountpath);
	if (!ctx->ovl_dir) {
		fail("Can't copy ovl dir name");
		return 1;
	}

	return 0;
}

static void action_to_string(char *buf, int bufsz, struct action *a)
{
	snprintf(buf, bufsz, "action: path:%s, fd:%d, type:%s, mode:%d",
		 (a->f && a->f->filepath) ? a->f->filepath : "<none>", a->f ? a->f->fd : -1,
		 action_type_to_string(a->type), a->mode);
}

static struct fileobject *fileobject_new(const char *current_dir, const char *ovl_dir, const char *name)
{
	char filepath[PATH_MAX];
	struct fileobject *f;

	f = malloc(sizeof(*f));
	if (!f) {
		pr_err("failed to allocated fileobject\n");
		return NULL;
	}

	f->fd = -1;
	if (name)
		snprintf(filepath, sizeof(filepath), "%s/%s/%s", current_dir, ovl_dir, name);
	else
		snprintf(filepath, sizeof(filepath), "%s/%s", current_dir, ovl_dir);

	f->filepath = strdup(filepath);
	if (!f->filepath) {
		pr_err("failed to copy filepath\n");
		free(f);
		return NULL;
	}
	return f;
}

void action_script_init(void)
{
	memset(&script, 0, sizeof(script));
}

int action_script_add(struct fileobject *f, int type, int flags, int mode, int event_mask)
{
	struct action *a;
	if (script.num_actions > ARRAY_SIZE(script.actions)) {
		pr_err("action_script_add: array limit reached (%ld items)\n", ARRAY_SIZE(script.actions));
		return 1;
	}
	a = &script.actions[script.num_actions++];
	a->f = f;
	a->type = type;
	a->mode = mode;
	a->flags = flags;
	a->event_mask = event_mask;
	return 0;
}

#define ACTION_ADD(f, t, fl, m, em)                     \
	do {                                            \
		if (action_script_add(f, t, fl, m, em)) \
			return -1;                      \
	} while (0)

int fsnotify_action_run_create(struct action *a)
{
	if (a->f->fd != -1) {
		pr_err("fsnotify_action_run_create: failed, fd for file %s already opened\n", a->f->filepath);
		return 1;
	}

	a->f->fd = open(a->f->filepath, O_CREAT | O_TRUNC | a->flags, a->mode);
	if (a->f->fd == -1) {
		pr_perror("fsnotify_action_run_create: failed to create %s", a->f->filepath);
		return 1;
	}
	return 0;
}

int fsnotify_action_run_open(struct action *a)
{
	a->f->fd = open(a->f->filepath, a->flags, a->mode);
	if (a->f->fd == -1) {
		pr_perror("open(%s,%x,%x) failed", a->f->filepath, a->flags, a->mode);
		return 1;
	}
	return 0;
}

int fsnotify_action_run_modify(struct action *a)
{
	int n;
	char payload[64];

	if (a->f->fd == -1) {
		pr_err("fsnotify_action_run_modify: fd for file %s not opened\n", a->f->filepath);
		return 1;
	}

	memset(payload, 0xce, sizeof(payload));

	n = write(a->f->fd, payload, sizeof(payload));
	if (n != sizeof(payload)) {
		pr_perror("fsnotify_action_run_modify: write to %s failed", a->f->filepath);
		return 1;
	}
	return 0;
}

int fsnotify_action_run_access(struct action *a)
{
	if (access(a->f->filepath, a->mode)) {
		pr_perror("access %s mode: %d failed", a->f->filepath, a->mode);
		return 1;
	}
	return 0;
}

int fsnotify_action_run_close(struct action *a)
{
	if (a->f->fd == -1) {
		pr_err("fsnotify_action_run_close: failed, fd for file %s not opened\n", a->f->filepath);
		return 1;
	}

	close(a->f->fd);
	a->f->fd = -1;
	return 0;
}

static inline int fsnotify_action_run(struct action *a)
{
	char actionbuf[512];

	action_to_string(actionbuf, sizeof(actionbuf), a);

	test_msg("fsnotify_action_run: run: %s\n", actionbuf);
	switch (a->type) {
	case ACTION_TYPE_ACCESS:
		return fsnotify_action_run_access(a);
	case ACTION_TYPE_OPEN:
		return fsnotify_action_run_open(a);
	case ACTION_TYPE_CLOSE:
		return fsnotify_action_run_close(a);
	case ACTION_TYPE_CREATE:
		return fsnotify_action_run_create(a);
	case ACTION_TYPE_MODIFY:
		return fsnotify_action_run_modify(a);
	default:
		pr_err("unknown action type %d\n", a->type);
		return 1;
	}
}

static int fsnotify_actions_run(void)
{
	int i;

	test_msg("fsnotify_actions_run, will perform %d actions\n", script.num_actions);

	for (i = 0; i < script.num_actions; ++i) {
		if (fsnotify_action_run(&script.actions[i])) {
			pr_err("fsnotify_action_run failed\n");
			return 1;
		}
		if (sleep_ms(500)) {
			pr_err("failed to sleep between actions\n");
			return 1;
		}
	}
	return 0;
}

/*
 * Event generator is forked process that will perform file operations
 * like open/close/write on file objects according to specified test
 * script.
 */
static int event_generator_fork(void)
{
	pid_t pid;

	event_generator_exited = false;
	pid = fork();
	if (pid == -1) {
		pr_perror("fork failed");
		return 1;
	}

	if (pid == 0)
		exit(fsnotify_actions_run());
	else
		test_msg("event_generator forked with pid %d\n", pid);
	return 0;
}

#ifdef ZDTM_OVL_FSNOTIFY_FANOTIFY
static int fanotify_setup(struct test_context *ctx)
{
	int fa_flags;
	int fa_fd;

	fa_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK, 0);

	if (fa_fd == -1) {
		pr_perror("fanotify_init");
		return -1;
	}

	fa_flags = FAN_ACCESS | FAN_MODIFY | FAN_OPEN |
		   FAN_CLOSE | FAN_ONDIR | FAN_EVENT_ON_CHILD;

	if (fanotify_mark(fa_fd, FAN_MARK_ADD, fa_flags, AT_FDCWD,
		ctx->ovl_dir)) {
		pr_perror("fanotify_mark FAN_MARK_ADD");
		close(fa_fd);
		return -1;
	}
	ctx->notify_fd = fa_fd;
	return 0;
}

static int fanotify_generate_actions(struct test_context *ctx)
{
	struct fileobject *f;

	action_script_init();

	f = fileobject_new(ctx->cwd, ctx->ovl_dir, "file1");
	if (f == NULL) {
		pr_err("failed to create fileobject\n");
		return 1;
	}

	ACTION_ADD(f, ACTION_TYPE_CREATE, 0, 0, FAN_OPEN);
	ACTION_ADD(f, ACTION_TYPE_CLOSE, 0, 0, FAN_CLOSE_NOWRITE);
	ACTION_ADD(f, ACTION_TYPE_OPEN, O_RDWR, 0, FAN_OPEN);
	ACTION_ADD(f, ACTION_TYPE_MODIFY, 0, 0, FAN_MODIFY);
	ACTION_ADD(f, ACTION_TYPE_CLOSE, 0, 0, FAN_CLOSE_WRITE);

	f = fileobject_new(ctx->cwd, ctx->ovl_dir, NULL);
	if (f == NULL) {
		pr_err("failed to create fileobject\n");
		return 1;
	}
	ACTION_ADD(f, ACTION_TYPE_OPEN, 0, 0, FAN_OPEN);
	ACTION_ADD(f, ACTION_TYPE_CLOSE, 0, 0, FAN_CLOSE_NOWRITE);
	return 0;
}

static int fanotify_meta_fd_to_path(int meta_fd, char *pathbuf, int pathbuf_len)
{
	char procfd_path[PATH_MAX];
	int procfd_path_len;

	snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d", meta_fd);
	procfd_path_len = readlink(procfd_path, pathbuf, pathbuf_len - 1);
	if (procfd_path_len == -1) {
		pr_perror("readlink");
		return 1;
	}
	pathbuf[procfd_path_len] = 0;
	return 0;
}

static void fanotify_event_mask_to_string(char *buf, int bufsz, int mask)
{
	int n = 0;

#define FAN_MASK_PRINT(a)                                          \
	do {                                                       \
		if (mask & FAN_##a)                                \
			n += snprintf(buf + n, bufsz - n, " " #a); \
	} while (0)

	FAN_MASK_PRINT(ACCESS);
	FAN_MASK_PRINT(MODIFY);
	FAN_MASK_PRINT(OPEN);
	FAN_MASK_PRINT(CLOSE_NOWRITE);
	FAN_MASK_PRINT(CLOSE_WRITE);
#undef FAN_MASK_PRINT
}

static void fanotify_event_print(struct fanotify_event_metadata *meta, const char *path)
{
	char eventbuf[512];

	fanotify_event_mask_to_string(eventbuf, sizeof(eventbuf), meta->mask);
	test_msg("fa_event: fd:%d, pid:%d, mask:%08llx, path:%s, events:%s\n",
		 meta->fd, meta->pid, meta->mask, path, eventbuf);
}

static int fanotify_process_event(struct fanotify_event_metadata *meta, struct action *expected_action)
{
	char path[PATH_MAX];

	if (meta->vers != FANOTIFY_METADATA_VERSION) {
		pr_err("err fanotify meta corrupted\n");
		return 1;
	}

	if (fanotify_meta_fd_to_path(meta->fd, path, sizeof(path))) {
		pr_err("failed to get file path from fanotify meta fd\n");
		return 1;
	}

	fanotify_event_print(meta, path);
	if (!is_same_filepath(path, expected_action->f->filepath)) {
		fail("fanotify event mismatch: not same filepath: %s %s",
		     path, expected_action->f->filepath);
		return 1;
	}
	if (expected_action->event_mask != meta->mask) {
		fail("fanotify event mismatch");
		return 1;
	}
	close(meta->fd);
	return 0;
}

static int fanotify_process_events(struct test_context *ctx,
				   const char *eventbuf, int eventbuf_sz,
				   struct action **expected_action,
				   struct action *end_action)
{
	struct fanotify_event_metadata *meta;

	meta = (struct fanotify_event_metadata *)eventbuf;
	while (FAN_EVENT_OK(meta, eventbuf_sz)) {
		if (*expected_action == end_action)
			break;

		if (fanotify_process_event(meta, *expected_action)) {
			fail("fanotify_process_events failed");
			return 1;
		}
		(*expected_action)++;
		meta = FAN_EVENT_NEXT(meta, eventbuf_sz);
	}
	return 0;
}
#endif /* ZDTM_OVL_FSNOTIFY_FANOTIFY */

static int fsnotify_events_skip(int notify_fd)
{
	int n = -1, sum = 0;
	char buf[256];

	while (n) {
		n = read(notify_fd, buf, sizeof(buf));
		if (n == -1) {
			if (errno == EAGAIN) {
				n = 0;
			} else {
				pr_perror("read error on notify_fd=%d", notify_fd);
				return 1;
			}
		}
		sum += n;
	}

	/*
	 * For now do not differentiate between inotify/fanotify events,
	 * just skip raw reports.
	 */
	test_msg("skipped events with total report size: %d\n", sum);
	return 0;
}

int fsnotify_events_catch(struct test_context *ctx,
			  struct fsnotify_test_ops *notify_ops, int notify_fd)
{
	time_t timeout;
	int n;
	char eventbuf[256];

	struct action_script *s = &script;
	struct action *expected_action = &s->actions[0];
	struct action *end_action = &s->actions[s->num_actions];

	memset(eventbuf, 0, sizeof(eventbuf));

	/*
	 * In this loop we read from fanotify descriptor
	 * and expected notifications to arrive in a specific
	 * order, which are specified in action_script in
	 * s->actions.
	 *
	 * For simplicity the loop just uses non-blocking reads
	 * with EAGAIN as normal return value between events,
	 * Smart polling would result in more complex code.
	 *
	 * It is expected that we succeed when all events arrive.
	 * But if for some reason events stop arriving, we'll get
	 * endless loop.
	 *
	 * We protect against endless loop by providing timeout.
	 *
	 * Another way to break from the loop is to check that the
	 * process that generates events has exited.
	 * event_generator_exited is the flag, set by SIGCHLD handler.
	 */
	timeout = time(0) + TEST_TIMEOUT_SECONDS;

	while (expected_action != end_action && !event_generator_exited) {
		if (time(0) > timeout) {
			fail("timeout reached");
			return 1;
		}
		n = read(notify_fd, eventbuf, sizeof(eventbuf));
		if (n == -1) {
			if (errno == EAGAIN)
				continue;

			pr_perror("read error on notify_fd=%d", notify_fd);
			return 1;
		}

		if (notify_ops->process_events(ctx, eventbuf, n, &expected_action, end_action))
			break;
	}

	if (expected_action != end_action) {
		fail("not all actions have been checked");
		return -1;
	}
	return 0;
}

static void event_generator_wait(void)
{
	while (!event_generator_exited)
		sleep_ms(100);
}

void fsnotify_test_ops_init(struct fsnotify_test_ops *ops)
{
#if defined(ZDTM_OVL_FSNOTIFY_FANOTIFY)
	ops->setup = fanotify_setup;
	ops->generate_actions = fanotify_generate_actions;
	ops->process_events = fanotify_process_events;
#else
#error "ZDTM_OVL_FSNOTIFY_* not defined"
#endif
}

int main(int argc, char **argv)
{
	int err;
	struct test_context *ctx = &context;
	struct fsnotify_test_ops notify_ops;

	test_init(argc, argv);

	fsnotify_test_ops_init(&notify_ops);

	memset(ctx, 0, sizeof(*ctx));
	ctx->cwd = get_current_dir_name();
	test_msg("cwd: %s\n", ctx->cwd);
	if (!ctx->cwd) {
		pr_perror("getcwd failed");
		return -1;
	}

	if (setup_overlayfs(ctx)) {
		fail("failed to setup overlayfd");
		return 1;
	}

	if (notify_ops.setup(ctx)) {
		fail("fanotify_setup failed");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/*
	 * Skip events that may have happened during overlayfs restore,
	 * because in this test we want to track events in given order
	 */
	if (fsnotify_events_skip(ctx->notify_fd)) {
		fail("fsnotify_events_skip failed");
		return 1;
	}

	/*
	 * Generate a list of events that should be generated by event
	 * generator and expected by testing code.
	 */
	if (notify_ops.generate_actions(ctx) == -1) {
		fail("fsnotify generate_actions failed");
		return 1;
	}

	/*
	 * Start catching SIGCHLD signal before forking the child event
	 * generator.
	 */
	signal(SIGCHLD, sigchld_handler);

	/*
	 * Start generating fanotify events in child process.
	 */
	if (event_generator_fork()) {
		fail("failed to start event_generator");
		return 1;
	}

	/*
	 * Catch fanotify events from event_generator according to
	 * generated script.
	 */
	err = fsnotify_events_catch(ctx, &notify_ops, ctx->notify_fd);

	/*
	 * Wait for event generator to exit.
	 */
	event_generator_wait();

	if (err) {
		fail("fsnotify_events_catch failed");
		return 1;
	}

	pass();
	return 0;
}
