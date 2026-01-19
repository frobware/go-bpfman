/*
 * bpfman-kernel: minimal libbpf shim for loading BPF programs.
 *
 * This is a stateless helper that loads a BPF program from an object file,
 * pins it, and outputs JSON with the kernel-derived facts.
 *
 * Usage:
 *   bpfman-kernel load <object.o> <program-name> <pin-dir>
 *   bpfman-kernel unpin <pin-dir>
 *
 * The program and its maps are pinned under <pin-dir>/.
 * Output is JSON on stdout.
 *
 * Note: "unpin" removes pins only; it does not detach attached programs.
 */

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cJSON.h"

static char *vmprintf(const char *fmt, va_list args)
{
	va_list ap;
	size_t size;
	char *p;

	va_copy(ap, args);
	size = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	size++;
	if ((p = malloc(size)) == NULL)
		return NULL;

	vsnprintf(p, size, fmt, args);
	return p;
}

__attribute__((format(printf, 1, 2), unused))
static char *mprintf(const char *fmt, ...)
{
	va_list ap;
	char *p;

	va_start(ap, fmt);
	p = vmprintf(fmt, ap);
	va_end(ap);

	return p;
}

static char *must_vmprintf(const char *fmt, va_list args)
{
	char *p = vmprintf(fmt, args);
	if (p == NULL)
		exit(1);
	return p;
}

__attribute__((format(printf, 1, 2), unused))
static char *must_mprintf(const char *fmt, ...)
{
	va_list ap;
	char *p;

	va_start(ap, fmt);
	p = must_vmprintf(fmt, ap);
	va_end(ap);

	return p;
}

/*
 * Buffer to capture libbpf log messages. These are global because
 * libbpf's print callback signature doesn't allow passing user data.
 */
static char *libbpf_log;
static size_t libbpf_log_len;
static size_t libbpf_log_cap;

static int libbpf_print_fn(enum libbpf_print_level level __attribute__((unused)),
			   const char *format, va_list args)
{
	va_list ap;
	size_t needed;
	char *new_log;

	va_copy(ap, args);
	needed = vsnprintf(NULL, 0, format, ap);
	va_end(ap);

	if (libbpf_log_len + needed + 1 > libbpf_log_cap) {
		size_t new_cap = libbpf_log_cap ? libbpf_log_cap * 2 : 1024;
		while (new_cap < libbpf_log_len + needed + 1)
			new_cap *= 2;
		new_log = realloc(libbpf_log, new_cap);
		if (new_log == NULL)
			return 0;
		libbpf_log = new_log;
		libbpf_log_cap = new_cap;
	}

	libbpf_log_len += vsnprintf(libbpf_log + libbpf_log_len,
				    libbpf_log_cap - libbpf_log_len, format, args);
	return 0;
}

static void libbpf_log_clear(void)
{
	libbpf_log_len = 0;
	if (libbpf_log != NULL)
		libbpf_log[0] = '\0';
}

/*
 * Convert the libbpf log buffer to a JSON array of strings.
 * Does not mutate the buffer (unlike strtok-based approaches).
 */
static cJSON *libbpf_log_to_json_array(void)
{
	cJSON *arr = cJSON_CreateArray();
	if (arr == NULL || libbpf_log == NULL || libbpf_log_len == 0)
		return arr;

	const char *start = libbpf_log;
	const char *end = libbpf_log + libbpf_log_len;

	while (start < end) {
		const char *nl = memchr(start, '\n', end - start);
		size_t len = nl ? (size_t)(nl - start) : (size_t)(end - start);

		if (len > 0) {
			char *line = malloc(len + 1);
			if (line != NULL) {
				memcpy(line, start, len);
				line[len] = '\0';
				cJSON_AddItemToArray(arr, cJSON_CreateString(line));
				free(line);
			}
		}

		if (nl == NULL)
			break;
		start = nl + 1;
	}

	return arr;
}

static int ensure_dir(const char *path)
{
	struct stat st;

	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return 0;
		errno = ENOTDIR;
		return -1;
	}

	if (mkdir(path, 0755) < 0)
		return -1;

	return 0;
}

/* Check if path is on a BPF filesystem */
static bool is_bpffs(const char *path)
{
	struct statfs st;
	if (statfs(path, &st) < 0)
		return false;
	return st.f_type == BPF_FS_MAGIC;
}

/*
 * Tracking structure for pinned paths, used for rollback on failure.
 */
struct pinned_set {
	char **paths;
	size_t len;
	size_t cap;
};

static void pinned_set_free(struct pinned_set *ps)
{
	for (size_t i = 0; i < ps->len; i++)
		free(ps->paths[i]);
	free(ps->paths);
	ps->paths = NULL;
	ps->len = 0;
	ps->cap = 0;
}

static bool pinned_set_add(struct pinned_set *ps, const char *path)
{
	if (ps->len == ps->cap) {
		size_t new_cap = ps->cap ? ps->cap * 2 : 8;
		char **new_paths = realloc(ps->paths, new_cap * sizeof(*new_paths));
		if (new_paths == NULL)
			return false;
		ps->paths = new_paths;
		ps->cap = new_cap;
	}
	ps->paths[ps->len] = strdup(path);
	if (ps->paths[ps->len] == NULL)
		return false;
	ps->len++;
	return true;
}

static void pinned_set_rollback(struct pinned_set *ps)
{
	for (size_t i = 0; i < ps->len; i++)
		unlink(ps->paths[i]);
	pinned_set_free(ps);
}

/* Reject names that are unsafe for use as pin path components */
static bool valid_pin_name(const char *name)
{
	if (name == NULL || name[0] == '\0')
		return false;
	if (strchr(name, '/') != NULL)
		return false;
	if (strcmp(name, "..") == 0)
		return false;
	if (strcmp(name, ".") == 0)
		return false;
	return true;
}

/*
 * Build a path from directory and name, returning a malloc'd string.
 * Returns NULL on allocation failure or if the name is invalid.
 */
static char *join_path(const char *dir, const char *name)
{
	if (!valid_pin_name(name))
		return NULL;
	return must_mprintf("%s/%s", dir, name);
}

static void print_json(cJSON *json)
{
	char *str = cJSON_Print(json);
	if (str != NULL) {
		printf("%s\n", str);
		free(str);
	}
}

/*
 * Emit an error response in envelope format.
 * op and pin_dir may be NULL if not yet known.
 */
static int emit_error_ctx(const char *op, const char *pin_dir, int errnum, const char *fmt, va_list args)
{
	cJSON *root = cJSON_CreateObject();
	cJSON *error = cJSON_CreateObject();
	cJSON *messages = cJSON_CreateArray();
	char *msg;

	if (op != NULL)
		cJSON_AddStringToObject(root, "op", op);
	if (pin_dir != NULL)
		cJSON_AddStringToObject(root, "pin_dir", pin_dir);

	msg = must_vmprintf(fmt, args);
	cJSON_AddItemToArray(messages, cJSON_CreateString(msg));
	free(msg);

	cJSON_AddNumberToObject(error, "errno", errnum);
	cJSON_AddItemToObject(error, "messages", messages);
	cJSON_AddItemToObject(error, "libbpf_log", libbpf_log_to_json_array());
	cJSON_AddItemToObject(root, "error", error);

	libbpf_log_clear();

	print_json(root);
	cJSON_Delete(root);

	return 1;
}

__attribute__((format(printf, 3, 4)))
static int emit_load_error(const char *pin_dir, int errnum, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = emit_error_ctx("load", pin_dir, errnum, fmt, args);
	va_end(args);

	return ret;
}

__attribute__((format(printf, 3, 4)))
static int emit_unpin_error(const char *pin_dir, int errnum, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = emit_error_ctx("unpin", pin_dir, errnum, fmt, args);
	va_end(args);

	return ret;
}

/* Usage error (no op/pin_dir context) */
__attribute__((format(printf, 2, 3)))
static int emit_usage_error(int errnum, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = emit_error_ctx(NULL, NULL, errnum, fmt, args);
	va_end(args);

	return ret;
}

static int cmd_load(const char *obj_path, const char *prog_name, const char *pin_dir)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_map *map;
	struct pinned_set pinned = {0};
	char *pin_path = NULL;
	int prog_fd, prog_id;
	int err;
	int ret = 1;
	cJSON *root = NULL;
	cJSON *prog_json = NULL;
	cJSON *maps_json = NULL;

	/* Open the object file */
	obj = bpf_object__open(obj_path);
	if (obj == NULL) {
		err = errno;
		emit_load_error(pin_dir, err, "failed to open %s: %s", obj_path, strerror(err));
		goto out;
	}

	/* Validate program name before using it in pin path */
	if (!valid_pin_name(prog_name)) {
		emit_load_error(pin_dir, EINVAL, "invalid program name '%s'", prog_name);
		goto out;
	}

	/* Find the program by name */
	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (prog == NULL) {
		emit_load_error(pin_dir, ENOENT, "program '%s' not found in %s", prog_name, obj_path);
		goto out;
	}

	/* Disable autoload for all programs except the target */
	struct bpf_program *p;
	bpf_object__for_each_program(p, obj) {
		bool want = (p == prog);
		bpf_program__set_autoload(p, want);
	}

	/* Load the object (programs + maps) into the kernel */
	err = bpf_object__load(obj);
	if (err) {
		emit_load_error(pin_dir, -err, "failed to load object: %s", strerror(-err));
		goto out;
	}

	/* Get program fd and id */
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		emit_load_error(pin_dir, -prog_fd, "failed to get program fd: %s", strerror(-prog_fd));
		goto out;
	}

	struct bpf_prog_info prog_info = {};
	__u32 info_len = sizeof(prog_info);
	/* bpf_prog_get_info_by_fd returns -1 and sets errno, not -errno */
	if (bpf_prog_get_info_by_fd(prog_fd, &prog_info, &info_len) < 0) {
		err = errno;
		emit_load_error(pin_dir, err, "failed to get program info: %s", strerror(err));
		goto out;
	}
	prog_id = prog_info.id;

	/* Ensure pin directory exists */
	if (ensure_dir(pin_dir) < 0) {
		err = errno;
		emit_load_error(pin_dir, err, "failed to create pin directory %s: %s", pin_dir, strerror(err));
		goto out;
	}

	/* Validate pin directory is on bpffs */
	if (!is_bpffs(pin_dir)) {
		emit_load_error(pin_dir, EINVAL, "pin directory %s is not on a BPF filesystem", pin_dir);
		goto out;
	}

	/* Pin the program */
	pin_path = join_path(pin_dir, prog_name);
	if (pin_path == NULL) {
		emit_load_error(pin_dir, ENOMEM, "failed to build pin path for program");
		goto out;
	}
	err = bpf_program__pin(prog, pin_path);
	if (err) {
		emit_load_error(pin_dir, -err, "failed to pin program to %s: %s", pin_path, strerror(-err));
		goto out;
	}
	if (!pinned_set_add(&pinned, pin_path)) {
		emit_load_error(pin_dir, ENOMEM, "failed to track pinned path");
		goto out_rollback;
	}

	/* Build JSON output */
	root = cJSON_CreateObject();
	cJSON_AddStringToObject(root, "op", "load");
	cJSON_AddStringToObject(root, "pin_dir", pin_dir);

	prog_json = cJSON_CreateObject();
	cJSON_AddNumberToObject(prog_json, "kernel_id", prog_id);
	cJSON_AddStringToObject(prog_json, "name", prog_name);
	cJSON_AddNumberToObject(prog_json, "type", bpf_program__type(prog));
	cJSON_AddStringToObject(prog_json, "pinned_path", pin_path);
	cJSON_AddItemToObject(root, "program", prog_json);

	free(pin_path);
	pin_path = NULL;

	maps_json = cJSON_CreateArray();

	/* Pin maps and collect info */
	bpf_object__for_each_map(map, obj) {
		int map_fd = bpf_map__fd(map);
		const char *map_name = bpf_map__name(map);
		struct bpf_map_info map_info = {};
		__u32 map_info_len = sizeof(map_info);
		cJSON *map_json;

		if (map_fd < 0)
			continue;

		/* Build pin path (validates map_name internally) */
		pin_path = join_path(pin_dir, map_name);
		if (pin_path == NULL) {
			emit_load_error(pin_dir, EINVAL, "invalid map name '%s'", map_name);
			goto out_rollback;
		}

		/* bpf_map_get_info_by_fd returns -1 and sets errno, not -errno */
		if (bpf_map_get_info_by_fd(map_fd, &map_info, &map_info_len) < 0) {
			err = errno;
			emit_load_error(pin_dir, err, "failed to get map info for '%s': %s", map_name, strerror(err));
			goto out_rollback;
		}

		/* Pin the map */
		err = bpf_map__pin(map, pin_path);
		if (err) {
			emit_load_error(pin_dir, -err, "failed to pin map '%s' to %s: %s", map_name, pin_path, strerror(-err));
			goto out_rollback;
		}
		if (!pinned_set_add(&pinned, pin_path)) {
			emit_load_error(pin_dir, ENOMEM, "failed to track pinned path");
			goto out_rollback;
		}

		map_json = cJSON_CreateObject();
		cJSON_AddNumberToObject(map_json, "kernel_id", map_info.id);
		cJSON_AddStringToObject(map_json, "name", map_name);
		cJSON_AddNumberToObject(map_json, "type", map_info.type);
		cJSON_AddStringToObject(map_json, "pinned_path", pin_path);
		cJSON_AddItemToArray(maps_json, map_json);

		free(pin_path);
		pin_path = NULL;
	}

	cJSON_AddItemToObject(root, "maps", maps_json);
	cJSON_AddItemToObject(root, "libbpf_log", libbpf_log_to_json_array());
	libbpf_log_clear();

	print_json(root);
	ret = 0;
	goto out;

out_rollback:
	pinned_set_rollback(&pinned);

out:
	free(pin_path);
	pinned_set_free(&pinned);
	if (root != NULL)
		cJSON_Delete(root);
	if (obj != NULL)
		bpf_object__close(obj);
	return ret;
}

static int cmd_unpin(const char *pin_dir)
{
	DIR *dir;
	struct dirent *entry;
	char *path = NULL;
	int count = 0;
	int errors = 0;
	int err;
	cJSON *root;

	dir = opendir(pin_dir);
	if (dir == NULL) {
		err = errno;
		return emit_unpin_error(pin_dir, err, "failed to open directory %s: %s", pin_dir, strerror(err));
	}

	/* Remove all entries in the directory */
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		free(path);
		path = must_mprintf("%s/%s", pin_dir, entry->d_name);
		if (unlink(path) < 0)
			errors++;
		else
			count++;
	}
	free(path);

	closedir(dir);

	/* Remove the directory itself */
	if (rmdir(pin_dir) < 0)
		errors++;

	/* Output JSON */
	root = cJSON_CreateObject();
	cJSON_AddStringToObject(root, "op", "unpin");
	cJSON_AddStringToObject(root, "pin_dir", pin_dir);
	cJSON_AddNumberToObject(root, "unpinned", count);
	cJSON_AddNumberToObject(root, "errors", errors);
	print_json(root);
	cJSON_Delete(root);

	return errors > 0 ? 1 : 0;
}

int main(int argc, char **argv)
{
	libbpf_set_print(libbpf_print_fn);

	if (argc < 2)
		return emit_usage_error(EINVAL, "usage: %s load <object.o> <program-name> <pin-dir> | unpin <pin-dir>", argv[0]);

	if (strcmp(argv[1], "load") == 0) {
		if (argc != 5)
			return emit_usage_error(EINVAL, "usage: %s load <object.o> <program-name> <pin-dir>", argv[0]);
		return cmd_load(argv[2], argv[3], argv[4]);
	}

	if (strcmp(argv[1], "unpin") == 0) {
		if (argc != 3)
			return emit_usage_error(EINVAL, "usage: %s unpin <pin-dir>", argv[0]);
		return cmd_unpin(argv[2]);
	}

	return emit_usage_error(EINVAL, "unknown command '%s'", argv[1]);
}
