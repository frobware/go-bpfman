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

/* Reject names containing path separators to prevent directory traversal */
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

static void print_json(cJSON *json)
{
	char *str = cJSON_Print(json);
	if (str != NULL) {
		printf("%s\n", str);
		free(str);
	}
}

static int emit_errorv(int errnum, const char *fmt, va_list args)
{
	cJSON *root = cJSON_CreateObject();
	cJSON *error = cJSON_CreateObject();
	cJSON *messages = cJSON_CreateArray();
	char *msg;

	/* Add any captured libbpf messages first (they happened before our error) */
	if (libbpf_log_len > 0) {
		char *line = strtok(libbpf_log, "\n");
		while (line) {
			if (*line)
				cJSON_AddItemToArray(messages, cJSON_CreateString(line));
			line = strtok(NULL, "\n");
		}
		libbpf_log_clear();
	}

	msg = must_vmprintf(fmt, args);
	cJSON_AddItemToArray(messages, cJSON_CreateString(msg));
	free(msg);

	cJSON_AddNumberToObject(error, "errno", errnum);
	cJSON_AddItemToObject(error, "messages", messages);
	cJSON_AddItemToObject(root, "error", error);

	print_json(root);
	cJSON_Delete(root);

	return 1;
}

static int emit_error(int errnum, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = emit_errorv(errnum, fmt, args);
	va_end(args);

	return ret;
}

static int cmd_load(const char *obj_path, const char *prog_name, const char *pin_dir)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_map *map;
	char pin_path[512];
	int prog_fd, prog_id;
	int err;
	cJSON *root = NULL;
	cJSON *prog_json = NULL;
	cJSON *maps_json = NULL;

	/* Open the object file */
	obj = bpf_object__open(obj_path);
	if (obj == NULL) {
		err = errno;
		return emit_error(err, "failed to open %s: %s", obj_path, strerror(err));
	}

	/* Validate program name before using it in pin path */
	if (!valid_pin_name(prog_name)) {
		bpf_object__close(obj);
		return emit_error(EINVAL, "invalid program name '%s': contains path separator", prog_name);
	}

	/* Find the program by name */
	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (prog == NULL) {
		bpf_object__close(obj);
		return emit_error(ENOENT, "program '%s' not found in %s", prog_name, obj_path);
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
		bpf_object__close(obj);
		return emit_error(-err, "failed to load object: %s", strerror(-err));
	}

	/* Get program fd and id */
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		bpf_object__close(obj);
		return emit_error(-prog_fd, "failed to get program fd: %s", strerror(-prog_fd));
	}

	struct bpf_prog_info prog_info = {};
	__u32 info_len = sizeof(prog_info);
	/* bpf_prog_get_info_by_fd returns -1 and sets errno, not -errno */
	if (bpf_prog_get_info_by_fd(prog_fd, &prog_info, &info_len) < 0) {
		err = errno;
		bpf_object__close(obj);
		return emit_error(err, "failed to get program info: %s", strerror(err));
	}
	prog_id = prog_info.id;

	/* Ensure pin directory exists */
	if (ensure_dir(pin_dir) < 0) {
		err = errno;
		bpf_object__close(obj);
		return emit_error(err, "failed to create pin directory %s: %s", pin_dir, strerror(err));
	}

	/* Validate pin directory is on bpffs */
	if (!is_bpffs(pin_dir)) {
		bpf_object__close(obj);
		return emit_error(EINVAL, "pin directory %s is not on a BPF filesystem", pin_dir);
	}

	/* Pin the program */
	snprintf(pin_path, sizeof(pin_path), "%s/%s", pin_dir, prog_name);
	err = bpf_program__pin(prog, pin_path);
	if (err) {
		bpf_object__close(obj);
		return emit_error(-err, "failed to pin program to %s: %s", pin_path, strerror(-err));
	}

	/* Build JSON output */
	root = cJSON_CreateObject();
	prog_json = cJSON_CreateObject();
	maps_json = cJSON_CreateArray();

	cJSON_AddStringToObject(prog_json, "name", prog_name);
	cJSON_AddNumberToObject(prog_json, "type", bpf_program__type(prog));
	cJSON_AddNumberToObject(prog_json, "id", prog_id);
	cJSON_AddStringToObject(prog_json, "pinned", pin_path);
	cJSON_AddItemToObject(root, "program", prog_json);

	/* Pin maps and collect info (fail hard on any error) */
	bpf_object__for_each_map(map, obj) {
		int map_fd = bpf_map__fd(map);
		const char *map_name = bpf_map__name(map);
		struct bpf_map_info map_info = {};
		__u32 map_info_len = sizeof(map_info);
		cJSON *map_json;

		if (map_fd < 0)
			continue;

		/* Validate map name before using it in pin path */
		if (!valid_pin_name(map_name)) {
			cJSON_Delete(root);
			bpf_object__close(obj);
			return emit_error(EINVAL, "invalid map name '%s': contains path separator", map_name);
		}

		/* bpf_map_get_info_by_fd returns -1 and sets errno, not -errno */
		if (bpf_map_get_info_by_fd(map_fd, &map_info, &map_info_len) < 0) {
			err = errno;
			cJSON_Delete(root);
			bpf_object__close(obj);
			return emit_error(err, "failed to get map info for '%s': %s", map_name, strerror(err));
		}

		/* Pin the map */
		snprintf(pin_path, sizeof(pin_path), "%s/%s", pin_dir, map_name);
		err = bpf_map__pin(map, pin_path);
		if (err) {
			cJSON_Delete(root);
			bpf_object__close(obj);
			return emit_error(-err, "failed to pin map '%s' to %s: %s", map_name, pin_path, strerror(-err));
		}

		map_json = cJSON_CreateObject();
		cJSON_AddStringToObject(map_json, "name", map_name);
		cJSON_AddNumberToObject(map_json, "type", map_info.type);
		cJSON_AddNumberToObject(map_json, "id", map_info.id);
		cJSON_AddStringToObject(map_json, "pinned", pin_path);
		cJSON_AddItemToArray(maps_json, map_json);
	}

	cJSON_AddItemToObject(root, "maps", maps_json);

	print_json(root);
	cJSON_Delete(root);

	bpf_object__close(obj);
	return 0;
}

static int cmd_unpin(const char *pin_dir)
{
	DIR *dir;
	struct dirent *entry;
	char path[512];
	int count = 0;
	int errors = 0;
	int err;
	cJSON *root;

	dir = opendir(pin_dir);
	if (dir == NULL) {
		err = errno;
		return emit_error(err, "failed to open directory %s: %s", pin_dir, strerror(err));
	}

	/* Remove all entries in the directory */
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", pin_dir, entry->d_name);
		if (unlink(path) < 0)
			errors++;
		else
			count++;
	}

	closedir(dir);

	/* Remove the directory itself */
	if (rmdir(pin_dir) < 0)
		errors++;

	/* Output JSON */
	root = cJSON_CreateObject();
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
		return emit_error(EINVAL, "usage: %s load <object.o> <program-name> <pin-dir> | unpin <pin-dir>", argv[0]);

	if (strcmp(argv[1], "load") == 0) {
		if (argc != 5)
			return emit_error(EINVAL, "usage: %s load <object.o> <program-name> <pin-dir>", argv[0]);
		return cmd_load(argv[2], argv[3], argv[4]);
	}

	if (strcmp(argv[1], "unpin") == 0) {
		if (argc != 3)
			return emit_error(EINVAL, "usage: %s unpin <pin-dir>", argv[0]);
		return cmd_unpin(argv[2]);
	}

	return emit_error(EINVAL, "unknown command '%s'", argv[1]);
}
