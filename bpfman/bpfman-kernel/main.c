/*
 * bpfman-kernel: minimal libbpf shim for loading BPF programs.
 *
 * This is a stateless helper that loads a BPF program from an object file,
 * pins it, and outputs JSON with the kernel-derived facts.
 *
 * Usage:
 *   bpfman-kernel load <object.o> <program-name> <pin-dir>
 *   bpfman-kernel unload <pin-dir>
 *
 * The program and its maps are pinned under <pin-dir>/.
 * Output is JSON on stdout.
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static int ensure_dir(const char *path)
{
	struct stat st;

	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return 0;
		fprintf(stderr, "error: %s exists but is not a directory\n", path);
		return -1;
	}

	if (mkdir(path, 0755) < 0) {
		fprintf(stderr, "error: mkdir %s: %s\n", path, strerror(errno));
		return -1;
	}

	return 0;
}

static void print_json_string(const char *s)
{
	putchar('"');
	for (; *s; s++) {
		switch (*s) {
		case '"':  printf("\\\""); break;
		case '\\': printf("\\\\"); break;
		case '\n': printf("\\n"); break;
		case '\t': printf("\\t"); break;
		default:   putchar(*s); break;
		}
	}
	putchar('"');
}

static int cmd_load(const char *obj_path, const char *prog_name, const char *pin_dir)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_map *map;
	char pin_path[512];
	int prog_fd, prog_id;
	int err;
	int first_map = 1;

	/* Open the object file */
	obj = bpf_object__open(obj_path);
	if (!obj) {
		err = -errno;
		fprintf(stderr, "error: failed to open %s: %s\n", obj_path, strerror(-err));
		return 1;
	}

	/* Find the program by name */
	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!prog) {
		fprintf(stderr, "error: program '%s' not found in %s\n", prog_name, obj_path);
		bpf_object__close(obj);
		return 1;
	}

	/* Load the object (programs + maps) into the kernel */
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "error: failed to load object: %s\n", strerror(-err));
		bpf_object__close(obj);
		return 1;
	}

	/* Get program fd and id */
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "error: failed to get program fd\n");
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_prog_info prog_info = {};
	__u32 info_len = sizeof(prog_info);
	err = bpf_prog_get_info_by_fd(prog_fd, &prog_info, &info_len);
	if (err) {
		fprintf(stderr, "error: failed to get program info: %s\n", strerror(-err));
		bpf_object__close(obj);
		return 1;
	}
	prog_id = prog_info.id;

	/* Ensure pin directory exists */
	if (ensure_dir(pin_dir) < 0) {
		bpf_object__close(obj);
		return 1;
	}

	/* Pin the program */
	snprintf(pin_path, sizeof(pin_path), "%s/%s", pin_dir, prog_name);
	err = bpf_program__pin(prog, pin_path);
	if (err) {
		fprintf(stderr, "error: failed to pin program to %s: %s\n", pin_path, strerror(-err));
		bpf_object__close(obj);
		return 1;
	}

	/* Output JSON */
	printf("{\n");
	printf("  \"program\": {\n");
	printf("    \"name\": "); print_json_string(prog_name); printf(",\n");
	printf("    \"type\": %d,\n", bpf_program__type(prog));
	printf("    \"id\": %u,\n", prog_id);
	printf("    \"pinned\": "); print_json_string(pin_path); printf("\n");
	printf("  },\n");

	/* Pin maps and collect info */
	printf("  \"maps\": [");

	bpf_object__for_each_map(map, obj) {
		int map_fd = bpf_map__fd(map);
		const char *map_name = bpf_map__name(map);
		struct bpf_map_info map_info = {};
		__u32 map_info_len = sizeof(map_info);

		if (map_fd < 0)
			continue;

		err = bpf_map_get_info_by_fd(map_fd, &map_info, &map_info_len);
		if (err)
			continue;

		/* Pin the map */
		snprintf(pin_path, sizeof(pin_path), "%s/%s", pin_dir, map_name);
		err = bpf_map__pin(map, pin_path);
		if (err) {
			fprintf(stderr, "warning: failed to pin map %s: %s\n", map_name, strerror(-err));
			continue;
		}

		if (!first_map)
			printf(",");
		first_map = 0;

		printf("\n    {\n");
		printf("      \"name\": "); print_json_string(map_name); printf(",\n");
		printf("      \"type\": %d,\n", map_info.type);
		printf("      \"id\": %u,\n", map_info.id);
		printf("      \"pinned\": "); print_json_string(pin_path); printf("\n");
		printf("    }");
	}

	printf("\n  ]\n");
	printf("}\n");

	bpf_object__close(obj);
	return 0;
}

static int cmd_unload(const char *pin_dir)
{
	DIR *dir;
	struct dirent *entry;
	char path[512];
	int count = 0;
	int errors = 0;

	dir = opendir(pin_dir);
	if (!dir) {
		fprintf(stderr, "error: failed to open directory %s: %s\n", pin_dir, strerror(errno));
		return 1;
	}

	/* Remove all entries in the directory */
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", pin_dir, entry->d_name);
		if (unlink(path) < 0) {
			fprintf(stderr, "warning: failed to unlink %s: %s\n", path, strerror(errno));
			errors++;
		} else {
			count++;
		}
	}

	closedir(dir);

	/* Remove the directory itself */
	if (rmdir(pin_dir) < 0) {
		fprintf(stderr, "warning: failed to remove directory %s: %s\n", pin_dir, strerror(errno));
		errors++;
	}

	/* Output JSON */
	printf("{\n");
	printf("  \"unpinned\": %d,\n", count);
	printf("  \"errors\": %d\n", errors);
	printf("}\n");

	return errors > 0 ? 1 : 0;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s load <object.o> <program-name> <pin-dir>\n", prog);
	fprintf(stderr, "  %s unload <pin-dir>\n", prog);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "load") == 0) {
		if (argc != 5) {
			usage(argv[0]);
			return 1;
		}
		return cmd_load(argv[2], argv[3], argv[4]);
	}

	if (strcmp(argv[1], "unload") == 0) {
		if (argc != 3) {
			usage(argv[0]);
			return 1;
		}
		return cmd_unload(argv[2]);
	}

	fprintf(stderr, "error: unknown command '%s'\n", argv[1]);
	usage(argv[0]);
	return 1;
}
