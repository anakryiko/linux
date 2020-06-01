// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Facebook
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <libelf.h>
#include <gelf.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/ptrace.h>
#include "libusdt.h"
#include "usdt_demo.skel.h"
#include "usdt_demo.h"

#define MAX_USDT_CNT 50

static struct env {
	bool verbose;
	bool discover;
	const char *binary_path;
	const char *usdts[MAX_USDT_CNT];
	int pid;
	int usdt_cnt;
	int skip_cnt, spec_cnt, bin_cnt;
} env = { .pid = -1 };

const char *argp_program_version = "usdt_demo 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"usdt-demo <binary-path> <provider>:<name>...\n"
"\n"
"./usdt-demo hello-usdt hello:probe_main2 hello:probe_main3\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Only attach to USDT within given PID" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "discover", 'd', NULL, 0, "Discover given USDTs across all active processes" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	char *p;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		env.discover = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno || env.pid < 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (!env.discover && !env.binary_path) {
			env.binary_path = arg;
			break;
		}

		if (env.usdt_cnt >= MAX_USDT_CNT) {
			fprintf(stderr, "Too many USDTs specified!\n");
			return -E2BIG;
		}

		p = strchr(arg, ':');
		if (!p) {
			fprintf(stderr, "USDT probe definition should be in the form 'provider:name', but got '%s'\n", arg);
			return -EINVAL;
		}

		env.usdts[env.usdt_cnt] = arg;
		env.usdt_cnt++;

		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

static int attach_binary(const char *filename, bool is_discovery, struct usdt_manager *usdt_man)
{
	int i;
	long id;

	if (is_discovery && access(filename, R_OK)) {
		env.skip_cnt++;
		fprintf(stderr, "Skipping unaccessible '%s' binary...\n", filename);
		return 0;
	}

	for (i = 0; i < env.usdt_cnt; i++) {
		char *provider = NULL, *name = NULL;
		size_t link_cnt_before, link_cnt;
		long usdt_cookie = 0;

		if (2 != sscanf(env.usdts[i], "%m[^:]:%ms", &provider, &name)) {
			fprintf(stderr, "Failed to parse '%s' into 'provider:name' form (errno %d)!\n",
				env.usdts[i], -errno);
			return -EINVAL;
		}

		if (strcmp(env.usdts[i], "thrift:strobelight_probe_data_destruct") == 0)
			usdt_cookie = STROBE_USDT_ID;

		link_cnt_before = usdt_manager__attached_cnt(usdt_man);
		id = usdt_manager__attach_usdt(usdt_man, filename, env.pid, provider, name, usdt_cookie);
		free(provider);
		free(name);
		link_cnt = usdt_manager__attached_cnt(usdt_man) - link_cnt_before;

		if (is_discovery && id == -EBADF) {
			env.skip_cnt++;
			fprintf(stderr, "Skipping bad ELF file '%s'...\n", filename);
			return 0;
		}

		if (id < 0) {
			if (id == -ENOENT) {
				fprintf(stderr, "Failed to find any instance of USDT '%s' in '%s'\n", env.usdts[i], filename);
				env.skip_cnt++;
				return 0;
			}
			fprintf(stderr, "Failed to prepare USDT '%s' in '%s': %ld\n", env.usdts[i], filename, id);
			return id;
		} else {
			printf("Discovered %zu USDT instances of '%s' in '%s' (USDT ID: %ld)...\n",
			       link_cnt, env.usdts[i], filename, id);
			env.spec_cnt += link_cnt;
			env.bin_cnt++;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct usdt_demo_bpf *obj;
	struct usdt_manager *usdt_man;
	int err, i;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!env.discover && !env.binary_path) {
		fprintf(stderr, "Please specify the path to traced binary.\n");
		return 1;
	}
	if (!env.usdt_cnt) {
		fprintf(stderr, "Please specify at least one provider:name USDT definitions.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d", err);
		return 1;
	}

	obj = usdt_demo_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	usdt_man = usdt_manager__new(obj->obj);
	if (!usdt_man) {
		fprintf(stderr, "failed to create usdt_manager\n");
		return 1;
	}

	err = usdt_demo_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	usdt_manager__set_verbose(usdt_man, env.verbose);

	if (env.discover) {
		static const char *cmd = "find /proc -maxdepth 1 -type d -name '[0-9]*' | "
					 "cut -c7- | xargs -I{} cat /proc/{}/maps | "
					 "awk '$2 ~ \"x\" && $6 ~ /^\\// { print $6; }' | "
					 "grep -vE '\\(deleted\\)$' | sort | uniq";
		FILE *f = popen(cmd, "r");
		char filename[PATH_MAX];

		if (!f) {
			err = -errno;
			fprintf(stderr, "Failed to get a list of running executables: %d\n", err);
			goto cleanup;
		}

		while (fscanf(f, "%s\n", filename) == 1) {
			err = attach_binary(filename, true, usdt_man);
			if (err)
				goto cleanup;
		}

		fclose(f);
	} else {
		err = attach_binary(env.binary_path, false, usdt_man);
		if (err)
			goto cleanup;
	}

	for (i = 0; i < env.usdt_cnt; i++) {
		printf("Tracing %d instances of USDT '%s' across %d binaries (%d binaries skipped).\n",
		       env.spec_cnt, env.usdts[i], env.bin_cnt, env.skip_cnt);
	}

	while (true) {
		fprintf(stdout, ".");
		fflush(stdout);
		sleep(1);
	}

cleanup:
	usdt_demo_bpf__destroy(obj);

	return err != 0;
}
