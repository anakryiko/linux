// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2019 Facebook
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <libbpf.h>
#include <bpf.h>
#include "bpf_core.h"
#include "runqslower.h"

struct env {
	pid_t pid;
	__u64 min_us;
	bool verbose;
} env = {
	.min_us = 10000,
};

const char *argp_program_version = "runqslower 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"runqslower    Trace long process scheduling delays.\n"
"              For Linux, uses eBPF, BPF CO-RE, libbpf, BTF.\n"
"\n"
"This script traces high scheduling delays between tasks being\n"
"ready to run and them running on CPU after that.\n"
"\n"
"USAGE: runqslower [-p PID] [min_us]\n"
"\n"
"EXAMPLES:\n"
"    runqslower         # trace run queue latency higher than 10000 us (default)\n"
"    runqslower 1000    # trace run queue latency higher than 1000 us\n"
"    runqslower -p 123  # trace pid 123 only\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID to trace"},
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	int pid;
	long long min_us;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		min_us = strtoll(arg, NULL, 10);
		if (errno || min_us <= 0) {
			fprintf(stderr, "Invalid delay (in us): %s\n", arg);
			argp_usage(state);
		}
		env.min_us = min_us;
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

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s %-16s %-6d %14llu\n", ts, e->task, e->pid, e->delta_us);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

struct prog_def {
	const char *name;
	const char *tp_name;
	struct bpf_program *prog;
	struct bpf_link *link;
};

BPF_EMBED_OBJ(runqslower_bpf, ".output/runqslower.bpf.o");

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	const char *RAW_TP_PREFIX = "raw_tracepoint/";
	/* TODO: libbpf should auto-guess program type and allow auto-attach */
	struct prog_def progs[] = {
		{ .name = "raw_tracepoint/sched_wakeup" },
		{ .name = "raw_tracepoint/sched_wakeup_new" },
		{ .name = "raw_tracepoint/sched_switch" },
	};
	size_t prog_cnt = sizeof(progs)/sizeof(progs[0]);
	struct prog_def *p;
	struct bpf_object *obj = NULL;
	struct bpf_map *events_map, *opts_map;
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;
	struct opts opts;
	int err, i, zero = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d", err);
		return 1;
	}

	obj = bpf_object__open_buffer(runqslower_bpf_data, runqslower_bpf_size,
				      "runqslower");
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "failed to open BPF object: %d\n", err);
		return 1;
	}

	for (i = 0; i < prog_cnt; i++) {
		p = &progs[i];
		if (!strstr(p->name, RAW_TP_PREFIX)) {
			err = 1;
			fprintf(stderr, "unexpected BPF program name: %s\n",
				p->name);
			goto cleanup;
		}
		p->tp_name = p->name + strlen(RAW_TP_PREFIX);
		p->prog = bpf_object__find_program_by_title(obj, p->name);
		bpf_program__set_raw_tracepoint(p->prog);
	}

	events_map = bpf_object__find_map_by_name(obj, "events");
	if (!events_map) {
		err = 1;
		fprintf(stderr, "failed to find 'events' perf buffer map\n");
		goto cleanup;
	}

	opts_map = bpf_object__find_map_by_name(obj, "runqslow.bss");
	if (!opts_map) {
		err = 1;
		fprintf(stderr, "failed to find global data map\n");
		goto cleanup;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* initialize global data (filtering options) */
	opts.pid = env.pid;
	opts.min_us = env.min_us;
	err = bpf_map_update_elem(bpf_map__fd(opts_map), &zero, &opts, 0);
	if (err) {
		fprintf(stderr, "failed to initialize BPF program optionsd\n");
		goto cleanup;
	}

	for (i = 0; i < prog_cnt; i++) {
		p = &progs[i];
		p->link = bpf_program__attach_raw_tracepoint(p->prog,
							     p->tp_name);
		err = libbpf_get_error(p->link);
		if (err) {
			p->link = NULL;
			fprintf(stderr, "failed to attach %s program: %d\n",
				p->tp_name, err);
			goto cleanup;
		}
	}

	printf("Tracing run queue latency higher than %llu us\n", env.min_us);
	printf("%-8s %-16s %-6s %14s\n", "TIME", "COMM", "PID", "LAT(us)");

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(events_map), 64, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	while ((err = perf_buffer__poll(pb, 100)) >= 0)
		;
	printf("Error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	for (i = 0; i < prog_cnt; i++)
		bpf_link__destroy(progs[i].link);
	bpf_object__close(obj);

	return err != 0;
}
