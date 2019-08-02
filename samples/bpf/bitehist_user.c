/*
 * bitesize - disk I/O sizes, using Linux eBPF.
 *
 * This uses eBPF to record a histogram of disk I/O sizes, in-kernel. This uses
 * current eBPF capabilities; it should be rewriten as more features are added.
 *
 * USAGE: ./bitesize [-h] [interval [count]]
 *
 * Based on eBPF sample tracex2 by Alexi Starovoitov.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * 15-Apr-2015    Brendan Gregg    Created this.
 * 21-May-2019       "     "    Updated bpf helper names.
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <linux/bpf.h>
#include "bpf/libbpf.h"
#include "bpf/bpf.h"

#define MAX_INDEX    64
#define MAX_STARS    38

struct bpf_object *obj;
struct bpf_link *kprobe_link;
struct bpf_map *map;

static void stars(char *str, long val, long max, int width)
{
	int i;

	for (i = 0; i < (width * val / max) - 1 && i < width - 1; i++)
		str[i] = '*';
	if (val > max)
		str[i - 1] = '+';
	str[i] = '\0';
}

struct hist_key {
	__u32 index;
};

static void print_log2_hist(int fd, const char *type)
{
	struct hist_key key = {}, next_key;
	char starstr[MAX_STARS];
	long value, low, high;
	long data[MAX_INDEX] = {};
	int max_ind = -1, min_ind = INT_MAX - 1;
	long max_value = 0;
	int i, ind;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);
		ind = next_key.index;
		data[ind] += value;
		if (value && ind > max_ind)
			max_ind = ind;
		if (value && ind < min_ind)
			min_ind = ind;
		if (data[ind] > max_value)
			max_value = data[ind];
		key = next_key;
	}

	if (max_ind >= 0)
		printf("     %-15s : count     distribution\n", type);
	for (i = min_ind + 1; i <= max_ind + 1; i++) {
		stars(starstr, data[i - 1], max_value, MAX_STARS);
		low = (1l << i) >> 1;
		high = (1l << i) - 1;
		if (low == high)
			low--;
		printf("%8ld -> %-8ld : %-8ld |%-*s|\n", low, high, data[i - 1],
				MAX_STARS, starstr);
	}
}

static void int_exit(int sig)
{
	printf("\n");
	print_log2_hist(bpf_map__fd(map), "kbytes");
	bpf_link__destroy(kprobe_link);
	bpf_object__close(obj);
	exit(0);
}

int main(int argc, char *argv[])
{
	struct rlimit lim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	struct bpf_program *prog;
	char filename[256];

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	setrlimit(RLIMIT_MEMLOCK, &lim);

	obj = bpf_object__open(filename);
	if (libbpf_get_error(obj))
		return 1;

	prog = bpf_object__find_program_by_title(obj,
			"kprobe/blk_account_io_completion");
	if (prog == NULL)
		return 2;
	bpf_program__set_type(prog, BPF_PROG_TYPE_KPROBE);

	if (bpf_object__load(obj)) {
		printf("ERROR: failed to load prog: '%s'\n", strerror(errno));
		return 3;
	}

	kprobe_link = bpf_program__attach_kprobe(prog, false /*retprobe*/,
						 "blk_account_io_completion");
	if (libbpf_get_error(kprobe_link))
		return 4;

	if ((map = bpf_object__find_map_by_name(obj, "hist_map")) == NULL)
		return 5;

	signal(SIGINT, int_exit);

	printf("Tracing block I/O... Hit Ctrl-C to end.\n");
	sleep(-1);

	return 0;
}
