// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include "bpf/libbpf.h"

#define DEBUGFS "/sys/kernel/debug/tracing/"

int main(int ac, char *argv[])
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	struct rlimit lim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	char filename[256];

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	setrlimit(RLIMIT_MEMLOCK, &lim);

	obj = bpf_object__open(filename);
	if (libbpf_get_error(obj)) {
		printf("ERROR: failed to open prog: '%s'\n", strerror(errno));
		return 1;
	}

	prog = bpf_object__find_program_by_title(obj, "kretprobe/vfs_read");
	bpf_program__set_type(prog, BPF_PROG_TYPE_KPROBE);

	if (bpf_object__load(obj)) {
		printf("ERROR: failed to load prog: '%s'\n", strerror(errno));
		return 1;
	}

	link = bpf_program__attach_kprobe(prog, true /*retprobe*/, "vfs_read");
	if (libbpf_get_error(link))
		return 2;

	
	system("cat " DEBUGFS "/trace_pipe");

	bpf_link__destroy(link);
	bpf_object__close(obj);

	return 0;
}
