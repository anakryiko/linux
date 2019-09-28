// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook

#include <linux/ptrace.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

static volatile const struct {
	unsigned a[4];
	/* avoid .rodata.cst16 section until it's handled by libbpf properly */
	unsigned _x;
} rdonly_values = { .a = {2, 2, 2, 2} };

static volatile struct {
	unsigned did_run;
	unsigned loop_iters;
} res;

SEC("raw_tracepoint/sys_enter")
int handle_sys_nanosleep_entry(struct pt_regs *ctx)
{
	unsigned * volatile p = (void *)&rdonly_values.a;

	while (*p % 2 == 1) {
		p++;
		res.loop_iters++;
	}
	res.did_run = 1;
	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
