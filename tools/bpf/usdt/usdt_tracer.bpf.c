// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Facebook */
#include "vmlinux.h"
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "libusdt.bpf.h"
#include "usdt_demo.h"

static void BPF_USDT(strobe_req_end_usdt,
		     __u32 version, __u64 req_id,
		     const char *endpoint, long latency_ms)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct task_struct *task = (void *)bpf_get_current_task();
	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	char comm[16];

	bpf_probe_read_kernel_str(comm, sizeof(comm), leader->comm);

	bpf_printk("STROBE_REQ_END COMM %s PID/TGID %d/%d", comm, (__u32)pid_tgid, pid_tgid >> 32);
	bpf_printk("               ENDPOINT %s LAT MS %ld", endpoint, latency_ms);
}

void handle_usdt(struct pt_regs *ctx, long cookie)
{
	long ip = PT_REGS_IP(ctx);
	long val;
	int i, n, err;
	const char *name;

	name = usdt_name(ctx);
	if (!name) {
		bpf_printk("USDT IP 0x%lx ERROR getting name\n", ip);
		return;
	}

	n = usdt_arg_cnt(ctx);
	if (n < 0) {
		bpf_printk("USDT '%s' IP 0x%lx ERROR getting arg cnt: %d\n", name, ip, n);
		return;
	}

	bpf_printk("USDT FIRED! NAME '%s' IP 0x%lx COOKIE %d", name, ip, cookie);
	bpf_printk("            ARG CNT %d", n);

	for (i = 0; i < n && i < USDT_MAX_ARG_CNT; i++) {
		err = usdt_arg(ctx, i, &val);
		if (err)
			bpf_printk("\tIP 0x%lx ARG #%d ERROR: %d", ip, i, err);
		else
			bpf_printk("\tIP 0x%lx ARG #%d VALUE 0x%lx", ip, i, val);
	}

	/* custom USDT handling logic */
	switch (cookie) {
	case STROBE_USDT_ID:
		strobe_req_end_usdt(ctx);
		break;
	};
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

