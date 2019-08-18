// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "runqslower.h"

#define TASK_RUNNING 0

#define BPF_F_INDEX_MASK		0xffffffffULL
#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK

const volatile __u64 min_us = 0;
const volatile pid_t targ_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

/* record enqueue timestamp */
__always_inline
static int trace_enqueue(u32 tgid, u32 pid)
{
	u64 ts;

	if (!pid || (targ_pid && targ_pid != pid))
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &pid, &ts, 0);
	return 0;
}

SEC("raw_tracepoint/sched_wakeup")
int handle__sched_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *p = (struct task_struct *)ctx->args[0];

	return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tracepoint/sched_wakeup_new")
int handle__sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *p = (struct task_struct *)ctx->args[0];

	return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tracepoint/sched_switch")
int handle__sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
	/* TP_PROTO(bool preempt, struct task_struct *prev,
	 *	    struct task_struct *next)
	 */
	struct task_struct *prev = (struct task_struct *)ctx->args[1];
	struct task_struct *next = (struct task_struct *)ctx->args[2];
	struct event event = {};
	u64 *tsp, delta_us;
	u32 pid, tgid;
	long state;

	/* ivcsw: treat like an enqueue event and store timestamp */
	if (BPF_CORE_READ(prev, state) == TASK_RUNNING) {
		tgid = BPF_CORE_READ(prev, tgid);
		pid = BPF_CORE_READ(prev, pid);
		trace_enqueue(tgid, pid);
	}

	tgid = BPF_CORE_READ(next, tgid);
	pid = BPF_CORE_READ(next, pid);

	/* fetch timestamp and calculate delta */
	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp)
		return 0;   /* missed enqueue */

	delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
	if (min_us && delta_us <= min_us)
		return 0;

	event.pid = pid;
	event.delta_us = delta_us;
	bpf_get_current_comm(&event.task, sizeof(event.task));

	/* output */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	bpf_map_delete_elem(&start, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
