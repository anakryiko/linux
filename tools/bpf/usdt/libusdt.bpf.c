// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Facebook */
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "usdt.h"

enum bpf_func_id___x {
	BPF_FUNC_get_attach_cookie___x = 123,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, USDT_MAX_SPEC_CNT);
	__type(key, int);
	__type(value, struct usdt_spec);
} usdt_specs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, USDT_MAX_SPEC_CNT);
	__type(key, int);
	__type(value, char[USDT_MAX_NAME_LEN]);
} usdt_names SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, USDT_MAX_SPEC_CNT);
	__type(key, long);
	__type(value, struct usdt_spec);
} usdt_specs_ip_to_id SEC(".maps");

static int usdt_spec_id(struct pt_regs *regs)
{
	/* TODO: this should be controllable from user-space with no CO-RE */
	if (!bpf_core_enum_value_exists(enum bpf_func_id___x,
					BPF_FUNC_get_attach_cookie___x)) {
		long ip = PT_REGS_IP(regs);
		int *spec_id_ptr;

		spec_id_ptr = bpf_map_lookup_elem(&usdt_specs_ip_to_id, &ip);
		if (!spec_id_ptr) {
			bpf_printk("Failed to find USDT at IP 0x%lx\n", ip);
			return -ESRCH;
		}
		return *spec_id_ptr;
	}

	return bpf_get_attach_cookie(regs);
}

__hidden const char *usdt_name(struct pt_regs *regs)
{
	struct usdt_spec *spec;
	int spec_id;

	spec_id = usdt_spec_id(regs);
	if (spec_id < 0)
		return NULL;

	return bpf_map_lookup_elem(&usdt_names, &spec_id);
}

__hidden int usdt_arg_cnt(struct pt_regs *regs)
{
	struct usdt_spec *spec;
	int spec_id;

	spec_id = usdt_spec_id(regs);
	if (spec_id < 0)
		return -EINVAL;

	spec = bpf_map_lookup_elem(&usdt_specs, &spec_id);
	if (!spec)
		return -EINVAL;

	return spec->arg_cnt;
}

__hidden int usdt_arg(struct pt_regs *regs, int arg, long *res)
{
	long ip = PT_REGS_IP(regs);
	struct usdt_spec *spec;
	struct usdt_arg_spec *arg_spec;
	unsigned long val;
	int err, spec_id;

	*res = 0;

	spec_id = usdt_spec_id(regs);
	if (spec_id < 0)
		return -ESRCH;

	spec = bpf_map_lookup_elem(&usdt_specs, &spec_id);
	if (!spec)
		return -ESRCH;
	
	if (arg >= spec->arg_cnt)
		return -ENOENT;

	arg_spec = &spec->args[arg];
	switch (arg_spec->arg_type) {
	case USDT_ARG_CONST:
		val = arg_spec->val_off;
		break;
	case USDT_ARG_REG:
		err = bpf_probe_read_kernel(&val, sizeof(val), (void *)regs + arg_spec->reg_off);
		if (err)
			return err;
		break;
	case USDT_ARG_REG_DEREF:
		err = bpf_probe_read_kernel(&val, sizeof(val), (void *)regs + arg_spec->reg_off);
		if (err)
			return err;
		err = bpf_probe_read_user(&val, sizeof(val), (void *)val + arg_spec->val_off);
		if (err)
			return err;
		break;
	default:
		return -EINVAL;
	}

	val <<= arg_spec->arg_bitshift;
	if (arg_spec->arg_signed)
		val = ((long)val) >> arg_spec->arg_bitshift;
	else
		val = val >> arg_spec->arg_bitshift;
	*res = val;
	return 0;
}

__hidden extern void handle_usdt(struct pt_regs *ctx, long cookie);

SEC("uprobe/usdt")
int usdt_multiplexor(struct pt_regs *ctx)
{
	long val;
	int i, n, err, spec_id;
	const char *name;
	struct usdt_info *info;
	struct usdt_spec *spec;

	spec_id = usdt_spec_id(ctx);
	if (spec_id < 0) {
		bpf_printk("Failed to find USDT at IP 0x%lx\n", PT_REGS_IP(ctx));
		return -1;
	}

	spec = bpf_map_lookup_elem(&usdt_specs, &spec_id);
	if (!spec) {
		bpf_printk("Failed to find USDT spec #%d\n", spec_id);
		return -1;
	}

	/* call into user's BPF program */
	handle_usdt(ctx, spec->cookie);

	return 0;
}
