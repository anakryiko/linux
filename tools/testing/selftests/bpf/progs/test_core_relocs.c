// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook

#include <linux/bpf.h>
#include "bpf_helpers.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, int);
} results_map SEC(".maps");

struct core_reloc_substruct {
	char dont_care[2];
	int a3;
	int b3;
};

struct core_reloc_struct {
	int irrelevant;
	union {
		struct core_reloc_substruct a2;
	} a1;
	struct {
		struct core_reloc_substruct b2;
	} b1;
};

SEC("xdp/test_core_relocs")
int test_core_relocs(struct xdp_md *xdp)
{
	struct core_reloc_struct *t = (void *)(long)xdp->data;
	const int key1 = 0, key2 = 1;
	int value1, value2;

	if (bpf_probe_read(&value1, sizeof(value1),
			   __builtin_preserve_access_index(&t->a1.a2.a3)))
		return XDP_ABORTED;
	if (bpf_probe_read(&value2, sizeof(value2),
			   __builtin_preserve_access_index(&t->b1.b2.b3)))
		return XDP_ABORTED;

	bpf_map_update_elem(&results_map, &key1, &value1, 0);
	bpf_map_update_elem(&results_map, &key2, &value2, 0);

	return XDP_TX;
}

