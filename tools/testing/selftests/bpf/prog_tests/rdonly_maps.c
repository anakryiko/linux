// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>

struct rodata {
	unsigned a[4];
	unsigned _x;
};

struct bss {
	unsigned did_run;
	unsigned loop_iters;
};

void test_rdonly_maps(void)
{
	const char *probe_name = "raw_tracepoint/sys_enter";
	const char *file = "test_rdonly_maps.o";
	struct bpf_object_open_attr open_attr = {
		.file = file,
		.prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT,
	};
	struct bpf_object_load_attr load_attr = {
		.log_level = 0,
	};
	struct bpf_map *rodata_map, *bss_map;
	int err, zero = 0, duration = 0;
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct rodata rodata;
	struct bss bss;

	obj = bpf_object__open_xattr(&open_attr);
	if (CHECK(IS_ERR(obj), "obj_open", "err %ld\n", PTR_ERR(obj)))
		return;

	prog = bpf_object__find_program_by_title(obj, probe_name);
	if (CHECK(!prog, "find_probe", "prog '%s' not found\n", probe_name))
		goto cleanup;
	bpf_program__set_raw_tracepoint(prog);

	load_attr.obj = obj;
	err = bpf_object__load_xattr(&load_attr);
	if (CHECK(err, "obj_load", "err %d errno %d\n", err, errno))
		goto cleanup;

	rodata_map = bpf_object__find_map_by_name(obj, "test_rdo.rodata");
	if (CHECK(!rodata_map, "find_rodata_map", "failed\n"))
		goto cleanup;
	bss_map = bpf_object__find_map_by_name(obj, "test_rdo.bss");
	if (CHECK(!bss_map, "find_bss_map", "failed\n"))
		goto cleanup;

	link = bpf_program__attach_raw_tracepoint(prog, "sys_enter");
	if (CHECK(IS_ERR(link), "attach_probe", "err %ld\n", PTR_ERR(link))) {
		link = NULL;
		goto cleanup;
	}

	/* trigger probe */
	usleep(1);

	err = bpf_map_lookup_elem(bpf_map__fd(rodata_map), &zero, &rodata);
	if (CHECK(err, "get_rodata", "failed to get rodata: %d\n", err))
		goto cleanup;
	err = bpf_map_lookup_elem(bpf_map__fd(bss_map), &zero, &bss);
	if (CHECK(err, "get_bssdata", "failed to get bss data: %d\n", err))
		goto cleanup;

	if (CHECK(bss.did_run == 0, "check_bss_did_run", "probe didn't run?\n"))
		goto cleanup;
	if (CHECK(bss.loop_iters != 0, "check_bss_iters", "loop executed?\n"))
		goto cleanup;

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
}
