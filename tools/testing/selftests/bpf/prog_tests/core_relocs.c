// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "progs/core_reloc_structs.h"

#define VALUE1 42
#define VALUE2 0xc001

#define TEST_DATA(case_name) &(struct case_name){	\
	.a1 = {						\
		.a2 = {					\
			.a3 = VALUE1,			\
		},					\
	},						\
	.b1 = {						\
		.b2 = {					\
			.b3 = VALUE2,			\
		},					\
	},						\
}

#define SUCCESS_CASE(name) {				\
	.case_name = #name,				\
	.btf_src_file = #name ".o",			\
	.data = TEST_DATA(name),			\
	.data_len = sizeof(*TEST_DATA(name)),		\
}

#define ERROR_CASE(name, error) {			\
	.case_name = #name,				\
	.btf_src_file = #name ".o",			\
	.error = error,					\
}

struct core_reloc_test_case {
	const char *case_name;
	const char *btf_src_file;
	void *data;
	int data_len;
	const char *error;
};

static struct core_reloc_test_case test_cases[] = {
	SUCCESS_CASE(core_reloc_struct___full_embed),
};

void test_core_relocs(void)
{
	const char *probe_name = "xdp/test_core_relocs";
	const char *file = "./test_core_relocs.o";
	struct bpf_object_load_attr load_attr = {};
	struct core_reloc_test_case *test_case;
	const int key1 = 0, key2 = 0;
	int err, duration = 0, i;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map;
	int value1, value2;

	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		struct bpf_prog_test_run_attr run_attr = {};

		test_case = &test_cases[i];

		obj = bpf_object__open(file);
		if (CHECK(IS_ERR_OR_NULL(obj), "obj_open",
			  "case #%d: failed to open '%s': %ld\n",
			  i, file, PTR_ERR(obj)))
			return;

		prog = bpf_object__find_program_by_title(obj, probe_name);
		if (CHECK(!prog, "find_probe",
			  "case #%d: prog '%s' not found\n",
			  i, probe_name))
			goto cleanup;
		bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

		load_attr.obj = obj;
		load_attr.log_level = 1;
		load_attr.target_btf_path = test_case->btf_src_file;
		err = bpf_object__load_xattr(&load_attr);
		if (CHECK(err, "obj_load",
			  "case #%d: failed to load prog '%s': %d\n",
			  i, probe_name, err))
			goto cleanup;

		map = bpf_object__find_map_by_name(obj, "results_map");
		if (CHECK(!map, "find_results_map",
			  "case #%d: failed to find results_map\n", i))
			goto cleanup;

		run_attr.prog_fd = bpf_program__fd(prog);
		run_attr.repeat = 1;
		run_attr.data_in = test_case->data;
		run_attr.data_size_in = test_case->data_len;
		err = bpf_prog_test_run_xattr(&run_attr);
		if (CHECK(err || errno || run_attr.retval != XDP_TX, "test_run",
			  "case #%d: test run failed, err %d errno %d retval %d\n",
			  i, err, errno, run_attr.retval))
			goto cleanup;

		err = bpf_map_lookup_elem(bpf_map__fd(map), &key1, &value1);
		if (CHECK(err, "get_value1",
			  "case #%d: failed to get value1 res: %d\n", i, err))
			goto cleanup;
		if (CHECK(value1 != VALUE1, "check_value1",
			  "case #%d: invalid value1=%d, expected=%d\n",
			  i, value1, VALUE1))
			goto cleanup;

		err = bpf_map_lookup_elem(bpf_map__fd(map), &key2, &value2);
		if (CHECK(err, "get_value2",
			  "case #%d: failed to get value2 res: %d\n", i, err))
			goto cleanup;
		if (CHECK(value2 != VALUE2, "check_value2",
			  "case #%d: invalid value2=%d, expected=%d\n",
			  i, value2, VALUE2))
			goto cleanup;

cleanup:
		bpf_object__close(obj);
	}
}
