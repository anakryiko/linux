// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <linux/version.h>
#include "test_core_extern.skel.h" 

static uint32_t get_kernel_version(void)
{
	uint32_t major, minor, patch;
	struct utsname info;

	uname(&info);
	if (sscanf(info.release, "%u.%u.%u", &major, &minor, &patch) != 3)
		return 0;
	return KERNEL_VERSION(major, minor, patch);
}

static struct test_case {
	const char *name;
	const char *cfg;
	const char *cfg_path;
	bool fails;
	struct test_core_extern__data data;
} test_cases[] = {
	{ .name = "default search path", .cfg_path = NULL },
	{ .name = "/proc/config.gz", .cfg_path = "/proc/config.gz" },
	{ .name = "missing config", .fails = true,
	  .cfg_path = "/proc/invalid-config.gz" },
	{
		.name = "custom values",
		.cfg = "CONFIG_TRISTATE=m\n"
		       "CONFIG_BOOL=y\n"
		       "CONFIG_CHAR=m\n"
		       "CONFIG_STRONG_SHORT=1\n"
		       "CONFIG_INT=123456\n"
		       "CONFIG_LONG=0xDEADBEEFC0DE\n"
		       "CONFIG_STR=\"abracad\"\n"
		       "CONFIG_MISSING=0\n",
		.data = {
			.tristate_val = TRI_MODULE,
			.bool_val = true,
			.char_val = 'm',
			.short_val = 1,
			.int_val = 123456,
			.long_val = 0xDEADBEEFC0DE,
			.str_val = "abracad",
		},
	},
	{
		/* there is no real typing, so any valid value is accepted */
		.name = "mixed up types",
		.cfg = "CONFIG_STRONG_SHORT=1\n"
		       "CONFIG_TRISTATE=123\n"
		       "CONFIG_BOOL=m\n"
		       "CONFIG_INT=y\n",
		.data = {
			.tristate_val = 123,
			.bool_val = 2,
			.int_val = 1,
		},
	},
	{
		/* somewhat weird behavior of strtoull */
		.name = "negative int",
		.cfg = "CONFIG_STRONG_SHORT=1\n"
		       "CONFIG_INT=-12\n",
		.data = { .int_val = (uint64_t)-12 },
	},
	{ .name = "bad tristate", .fails = true, .cfg = "CONFIG_TRISTATE=M" },
	{ .name = "bad bool", .fails = true, .cfg = "CONFIG_BOOL=X" },
	{ .name = "int (not int)", .fails = true, .cfg = "CONFIG_INT=abc" },
	{ .name = "int (string)", .fails = true, .cfg = "CONFIG_INT=\"abc\"" },
	{ .name = "int (empty)", .fails = true, .cfg = "CONFIG_INT=" },
	{ .name = "int (mixed up 1)", .fails = true, .cfg = "CONFIG_INT=123abc",
	  .fails = true, },
	{ .name = "int (mixed up 2)", .fails = true, .cfg = "CONFIG_INT=123abc\n",
	  .fails = true, },
	{ .name = "int (too big)", .fails = true,
	  .cfg = "CONFIG_INT=123456789123456789123\n" },
};

BPF_EMBED_OBJ(core_extern, "test_core_extern.o");

void test_core_extern(void)
{
	const uint32_t kern_ver = get_kernel_version();
	int err, duration = 0, i;
	struct test_core_extern *skel = NULL;
	uint64_t *got, *exp;
	int n = sizeof(*skel->data) / sizeof(uint64_t);

	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		char tmp_cfg_path[] = "/tmp/test_core_extern_cfg.XXXXXX";
		struct test_case *t = &test_cases[i];
		DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			.kconfig_path = t->cfg_path,
		);

		if (!test__start_subtest(t->name))
			continue;

		if (t->cfg) {
			size_t n = strlen(t->cfg) + 1;
			int fd = mkstemp(tmp_cfg_path);
			int written;

			if (CHECK(fd < 0, "mkstemp", "errno: %d\n", errno))
				continue;
			printf("using '%s' as config file\n", tmp_cfg_path);
			written = write(fd, t->cfg, n);
			close(fd);
			if (CHECK_FAIL(written != n))
				goto cleanup;
			opts.kconfig_path = tmp_cfg_path;
		}

		skel = test_core_extern__open_and_load_opts(&core_extern_embed,
							    &opts, NULL);
		if (t->fails) {
			CHECK(skel, "skel_load",
			      "shouldn't succeed open/load of skeleton\n");
			goto cleanup;
		} else if (CHECK(!skel, "skel_load",
				 "failed to open/load skeleton\n")) {
			goto cleanup;
		}
		err = test_core_extern__attach(skel);
		if (CHECK(err, "attach_raw_tp", "failed attach: %d\n", err))
			goto cleanup;

		usleep(1);

		t->data.kern_ver = kern_ver;
		t->data.missing_val = 0xDEADC0DE;
		got = (uint64_t *)skel->data;
		exp = (uint64_t *)&t->data;
		for (i = 0; i < n; i++) {
			CHECK(got[i] != exp[i], "check_res",
			      "result #%d: expected %lx, but got %lx\n",
			       i, exp[i], got[i]);
		}
cleanup:
		if (t->cfg)
			unlink(tmp_cfg_path);
		test_core_extern__destroy(skel);
		skel = NULL;
	}
}
