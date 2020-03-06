// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "test_cgroup_attach.skel.h"

static __u32 duration = 0;
#define PING_CMD	"ping -q -c1 -w1 127.0.0.1 > /dev/null"

void test_cgroup_attach_link(void)
{
	struct test_cgroup_attach *skel;
	struct {
		const char *path;
		int fd;
	} cgs[] = {
		{ "/cg1" },
		{ "/cg1/cg2" },
		/*
		{ "/cg1/cg2/cg3" },
		{ "/cg1/cg2/cg3/cg4" },
		{ "/cg1/cg2/cg3/cg4/cg5" },
		*/
	};
	int last_cg = ARRAY_SIZE(cgs) - 1, cg_nr = ARRAY_SIZE(cgs);
	struct bpf_link *links[ARRAY_SIZE(cgs)] = {};
	__u32 prog_ids[5], prog_cnt = 0, attach_flags;
	int i = 0, err, prog_fd;
	bool detach_legacy = false;

	skel = test_cgroup_attach__open_and_load();
	if (CHECK(!skel, "skel_open_load", "failed to open/load skeleton\n"))
		return;
	prog_fd = bpf_program__fd(skel->progs.egress);

	err = setup_cgroup_environment();
	if (CHECK(err, "cg_init", "failed: %d\n", err))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(cgs); i++) {
		cgs[i].fd = create_and_get_cgroup(cgs[i].path);
		if (CHECK(cgs[i].fd < 0, "cg_create", "fail: %d\n", cgs[i].fd))
			goto cleanup;
	}

	err = join_cgroup(cgs[last_cg].path);
	if (CHECK(err, "cg_join", "fail: %d\n", err))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(cgs); i++) {
		links[i] = bpf_program__attach_cgroup(skel->progs.egress,
						      cgs[i].fd);
		if (CHECK(IS_ERR(links[i]), "cg_attach", "i: %d, err: %ld\n",
				 i, PTR_ERR(links[i])))
			goto cleanup;
	}

	CHECK_FAIL(system(PING_CMD));
	if (CHECK(skel->bss->calls != cg_nr, "call_cnt", "exp %d, got %d\n",
		  cg_nr, skel->bss->calls))
		goto cleanup;

	/* query the number of effective progs in cg5 */
	CHECK_FAIL(bpf_prog_query(cgs[last_cg].fd, BPF_CGROUP_INET_EGRESS,
				  BPF_F_QUERY_EFFECTIVE, &attach_flags,
				  prog_ids, &prog_cnt));
	if (CHECK(prog_cnt != cg_nr, "effect_cnt", "exp %d, got %d\n",
		  cg_nr, prog_cnt))
		goto cleanup;
	CHECK_FAIL(attach_flags != BPF_F_ALLOW_MULTI);

	for (i = 1; i < prog_cnt; i++)
		CHECK(prog_ids[i - 1] != prog_ids[i], "prod_id_check",
		      "idx %d, prev id %d, cur id %d\n",
		      i, prog_ids[i - 1], prog_ids[i]);

	/* detach bottom program and ping again */
	bpf_link__destroy(links[last_cg]);
	links[last_cg] = NULL;

	skel->bss->calls = 0;
	CHECK_FAIL(system(PING_CMD));
	if (CHECK(skel->bss->calls != cg_nr - 1, "call_cnt", "exp %d, got %d\n",
		  cg_nr - 1, skel->bss->calls))
		goto cleanup;

	/* mix in with non link-based multi-attachments */
	err = bpf_prog_attach(prog_fd, cgs[last_cg].fd,
			      BPF_CGROUP_INET_EGRESS, BPF_F_ALLOW_MULTI);
	if (CHECK(err, "cg_attach_legacy", "errno=%d\n", errno))
		goto cleanup;
	detach_legacy = true;

	links[last_cg] = bpf_program__attach_cgroup(skel->progs.egress,
						    cgs[last_cg].fd);
	if (CHECK(IS_ERR(links[last_cg]), "cg_attach", "err: %ld\n",
		  PTR_ERR(links[last_cg])))
		goto cleanup;

	skel->bss->calls = 0;
	CHECK_FAIL(system(PING_CMD));
	CHECK(skel->bss->calls != cg_nr + 1, "call_cnt", "exp %d, got %d\n",
	      cg_nr + 1, skel->bss->calls);

	bpf_link__destroy(links[last_cg]);
	links[last_cg] = NULL;

	if (CHECK(bpf_prog_detach2(prog_fd, cgs[last_cg].fd,
		  BPF_CGROUP_INET_EGRESS), "cg_detach_legacy",
		  "errno=%d\n", errno))
		goto cleanup;
	detach_legacy = false;

	/* attempt to mix in with legacy exclusive prog attachment */
	err = bpf_prog_attach(prog_fd, cgs[last_cg].fd,
			      BPF_CGROUP_INET_EGRESS, 0);
	if (CHECK(err, "cg_attach_exclusive", "errno=%d\n", errno))
		goto cleanup;
	detach_legacy = true;

	links[last_cg] = bpf_program__attach_cgroup(skel->progs.egress,
						    cgs[last_cg].fd);
	if (CHECK(!IS_ERR(links[last_cg]), "cg_attach_fail", "unexpected success\n"))
		goto cleanup;

	skel->bss->calls = 0;
	CHECK_FAIL(system(PING_CMD));
	CHECK(skel->bss->calls != cg_nr, "call_cnt", "exp %d, got %d\n",
	      cg_nr, skel->bss->calls);

	if (CHECK(bpf_prog_detach2(prog_fd, cgs[last_cg].fd, BPF_CGROUP_INET_EGRESS),
		  "cg_detach_exclusive", "errno=%d\n", errno))
		goto cleanup;
	detach_legacy = false;

	/* re-attach last bpf_link to finish off test */
	links[last_cg] = bpf_program__attach_cgroup(skel->progs.egress,
						    cgs[last_cg].fd);
	if (CHECK(IS_ERR(links[last_cg]), "cg_attach", "err: %ld\n",
		  PTR_ERR(links[last_cg])))
		goto cleanup;

	skel->bss->calls = 0;
	CHECK_FAIL(system(PING_CMD));
	if (CHECK(skel->bss->calls != cg_nr, "call_cnt", "exp %d, got %d\n",
		  cg_nr, skel->bss->calls))
		goto cleanup;

	/* close cgroup FDs before detaching links */
	for (i = 0; i < ARRAY_SIZE(cgs); i++) {
		if (cgs[i].fd > 0) {
			close(cgs[i].fd);
			cgs[i].fd = -1;
		}
	}

	/* BPF programs should still get called */
	skel->bss->calls = 0;
	CHECK_FAIL(system(PING_CMD));
	if (CHECK(skel->bss->calls != cg_nr, "call_cnt", "exp %d, got %d\n",
		  cg_nr, skel->bss->calls))
		goto cleanup;

cleanup:
	if (detach_legacy)
		bpf_prog_detach2(prog_fd, cgs[last_cg].fd,
				 BPF_CGROUP_INET_EGRESS);

	for (i = 0; i < ARRAY_SIZE(links); i++) {
		if (!IS_ERR(links[i]))
			bpf_link__destroy(links[i]);
	}
	test_cgroup_attach__destroy(skel);

	for (i = 0; i < ARRAY_SIZE(cgs); i++) {
		if (cgs[i].fd > 0)
			close(cgs[i].fd);
	}
	cleanup_cgroup_environment();
}
