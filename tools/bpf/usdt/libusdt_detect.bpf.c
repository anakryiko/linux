// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* this program won't load if kernel doesn't support bpf_cookie */
SEC("tp/foo/bar")
int detect_get_attach_cookie(void *ctx)
{
	return bpf_get_attach_cookie(ctx);
}
