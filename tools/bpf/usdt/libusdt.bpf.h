/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
/* Copyright (c) 2021 Facebook */
#ifndef __LIBUSDT_BPF_H
#define __LIBUSDT_BPF_H

#define USDT_MAX_ARG_CNT 12
#define USDT_MAX_NAME_LEN 128

struct pt_regs;

extern const char *usdt_name(struct pt_regs *ctx);
extern int usdt_arg_cnt(struct pt_regs *ctx);
extern int usdt_arg(struct pt_regs *ctx, int arg, long *res);

#ifndef ___bpf_concat
#define ___bpf_concat(a, b) a ## b
#endif
#ifndef ___bpf_apply
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#endif
#ifndef ___bpf_nth
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#endif
#ifndef ___bpf_narg
#define ___bpf_narg(...) \
	___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#endif

#define ___bpf_usdt_args0() ctx
#define ___bpf_usdt_args1(x) ___bpf_usdt_args0(), ({ long _x; usdt_arg(ctx, 0, &_x); (void *)_x; })
#define ___bpf_usdt_args2(x, args...) ___bpf_usdt_args1(args), ({ long _x; usdt_arg(ctx, 1, &_x); (void *)_x; })
#define ___bpf_usdt_args3(x, args...) ___bpf_usdt_args2(args), ({ long _x; usdt_arg(ctx, 2, &_x); (void *)_x; })
#define ___bpf_usdt_args4(x, args...) ___bpf_usdt_args3(args), ({ long _x; usdt_arg(ctx, 3, &_x); (void *)_x; })
#define ___bpf_usdt_args5(x, args...) ___bpf_usdt_args4(args), ({ long _x; usdt_arg(ctx, 4, &_x); (void *)_x; })
#define ___bpf_usdt_args6(x, args...) ___bpf_usdt_args5(args), ({ long _x; usdt_arg(ctx, 5, &_x); (void *)_x; })
#define ___bpf_usdt_args7(x, args...) ___bpf_usdt_args6(args), ({ long _x; usdt_arg(ctx, 6, &_x); (void *)_x; })
#define ___bpf_usdt_args8(x, args...) ___bpf_usdt_args7(args), ({ long _x; usdt_arg(ctx, 7, &_x); (void *)_x; })
#define ___bpf_usdt_args9(x, args...) ___bpf_usdt_args8(args), ({ long _x; usdt_arg(ctx, 8, &_x); (void *)_x; })
#define ___bpf_usdt_args10(x, args...) ___bpf_usdt_args9(args), ({ long _x; usdt_arg(ctx, 9, &_x); (void *)_x; })
#define ___bpf_usdt_args11(x, args...) ___bpf_usdt_args10(args), ({ long _x; usdt_arg(ctx, 10, &_x); (void *)_x; })
#define ___bpf_usdt_args12(x, args...) ___bpf_usdt_args11(args), ({ long _x; usdt_arg(ctx, 11, &_x); (void *)_x; })
#define ___bpf_usdt_args(args...) ___bpf_apply(___bpf_usdt_args, ___bpf_narg(args))(args)

/*
 * BPF_USDT serves the same purpose for USDT handlers as BPF_PROG for
 * tp_btf/fentry/fexit BPF programs and BPF_KPROBE for kprobes.
 * Original struct pt_regs* context is preserved as 'ctx' argument.
 */
#define BPF_USDT(name, args...)						    \
name(struct pt_regs *ctx);						    \
static __attribute__((always_inline)) typeof(name(0))			    \
____##name(struct pt_regs *ctx, ##args);				    \
typeof(name(0)) name(struct pt_regs *ctx)				    \
{									    \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	return ____##name(___bpf_usdt_args(args));			    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __attribute__((always_inline)) typeof(name(0))			    \
____##name(struct pt_regs *ctx, ##args)


#endif /* __LIBUSDT_BPF_H */
