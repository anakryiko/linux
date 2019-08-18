/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_LIB_H
#define __BPF_LIB_H

/* XXX: remove this, merge with helpers */
#undef BPF_CORE_READ

#define TASK_COMM_LEN 16
#define TASK_RUNNING 0

#define BPF_F_INDEX_MASK		0xffffffffULL
#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK

#define __always_inline __attribute__((always_inline))

#define ___nth(_1, _2, _3, _4, _5, N, ...) N

#define ___arrowify1(x1) x1
#define ___arrowify2(x1, x2) x1->x2
#define ___arrowify3(x1, x2, x3) x1->x2->x3
#define ___arrowify4(x1, x2, x3, x4) x1->x2->x3->x4
#define ___arrowify5(x1, x2, x3, x4, x5) x1->x2->x3->x4->x5
#define ___arrowify(...) \
	___nth(                \
			__VA_ARGS__,       \
			___arrowify5,      \
			___arrowify4,      \
			___arrowify3,      \
			___arrowify2,      \
			___arrowify1)(__VA_ARGS__)

#define bpf_core_read(dst, sz, src) \
	bpf_probe_read(dst, sz, __builtin_preserve_access_index(src))

#define bpf_core_read_str(dst, sz, src) \
	bpf_probe_read_str(dst, sz, __builtin_preserve_access_index(src))

#define __core_rd(read_fn, dst, src_type, src, accessor) \
	read_fn((dst), sizeof(*(dst)), &((src_type)(src))->accessor)

#define __core_rd_ptr(dst, src_type, src, accessor) \
	__core_rd(bpf_core_read, dst, src_type, src, accessor)

#define _bpf_core_read1(read_fn, dst, src, a1) \
	__core_rd_ptr(dst, typeof(src), src, a1)

#define _bpf_core_read2(read_fn, dst, src, a1, a2)                   \
	do {                                                               \
		const void *__t1;                                                \
		__core_rd_ptr(&__t1, typeof(___arrowify(src)), src, a1);         \
		__core_rd(read_fn, dst, typeof(___arrowify(src, a1)), __t1, a2); \
	} while (0)

#define _bpf_core_read3(read_fn, dst, src, a1, a2, a3)                   \
	do {                                                                   \
		const void *__t1;                                                    \
		__core_rd_ptr(&__t1, typeof(___arrowify(src)), src, a1);             \
		__core_rd_ptr(&__t1, typeof(___arrowify(src, a1)), __t1, a2);        \
		__core_rd(read_fn, dst, typeof(___arrowify(src, a1, a2)), __t1, a3); \
	} while (0)

#define _bpf_core_read4(read_fn, dst, src, a1, a2, a3, a4)                   \
	do {                                                                       \
		const void *__t1;                                                        \
		__core_rd_ptr(&__t1, typeof(___arrowify(src)), src, a1);                 \
		__core_rd_ptr(&__t1, typeof(___arrowify(src, a1)), __t1, a2);            \
		__core_rd_ptr(&__t1, typeof(___arrowify(src, a1, a2)), __t1, a3);        \
		__core_rd(read_fn, dst, typeof(___arrowify(src, a1, a2, a3)), __t1, a4); \
	} while (0)

#define _bpf_core_read5(read_fn, dst, src, a1, a2, a3, a4, a5)             \
	do {                                                                     \
		const void *__t1;                                                      \
		__core_rd_ptr(&__t1, typeof(___arrowify(src)), src, a1);               \
		__core_rd_ptr(&__t1, typeof(___arrowify(src, a1)), __t1, a2);          \
		__core_rd_ptr(&__t1, typeof(___arrowify(src, a1, a2)), __t1, a3);      \
		__core_rd_ptr(&__t1, typeof(___arrowify(src, a1, a2, a3)), __t1, a4);  \
		__core_rd(                                                             \
				read_fn, dst, typeof(___arrowify(src, a1, a2, a3, a4)), __t1, a5); \
	} while (0)

#define BPF_CORE_READ_INTO(dst, src, ...) \
	___nth(                                 \
			__VA_ARGS__,                        \
			_bpf_core_read5,                    \
			_bpf_core_read4,                    \
			_bpf_core_read3,                    \
			_bpf_core_read2,                    \
			_bpf_core_read1)(bpf_core_read, dst, src, __VA_ARGS__)

#define BPF_CORE_READ(src, ...)                  \
	({                                             \
	 typeof(___arrowify(src, __VA_ARGS__)) __t2;  \
	 BPF_CORE_READ_INTO(&__t2, src, __VA_ARGS__); \
	 __t2;                                        \
	 })

#define BPF_CORE_READ_STR_INTO(dst, src, ...) \
	___nth(                                     \
			__VA_ARGS__,                            \
			_bpf_core_read5,                        \
			_bpf_core_read4,                        \
			_bpf_core_read3,                        \
			_bpf_core_read2,                        \
			_bpf_core_read1)(bpf_core_read_str, dst, src, __VA_ARGS__)

#define BPF_CORE_READ_STR(src, ...)                  \
	({                                                 \
	 typeof(___arrowify(src, __VA_ARGS__)) __t2;      \
	 BPF_CORE_READ_INTO_STR(&__t2, src, __VA_ARGS__); \
	 __t2;                                            \
	 })

#endif /* __BPF_LIB_H */
