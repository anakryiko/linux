/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_CORE_H
#define __BPF_CORE_H

#define BPF_EMBED_OBJ(NAME, PATH)					\
asm (									\
"	.pushsection \".rodata\", \"a\", @progbits		\n"	\
"	.global "#NAME"_data					\n"	\
#NAME"_data:							\n"	\
"	.incbin \"" PATH "\"					\n"	\
#NAME"_data_end:						\n"	\
"	.global "#NAME"_size					\n"	\
"	.type "#NAME"_size, @object				\n"	\
"	.size "#NAME"_size, 4					\n"	\
"	.align 4,						\n"	\
#NAME"_size:							\n"	\
"	.int "#NAME"_data_end - "#NAME"_data 			\n"	\
"	.popsection						\n"	\
);									\
extern char NAME##_data[];						\
extern int NAME##_size;


#endif /* __BPF_CORE_H */
