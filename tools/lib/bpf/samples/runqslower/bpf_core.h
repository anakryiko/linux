/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_CORE_H
#define __BPF_CORE_H
#include <stdio.h>
#include <libbpf.h>

#define BPF_EMBED_OBJ(NAME, PATH)					\
asm (									\
"	.pushsection \".rodata\", \"a\", @progbits		\n"	\
"	.global "#NAME"_data					\n"	\
#NAME"_data:							\n"	\
"	.incbin \"" PATH "\"					\n"	\
"	.global "#NAME"_data_end				\n"	\
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
extern char NAME##_data_end[];						\
extern int NAME##_size;

struct bpf_item_def {
	const char *name;
	void **ptr;
};

struct bpf_object_def {
	const char *name;
	void *data;
	void *data_end;

	struct bpf_object **obj_ptr;

	int map_cnt;
	struct bpf_item_def *maps;
	int prog_cnt;
	struct bpf_item_def *progs;
	int link_cnt;
	struct bpf_item_def *links;
};

static inline void bpf_object_def__destroy(struct bpf_object_def *def)
{
	int i;

	for (i = 0; i < def->map_cnt; i++) {
		struct bpf_map **dst = (struct bpf_map **)def->maps[i].ptr;

		*dst = NULL;
	}
	for (i = 0; i < def->prog_cnt; i++) {
		struct bpf_program **dst = (struct bpf_program **)def->progs[i].ptr;

		*dst = NULL;
	}
	for (i = 0; i < def->link_cnt; i++) {
		struct bpf_link **dst = (struct bpf_link **)def->links[i].ptr;

		bpf_link__destroy(*dst);
		*dst = NULL;
	}
	bpf_object__close(*def->obj_ptr);
	*def->obj_ptr = NULL;
}

static inline int bpf_object_def__load(struct bpf_object_def *def, const void *opts)
{
	struct bpf_object *obj;
	int err, i;

	obj = bpf_object__open_buffer(def->data, def->data_end - def->data,
				      def->name);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "failed to initialize BPF object '%s': %d\n",
			def->name, err);
		return err;
	}

	*def->obj_ptr = obj;

	for (i = 0; i < def->map_cnt; i++) {
		struct bpf_map **dst = (struct bpf_map **)def->maps[i].ptr;
		const char *name = def->maps[i].name;
		struct bpf_map *map;

		map = bpf_object__find_map_by_name(obj, name);
		if (!map) {
			err = -1;
			fprintf(stderr, "failed to find map '%s'\n", name);
			goto cleanup;
		}
		*dst = map;
	}

	for (i = 0; i < def->prog_cnt; i++) {
		struct bpf_program **dst = (struct bpf_program **)def->progs[i].ptr;
		const char *name = def->progs[i].name;
		struct bpf_program *prog;

		prog = bpf_object__find_program_by_title(obj, name);
		if (!prog) {
			err = -1;
			fprintf(stderr, "failed to find program '%s'\n", name);
			goto cleanup;
		}
		*dst = prog;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object '%s': %d\n", def->name, err);
		goto cleanup;
	}
	
	return 0;

cleanup:
	bpf_object_def__destroy(def);
	return err;
}

static inline int bpf_object_def__attach(struct bpf_object_def *def, const void *opts)
{
	struct bpf_object *obj;
	int err, i;

	obj = *def->obj_ptr;

	for (i = 0; i < def->link_cnt; i++) {
		struct bpf_link **dst = (struct bpf_link **)def->links[i].ptr;
		const char *name = def->links[i].name;
		struct bpf_program *p;
		struct bpf_link *link;

		p = bpf_object__find_program_by_title(obj, name);
		if (!p) {
			err = -1;
			fprintf(stderr, "failed to find program '%s'\n", name);
			goto cleanup;
		}
		// TODO: do this properly for all supported types
		
		if (!bpf_program__is_raw_tracepoint(p)) {
			err = -1;
			fprintf(stderr, "unrecognized type for program '%s'\n",
				name);
			goto cleanup;
		}
		link = bpf_program__attach_raw_tracepoint(p, name + 15);
		err = libbpf_get_error(link);
		if (err) {
			fprintf(stderr, "failed to auto-attach program '%s': %d\n",
				name, err);
			goto cleanup;
		}

		*dst = link;
	}
	
	return 0;

cleanup:
	bpf_object_def__destroy(def);
	return err;
}

#endif /* __BPF_CORE_H */
