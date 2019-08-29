#ifndef __RUNQSLOWER_EMBED_H
#define __RUNQSLOWER_EMBED_H

struct bpf_object_def;
struct bpf_object;
struct bpf_program;
struct bpf_map;
struct bpf_link;

struct runqslower_bpf {
	struct bpf_object_def *def;
	struct bpf_object *obj;
	struct {
		struct bpf_map *bss;
		struct bpf_map *start;
		struct bpf_map *events;
	} map;
	struct {
		struct bpf_program *sched_wakeup;
		struct bpf_program *sched_wakeup_new;
		struct bpf_program *sched_switch;
	} prog;
	struct {
		struct bpf_link *sched_wakeup;
		struct bpf_link *sched_wakeup_new;
		struct bpf_link *sched_switch;
	} link;
};

extern struct runqslower_bpf runqslower_bpf;

#endif /* __RUNQSLOWER_EMBED_H */
