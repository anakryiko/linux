#include "bpf_core.h"
#include "runqslower.embed.h"

BPF_EMBED_OBJ(runqslower_bpf, ".output/runqslower.bpf.o");

struct runqslower_bpf runqslower_bpf = {
	.def = &(struct bpf_object_def){
		.name = "runqslower",
		.data = runqslower_bpf_data,
		.data_end = runqslower_bpf_data_end,
		.obj_ptr = &runqslower_bpf.obj,
		.map_cnt = 3,
		.maps = (struct bpf_item_def[]){
			{
				.name = "runqslow.bss",
				.ptr = (void **)&runqslower_bpf.map.bss,
			},
			{
				.name = "start",
				.ptr = (void **)&runqslower_bpf.map.start,
			},
			{
				.name = "events",
				.ptr = (void **)&runqslower_bpf.map.events,
			},
		},
		.prog_cnt = 3,
		.progs = (struct bpf_item_def[]){
			{
				.name = "raw_tracepoint/sched_wakeup",
				.ptr = (void **)&runqslower_bpf.prog.sched_wakeup,
			},
			{
				.name = "raw_tracepoint/sched_wakeup_new",
				.ptr = (void **)&runqslower_bpf.prog.sched_wakeup_new,
			},
			{
				.name = "raw_tracepoint/sched_switch",
				.ptr = (void **)&runqslower_bpf.prog.sched_switch,
			},
		},
		.link_cnt = 3,
		.links = (struct bpf_item_def[]){
			{
				.name = "raw_tracepoint/sched_wakeup",
				.ptr = (void **)&runqslower_bpf.link.sched_wakeup,
			},
			{
				.name = "raw_tracepoint/sched_wakeup_new",
				.ptr = (void **)&runqslower_bpf.link.sched_wakeup_new,
			},
			{
				.name = "raw_tracepoint/sched_switch",
				.ptr = (void **)&runqslower_bpf.link.sched_switch,
			},
		},
	},
};
