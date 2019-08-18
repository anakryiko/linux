# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
CLANG := clang
LLC := llc
LLVM-STRIP := llvm-strip
BPFTOOL := bpftool
VMLINUX_BTF := /sys/kernel/btf/vmlinux
LIBBPF_SRC := ../..
CFLAGS := -g -Wall

out := .output
abs_out := $(abspath $(out))
libbpf_src := $(abspath $(LIBBPF_SRC))

.DELETE_ON_ERROR:

.PHONY: all
all: runqslower

.PHONY: clean
clean:
	rm -rf $(out) runqslower

runqslower: $(out)/runqslower.o $(out)/libbpf.a
	$(CC) $(CFLAGS) -lelf $^ -o $@

$(out)/vmlinux.h: $(VMLINUX_BTF) | $(out)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(out)/libbpf.a: | $(out)
	cd $(out) && $(MAKE) -C $(libbpf_src) OUTPUT=$(abs_out)/ $(abs_out)/libbpf.a

$(out)/runqslower.o: runqslower.h $(out)/runqslower.bpf.o $(out)/runqslower.skel.h

$(out)/runqslower.bpf.o: $(out)/vmlinux.h runqslower.h

$(out)/%.skel.h: $(out)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(out)/%.bpf.o: %.bpf.c | $(out)
	($(CLANG) -g -O2 -target bpf -emit-llvm -I$(out) -I$(LIBBPF_SRC)      \
		  -c $(filter %.c,$^) -o - || echo "BPF compilation failed")  \
	| $(LLC) -mattr=dwarfris -march=bpf -mcpu=probe -filetype=obj -o $@   \
	&& $(LLVM-STRIP) -g $@

$(out)/%.o: %.c | $(out)
	$(CC) $(CFLAGS) -I$(LIBBPF_SRC) -I$(out) -c $(filter %.c,$^) -o $@

$(out):
	mkdir -p $(out)

