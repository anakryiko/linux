# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
CLANG := clang
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

$(out)/runqslower.o: $(out)/runqslower.bpf.o bpf_core.h runqslower.h

$(out)/runqslower.bpf.o: $(out)/vmlinux.h runqslower.h bpf_lib.h

$(out)/%.bpf.o: %.bpf.c | $(out)
	$(CLANG) -g -O2 -target bpf				\
		 -I$(out) -I../../../../testing/selftests/bpf	\
		 -c $(filter %.c,$^) -o $@

$(out)/%.o: %.c | $(out)
	$(CC) $(CFLAGS) -I$(LIBBPF_SRC) -c $(filter %.c,$^) -o $@

$(out)/vmlinux.h: $(VMLINUX_BTF) | $(out)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(out)/libbpf.a: | $(out)
	mkdir -p $(out) && cd $(out) && \
	$(MAKE) -C $(libbpf_src) OUTPUT=$(abs_out)/ $(abs_out)/libbpf.a

$(out):
	mkdir -p $(out)

