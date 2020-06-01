// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Facebook
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "usdt.h"
#include <libelf.h>
#include <gelf.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/ptrace.h>
#include "libusdt.h"

#include "libusdt_detect.skel.h"

#define PERF_UPROBE_REF_CTR_OFFSET_SHIFT 32

#define USDT_BASE_SEC ".stapsdt.base"
#define USDT_SEMA_SEC ".probes"
#define USDT_NOTE_SEC  ".note.stapsdt"
#define USDT_NOTE_TYPE 3
#define USDT_NOTE_NAME "stapsdt"
#define NR_ADDR 3

struct usdt_note {
	const char *provider;
	const char *name;
	/* args specification string, e.g.:
	 * "-4@%esi -4@-24(%rbp) -4@%ecx 2@%ax 8@%rdx"
	 */
	const char *args;
	size_t loc_addr;
	size_t base_addr;
	size_t sema_addr;

	bool in_shared_lib;
};

struct usdt_link {
	size_t usdt_id;
	struct bpf_link *link;
	union {
		long abs_ip;
		int next_spec_idx; /* used for freed spec_idx maintenance */
	};
};

struct usdt_manager {
	struct bpf_object *obj;
	struct bpf_program *usdt_entry_prog;

	struct bpf_map *specs_map;
	struct bpf_map *names_map;
	struct bpf_map *ip_to_id_map;

	size_t last_usdt_id;
	size_t next_spec_idx;
	struct usdt_link *links;
	size_t link_cnt;

	bool verbose;
	bool has_bpf_cookie;
	bool has_sema_refcnt;
};

static void libusdt_default_print_fn(const char *format, va_list args)
{
	vfprintf(stderr, format, args);
}

static libusdt_print_fn print_fn = libusdt_default_print_fn;

libusdt_print_fn libusdt_set_print(libusdt_print_fn fn)
{
	libusdt_print_fn old_print_fn = print_fn;

	print_fn = fn ?: libusdt_default_print_fn;

	return old_print_fn;
}

__attribute__((format(printf, 1, 2)))
static void libusdt_printf(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	print_fn(format, args);
	va_end(args);
}

static int populate_usdt_note(struct usdt_manager *man, Elf *elf, const char *path,
			      const char *data, size_t len, struct usdt_note *usdt_note);

static int populate_usdt_spec(struct usdt_manager *man, struct usdt_spec *spec,
			      const struct usdt_note *note, long usdt_cookie);

static int libbpf_print_noop(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	return 0;
}

struct usdt_manager *usdt_manager__new(struct bpf_object *obj)
{
	struct usdt_manager *man;
	struct libusdt_detect_bpf *skel;
	libbpf_print_fn_t old_libbpf_print;

	man = calloc(1, sizeof(*man));
	if (!man)
		return NULL;

	man->obj = obj;
	man->usdt_entry_prog = bpf_object__find_program_by_name(obj, "usdt_multiplexor");

	man->specs_map = bpf_object__find_map_by_name(obj, "usdt_specs");
	man->names_map = bpf_object__find_map_by_name(obj, "usdt_names");
	man->ip_to_id_map = bpf_object__find_map_by_name(obj, "usdt_specs_ip_to_id");

	/* detect bpf_cookie support */
	old_libbpf_print = libbpf_set_print(libbpf_print_noop);
	skel = libusdt_detect_bpf__open_and_load();
	if (!libbpf_get_error(skel))
		man->has_bpf_cookie = true;
	libusdt_detect_bpf__destroy(skel);
	skel = NULL;
	libbpf_set_print(old_libbpf_print);

	/* we don't need IP-to-ID mapping if we can use bpf_cookie */
	if (man->has_bpf_cookie)
		bpf_map__set_max_entries(man->ip_to_id_map, 1);

	/* Detect kernel support for automatic refcounting of USDT semaphore:
	 * a6ca88b241d5 ("trace_uprobe: support reference counter in fd-based uprobe")
	 * If this is not supported, USDTs with semaphores will not be supported.
	 */
	if (access("/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset", F_OK) == 0)
		man->has_sema_refcnt = true;

	return man;
}

void usdt_manager__free(struct usdt_manager *man)
{
	int i;

	if (!man)
		return;

	for (i = 0; i < man->link_cnt; i++)
		bpf_link__destroy(man->links[i].link);

	free(man->links);
	free(man);
}

size_t usdt_manager__attached_cnt(const struct usdt_manager *man)
{
	return man->link_cnt;
}

void usdt_manager__set_verbose(struct usdt_manager *man, bool verbose)
{
	man->verbose = verbose;
}

struct elf_seg {
	long start;
	long end;
	long offset;
	bool is_exec;
};

static int cmp_elf_segs(const void *_a, const void *_b)
{
	const struct elf_seg *a = _a;
	const struct elf_seg *b = _b;

	return a->start < b->start ? -1 : 1;
}

static int parse_elf_segments(struct usdt_manager *man, Elf *elf, const char *path,
			      struct elf_seg **segs, size_t *seg_cnt)
{
	GElf_Phdr phdr;
	size_t n;
	int i, err;
	struct elf_seg *seg;
	void *tmp;

	if (elf_getphdrnum(elf, &n)) {
		err = -errno;
		return err;
	}

	*seg_cnt = 0;

	for (i = 0; i < n; i++) {
		if (!gelf_getphdr(elf, i, &phdr)) {
			err = -errno;
			return err;
		}

		if (man->verbose) {
			libusdt_printf("libusdt: BINARY '%s' ELF PHDR #%d TYPE 0x%x FLAGS 0x%x VADDR 0x%lx\n",
				       path, i, phdr.p_type, phdr.p_flags, phdr.p_vaddr);
		}

		if (phdr.p_type != PT_LOAD)
			continue;

		tmp = realloc(*segs, (*seg_cnt + 1) * sizeof(**segs));
		if (!tmp)
			return -ENOMEM;

		*segs = tmp;
		seg = *segs + *seg_cnt;
		(*seg_cnt)++;

		seg->start = phdr.p_vaddr;
		seg->end = phdr.p_vaddr + phdr.p_memsz;
		seg->offset = phdr.p_offset;
		seg->is_exec = phdr.p_flags & PF_X;
	}

	if (*seg_cnt == 0) {
		libusdt_printf("libusdt: failed to find any program header of PT_LOAD type in '%s'\n",
			       path);
		return -ESRCH;
	}

	qsort(*segs, *seg_cnt, sizeof(**segs), cmp_elf_segs);
	return 0;
}

static struct elf_seg *find_elf_seg(struct elf_seg *segs, size_t seg_cnt, long addr, bool relative)
{
	struct elf_seg *seg;
	int i;

	if (relative) {
		for (i = 0, seg = segs; i < seg_cnt; i++, seg++) {
			if (seg->offset <= addr && addr - seg->offset <= seg->end - seg->start)
				return seg;
		}
	} else {
		for (i = 0, seg = segs; i < seg_cnt; i++, seg++) {
			if (seg->start <= addr && addr < seg->end)
				return seg;
		}
	}

	return NULL;
}

static int parse_shlib_segments(struct usdt_manager *man, int pid, const char *lib_path,
				struct elf_seg **segs, size_t *seg_cnt)
{
	char path[PATH_MAX], line[PATH_MAX], mode[16];
	size_t addr_start, addr_end, addr_off;
	struct elf_seg *seg;
	int tmp_pid, i, err;
	void *tmp;
	FILE *f;

	*seg_cnt = 0;

	/* Handle containerized binaries only accessible from
	 * /proc/<pid>/root/<path>. They will be reported as just /<path> in
	 * /proc/<pid>/maps.
	 */
	if (sscanf(lib_path, "/proc/%d/root%s", &tmp_pid, path) == 2) {
		if (pid == tmp_pid)
			goto proceed;
	}
	if (!realpath(lib_path, path)) {
		libusdt_printf("libusdt: failed to get absolute path of '%s' (err %d), using path as is...\n",
			       lib_path, -errno);
		strcpy(path, lib_path);
	}

proceed:
	sprintf(line, "/proc/%d/maps", pid);
	f = fopen(line, "r");
	if (!f) {
		err = -errno;
		libusdt_printf("libusdt: failed to open '%s' to get base addr of '%s': %d\n",
			       line, lib_path, err);
		return err;
	}

	/* We need to handle lines with no path at the end:
	 *
	 * 7f5c6f5d1000-7f5c6f5d3000 rw-p 001c7000 08:04 21238613      /usr/lib64/libc-2.17.so
	 * 7f5c6f5d3000-7f5c6f5d8000 rw-p 00000000 00:00 0
	 * 7f5c6f5d8000-7f5c6f5d9000 r-xp 00000000 103:01 362990598    /data/users/andriin/linux/tools/bpf/usdt/libhello_usdt.so
	 */
	while (fscanf(f, "%zx-%zx %s %zx %*s %*d%[^\n]\n",
		      &addr_start, &addr_end, mode, &addr_off, line) == 5) {
		/* to handle no path case (see above) we scan string including
		 * leading whitespaces; so skip whitespaces now, if any
		 */
		i = 0;
		while (isblank(line[i]))
			i++;

		if (strcmp(line + i, path) != 0)
			continue;

		if (man->verbose) {
			libusdt_printf("libusdt: SHLIB '%s' SEG #%zx VADDR %zx-%zx MODE %s OFF %zx\n",
				       lib_path, *seg_cnt, addr_start, addr_end, mode, addr_off);
		}

		/* ignore non-executable sections for shared libs */
		if (mode[2] != 'x')
			continue;

		tmp = realloc(*segs, (*seg_cnt + 1) * sizeof(**segs));
		if (!tmp) {
			err = -ENOMEM;
			goto err_out;
		}

		*segs = tmp;
		seg = *segs + *seg_cnt;
		(*seg_cnt)++;

		seg->start = addr_start;
		seg->end = addr_end;
		seg->offset = addr_off;
		seg->is_exec = true;
	}

	if (*seg_cnt == 0) {
		libusdt_printf("libusdt: failed to find '%s' (resolved to '%s') within PID %d memory mappings\n",
			       lib_path, path, pid);
		err = -ESRCH;
		goto err_out;
	}

	qsort(*segs, *seg_cnt, sizeof(**segs), cmp_elf_segs);
	err = 0;

err_out:
	fclose(f);
	return err;
}

static int find_usdt_elf_sec(int fd, const char *path, Elf **out_elf, Elf_Scn **out_scn)
{
	Elf *elf;
	GElf_Ehdr ehdr;
	Elf_Scn *scn = NULL;
	size_t shdr_stridx;
	int err = -EINVAL;
	int endianness;

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf) {
		libusdt_printf("libusdt: failed to parse ELF file '%s': %s\n", path, elf_errmsg(-1));
		goto err_out;
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		libusdt_printf("libusdt: unrecognized ELF kind %d for '%s'\n", elf_kind(elf), path);
		err = -EBADF;
		goto err_out;
	}

	switch (gelf_getclass(elf)) {
	case ELFCLASS64:
		break;
	case ELFCLASS32:
		libusdt_printf("libusdt: 32-bit ELF binary '%s' is not supported\n", path);
		goto err_out;
	default:
		libusdt_printf("libusdt: unsupported ELF class for '%s'\n", path);
		goto err_out;
	}

	if (!gelf_getehdr(elf, &ehdr))
		goto err_out;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	endianness = ELFDATA2LSB;
#elif __BYTE_ORDER == __BIG_ENDIAN
	endianness = ELFDATA2MSB;
#else
# error "Unrecognized __BYTE_ORDER__"
#endif
	if (endianness != ehdr.e_ident[EI_DATA]) {
		libusdt_printf("libusdt: ELF endianness mismatch for '%s'\n", path);
		goto err_out;
	}

	if (elf_getshdrstrndx(elf, &shdr_stridx))
		goto err_out;

	if (!elf_rawdata(elf_getscn(elf, shdr_stridx), NULL))
		goto err_out;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		char *sec_name;
		GElf_Shdr sh;

		if (gelf_getshdr(scn, &sh) != &sh) {
			err = -EINVAL;
			goto err_out;
		}

		if (sh.sh_type != SHT_NOTE)
			continue;

		sec_name = elf_strptr(elf, shdr_stridx, sh.sh_name);
		if (!sec_name)
			continue;

		if (strcmp(sec_name, USDT_NOTE_SEC) == 0) {
			*out_elf = elf;
			*out_scn = scn;
			return 0;
		}
	}

err_out:
	*out_elf = NULL;
	*out_scn = NULL;
	elf_end(elf);
	return err;
}

static int get_usdt_name_by_id(struct usdt_manager *man, int spec_id, char *usdt_name)
{
	int err;

	if (bpf_map_lookup_elem(bpf_map__fd(man->names_map), &spec_id, usdt_name) < 0) {
		err = -errno;
		sprintf(usdt_name, "<unknown>");
		return err;
	}

	return 0;
}

static int attach_usdt_probe(struct usdt_manager *man, const char *path, int pid,
			     int usdt_id, struct usdt_spec *spec, struct usdt_note *note,
			     long usdt_abs_ip, long usdt_rel_ip, long usdt_sema_off)
{
	DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts);
	char usdt_full_name[USDT_MAX_NAME_LEN];
	struct bpf_link *link;
	void *tmp;
	int err, spec_idx;

	if (man->next_spec_idx >= man->link_cnt) {
		spec_idx = man->link_cnt;

		tmp = realloc(man->links, (man->link_cnt + 1) * sizeof(*man->links));
		if (!tmp)
			return -ENOMEM;
		man->links = tmp;
	} else {
		spec_idx = man->next_spec_idx;
	}

	if (bpf_map_update_elem(bpf_map__fd(man->specs_map), &spec_idx, spec, BPF_ANY)) {
		err = -errno;
		libusdt_printf("libusdt: failed to set USDT spec #%d for '%s:%s' in '%s': %d\n",
			       spec_idx, note->provider, note->name, path, err);
		return err;
	}
	snprintf(usdt_full_name, sizeof(usdt_full_name), "%s:%s", note->provider, note->name);
	if (bpf_map_update_elem(bpf_map__fd(man->names_map), &spec_idx, usdt_full_name, 0)) {
		err = -errno;
		libusdt_printf("libusdt: failed to set USDT name for spec #%d for '%s:%s' in '%s': %d\n",
			       spec_idx, note->provider, note->name, path, err);
		return err;
	}
	if (!man->has_bpf_cookie && bpf_map_update_elem(bpf_map__fd(man->ip_to_id_map),
							&usdt_abs_ip, &spec_idx, BPF_NOEXIST)) {
		err = -errno;
		if (err == -EEXIST) {
			get_usdt_name_by_id(man, spec_idx, usdt_full_name);
			libusdt_printf("libusdt: USDT IP collision detected for spec #%d for '%s:%s' in '%s', '%s' is at the same IP 0x%lx, can't proceed\n",
				       spec_idx, note->provider, note->name, path,
				       usdt_full_name, usdt_abs_ip);
		} else {
			libusdt_printf("libusdt: failed to set USDT IP (0x%lx) to spec ID (%d) mapping for '%s' in '%s': %d\n",
				usdt_abs_ip, spec_idx, usdt_full_name, path, err);
		}
		return err;
	}

	opts.refcnt_offset = usdt_sema_off;
	opts.bpf_cookie = man->has_bpf_cookie ? spec_idx : 0;
	link = bpf_program__attach_uprobe_opts(man->usdt_entry_prog, pid, path, usdt_rel_ip, &opts);
	err = libbpf_get_error(link);
	if (err) {
		libusdt_printf("libusdt: failed to attach USDT spec #%d for '%s:%s' in '%s': %d\n",
			       spec_idx, note->provider, note->name, path, err);
		return err;
	}

	if (spec_idx == man->link_cnt) {
		man->link_cnt++;
		man->next_spec_idx = man->link_cnt;
	} else {
		man->next_spec_idx = man->links[spec_idx].next_spec_idx;
	}

	man->links[spec_idx].usdt_id = usdt_id;
	man->links[spec_idx].link = link;
	man->links[spec_idx].abs_ip = usdt_abs_ip;

	return 0;
}

static int attach_usdt_probes(struct usdt_manager *man, int usdt_id,
			      const char *path, int pid,
			      const char *usdt_provider, const char *usdt_name,
			      long usdt_cookie)
{
	size_t off, name_off, desc_off, seg_cnt, shlib_seg_cnt = 0;
	struct elf_seg *segs = NULL, *shlib_segs = NULL;
	struct usdt_spec spec;
	int fd, err, cnt = 0;
	Elf *elf;
	Elf_Scn *scn;
	GElf_Nhdr nhdr;
	Elf_Data *data;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		libusdt_printf("libusdt: failed to open ELF binary '%s': %d\n", path, err);
		return err;
	}

	err = find_usdt_elf_sec(fd, path, &elf, &scn);
	if (err == -ENOENT) { /* no USDT note section found */
		close(fd);
		return 0;
	} else if (err) {
		goto err_out;
	}

	data = elf_getdata(scn, 0);
	if (!data) {
		err = -EINVAL;
		goto err_out;
	}

	err = parse_elf_segments(man, elf, path, &segs, &seg_cnt);
	if (err) {
		libusdt_printf("libusdt: failed to process ELF program headers for '%s': %d\n",
			       path, err);
		goto err_out;
	}

	off = 0;
	while ((off = gelf_getnote(data, off, &nhdr, &name_off, &desc_off)) > 0) {
		long usdt_abs_ip, usdt_rel_ip, usdt_sema_off;
		struct usdt_note note;

		if (strcmp(data->d_buf + name_off, USDT_NOTE_NAME)) {
			err = -EINVAL;
			goto err_out;
		}
		if (nhdr.n_type != USDT_NOTE_TYPE) {
			err = -EINVAL;
			goto err_out;
		}

		err = populate_usdt_note(man, elf, path,
					 data->d_buf + desc_off, nhdr.n_descsz, &note);
		if (err)
			goto err_out;

		if (strcmp(note.provider, usdt_provider) != 0 || strcmp(note.name, usdt_name) != 0)
			continue;

		err = populate_usdt_spec(man, &spec, &note, usdt_cookie);
		if (err)
			goto err_out;

		usdt_rel_ip = usdt_abs_ip = note.loc_addr;

		if (note.in_shared_lib && !man->has_bpf_cookie) {
			struct elf_seg *seg;

			if (pid < 0) {
				libusdt_printf("libusdt: shared library '%s' with no PID specified is not supported on current Linux kernel\n",
					       path);
				err = -ENOTSUP;
				goto err_out;
			}

			if (shlib_seg_cnt == 0) {
				err = parse_shlib_segments(man, pid, path, &shlib_segs, &shlib_seg_cnt);
				if (err) {
					libusdt_printf("libusdt: failed to get memory segments for shared library '%s': %d\n",
						       path, err);
					goto err_out;
				}
			}

			seg = find_elf_seg(shlib_segs, shlib_seg_cnt, usdt_rel_ip, true /* relative */);
			if (!seg) {
				err = -ESRCH;
				libusdt_printf("libusdt: failed to find shared lib memory segment for '%s:%s' in '%s' at relative IP 0x%lx\n",
					       usdt_provider, usdt_name, path, usdt_rel_ip);
				goto err_out;
			}
			if (!seg->is_exec) {
				err = -ESRCH;
				libusdt_printf("libusdt: matched ELF shared lib '%s' segment [0x%lx, 0x%lx] for '%s:%s' at relative IP 0x%lx is not executable\n",
					       path, seg->start, seg->end, usdt_provider, usdt_name, usdt_rel_ip);
				goto err_out;
			}

			if (man->verbose) {
				libusdt_printf("libusdt: USDT '%s:%s' SHLIB  '%s' PROBE SEG [0x%lx, 0x%lx] at offset 0x%lx\n",
					       usdt_provider, usdt_name, path, seg->start, seg->end, seg->offset);
			}

			usdt_abs_ip = seg->start + usdt_rel_ip - seg->offset;
		} else if (!note.in_shared_lib) {
			struct elf_seg *seg;
			
			seg = find_elf_seg(segs, seg_cnt, usdt_abs_ip, false /* relative */);
			if (!seg) {
				err = -ESRCH;
				libusdt_printf("libusdt: failed to find ELF loadable segment for '%s:%s' in '%s' at IP 0x%lx\n",
					       usdt_provider, usdt_name, path, usdt_abs_ip);
				goto err_out;
			}
			if (!seg->is_exec) {
				err = -ESRCH;
				libusdt_printf("libusdt: matched ELF binary '%s' segment [0x%lx, 0x%lx] for '%s:%s' at IP 0x%lx is not executable\n",
					       path, seg->start, seg->end, usdt_provider, usdt_name, usdt_abs_ip);
				goto err_out;
			}

			if (man->verbose) {
				libusdt_printf("libusdt: USDT '%s:%s' EXEC   '%s' PROBE SEG [0x%lx, 0x%lx] at offset 0x%lx\n",
					       usdt_provider, usdt_name, path, seg->start, seg->end, seg->offset);
			}

			usdt_rel_ip -= seg->start - seg->offset;
		}

		usdt_sema_off = note.sema_addr;
		if (usdt_sema_off) {
			struct elf_seg *seg;

			if (!man->has_sema_refcnt) {
				libusdt_printf("libusdt: kernel doesn't support refcounting USDT semaphore for '%s:%s' in '%s'\n",
					       usdt_provider, usdt_name, path);
				err = -ENOTSUP;
				goto err_out;
			}
			
			seg = find_elf_seg(segs, seg_cnt, usdt_sema_off, false /* relative */);
			if (!seg) {
				err = -ESRCH;
				libusdt_printf("libusdt: failed to find ELF loadable segment with semaphore of '%s:%s' in '%s' at 0x%lx\n",
					       usdt_provider, usdt_name, path, usdt_abs_ip);
				goto err_out;
			}
			if (seg->is_exec) {
				err = -ESRCH;
				libusdt_printf("libusdt: matched ELF binary '%s' segment [0x%lx, 0x%lx] for semaphore of '%s:%s' at 0x%lx is executable\n",
					       path, seg->start, seg->end, usdt_provider, usdt_name, usdt_sema_off);
				goto err_out;
			}

			if (man->verbose) {
				libusdt_printf("libusdt: USDT '%s:%s' BINARY '%s' SEMA SEG [0x%lx, 0x%lx] at off 0x%lx\n",
					       usdt_provider, usdt_name, path, seg->start, seg->end, seg->offset);
			}

			usdt_sema_off -= seg->start - seg->offset;
		}

		if (man->verbose) {
			libusdt_printf("libusdt: USDT '%s:%s' BINARY '%s' ABSIP 0x%lx RELIP 0x%lx SEMA 0x%lx LOC 0x%lx BASE 0x%lx ORIG SEMA 0x%lx ARGS '%s'\n",
				       note.provider, note.name, path,
				       usdt_abs_ip, usdt_rel_ip, usdt_sema_off,
				       note.loc_addr, note.base_addr, note.sema_addr, note.args);
		}

		err = attach_usdt_probe(man, path, pid, usdt_id, &spec, &note,
					usdt_abs_ip, usdt_rel_ip, usdt_sema_off);
		if (err)
			goto err_out;

		cnt++;
	}

	err = cnt;

err_out:
	free(segs);
	free(shlib_segs);
	if (err < 0)
		usdt_manager__detach_usdt(man, usdt_id);
	if (elf)
		elf_end(elf);
	close(fd);
	return err;
}

long usdt_manager__attach_usdt(struct usdt_manager *man,
			       const char *binary_path, int pid,
			       const char *usdt_provider, const char *usdt_name,
			       long usdt_cookie)
{
	int err, usdt_id;

	if (bpf_program__fd(man->usdt_entry_prog) < 0) {
		libusdt_printf("libusdt: USDT BPF entry point program is not loaded\n");
		return -EAGAIN;
	}

	/* normalize PID filter */
	if (pid < 0)
		pid = -1;
	else if (pid == 0)
		pid = getpid();

	usdt_id = man->last_usdt_id + 1;

	/* discover USDT in given binary, optionally limiting
	 * activations to a given PID, if pid > 0
	 */
	err = attach_usdt_probes(man, usdt_id, binary_path, pid,
				 usdt_provider, usdt_name, usdt_cookie);
	if (err < 0)
		return err;
	if (err == 0)
		return -ENOENT;

	man->last_usdt_id = usdt_id;
	return usdt_id;
}

static void detach_usdt(struct usdt_manager *man, struct usdt_link *usdt_link, int spec_idx)
{
	bpf_link__destroy(usdt_link->link);
	if (usdt_link->link && usdt_link->abs_ip)
		bpf_map_delete_elem(bpf_map__fd(man->ip_to_id_map), &usdt_link->abs_ip);

	usdt_link->link = NULL;
	usdt_link->usdt_id = 0;
	usdt_link->next_spec_idx = man->next_spec_idx;
	man->next_spec_idx = spec_idx;
}

int usdt_manager__detach_usdt(struct usdt_manager *man, int usdt_id)
{
	int i, found_cnt = 0;

	if (usdt_id < 0)
		return -EINVAL;

	for (i = 0; i < man->link_cnt; i++) {
		if (man->links[i].usdt_id != usdt_id) {
			detach_usdt(man, &man->links[i], i);
			found_cnt++;
		}
	}

	return found_cnt == 0 ? -ENOENT : 0;
}

void usdt_manager__detach_all(struct usdt_manager *man)
{
	int i;

	for (i = 0; i < man->link_cnt; i++) {
		detach_usdt(man, &man->links[i], i);
	}

	free(man->links);
	man->links = NULL;
	man->link_cnt = 0;
	man->next_spec_idx = 0;
}

/*
 * USDT parsing and processing logic
 */

static int find_elf_sec_hdr_by_name(Elf *elf, GElf_Ehdr *ehdr,
				    const char *sec_name, GElf_Shdr *shdr)
{
	Elf_Scn *sec = NULL;

	if (!elf_rawdata(elf_getscn(elf, ehdr->e_shstrndx), NULL))
		return -EINVAL;

	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *name;

		gelf_getshdr(sec, shdr);

		name = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
		if (name && !strcmp(sec_name, name))
			return 0;
	}

	return -ENOENT;
}

/* Parse out USDT ELF note from '.note.stapsdt' section.
 * Logic inspired by perf's code.
 */
static int populate_usdt_note(struct usdt_manager *man, Elf *elf, const char *path,
			      const char *data, size_t len, struct usdt_note *note)
{
	const char *provider, *name, *args;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	size_t addrs[3];

	if (!gelf_getehdr(elf, &ehdr))
		return -EINVAL;

	if (len < sizeof(addrs) + 3) {
		libusdt_printf("libusdt: ELF note in '%s' is too small (%zd bytes only)\n",
			       path, len);
		return -EINVAL;
	}

	/* get location, base, and semaphore addrs */
	memcpy(&addrs, data, sizeof(addrs));

	/* parse string fields: provider, name, args */
	provider = data + sizeof(addrs);

	name = (const char *)memchr(provider, '\0', data + len - provider);
	if (!name) /* non-zero-terminated provider */
		return -EINVAL;
	name++;
	if (name >= data + len || *name == '\0') /* missing or empty name */
		return -EINVAL;

	args = memchr(name, '\0', data + len - name);
	if (!args) /* non-zero-terminated name */
		return -EINVAL;
	++args;
	if (args >= data + len) /* missing arguments spec */
		return -EINVAL;

	note->provider = provider;
	note->name = name;
	if (*args == '\0' || *args == ':')
		note->args = NULL;
	else
		note->args = args;
	note->loc_addr = addrs[0];
	note->base_addr = addrs[1];
	note->sema_addr = addrs[2];

	note->in_shared_lib = ehdr.e_type == ET_DYN;

	/* Adjust the prelink effect.
	 * Find out the .stapsdt.base section.
	 * This scn will help us to handle prelinking (if present).
	 * Compare the retrieved file offset of the base section with the
	 * base address in the description of the SDT note. If its different,
	 * then accordingly, adjust the note location.
	 */
	if (find_elf_sec_hdr_by_name(elf, &ehdr, USDT_BASE_SEC, &shdr) == 0) {
		if (shdr.sh_addr)
			note->loc_addr += shdr.sh_addr - note->base_addr;
	}

	return 0;
}

struct pt_regs_x86_kern {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static int calc_pt_regs_off(const char *reg_name)
{
#define REG_VARIANT_CNT 4
	static struct {
		const char *names[REG_VARIANT_CNT];
		size_t pt_regs_off;
	} reg_map[] = {
		{ {"rip", "eip", "", ""}, offsetof(struct pt_regs_x86_kern, ip) },
		{ {"rax", "eax", "ax", "al"}, offsetof(struct pt_regs_x86_kern, ax) },
		{ {"rbx", "ebx", "bx", "bl"}, offsetof(struct pt_regs_x86_kern, bx) },
		{ {"rcx", "ecx", "cx", "cl"}, offsetof(struct pt_regs_x86_kern, cx) },
		{ {"rdx", "edx", "dx", "dl"}, offsetof(struct pt_regs_x86_kern, dx) },
		{ {"rsi", "esi", "si", "sil"}, offsetof(struct pt_regs_x86_kern, si) },
		{ {"rdi", "edi", "di", "dil"}, offsetof(struct pt_regs_x86_kern, di) },
		{ {"rbp", "ebp", "bp", "bpl"}, offsetof(struct pt_regs_x86_kern, bp) },
		{ {"rsp", "esp", "sp", "spl"}, offsetof(struct pt_regs_x86_kern, sp) },
		{ {"r8", "r8d", "r8w", "r8b"}, offsetof(struct pt_regs_x86_kern, r8) },
		{ {"r9", "r9d", "r9w", "r9b"}, offsetof(struct pt_regs_x86_kern, r9) },
		{ {"r10", "r10d", "r10w", "r10b"}, offsetof(struct pt_regs_x86_kern, r10) },
		{ {"r11", "r11d", "r11w", "r11b"}, offsetof(struct pt_regs_x86_kern, r11) },
		{ {"r12", "r12d", "r12w", "r12b"}, offsetof(struct pt_regs_x86_kern, r12) },
		{ {"r13", "r13d", "r13w", "r13b"}, offsetof(struct pt_regs_x86_kern, r13) },
		{ {"r14", "r14d", "r14w", "r14b"}, offsetof(struct pt_regs_x86_kern, r14) },
		{ {"r15", "r15d", "r15w", "r15b"}, offsetof(struct pt_regs_x86_kern, r15) },
	};
	int i, j, n;

	n = ARRAY_SIZE(reg_map);
	for (i = 0; i < n; i++) {
		for (j = 0; j < REG_VARIANT_CNT; j++) {
			if (strcmp(reg_name, reg_map[i].names[j]) == 0)
				return reg_map[i].pt_regs_off;
		}
	}

	libusdt_printf("libusdt: unrecognized register '%s'\n", reg_name);
	return -ENOENT;
}

static int populate_usdt_arg(const char *arg_str, int arg_num, struct usdt_arg_spec *arg)
{
	char *reg_name = NULL;
	int arg_sz, len, reg_off;
	long off;

	if (3 == sscanf(arg_str, " %d @ %ld ( %%%m[^)] ) %n", &arg_sz, &off, &reg_name, &len)) {
		/* -4@-20(%rbp) */
		arg->arg_type = USDT_ARG_REG_DEREF;
		arg->val_off = off;
		reg_off = calc_pt_regs_off(reg_name);
		free(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (2 == sscanf(arg_str, " %d @ %%%ms %n", &arg_sz, &reg_name, &len)) {
		/* -4@%eax */
		arg->arg_type = USDT_ARG_REG;
		arg->val_off = 0;

		reg_off = calc_pt_regs_off(reg_name);
		free(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (2 == sscanf(arg_str, " %d @ $%ld %n", &arg_sz, &off, &len)) {
		/* -4@$71 */
		arg->arg_type = USDT_ARG_CONST;
		arg->val_off = off;
		arg->reg_off = 0;
	} else {
		libusdt_printf("libusdt: unrecognized arg #%d spec '%s'\n", arg_num, arg_str);
		return -EINVAL;
	}

	arg->arg_signed = arg_sz < 0;
	if (arg_sz < 0)
		arg_sz = -arg_sz;

	switch (arg_sz) {
	case 1: case 2: case 4: case 8:
		arg->arg_bitshift = 64 - arg_sz * 8;
		break;
	default:
		libusdt_printf("libusdt: unsupported arg #%d spec '%s' size: %d\n",
			       arg_num, arg_str, arg_sz);
		return -EINVAL;
	}

	return len;
}

static int populate_usdt_spec(struct usdt_manager *man, struct usdt_spec *spec,
			      const struct usdt_note *note, long usdt_cookie)
{
	const char *s;
	int len;

	spec->cookie = usdt_cookie;
	spec->arg_cnt = 0;

	s = note->args;
	while (s && s[0]) {
		if (spec->arg_cnt >= USDT_MAX_ARG_CNT) {
			libusdt_printf("libusdt: too many USDT arguments (> %d) for '%s:%s' with args spec '%s'\n",
				       USDT_MAX_ARG_CNT, note->provider, note->name, note->args);
			return -E2BIG;
		}

		len = populate_usdt_arg(s, spec->arg_cnt, &spec->args[spec->arg_cnt]);
		if (len < 0)
			return len;

		s += len;
		spec->arg_cnt++;
	}

	return 0;
}
