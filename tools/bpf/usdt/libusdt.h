/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __LIBUSDT_H
#define __LIBUSDT_H

#include <bpf/libbpf.h>

typedef void (*libusdt_print_fn)(const char *fmt, va_list args);

libusdt_print_fn libusdt_set_print(libusdt_print_fn fn);

struct usdt_manager;

struct usdt_manager *usdt_manager__new(struct bpf_object *obj);

void usdt_manager__free(struct usdt_manager *man);

void usdt_manager__set_verbose(struct usdt_manager *man, bool verbose);

long usdt_manager__attach_usdt(struct usdt_manager *man,
			       const char *binary_path, int pid,
			       const char *usdt_provider, const char *usdt_name,
			       long usdt_cookie);

size_t usdt_manager__attached_cnt(const struct usdt_manager *man);

int usdt_manager__detach_usdt(struct usdt_manager *man, int usdt_id);

void usdt_manager__detach_all(struct usdt_manager *man);

#endif /* __USDT_H */
