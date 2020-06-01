/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __USDT_H
#define __USDT_H

#ifndef USDT_MAX_ARG_CNT
#define USDT_MAX_ARG_CNT 12
#endif

#ifndef USDT_MAX_NAME_LEN
#define USDT_MAX_NAME_LEN 128
#endif

#define USDT_MAX_SPEC_CNT 8192

enum usdt_arg_type {
	USDT_ARG_CONST,
	USDT_ARG_REG,
	USDT_ARG_REG_DEREF,
};

struct usdt_arg_spec {
	long val_off;
	enum usdt_arg_type arg_type;
	short reg_off;
	bool arg_signed;
	char arg_bitshift;
};

struct usdt_spec {
	struct usdt_arg_spec args[USDT_MAX_ARG_CNT];
	long cookie;
	short arg_cnt;
};

#endif /* __USDT_H */
