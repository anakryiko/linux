// SPDX-License-Identifier: GPL-2.0

#if defined(__x86_64__)

/*
 * USDT probe using nop,nop5 combo with arguments in a regular function.
 * When the compiler places USDT arguments in the red zone (below rsp),
 * the nop5->call optimization clobbers them.
 *
 * We use volatile reads and enough arguments to force the compiler to
 * spill to the stack (red zone).
 */
#include "usdt.h"

static volatile unsigned long usdt_red_zone_arg1 = 0xDEADBEEF;
static volatile unsigned long usdt_red_zone_arg2 = 0xCAFEBABE;
static volatile unsigned long usdt_red_zone_arg3 = 0xFEEDFACE;

void __attribute__((noinline)) usdt_red_zone_trigger(void)
{
	unsigned long a1 = usdt_red_zone_arg1;
	unsigned long a2 = usdt_red_zone_arg2;
	unsigned long a3 = usdt_red_zone_arg3;

	USDT(optimized_attach, usdt_red_zone, a1, a2, a3);
}

#endif
