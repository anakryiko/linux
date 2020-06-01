#define _SDT_HAS_SEMAPHORES 1

#include <sys/sdt.h>
#include <unistd.h>
#include <stdio.h>

__extension__ unsigned short hello_shlib_probe_semaphore __attribute__((unused)) __attribute__((section (".probes")));

static inline __attribute__((always_inline)) void trigger_usdt(int x, int y)
{
	STAP_PROBE5(hello, shlib_probe, getpid(), y, x + 5, hello_shlib_probe_semaphore, &hello_shlib_probe_semaphore);
}

void do_something(int x)
{
	printf("SHARED LIB DOING SOMETHING X %d (PID %d)\n", x, getpid());
	if (hello_shlib_probe_semaphore) {
		printf("SHARED LIB SEMAPHORE ENABLED! %d PID %d\n", x, getpid());
		trigger_usdt(x, 1);
		trigger_usdt(x * 10, 2);
		trigger_usdt(x * 100, 3);
	}
}
