#define _SDT_HAS_SEMAPHORES 1

#include <sys/sdt.h>
#include <unistd.h>
#include <stdio.h>

int idx = 2;
int bla = 0x123;
int nums[100] = {1, 2, 3, };
extern int ext __attribute__((weak));

struct t {
	int x;
	int y;
};

struct t t1 = { 4, 7 };

struct t ts[] = { {1, 2}, {3, 4}, {5, 6} };

__extension__ unsigned short hello_probe_main0_semaphore __attribute__((unused)) __attribute__((section (".probes")));
__extension__ unsigned short hello_probe_main1_semaphore __attribute__((unused)) __attribute__((section (".probes")));
__extension__ unsigned short hello_probe_main2_semaphore __attribute__((unused)) __attribute__((section (".probes")));
__extension__ unsigned short hello_probe_main3_semaphore __attribute__((unused)) __attribute__((section (".probes")));
__extension__ unsigned short hello_probe_main4_semaphore __attribute__((unused)) __attribute__((section (".probes")));
__extension__ unsigned short hello_probe_main5_semaphore __attribute__((unused)) __attribute__((section (".probes")));

extern void do_something(int x);

int main(int argc, char **argv) {
	int a = -1;
	struct t t2 = { 10, 11};
	int cnt = 0;

	while (a) {
		if (hello_probe_main0_semaphore) {
			printf("PROBE0 ENABLED\n");
			STAP_PROBE(hello, probe_main0);
		}
		if (hello_probe_main1_semaphore) {
			printf("PROBE1 ENABLED %d\n", getpid());
			STAP_PROBE1(hello, probe_main1, getpid());
		}
		if (hello_probe_main2_semaphore) {
			printf("PROBE2 ENABLED %x %x\n", 0x47, argc);
			STAP_PROBE2(hello, probe_main2, 0x47, argc);
		}
		if (hello_probe_main3_semaphore) {
			printf("PROBE3 ENABLED %x %x %p\n", bla, argc, argv);
			STAP_PROBE3(hello, probe_main3, bla, argc, argv);
		}
		if (hello_probe_main4_semaphore) {
			printf("PROBE4 ENABLED %x %x %p %p %p\n", (short)a, a, &a, &bla, &ext);
			STAP_PROBE5(hello, probe_main4, (short)a, a, &a, &bla, &ext);
		}
		if (hello_probe_main5_semaphore) {
			printf("PROBE5 ENABLED\n");
			STAP_PROBE12(hello, probe_main5,
				     nums[2], &nums[3], nums[idx], &nums[idx],
				     t1.y, &t1.y,
				     ts[1].y, ts[2].x, &ts[1].y, &ts[2].y,
				     t2.y, &t2.x);
		}
		printf("%d %x %d %x\n", (int)(short)a, (int)(short)a, a, a);
		do_something(cnt++);
		sleep(1);
	}
	return 0;
}
