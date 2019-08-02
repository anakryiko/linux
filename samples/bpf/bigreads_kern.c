#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/version.h>
#include "bpf_helpers.h"

#define MIN_BYTES (1024 * 1024)

SEC("kretprobe/vfs_read")
int bpf_myprog(struct pt_regs *ctx)
{
    char fmt[] = "READ: %d bytes\n";
    int bytes = PT_REGS_RC(ctx);
    if (bytes >= MIN_BYTES) {
        bpf_trace_printk(fmt, sizeof(fmt), bytes, 0, 0);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
