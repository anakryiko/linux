// SPDX-License-Identifier: GPL-2.0
/*
 * Provide kernel BTF information for introspection and use by eBPF tools.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/init.h>

/*
 * Embed raw BTF data between btf_kernel_data_start and btf_kernel_data_end.
 * Raw BTF data is dumped into .btf.kernel file by scripts/link-vmlinux.sh.
 */
asm (
"	.pushsection .BTF, \"a\"		\n"
"	.global btf_kernel_data_start		\n"
"btf_kernel_data_start:				\n"
"	.incbin \".btf.kernel.bin\"	\n"
"	.global btf_kernel_data_end		\n"
"btf_kernel_data_end:				\n"
"	.popsection				\n"
);

extern char btf_kernel_data_start[];
extern char btf_kernel_data_end[];

static ssize_t
btf_kernel_read(struct file *file,  struct kobject *kobj,
		struct bin_attribute *bin_attr,
		char *buf, loff_t off, size_t len)
{
	memcpy(buf, btf_kernel_data_start + off, len);
	return len;
}

static struct bin_attribute btf_kernel_attr __ro_after_init = {
	.attr = {
		.name = "btf",
		.mode = 0444,
	},
	.read = btf_kernel_read,
};

static int __init btf_kernel_init(void)
{
	btf_kernel_attr.size = btf_kernel_data_end - btf_kernel_data_start;
	return sysfs_create_bin_file(kernel_kobj, &btf_kernel_attr);
}

subsys_initcall(btf_kernel_init);
