/// @brief Linux kernel exported symbols enumeration

#include "debug.h"		// xPRINTF()
#include "print_kernel_memory_map.h"

#include <linux/errno.h>
#include <linux/module.h>

static int __init module_init_impl(void)
{
	IPRINTF("");
	print_kernel_memory_map();
	return -EFAULT;
}

static void __exit module_down_impl(void)
{
	IPRINTF("");
}

MODULE_AUTHOR("Acro Team");
MODULE_DESCRIPTION("kernel memory map)");
MODULE_LICENSE("GPL");
module_init(module_init_impl);
module_exit(module_down_impl);
