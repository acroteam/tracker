/// @brief Linux kernel exported symbols enumeration

#include "debug.h"		// xPRINTF()
#include "device.h"
#include "kernel_symbols.h"

#include <linux/module.h>

// centos-6-10-64 kernel: sys_init_module: 'kernel_symbols_test'->init suspiciously returned 38, it should follow 0/-E convention
// centos-6-10-64 kernel: sys_init_module: loading module anyway...

static int __init module_init_impl(void)
{
	int ret;

	IPRINTF("");

	count_kernel_symbols();

	ret = device_init();
	if (ret) {
		EPRINTF("'%s()' failure %i", "device_init", ret);
		goto out;
	}

	// Note: 'ret' is already 0 here
	goto out;

out:
	DPRINTF("ret=%i", ret);
	return ret;
}

static void __exit module_down_impl(void)
{
	IPRINTF("");
	device_down();
	IPRINTF("");
}

MODULE_AUTHOR("Acro Team");
MODULE_DESCRIPTION("kernel symbols enumeration)");
MODULE_LICENSE("GPL");
module_init(module_init_impl);
module_exit(module_down_impl);
