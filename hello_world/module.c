/// @brief Linux kernel 'module'

#include "debug.h"		// xPRINTF

#include <linux/module.h>

static int __init module_init_impl(void)
{
	IPRINTF("module init");
	return 0;
}

static void __exit module_down_impl(void)
{
	IPRINTF("module down");
}

MODULE_AUTHOR("Acro Team");
MODULE_DESCRIPTION("Hello World");
MODULE_LICENSE("GPL");
module_init(module_init_impl);
module_exit(module_down_impl);
