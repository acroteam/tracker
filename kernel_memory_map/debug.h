#pragma once

/// @brief Debug printing

#include <asm/current.h>	// struct task_struct *current
#include <linux/printk.h>
#include <linux/sched.h>	// struct task_struct
#include <linux/string.h>	// strrchr()

#define xPRINTF(prefix, format, args...) do { \
        const char *f = __FILE__; \
        const char *n = strrchr(f, '/'); \
        printk(PRINTK_TAG "| %5u:%5u:%s:%u:%s| " prefix format "\n", \
		(unsigned)current->tgid, \
		(unsigned)current->pid, \
		(n) ? n+1 : f, __LINE__, __FUNCTION__, ##args); \
    } while(0)

// in descending order of importance
#define FPRINTF(format, args...) xPRINTF("EMERGENCY: ", format, ##args)
#define APRINTF(format, args...) xPRINTF(    "ALERT: ", format, ##args)
#define CPRINTF(format, args...) xPRINTF( "CRITICAL: ", format, ##args)
#define EPRINTF(format, args...) xPRINTF(    "ERROR: ", format, ##args)
#define WPRINTF(format, args...) xPRINTF(  "WARNING: ", format, ##args)
#define NPRINTF(format, args...) xPRINTF(   "NOTICE: ", format, ##args)
#define IPRINTF(format, args...) xPRINTF(     "INFO: ", format, ##args)
#ifdef __DEBUG__
#define DPRINTF(format, args...) xPRINTF(     "DEBUG ", format, ##args)
#else
#define DPRINTF(format, args...)
#endif

#define HEX_DUMP(dump_prefix, addr, size) \
	print_hex_dump(PRINTK_TAG "| ", dump_prefix, DUMP_PREFIX_OFFSET, \
		 16, 1, addr, size, true)
