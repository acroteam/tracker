/// @brief Linux kernel memory map

#include "print_kernel_memory_map.h"

#include "debug.h"		// xPRINTF

#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#define toULL(x) ((unsigned long long)(x))

#define VM_PAGE_SIZE 0x1000

// Note: check for 0x1000000 mising pages on my VM takes 10 seconds.
// Kernel reports 'soft lockup' if CPU is not released too long.
#define YIELD_PAGES 0x10000
// break big zones into chunks to make progress visible in the log
#define ZONE_PAGES_MAX 0x1000000

// long probe_kernel_read(void *dst, const void *src, size_t size)
// returns 0 on success or -EFAULT otherwise

bool is_readable(uint64_t page)
{
	uint64_t addr = page * VM_PAGE_SIZE;
	char dummy;
	return !probe_kernel_read(&dummy, (const void *)addr, sizeof(dummy));
}

#define crop_page_addr(p) ((p) & ((1ULL<<(64-12))-1))

// 'zone' is sequential set of pages with the same 'access mode'
static void print_kernel_memory_range_map(uint64_t addr, uint64_t size)
{
	// let's round everything to page size
	uint64_t curr_page = (addr + (VM_PAGE_SIZE - 1)) / VM_PAGE_SIZE;
	uint64_t vm_pages = (size + (VM_PAGE_SIZE - 1)) / VM_PAGE_SIZE;

	uint64_t yield_pages = 0;
	bool zone_readable;
	bool next_zone_readable;
	zone_readable = is_readable(curr_page);
	while (vm_pages) {
		// start of new 'zone'
		uint64_t zone_start = curr_page;
		uint64_t zone_pages = 1;
		// search for end of 'zone'
		while (--vm_pages) {
			next_zone_readable = is_readable(++curr_page);
			if (next_zone_readable != zone_readable) { break; }
			// periodically release CPU to prevent kernel reporting 'soft lockup'
			if (!(++yield_pages % YIELD_PAGES)) {
				yield();
			}
			if (!(curr_page % ZONE_PAGES_MAX)) { break; }
			++zone_pages;
		}
		printk(PRINTK_TAG " %13llXxxx %7llXxxx %13llXxxx %c\n", crop_page_addr(zone_start), zone_pages,
			crop_page_addr(zone_start + zone_pages), zone_readable ? 'R' : '-');
		// 'access mode' of next 'zone' is already known
		zone_readable = next_zone_readable;
	}
}

void print_kernel_memory_map()
{
	print_kernel_memory_range_map(0xFFFFFFE000000000, 0x4000000000);
}
