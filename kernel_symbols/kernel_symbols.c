/// @brief Linux kernel exported symbols enumeration

#include "kernel_symbols.h"

#include "debug.h"              // xPRINTF

#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/module.h>	// struct module

// centos 6.? 2.6.32-71.el6
// EXPORT_SYMBOL_GPL(kallsyms_on_each_symbol);

// centos 6.? 2.6.32-754.el6
// EXPORT_SYMBOL_GPL(kallsyms_on_each_symbol);
// EXPORT_SYMBOL_GPL(sprint_symbol);
// EXPORT_SYMBOL(__print_symbol);

// stable/v5.7.5
// EXPORT_SYMBOL_GPL(sprint_symbol);
// EXPORT_SYMBOL_GPL(sprint_symbol_no_offset);

int symbol_to_text(char* data, size_t size,
	const char *namebuf,
	struct module *module,
	unsigned long kallsyms_address)
{
	int snprintf_result;
	if (module) {
		snprintf_result =
		snprintf(data, size, "%p='%s:%s'\n", (void*)kallsyms_address, module->name, namebuf);
	} else {
		snprintf_result =
		snprintf(data, size, "%p='%s'\n", (void*)kallsyms_address, namebuf);
	}
	return snprintf_result;
}

typedef struct {
	unsigned kernel_symbols_count;
	unsigned module_symbols_count;
	size_t report_size;
} count_kernel_symbols_context_t;

// Warning: There are too many 'symbols' to fit complete report into
// kernel's log buffer. As result report reaches user space incomplete
// and damaged.
// kernel_symbols_count=63530 module_symbols_count=16575 report_size=3 393 108
static int count_kernel_symbols_on_each_symbol_cb(
	void *cb_context,
	const char *namebuf,
	struct module *module,
	unsigned long kallsyms_address)
{
	count_kernel_symbols_context_t *context = cb_context;
	int snprintf_result;
	char s[100];

	if (!context) {
		return -EINVAL;
	}

	snprintf_result =
	symbol_to_text(s, sizeof(s), namebuf, module, kallsyms_address);
	if (module) {
		++context->module_symbols_count;
	} else {
		++context->kernel_symbols_count;
	}
	if (snprintf_result > 0) {
		context->report_size += snprintf_result;
	} else {
		WPRINTF("snprintf_result=%i", snprintf_result);
	}
	return 0;
}

void count_kernel_symbols(void)
{
	count_kernel_symbols_context_t context = {
		.kernel_symbols_count = 0,
		.module_symbols_count = 0,
		.report_size = 0,
	};
	int kallsyms_on_each_symbol_result;

	IPRINTF("%s=%p", "kallsyms_on_each_symbol", kallsyms_on_each_symbol);

	kallsyms_on_each_symbol_result =
		kallsyms_on_each_symbol(count_kernel_symbols_on_each_symbol_cb, &context);
	if (kallsyms_on_each_symbol_result < 0) {
		WPRINTF("kallsyms_on_each_symbol_result=%i", kallsyms_on_each_symbol_result);
	} else {
		IPRINTF("kernel_symbols_count=%u module_symbols_count=%u report_size=%zu",
			context.kernel_symbols_count, context.module_symbols_count, context.report_size);
	}
}

typedef struct {
	enumerate_kernel_symbols_cb_t cb;
	void* cb_context;
} enumerate_kernel_symbols_context_t;

static int enumerate_kernel_symbols_cb(
	void* cb_context,
	const char *namebuf,
	struct module *module,
	unsigned long kallsyms_address)
{
	enumerate_kernel_symbols_context_t* context = cb_context;
	int snprintf_result;
	char s[100];

	if (!context) {
		return -EINVAL;
	}

	snprintf_result =
	symbol_to_text(s, sizeof(s), namebuf, module, kallsyms_address);
	if (snprintf_result > 0) {
		context->cb(context->cb_context, s, snprintf_result);
	} else {
		WPRINTF("snprintf_result=%i", snprintf_result);
	}
	return 0;
}

int enumerate_kernel_symbols(void* cb_context, enumerate_kernel_symbols_cb_t cb)
{
	enumerate_kernel_symbols_context_t context = {
		.cb = cb,
		.cb_context = cb_context,
	};
	return kallsyms_on_each_symbol(enumerate_kernel_symbols_cb, &context);
}
