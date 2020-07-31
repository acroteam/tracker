#pragma once

/// @brief Linux kernel exported symbols enumeration

#include <linux/types.h>

void count_kernel_symbols(void);

typedef int (*enumerate_kernel_symbols_cb_t)(
	void* cb_context, const char* data, size_t size);

int enumerate_kernel_symbols(void* cb_context, enumerate_kernel_symbols_cb_t cb);

