#pragma once

/// @brief Logger's 'log_line()'

#include "logger/log_level.h"

#ifdef __cplusplus
extern "C" {
#endif

void logger_log_line(logger_log_level_t log_level, const char* file,
    unsigned line, const char* function, const char* format, ...)
    __attribute__ ((format (printf, 5, 6)));

#ifdef __cplusplus
}
#endif
