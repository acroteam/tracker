#pragma once

/// @brief Logger's self debug logging

#include "logger/debug_level.h"
#include "logger/FUNCTION_NAME.h"

#include <stdio.h>                      // fprintf(), stderr

#define LOGGER_xPRINTF(prefix, format, args...) \
    fprintf(stderr, "%s:%u:%s| %s: " format "\n", \
        __FILE__, __LINE__, LOGGER_FUNCTION_NAME, prefix, ##args)

#define LOGGER_EPRINTF(format, args...) LOGGER_xPRINTF("ERROR", format, ##args)
#define LOGGER_IPRINTF(format, args...) LOGGER_xPRINTF("INFO", format, ##args)

#if defined LOGGER_ENABLE_LOGGER_DEBUG
#define LOGGER_DPRINTF(format, args...) \
    do { \
      if (debug_level) \
      { \
        LOGGER_xPRINTF("DEBUG", format, ##args); \
      } \
    } while (0)
#else
#define LOGGER_DPRINTF(format, args...)
#endif
