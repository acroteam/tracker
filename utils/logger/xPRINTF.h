#pragma once

/// @brief Logger's 'xPRINTF()'

#include "logger/FUNCTION_NAME.h"
#include "logger/log_line.h"

#define xPRINTF(level, format, args...) \
    do { \
      logger_log_line(level, __FILE__, __LINE__, LOGGER_FUNCTION_NAME, format, ##args); \
    } while(0)

// in descending order of importance
#define FPRINTF(format, args...) xPRINTF(LOG_LEVEL_EMERGENCY, format, ##args)
#define APRINTF(format, args...) xPRINTF(LOG_LEVEL_ALERT    , format, ##args)
#define CPRINTF(format, args...) xPRINTF(LOG_LEVEL_CRITICAL , format, ##args)
#define EPRINTF(format, args...) xPRINTF(LOG_LEVEL_ERROR    , format, ##args)
#define WPRINTF(format, args...) xPRINTF(LOG_LEVEL_WARNING  , format, ##args)
#define NPRINTF(format, args...) xPRINTF(LOG_LEVEL_NOTICE   , format, ##args)
#define IPRINTF(format, args...) xPRINTF(LOG_LEVEL_INFO     , format, ##args)
