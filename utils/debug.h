#pragma once

/// @brief Debug logging

#include "logger/debug_level.h"
#include "logger/log_level.h"
#include "logger/xPRINTF.h"

#define DPRINTFx(level, format, args...) \
    do { \
      if (debug_level > (level - LOG_LEVEL_DEBUG)) { \
        xPRINTF(level, format, ##args); \
      } \
    } while(0)

#define DPRINTF(format, args...) DPRINTFx(LOG_LEVEL_DEBUG, format, ##args)

#define DPRINTF1(format, args...) DPRINTFx(LOG_LEVEL_DEBUG1, format, ##args)
#define DPRINTF2(format, args...) DPRINTFx(LOG_LEVEL_DEBUG2, format, ##args)
#define DPRINTF3(format, args...) DPRINTFx(LOG_LEVEL_DEBUG3, format, ##args)
#define DPRINTF4(format, args...) DPRINTFx(LOG_LEVEL_DEBUG4, format, ##args)
#define DPRINTF5(format, args...) DPRINTFx(LOG_LEVEL_DEBUG5, format, ##args)
#define DPRINTF6(format, args...) DPRINTFx(LOG_LEVEL_DEBUG6, format, ##args)
#define DPRINTF7(format, args...) DPRINTFx(LOG_LEVEL_DEBUG7, format, ##args)
#define DPRINTF8(format, args...) DPRINTFx(LOG_LEVEL_DEBUG8, format, ##args)
#define DPRINTF9(format, args...) DPRINTFx(LOG_LEVEL_DEBUG9, format, ##args)
