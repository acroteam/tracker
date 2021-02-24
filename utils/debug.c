/// @brief Debug logging

// Note: libraries shall use 'external' debug level check
#if !defined LOGGER_EXTERNAL_DEBUG_LEVEL_CHECK

#include "logger/debug_level.h"

unsigned debug_level
#if defined DEBUG_LEVEL_DEFAULT
    = DEBUG_LEVEL_DEFAULT
#endif
    ;

#endif
