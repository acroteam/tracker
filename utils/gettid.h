#pragma once

/// @brief Return thread identifier (TID)

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

pid_t gettid(void);
void update_gettid_cache(void);

#ifdef __cplusplus
}
#endif
