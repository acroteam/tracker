#pragma once

/// @brief Popular macro for the C macro preprocessor

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define CONSTSTRLEN(s) (sizeof(s)-1)

#define toUI(x) static_cast<unsigned>(x)
#define toULL(x) static_cast<unsigned long long>(x)
