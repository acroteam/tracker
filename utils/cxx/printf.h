#pragma once

/// @brief 'printf()' into 'std::string'

#include <cstdarg> // ::va_list
#include <string> // std::string

namespace cxx {

/*
    The "string_printf()" and "string_vprintf()" functions are analogs of
    "sprintf()" and "vsprintf()" (or "asprintf()" and "vasprintf()"),
    except that they return std::string.

    Note: Output can't be truncated and always complete. Actual size of
    output can be obtained with "size()" or "length()" if necessary.
*/

std::string printf(const char * format, ...);
std::string vprintf(const char * format, va_list args);

} // namespace cxx
