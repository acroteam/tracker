/// @brief 'printf()' into 'std::string'

#include "cxx/printf.h"

#include <cstdarg> // ::va_list
#include <cstdio> // ::vsnprintf()
#include <string> // std::string

namespace cxx {

/*
    The "string_printf()" and "string_vprintf()" functions are analogs of
    "sprintf()" and "vsprintf()" (or "asprintf()" and "vasprintf()"),
    except that they return std::string.

    Note: Output is never truncated and always complete. Actual size of
    output can be obtained with "size()" or "length()" if necessary.
*/

std::string printf(const char * format, ...)
{
    std::string s;
    va_list args;

    va_start(args, format);
    s = vprintf(format, args);
    va_end(args);

    return s;
}

// Note: On buffer overflow some ancient "vsnprintf" implementations may
// return -1 instead of size necessary for complete output.

// Minimal buffer must have space at least for terminating '\0'
#define MINIMAL_BUFFER_SIZE 1

// Initial guess must cover frequent cases
#define INITIAL_GUESS_BUFFER_SIZE 0x1000

std::string vprintf(const char * format, va_list args)
{
    std::string s;
    va_list args_copy;
    int result;

    // We need to determine size of buffer necessary to fit complete output.
    // Let's assume modern 'vsnprintf' always returning size necessary for
    // complete output. In such case we can use very small local buffer.
    {
	char small_buffer[MINIMAL_BUFFER_SIZE];
	va_copy(args_copy, args);
	result = vsnprintf(small_buffer, sizeof(small_buffer), format, args_copy);
	va_end(args_copy);
    }
    if (result < 0)
    {
	// Buffer overflow report from old glibc.
	// We need real buffer big enough to fit complete output.
	// We have to guess and check iteratively.
	// To speed-up below loop let's start with reasonable big buffer.
	size_t buffer_size = INITIAL_GUESS_BUFFER_SIZE; // including trailing '\0'
	for(;;)
        {
	    s.resize(buffer_size);

	    va_copy(args_copy, args);
	    result = vsnprintf(&s[0], buffer_size, format, args_copy);
	    va_end(args_copy);

	    if (result >= 0) { break; } // success

	    buffer_size *= 2; // try again with bigger buffer
	}
    }
    else
    {
        // "result" doesn't include trailing '\0'
        size_t buffer_size = result + 1; // one extra byte for trailing '\0'
        s.resize(buffer_size);
        result = vsnprintf(&s[0], buffer_size, format, args); // must be successful
    }
    s.resize(result); // exclude trailing '\0'

    return s;
}

} // namespace cxx
