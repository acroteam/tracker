/// @brief Logger

#if !defined _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "logger.h"

#include "gettid.h"
#include "logger/self_debug.h"
#include "time.h"

#include <stdarg.h>             // va_list
#include <stdio.h>              // dprintf(), fprintf(), stderr, snprintf(), vasprintf()
#include <stdlib.h>             // free()
#if defined LOGGER_ENABLE_MONOTONIC_TIMESTAMP
#include <time.h>               // clock_gettime()
#endif
#include <unistd.h>             // close(), getpid(), unlink()

#if !defined LOGGER_SUPPRESS_DETAILS
static const char* logger_log_level_to_string(logger_log_level_t log_level)
{
  switch (log_level)
  {
  case LOG_LEVEL_EMERGENCY: return "EMERGENCY";
  case LOG_LEVEL_ALERT    : return "ALERT";
  case LOG_LEVEL_CRITICAL : return "CRITICAL";
  case LOG_LEVEL_ERROR    : return "ERROR";
  case LOG_LEVEL_WARNING  : return "WARNING";
  case LOG_LEVEL_NOTICE   : return "NOTICE";
  case LOG_LEVEL_INFO     : return "INFO";
  case LOG_LEVEL_DEBUG    : return "DEBUG";
  case LOG_LEVEL_DEBUG1   : return "DEBUG1";
  case LOG_LEVEL_DEBUG2   : return "DEBUG2";
  case LOG_LEVEL_DEBUG3   : return "DEBUG3";
  case LOG_LEVEL_DEBUG4   : return "DEBUG4";
  case LOG_LEVEL_DEBUG5   : return "DEBUG5";
  case LOG_LEVEL_DEBUG6   : return "DEBUG6";
  case LOG_LEVEL_DEBUG7   : return "DEBUG7";
  case LOG_LEVEL_DEBUG8   : return "DEBUG8";
  case LOG_LEVEL_DEBUG9   : return "DEBUG9";
  default                 : return "UNKNOWN";
  }
}
#endif

#if !defined LOGGER_ENABLE_STDERR
#error "Define at least one of: LOGGER_ENABLE_STDERR"
#endif

static void logger_output_log_line_sync(logger_log_level_t log_level, const char* log_line)
{
  (void)log_level;
  (void)log_line;

#if defined LOGGER_ENABLE_STDERR
  fprintf(stderr, "%s\n", log_line);
#endif
}

static char* logger_format_log_line(logger_log_level_t log_level, const char* file,
    unsigned line, const char* function, const char* format, va_list argsList)
{
  char* log_text = NULL;
  if (-1 == vasprintf(&log_text, format, argsList))
  {
    return NULL;
  }

#if defined LOGGER_SUPPRESS_DETAILS

  if (log_level < LOG_LEVEL_DEBUG)
  {
    return log_text;
  }
  char* log_line = NULL;
  if (-1 == asprintf(&log_line, "%s:%u %s| %s", file, line, function, log_text))
  {
    return log_text;
  }

#else

#if defined LOGGER_ENABLE_DATE_TIME
  char date_time_string[DATE_TIME_STRING_NSEC_LEN+1];
  date_time_string_nsec(date_time_string, sizeof(date_time_string));
#endif

#if defined LOGGER_ENABLE_MONOTONIC_TIMESTAMP
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
  {
    ts.tv_sec = ts.tv_nsec = 0;
  }
  // 2147483648 = 0x80000000
  char monotonic_timestamp[sizeof("2147483648.000000000")];
  snprintf(monotonic_timestamp, sizeof(monotonic_timestamp), "%u.%09u",
      (unsigned)ts.tv_sec, (unsigned)ts.tv_nsec);
#endif

  char* log_line = NULL;
  if (-1 == asprintf(&log_line,
#if defined LOGGER_ENABLE_DATE_TIME
      "%s "
#endif
#if defined LOGGER_ENABLE_MONOTONIC_TIMESTAMP
      "%s "
#endif
 "%5u:%5u %s:%u %s| %s: %s",
#if defined LOGGER_ENABLE_DATE_TIME
      date_time_string,
#endif
#if defined LOGGER_ENABLE_MONOTONIC_TIMESTAMP
      monotonic_timestamp,
#endif
      (unsigned)getpid(), (unsigned)gettid(),
      file, line, function,
      logger_log_level_to_string(log_level), log_text))
  {
    log_line = NULL;
  }

#endif

  free(log_text);
  return log_line;
}

void logger_log_line(logger_log_level_t log_level, const char* file,
    unsigned line, const char* function, const char* format, ...)
{
  va_list argsList;
  va_start(argsList, format);
  char* log_line = logger_format_log_line(log_level, file, line, function, format, argsList);
  va_end(argsList);

  if (log_line)
  {
    logger_output_log_line_sync(log_level, log_line);
    free(log_line);
  }
}
