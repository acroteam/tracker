#pragma once

/// @brief Logger's 'log level'

typedef enum logger_log_level_e {
  // A panic condition (system is unusable)
  LOG_LEVEL_EMERGENCY,
  // A condition that should be corrected immediately
  LOG_LEVEL_ALERT    ,
  // A critical condition
  LOG_LEVEL_CRITICAL ,
  // An error conditions
  LOG_LEVEL_ERROR    ,
  // A warning condition
  LOG_LEVEL_WARNING  ,
  // Normal but significant condition requiring special handling
  LOG_LEVEL_NOTICE   ,
  // A general information message.
  LOG_LEVEL_INFO     ,
  // A message useful for debugging programs.
  LOG_LEVEL_DEBUG    ,

  // It could be good for debugging purposes to internally support
  // several 'DEBUG' levels but map them all to the same 'LOG_DEBUG'
  // if log output is directed to 'syslog'.
  LOG_LEVEL_DEBUG1,
  LOG_LEVEL_DEBUG2,
  LOG_LEVEL_DEBUG3,
  LOG_LEVEL_DEBUG4,
  LOG_LEVEL_DEBUG5,
  LOG_LEVEL_DEBUG6,
  LOG_LEVEL_DEBUG7,
  LOG_LEVEL_DEBUG8,
  LOG_LEVEL_DEBUG9,
} logger_log_level_t;
