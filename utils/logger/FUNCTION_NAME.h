#pragma once

/// @brief Logger's 'function name' representation

#if !defined LOGGER_FUNCTION_NAME
#if defined __cplusplus
#define LOGGER_FUNCTION_NAME __PRETTY_FUNCTION__
#else // defined __cplusplus
#define LOGGER_FUNCTION_NAME __FUNCTION__
#endif // defined __cplusplus
#endif // !defined(LOGGER_FUNCTION_NAME)
