#pragma once

/// @brief 'cxx::Result' wrapper to handle errors in functions

namespace cxx {

template <typename R, typename E>
struct Result
{
  bool success;
  R result;
  E error;
};

} // namespace cxx
