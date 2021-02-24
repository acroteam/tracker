#pragma once

// @brief 'libc::Result' convenience wrapper for libc's functions

#include <stdexcept>

#include <errno.h>

namespace libc {

namespace impl {

template <typename R>
struct Result { typedef R S; };

template <>
struct Result<unsigned> { typedef int S; };

template <>
struct Result<unsigned long> { typedef long S; };

template <>
struct Result<void*> { typedef void* S; };

} // namespace impl

// S - storage, for both 'result' and 'error tag'
// R - result, to be extracted from 'storage'
// E - error number, comes from 'errno'
template <typename R, int error_tag = -1>
class Result
{
public:
  typedef typename impl::Result<R>::S S;
  typedef int E;

private:
  S v_;
  E e_;

  static const int ERROR_TAG = error_tag;

public:
  inline Result(S v, E e) : v_(v), e_(e) {}
  inline explicit Result(S v) : Result(v, errno) {}
  inline static Result Success(R r) { return Result(r, 0); }
  inline static Result Failure(E e) { return Result(ERROR_TAG, e); }

  inline bool isError() const { return ((S)(ERROR_TAG)) == v_; }
  inline operator bool() const { return !isError(); }

  inline R result_nothrow() const { return v_; }
  R result() const
  {
    if (isError()) { throw std::logic_error("no result"); }
    return v_;
  }

  inline E error_nothrow() const { return e_; }
  E error() const
  {
    if (!isError()) { throw std::logic_error("no error"); }
    return e_;
  }
};

} // namespace libc
