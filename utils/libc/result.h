#pragma once

/// @brief 'libc::Result' convenience wrapper for libc's functions

#include <stdexcept>

#include <errno.h>

namespace libc {

namespace impl {

template <typename T>
struct Storage
{
  using type = T;
};

template <>
struct Storage<unsigned short>
{
  using type = short;
};

template <>
struct Storage<unsigned>
{
  using type = int;
};

template <>
struct Storage<unsigned long>
{
  using type = long;
};

template <>
struct Storage<unsigned long long>
{
  using type = long long;
};

} // namespace impl

namespace raw {

// S - storage, for both 'result' and 'error tag'
// R - result, to be extracted from 'storage'
// E - error number, comes from 'errno'
template <typename R, int ERROR_TAG = -1>
class Result
{
protected:
  using S = typename impl::Storage<R>::type;
  using E = int;

private:
  S v_;
  E e_;

public:
  inline Result(S v, E e) : v_(v), e_(e) {}
  inline explicit Result(S v) : Result(v, errno) {}
  inline static Result Success(R r) { return Result((S)r, 0); }
  inline static Result Failure(E e) { return Result((S)ERROR_TAG, e); }

  inline bool isError() const { return ((S)ERROR_TAG) == v_; }
  inline operator bool() const { return !isError(); }

  inline E error() const { return e_; }
  inline R result() const { return v_; }
};

} // namespace raw

template <typename R, int ERROR_TAG = -1>
class Result
  : private raw::Result<R, ERROR_TAG>
{
private:
  using rawResult = raw::Result<R, ERROR_TAG>;

protected:
  using S = typename rawResult::S;
  using E = typename rawResult::E;

public:
  inline const rawResult& raw() const
  {
    return *static_cast<const rawResult*>(this);
  }

  inline rawResult& raw()
  {
    return *static_cast<rawResult*>(this);
  }

  inline Result(S v, E e) : rawResult::Result(v, e) {}
  inline explicit Result(S v) : rawResult::Result(v) {}
  inline static Result Success(R r) { return Result((S)r, 0); }
  inline static Result Failure(E e) { return Result((S)ERROR_TAG, e); }

  inline bool isError() const { return rawResult::isError(); }
  inline operator bool() const { return !isError(); }

  R result() const
  {
    if (isError()) { throw std::logic_error("no result"); }
    return rawResult::result();
  }

  E error() const
  {
    if (!isError()) { throw std::logic_error("no error"); }
    return rawResult::error();
  }
};

} // namespace libc
