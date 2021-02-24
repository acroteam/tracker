#pragma once

#include "libc/Result.h"

#include <signal.h>

namespace libc {

typedef Result<int> SigactionResult;

inline SigactionResult sigaction(
    int signum,
    const struct sigaction *new_sigaction,
    struct sigaction *old_sigaction)
{
  return SigactionResult(::sigaction(signum, new_sigaction, old_sigaction));
}

} // namespace libc
