/// @brief  Return thread identifier (TID)

#if !defined _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "gettid.h"

#include <sys/syscall.h> // syscall
#include <sys/types.h>
#include <unistd.h>

/*
    Variables marked with '__thread' are placed into 'thread local
    storage' (TLS) and become unique for each thread. 'Thread identifier'
    ('tid') can be cached in TLS reducing numbers of 'gettid' syscalls.

    'fork' invalidates cached 'tid'. Call 'update_gettid_cache()' to fix
    cached 'tid'.
*/
static __thread pid_t tid;

pid_t gettid(void)
{
  // 'tid' can't be zero
  if (!tid) {
    tid = syscall(SYS_gettid);
  }
  return tid;
}

void update_gettid_cache()
{
  tid = syscall(SYS_gettid);
}
