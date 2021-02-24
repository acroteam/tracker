/// @brief setup signal handlers

#include "signal_handlers.h"

#include "debug.h"          // logging: *PRINTF()
#include "global.h"
#include "preprocessor.h"

#include <signal.h>
#include <string.h>

// Warning: 'handleSignal' is invoked in 'restricted signal handler
// context' where most system function are dangerous to call.
static void handleSignal(int sigNum)
{
  DPRINTF9("sigNum=%i", sigNum);
  if (sigNum == SIGINT || sigNum == SIGTERM) {
    global::shutdown = true;
  }
  else if (SIGUSR1 == sigNum) {
    ++debug_level;
  }
  else if (SIGUSR2 == sigNum && debug_level) {
    --debug_level;
  }
}

static const int signals[] = {
  SIGINT,
  SIGTERM,
  SIGUSR1,
  SIGUSR2,
};

libc::SigactionResult setup_signal_handlers()
{
  for (unsigned i = 0; i < ARRAY_SIZE(signals); ++i) {
    int sigNum = signals[i];
    struct sigaction sa = {};
    sa.sa_handler = handleSignal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags &= ~SA_RESTART;
    auto r(libc::sigaction(sigNum, &sa, NULL));
    if (!r) {
      int errorNumber(r.error_nothrow());
      EPRINTF("'%s(%i)' failure %i %s", "sigaction", sigNum, errorNumber, strerror(errorNumber));
      return r;
    }
  }
  return libc::SigactionResult::Success(0);
}
