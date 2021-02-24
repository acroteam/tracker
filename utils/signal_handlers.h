#pragma once

/// @brief setup signal handlers

#include "libc/sigaction.h"

libc::SigactionResult setup_signal_handlers();
// FIXME: add 'reset_signal_handlers()'
