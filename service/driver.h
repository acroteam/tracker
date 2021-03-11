#pragma once

/// @brief driver

#include <mutex>
#include <thread>

#include "event.h"


class Driver
{
private:
  event::Observer& driverEventObserver_;

  void onErrorHelper(const char* errorMessage);
  void onEventHelper(event::Type driverEventType, const void* eventData);

  mutable std::recursive_mutex mutex_;
  bool shutdown_ = false;
  static void run_proxy(void* self) { static_cast<Driver*>(self)->run(); }
  void run();
  std::thread thread_;

public:
  Driver(event::Observer& driverEventObserver); // may throw
  ~Driver(); // shall not throw
};
