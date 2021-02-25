#pragma once

/// @brief driver

#include <mutex>
#include <thread>

#include "event.h"

namespace driver {
namespace event {

enum class Type
{
  EXEC,
  OPEN,
  OPENAT,
  READ,
  WRITE,
};

const char* toString(Type type);


// Warning: It is prohibited to destroy 'DriverObserver' in callbacks.
class Observer
{
public:
  virtual ~Observer() = default;
  // Shall not throw. It is logical error if 'onDriverError()' throws exception.
  virtual void onDriverError(const char* origin, const char* errorMessage) = 0;
  virtual bool onDriverEvent(event::Type driverEventType, const void* eventData) = 0;
};

} // namespace event
} // namespace driver

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
