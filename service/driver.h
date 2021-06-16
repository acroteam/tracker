#pragma once

/// @brief driver

#include <mutex>
#include <thread>

namespace driver {
namespace event {

enum class Type
{
  EXEC,
  OPEN,
};

const char* toString(Type type);

namespace data {

struct Exec
{
  const char* parent_path;
  const char* child_path;
};

struct Open
{
  const char* executable_path;
  const char* data_path;
};

} // namespace data

// Warning: It is prohibited to destroy 'DriverObserver' in callbacks.
class Observer
{
public:
  virtual ~Observer() = default;
  // Shall not throw. It is logical error if 'onDriverError()' throws exception.
  virtual void onDriverError(const char* origin, const char* errorMessage) = 0;
  virtual bool onDriverEvent(driver::event::Type driverEventType, const void* eventData) = 0;
};

} // namespace event
} // namespace driver

class Driver
{
private:
  driver::event::Observer& driverEventObserver_;

  void onErrorHelper(const char* errorMessage);
  void onEventHelper(driver::event::Type driverEventType, const void* eventData);

  mutable std::recursive_mutex mutex_;
  bool shutdown_ = false;
  static void run_proxy(void* self) { static_cast<Driver*>(self)->run(); }
  void run();
  std::thread thread_;

public:
  Driver(driver::event::Observer& driverEventObserver); // may throw
  ~Driver(); // shall not throw
};
