#pragma once

/// @brief service

#include "driver.h"

#include <memory>               // std::shared_ptr<>

class Service
  : private driver::event::Observer
{
private:

  mutable std::recursive_mutex mutex_;
  std::unique_ptr<Driver> driver_;

  // driver::event::Observer
  virtual void onDriverError(const char* origin, const char* errorMessage) override;
  virtual bool onDriverEvent(driver::event::Type driverEventType, const void* eventData) override;

public:
  Service(); // may throw
  ~Service(); // shall not throw
  void start(); // may throw
  void stop(); // shall not throw
};
