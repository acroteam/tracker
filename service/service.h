#pragma once

/// @brief service

#include "tracer.h"
#include "event.h"
#include "driver.h"


#include <memory>               // std::shared_ptr<>

class Service
  : private event::Observer
{
private:

  mutable std::recursive_mutex mutex_;
  std::unique_ptr<Tracer> tracer_;

  // event::Observer
  virtual void onDriverError(const char* origin, const char* errorMessage) override;
  virtual bool onDriverEvent(event::Type driverEventType, const void* eventData) override;

public:
  Service(); // may throw
  ~Service(); // shall not throw
  void start(); // may throw
  void stop(); // shall not throw
};
