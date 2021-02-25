#pragma once

/// @brief service

#include "tracer.h"
#include "event.h"


#include <memory>               // std::shared_ptr<>

class Service
  : private tracer::event::source::Observer
{
private:

  mutable std::recursive_mutex mutex_;
  std::unique_ptr<tracer::Tracer> tracer_;

  // tracer::event::Observer
  virtual void onError(const char* origin, const char* errorMessage) override;
  virtual bool onEvent(tracer::event::Type driverEventType, const void* eventData) override;

public:
  Service(); // may throw
  ~Service(); // shall not throw
  void start(); // may throw
  void stop(); // shall not throw
};
