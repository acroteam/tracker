/// @brief service

#include "service.h"

#include "debug.h"
#include "preprocessor.h"	// toUI()

// FIXME: Do something useful
void Service::onDriverError(const char* origin, const char* errorMessage)
{
  EPRINTF("%s: %s", origin, errorMessage);
}

// TODO: send 'event' to 'appliance' for processing
// Meanwhile block each 3-rd event
bool Service::onDriverEvent(driver::event::Type driverEventType, const void* eventData)
{
  static unsigned event_count = 0;
  DPRINTF("event[%u]: %u/%s, %p", event_count, toUI(driverEventType), driver::event::toString(driverEventType), eventData);
  return ++event_count % 3;
}

Service::Service() // may throw
{
  DPRINTF9("'service' created");
}

Service::~Service() // shall not throw
{
  stop();
  DPRINTF9("destroying 'service'");
}

void Service::start() // may throw
{
  std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
  if (driver_)
  {
    WPRINTF("driver is already active");
  }
  else
  {
    IPRINTF("activationg driver");
    driver_.reset(new Driver(*static_cast<driver::event::Observer*>(this)));
  }
}

void Service::stop() // shall not throw
{
  std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
  if (!driver_)
  {
    DPRINTF("driver is already inactive");
  }
  else
  {
    IPRINTF("deactivationg driver");
    driver_.reset();
  }
}
