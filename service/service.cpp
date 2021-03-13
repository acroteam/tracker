/// @brief service

#include "service.h"
#include "debug.h"


#include "preprocessor.h"	// toUI()

// FIXME: Do something useful
void Service::onError(const char* origin, const char* errorMessage)
{
  EPRINTF("%s: %s", origin, errorMessage);
}

// TODO: send 'event' to 'appliance' for processing
// Meanwhile block each 3-rd event
bool Service::onEvent(event::Type EventType, const void* eventData)
{

  static unsigned event_count = 0;
  DPRINTF("event[%u]: %u/%s, %p", event_count, toUI(EventType), event::toString(EventType), eventData);
  return true;//return ++event_count % 3;
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
  if (tracer_)
  {
    WPRINTF("tracer is already active");
  }
  else
  {
    IPRINTF("activation tracer");
    tracer_.reset(new Tracer(*static_cast<event::source::Observer*>(this)));
  }
}

void Service::stop() // shall not throw
{
  std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
  if (!tracer_)
  {
    DPRINTF("tracer is already inactive");
  }
  else
  {
    IPRINTF("deactivation tracer");
    tracer_.reset();
  }
}
