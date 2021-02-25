/// @brief driver

#include "driver.h"

#include "cxx/printf.h"
#include "debug.h"
#include "event.h"
#include "preprocessor.h"	// ARRAY_SIZE(), toUI()

#include <chrono>               // std::chrono::milliseconds()
#include <exception>            // std::exception
#include <thread>               // std::this_thread::sleep_for()


static char const * const exec_paths[] = {
  "/path/to/some/executable/file",
  "/path/to/another/executable/file",
  "/path/to/some/missing/executable/file",
};

// Note 'executable file' can be used as 'data file' as well
static char const * const data_paths[] = {
  "/path/to/some/data/file",
  "/path/to/another/data/file",
  "/path/to/some/missing/data/file",
  "/some/path/to/file",
  "/some/path/to/another_file",
  "/some/path/to/directory",
  "/another/path/to/file",
  "/another/path/to/directory",
  "/path/to/some/executable/file",
  "/path/to/another/executable/file",
};

static void fill_next_exec_event(event::data::Exec& data)
{
  static unsigned exec_event_count = 0;
  data.parent_path = exec_paths[exec_event_count++ % ARRAY_SIZE(exec_paths)];
  data.child_path  = exec_paths[exec_event_count++ % ARRAY_SIZE(exec_paths)];
}

static void fill_next_open_event(event::data::Open& data)
{
  static unsigned open_event_count = 0;
  data.executable_path = exec_paths[open_event_count % ARRAY_SIZE(exec_paths)];
  data.data_path       = data_paths[open_event_count % ARRAY_SIZE(data_paths)];
  ++open_event_count;
}

void Driver::onErrorHelper(const char* errorMessage)
{
  DPRINTF9("errorMessage='%s'", errorMessage);
  try
  {
    driverEventObserver_.onDriverError("Driver", errorMessage);
  }
  catch (const std::exception& e)
  {
    EPRINTF("'%s' exception: %s", "onDriverError", e.what());
  }
  catch (...)
  {
    EPRINTF("unexpected '%s' exception", "onDriverError");
  }
}

void Driver::onEventHelper(event::Type driverEventType, const void* eventData)
{
  try
  {
    // TODO: Use 'onDriverEvent()' result to block 'events'
    const auto r = driverEventObserver_.onDriverEvent(driverEventType, eventData);
    switch (driverEventType)
    {
      case event::Type::EXEC:
      {
        const auto execData = static_cast<const event::data::Exec*>(eventData);
        IPRINTF("onEvent(%u/%s, parent='%s', child='%s')=%u",
            toUI(driverEventType), event::toString(driverEventType),
            execData->parent_path, execData->child_path, r);
        break;
      }
      case event::Type::OPEN:
      {
        const auto openData = static_cast<const event::data::Open*>(eventData);
        IPRINTF("onEvent(%u/%s, executable='%s', data='%s')=%u",
            toUI(driverEventType), event::toString(driverEventType),
            openData->executable_path, openData->data_path, r);
        break;
      }
      default:
      {
        IPRINTF("onEvent(%u/%s, %p)=%u", toUI(driverEventType), event::toString(driverEventType), eventData, r);
        break;
      }
    }
  }
  catch (const std::exception& e)
  {
    const auto errorMessage = ::cxx::printf("'%s' exception: %s", "onDriverEvent", e.what());
    onErrorHelper(errorMessage.c_str());
  }
  catch (...)
  {
    const auto errorMessage = ::cxx::printf("unexpected '%s' exception", "onDriverEvent");
    onErrorHelper(errorMessage.c_str());
  }
}

/*
    Each  5 seconds produce random 'open' event'
    Each 15 seconds produce random 'exec' event'
    Each 60 seconds produce random 'driver error'
*/
#define OPEN_EVENT_PERIOD_SEC 5
#define EXEC_EVENT_PERIOD_SEC 15
#define DRIVER_ERROR_PERIOD_SEC 60

#define RUN_PERIOD_MS 100
#define OPEN_EVENT_PERIOD (OPEN_EVENT_PERIOD_SEC * 1000 / RUN_PERIOD_MS)
#define EXEC_EVENT_PERIOD (EXEC_EVENT_PERIOD_SEC * 1000 / RUN_PERIOD_MS)
#define DRIVER_ERROR_PERIOD (DRIVER_ERROR_PERIOD_SEC * 1000 / RUN_PERIOD_MS)
void Driver::run()
{
  DPRINTF9("thread started");
  try
  {
    for (;;)
    {
      {
        std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
        if (shutdown_) { break; }
      }
      static unsigned run_count = 0;
      std::this_thread::sleep_for(std::chrono::milliseconds(RUN_PERIOD_MS));
      ++run_count;
      if (!(run_count % OPEN_EVENT_PERIOD))
      {
        event::data::Open openData;
        fill_next_open_event(openData);
        onEventHelper(event::Type::OPEN, &openData);
      }
      if (!(run_count % EXEC_EVENT_PERIOD))
      {
        event::data::Exec execData;
        fill_next_exec_event(execData);
        onEventHelper(event::Type::EXEC, &execData);
      }
      if (!(run_count % DRIVER_ERROR_PERIOD))
      {
        const auto errorMessage = ::cxx::printf("some random error (run_count=%u)", run_count);
        onErrorHelper(errorMessage.c_str());
      }
    }
  }
  catch (const std::exception& e)
  {
    const auto errorMessage = ::cxx::printf("exception: %s", e.what());
    onErrorHelper(errorMessage.c_str());
  }
  catch (...)
  {
    onErrorHelper("unexpected exception");
  }
  DPRINTF9("thread finished");
}

Driver::Driver(event::Observer& driverEventObserver)
  : driverEventObserver_(driverEventObserver)
  , thread_(std::thread(run_proxy, this))
{
  DPRINTF9("'driver' created");
}

Driver::~Driver()
{
  DPRINTF9("stopping 'driver' thread");
  {
    std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
    shutdown_ = true;
  }
  thread_.join();
  DPRINTF9("destroying 'driver'");
}
