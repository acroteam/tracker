#pragma once

namespace event
{
namespace data 
{

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


enum Syscalls
{
  EXEC = 59,
  OPEN = 2,
  OPENAT = 257,
  READ = 0,
  WRITE = 1,
};

enum class Type
{
  EXEC,
  OPEN,
  OPENAT,
  READ,
  WRITE,
  UNKNOWN
};



const char* toString(unsigned int type);
const char* toString(Type type);


namespace source
{

class Observer
{
public:
  virtual ~Observer() = default;
  // Shall not throw. It is logical error if 'onDriverError()' throws exception.
  virtual void onError(const char* origin, const char* errorMessage) = 0;
  virtual bool onEvent(Type driverEventType, const void* eventData) = 0;
};

}

} // event