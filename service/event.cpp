#include "event.h"

namespace tracer
{
namespace event
{
	#define CASE(SYSCALL) \
	case SYSCALL: return #SYSCALL

	const char* toString(unsigned int type)
	{
		switch (type)
		{
		    CASE(OPEN);
		    CASE(EXEC);
		    CASE(OPENAT);
		    CASE(READ);
		    CASE(WRITE);
		    default: return "?";
		}
	}
	#undef CASE


	
	const char* toString(Type type)
	{
		switch (type)
		{
    		case Type::EXEC: return "EXEC";
    		case Type::OPEN: return "OPEN";
    		default: return "?";
		}
	}
} // event
} // tracer
