ROOTDIR := ..
TARGET := service

CFLAGS += -DLOGGER_ENABLE_STDERR

# comment/uncomment to set default debug level
CFLAGS += -DDEBUG_LEVEL_DEFAULT=10

SOURCES += tracer.cpp
SOURCES += event.cpp
SOURCES += driver.cpp
SOURCES += main.cpp
SOURCES += service.cpp

SOURCES_DIRS += $(ROOTDIR)/utils
SOURCES += cxx/printf.cpp
SOURCES += debug.c
SOURCES += gettid.c
SOURCES += global.cpp
SOURCES += logger.c
SOURCES += signal_handlers.cpp
SOURCES += time.c

LIBS += pthread
LIBS += rt

include $(ROOTDIR)/executable.Makefile
