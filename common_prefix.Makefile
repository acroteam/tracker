.PHONY: default
default: all

.PHONY: all
.PHONY: clean
.PHONY: install
install: all

# Let's use '.SECONDEXPANSION:' for substitutions in prerequisites
.SECONDEXPANSION:

BASE_BUILD_DIR := $(ROOTDIR)/BUILD_DIR
BASE_INSTALL_DIR := $(ROOTDIR)/INSTALL_DIR

TARGET_BUILD_DIR := $(BASE_BUILD_DIR)/$(TARGET)

# search $(SOURCES) in $(SOURCES_DIRS)
vpath %.c $(SOURCES_DIRS)
vpath %.cpp $(SOURCES_DIRS)

# search include files next to sources
INCLUDE += $(SOURCES_DIRS)

OBJECTS := $(patsubst %,$(TARGET_BUILD_DIR)/%.o,$(SOURCES))
OBJECTS_DIRS := $(sort $(dir $(OBJECTS)))

CC := gcc
CXX := g++
MAKE += -r
#$(info "MAKE='$(MAKE)'")

CXXFLAGS += -std=c++11

CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Werror
CFLAGS += -Wno-format-zero-length
CFLAGS += -g
CFLAGS += -O2
CFLAGS += -fvisibility=hidden

CFLAGS += $(addprefix -isystem , $(SYS_INCLUDE))
CFLAGS += $(addprefix -iquote , $(INCLUDE))

# Generate dependencies
CFLAGS += -MMD

# Load dependencies if present
-include $(OBJECTS:.o=.d)

LDFLAGS += -Wl,--as-needed
#LDFLAGS += -Wl,-Map=$@.map

LDFLAGS += $(addprefix -L, $(LIB_DIRS))
LDFLAGS += $(addprefix -l, $(LIBS))

# C sources compilation
$(TARGET_BUILD_DIR)/%.c.o : %.c | $$(dir $$@)
	$(CC) -c $(CFLAGS) -o $@ $<

# C++ sources compilation
$(TARGET_BUILD_DIR)/%.cpp.o: %.cpp | $$(dir $$@)
	$(CXX) -c $(CXXFLAGS) $(CFLAGS) -o $@ $<
