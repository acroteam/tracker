include $(ROOTDIR)/common_prefix.Makefile

TARGET_INSTALL_DIR := $(BASE_INSTALL_DIR)/bin
#EXECUTABLE := $(TARGET_INSTALL_DIR)/$(TARGET)

all: $(TARGET_BUILD_DIR)/$(TARGET)
# 'link' executable
$(TARGET_BUILD_DIR)/$(TARGET): $(OBJECTS) | $$(dir $$@)
	$(CXX) $(CXXFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: install_executable
install: install_executable
install_executable:
	install -D -m 0755 $(TARGET_BUILD_DIR)/$(TARGET) $(TARGET_INSTALL_DIR)/$(TARGET)

include $(ROOTDIR)/common_suffix.Makefile
