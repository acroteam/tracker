.PHONY: all clean default modules
default: all

# verbose make:
#MAKE += V=1
$(info "MAKE='$(MAKE)'")

SRC_DIR := $(CURDIR)
BUILD_DIR := $(abspath BUILD_DIR)
$(info "BUILD_DIR='$(BUILD_DIR)'")

# Linux kernel build system 'kbuild' can put object files into dedicated
# directory but fails to create that directory. Thus we need to create
# all necessary directories in advance.

# Add all source subdirecories to MODULE_SUBDIRS
MODULE_SUBDIRS += some_subdir

# This is list of [sub]directories we need to precreate for 'kbuild' to
# store object files
OBJ_DIRS := $(addprefix $(BUILD_DIR)/,$(MODULE_SUBDIRS))
OBJ_DIRS += $(BUILD_DIR)

# '_mkdir' variable and following rule will help create directories on
# demand. Use '$(call _mkdir,$(DIR_LIST))' to get necessary dependencies.
_mkdir = $(addsuffix /.mkdir,$(1))
%/.mkdir:
	@mkdir -pv $(@D)
	@touch $@

# Use '*_MKDIR' variables as dependencies instead of respective
# directories to make them on demand
BUILD_DIR_MKDIR := $(call _mkdir,$(BUILD_DIR))
#$(info "BUILD_DIR_MKDIR='$(BUILD_DIR_MKDIR)'")
OBJ_DIRS_MKDIR := $(call _mkdir,$(OBJ_DIRS))
#$(info "OBJ_DIRS_MKDIR='$(OBJ_DIRS_MKDIR)'")

# Linux kernel build system 'kbuild' needs 'Kbuild' file (or symlink to
# actual file) in $(BUILD_DIR)
KBUILD_SYMLINK := $(BUILD_DIR)/Kbuild
# Note: symlink is always recreated if depends on $(BUILD_DIR_MKDIR)
$(KBUILD_SYMLINK):
	@mkdir -p $(@D)
	@ln -fsv $(SRC_DIR)/Kbuild $@

all: $(OBJ_DIRS_MKDIR) $(KBUILD_SYMLINK)
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(BUILD_DIR) src=$(SRC_DIR) modules

clean:
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(BUILD_DIR) src=$(SRC_DIR) clean
	@$(RM) $(KBUILD_SYMLINK) $(OBJ_DIRS_MKDIR) $(BUILD_DIR_MKDIR)
	@-rmdir $(OBJ_DIRS)
