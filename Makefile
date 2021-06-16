ROOTDIR := .

SUBDIRS += service

include $(ROOTDIR)/Makefile.SUBDIRS
include $(ROOTDIR)/common_prefix.Makefile
include $(ROOTDIR)/common_suffix.Makefile
