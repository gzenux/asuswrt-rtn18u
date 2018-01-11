# Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#

TOP_SRCDIR = ../../
include $(TOP_SRCDIR)/Makefile.defs

SUBDIRS =
INSTALLHEADERS = plcManager.h
TARGET_LIB = libplcManager.a
TARGET_OBJECTS = plcManager.$(OBJEXT)

all: $(TARGET_LIB) subdir install

$(TARGET_LIB): $(TARGET_OBJECTS)
	@rm -f $(TARGET_LIB)
	$(AR) $(ARFLAGS) $(TARGET_LIB) $(TARGET_OBJECTS)
	$(RANLIB) $(TARGET_LIB)

.c.o:
	$(COMPILE) -c $<

subdir:
	@for dir in $(SUBDIRS) ; do (cd $$dir && $(MAKE) all) || exit 1; done
	@echo All subdirectories of `pwd` done.

install: $(TARGET_LIB)
	@cp -a -f $(TARGET_LIB) $(MCSLIB_STATIC)/.
	@for file in $(INSTALLHEADERS) ; do ln -s -f `pwd`/$$file $(MCSINCLUDE)/. ; done

clean:
	@rm -f *.o $(TARGET_LIB) *~
	@for dir in $(SUBDIRS)  ; do (cd $$dir && $(MAKE) clean) || exit 1; done

.PHONY: all clean

