# Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#

TOP_SRCDIR = ../../
include $(TOP_SRCDIR)/Makefile.defs
CFLAGS += -I$(TOP_SRCDIR)/services/tdService
CFLAGS += -I$(TOP_SRCDIR)/services/pcwService

INSTALLHEADERS = wlanManager.h
TARGET_LIB = libwlanManager.a
TARGET_OBJECTS = wlanManager.$(OBJEXT)

all: $(TARGET_LIB) install

$(TARGET_LIB): $(TARGET_OBJECTS)
	@rm -f $(TARGET_LIB)
	$(AR) $(ARFLAGS) $(TARGET_LIB) $(TARGET_OBJECTS)
	$(RANLIB) $(TARGET_LIB)

.c.o:
	$(COMPILE) $(CFLAGS) -c $<

install: $(TARGET_LIB)
	@cp -a -f $(TARGET_LIB) $(MCSLIB_STATIC)/.
	@for file in $(INSTALLHEADERS) ; do ln -s -f `pwd`/$$file $(MCSINCLUDE)/. ; done

clean:
	@rm -f *.o $(TARGET_LIB) *~

.PHONY: all clean

