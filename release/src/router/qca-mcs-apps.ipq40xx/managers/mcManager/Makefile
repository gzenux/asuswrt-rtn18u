# Copyright (c) 2014-2015 Qualcomm Atheros, Inc.
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#

TOP_SRCDIR = ../../
include $(TOP_SRCDIR)/Makefile.defs

INSTALLHEADERS = mcManager.h
TARGET_LIB = libmcManager.a
TARGET_OBJECTS = mcManager.$(OBJEXT)

all: $(TARGET_LIB) install

CFLAGS += -I$(TOP_SRCDIR)/services/tdService -I$(TOP_SRCDIR)/managers/wlanManager -I$(TOP_SRCDIR)/managers/plcManager \
	-I$(TOP_SRCDIR)/plugins/mcfwdtbl-wlan5g -I$(TOP_SRCDIR)/plugins/mcfwdtbl-wlan2g -I$(TOP_SRCDIR)/plugins/mcfwdtbl-eswitch

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

