# Copyright (c) 2012, 2015 Qualcomm Atheros
# All rights reserved.
# Qualcomm Atheros Confidential and Proprietary.

TOP_SRCDIR = ..
include $(TOP_SRCDIR)/Makefile.defs

TARTGET_OBJECTS = mcsctl.$(OBJEXT)
LIBS += -lmcscore

all: mcsctl$(EXEEXT) install

mcsctl$(EXEEXT): $(TARTGET_OBJECTS)
	$(LINK) -o $@ $(TARTGET_OBJECTS) -Xlinker --start-group $(LIBS) -Xlinker --end-group

.c.o:
	$(COMPILE) -c $<

install:
	@cp mcsctl$(EXEEXT) $(INSTALL_ROOT)/sbin

clean:
	@rm -f *.o *~ mcsctl$(EXEEXT)


.PHONY: all clean install

