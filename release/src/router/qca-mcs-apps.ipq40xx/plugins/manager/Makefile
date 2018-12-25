# Makefile for multicast forwarding plugins
# Copyright (c) 2012-2015 Qualcomm Atheros, Inc.
# All rights reserved.
# Qualcomm Atheros Confidential and Proprietary.
#

TOP_SRCDIR := ../../
include $(TOP_SRCDIR)/Makefile.defs

# The output library
TARGET_LIB := libpluginManager.a

# The Makefile will automatically compile all C files.
TARGET_OBJECTS := $(patsubst %.c,%.o,$(shell ls *.c 2> /dev/null))

all: $(TARGET_LIB) install

$(TARGET_LIB): $(TARGET_OBJECTS)
	@rm -f $(TARGET_LIB)
	$(AR) $(ARFLAGS) $(TARGET_LIB) $(TARGET_OBJECTS)
	$(RANLIB) $(TARGET_LIB)

.c.o:
	$(COMPILE) $(EXTRA_CFLAGS) -c $<

install: $(TARGET_LIB)
	@cp -a -f $(TARGET_LIB) $(INSTALL_ROOT)/lib

clean:
	@rm -f *.o *.d $(TARGET_LIB) *~

.PHONY: all clean install
