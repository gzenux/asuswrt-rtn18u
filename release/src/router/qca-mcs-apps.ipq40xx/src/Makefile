# Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#

TOP_SRCDIR = ..
include $(TOP_SRCDIR)/Makefile.defs

ifdef CONFIG_SUPPORT_PCD
COMPILE += -DMCS_USE_PCD -I$(TOPDIR)/apps/pcd-1.1.0/include
LIBS += -lpcd -lipc
endif

LIBS += -lpluginManager -lpthread \
	-lmcfwdtblwlan5g -lmcfwdtblwlan2g -lmcfwdtbleswitch

TARTGET_OBJECTS = mcsMain.$(OBJEXT)

MCS_LIBS = -lmcscore \
           -lmcManager

ifeq ($(MCS_MODULE_WLAN),y)
MCS_LIBS += -lwlanManager
endif

ifeq ($(MCS_MODULE_PLC),y)
MCS_LIBS += -lplcManager
endif

ifeq ($(MCS_MODULE_DBG),y)
MCS_LIBS += -ldbgService
endif

MCS_OPTIMIZE := -Wl,--gc-sections -fwhole-program -Wl,--sort-section,alignment -Wl,--sort-common

LIBS += $(MCS_LIBS)

all: mcsd$(EXEEXT) install

mcsd$(EXEEXT): $(TARTGET_OBJECTS) $(MCS_LIBS)
	$(LINK) -o $@ $(TARTGET_OBJECTS) -Xlinker --start-group $(LIBS) -Xlinker --end-group

.c.o:
	$(COMPILE) -c $<

install:
	@cp mcsd$(EXEEXT) $(INSTALL_ROOT)/sbin

clean:
	@rm -f *.o *~ mcsd$(EXEEXT)


.PHONY: all clean install

