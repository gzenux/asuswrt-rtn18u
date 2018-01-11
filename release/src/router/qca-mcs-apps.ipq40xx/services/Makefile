# Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#

TOP_SRCDIR = ..
include $(TOP_SRCDIR)/Makefile.defs

SRCDIRS =

ifeq ($(MCS_MODULE_DBG),y)
SRCDIRS += dbgService
endif


all: header
	@for dir in $(SRCDIRS) ; do (cd $$dir && $(MAKE) all) || exit 1; done
header:
	@for dir in $(SRCDIRS) ; do (cd $$dir && $(MAKE) header) || exit 1; done
clean:
	@for dir in $(SRCDIRS)  ; do (cd $$dir && $(MAKE) clean) || exit 1; done


.PHONY: all clean

