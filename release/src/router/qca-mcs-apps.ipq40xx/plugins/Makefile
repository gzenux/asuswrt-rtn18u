# Makefile for multicast forwarding plugins
# Copyright (c) 2012-2015 Qualcomm Atheros, Inc.
# All rights reserved.
# Qualcomm Atheros Confidential and Proprietary.


all: $(psService) manager mcfwdtbl-wlan5g mcfwdtbl-wlan2g mcfwdtbl-eswitch

manager:
	@$(MAKE) -C manager all

mcfwdtbl-wlan5g:
	@$(MAKE) -C mcfwdtbl-wlan5g all

mcfwdtbl-wlan2g:
	@$(MAKE) -C mcfwdtbl-wlan2g all

mcfwdtbl-eswitch:
	@$(MAKE) -C mcfwdtbl-eswitch all

clean:
	@$(MAKE) -C manager clean
	@$(MAKE) -C mcfwdtbl-wlan5g clean
	@$(MAKE) -C mcfwdtbl-wlan2g clean
	@$(MAKE) -C mcfwdtbl-eswitch clean

.PHONY: manager mcfwdtbl-wlan5g mcfwdtbl-wlan2g mcfwdtbl-eswitch
