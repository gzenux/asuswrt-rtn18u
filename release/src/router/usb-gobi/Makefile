include ../common.mak

NET_USB_GOBI = $(INSTALLDIR)/lib/modules/$(LINUX_KERNEL)/kernel/drivers/net/usb/gobi/
GOBI_KO_DIR = prebuild
GOBI_UTIL_DIR = prebuild
GOBI_LIB_DIR = prebuild
LIB_GOBI_CONN_MGMT = libGobiConnectionMgmt.00.00.04.so


ifeq ($(RTCONFIG_BCMARM),y)
LIBSTDC=$(shell dirname $(shell which $(CXX)))/../arm-brcm-linux-uclibcgnueabi/lib/libstdc++.so.6
else # QCA
LIBSTDC=$(shell dirname $(shell which $(CXX)))/../lib/libstdc++.so.6
endif
LIBRT=$(shell dirname $(shell which $(CXX)))/../lib/librt.so.0


all:
clean:
	@echo "do nothing"


install: $(GOBI_KO_DIR)/gobi.ko $(GOBI_UTIL_DIR)/gobi
	@rm -rf $(INSTALLDIR)
	@install -d $(INSTALLDIR)
	@install -d $(INSTALLDIR)/usr/sbin
	@install $(GOBI_UTIL_DIR)/gobi $(INSTALLDIR)/usr/sbin/
	@$(STRIP) $(INSTALLDIR)/usr/sbin/gobi
	@install $(GOBI_UTIL_DIR)/gobi_api $(INSTALLDIR)/usr/sbin/gobi_api
	@$(STRIP) $(INSTALLDIR)/usr/sbin/gobi_api
#	@cp -rf usr $(INSTALLDIR)/
	@install -d $(INSTALLDIR)/lib
	@install $(GOBI_LIB_DIR)/$(LIB_GOBI_CONN_MGMT) $(INSTALLDIR)/lib/
	@cd $(INSTALLDIR)/lib/ && ln -s $(LIB_GOBI_CONN_MGMT) libGobiConnectionMgmt.so
	@install -D $(LIBRT) $(INSTALLDIR)/lib/librt.so.0
	@install -D $(LIBSTDC) $(INSTALLDIR)/lib/libstdc++.so.6
	@install -d $(NET_USB_GOBI)
	@install $(GOBI_KO_DIR)/gobi.ko $(NET_USB_GOBI)


.PHONY: all clean install

