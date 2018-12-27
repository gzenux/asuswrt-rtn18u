NET_USB_GOBI = $(INSTALLDIR)/lib/modules/$(LINUX_KERNEL)/kernel/drivers/net/usb/gobi/
GOBI_KO_DIR = prebuild
GOBI_UTIL_DIR = prebuild
GOBI_LIB_DIR = prebuild

include $(LINUXDIR)/.config
include $(TOP)/.config

ifeq ($(RTCONFIG_QCA),y)
CROSS_TOOLCHAIN_DIR=$(TOOLCHAIN)
LIBRT_VERSION=0.9.33.2
endif

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
	@install $(GOBI_LIB_DIR)/libGobiConnectionMgmt.00.00.02.so $(INSTALLDIR)/lib/
	@cd $(INSTALLDIR)/lib/ && ln -s libGobiConnectionMgmt.00.00.02.so libGobiConnectionMgmt.so
	@install -D $(CROSS_TOOLCHAIN_DIR)/lib/librt-$(LIBRT_VERSION).so $(INSTALLDIR)/lib/librt-$(LIBRT_VERSION).so
	@cd $(INSTALLDIR)/lib && ln -sf librt-$(LIBRT_VERSION).so librt.so.0
	@install $(GOBI_LIB_DIR)/libstdc++.so.6.0.16 $(INSTALLDIR)/lib/
	@cd $(INSTALLDIR)/lib && ln -sf libstdc++.so.6.0.16 libstdc++.so.6
	@install -d $(NET_USB_GOBI)
	@install $(GOBI_KO_DIR)/gobi.ko $(NET_USB_GOBI)


.PHONY: all clean install

