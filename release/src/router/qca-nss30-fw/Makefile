# Convert asuswrt build environment variable to qca-nss-fw
-include ../.config
NSSFW=$(if $(RTCONFIG_NSS_IPSEC),E/enterprise_ap,R/retail_router)
TYPE=$(shell echo $(NSSFW) | sed -e "s,./\([^_]*\)_.*,\1,")
PKG_BUILD_DIR=$(shell pwd)/source

# Define variables for qca-nss-fw
INSTALLFWDIR:=$(INSTALLDIR)/lib/firmware

all:
	@#Nothing to do

install:
	@echo Install $(TYPE) NSS firmware.
	install -d $(INSTALLFWDIR)
	install -m 644 $(PKG_BUILD_DIR)/$(NSSFW)0.bin $(INSTALLFWDIR)/qca-nss0-$(TYPE).bin
	install -m 644 $(PKG_BUILD_DIR)/$(NSSFW)1.bin $(INSTALLFWDIR)/qca-nss1-$(TYPE).bin
	ln -sf qca-nss0-$(TYPE).bin $(INSTALLFWDIR)/qca-nss0.bin
	ln -sf qca-nss1-$(TYPE).bin $(INSTALLFWDIR)/qca-nss1.bin

clean:
	@#Nothing to do
