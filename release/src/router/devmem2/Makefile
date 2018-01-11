# Convert asuswrt build environment variable to qca-nss-cfi
TARGET_CC=$(CROSS_COMPILE)gcc
PKG_BUILD_DIR=$(shell pwd)/source

all:
	$(MAKE) -C "$(PKG_BUILD_DIR)" CC="$(TARGET_CC)" $@

install:
	install -d $(INSTALLDIR)/usr/bin
	install -m 755 $(PKG_BUILD_DIR)/devmem2 $(INSTALLDIR)/usr/bin
	$(STRIP) $(INSTALLDIR)/usr/bin/*

clean:
	make -C $(PKG_BUILD_DIR) $@
