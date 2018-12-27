# Convert asuswrt build environment variable for gmp
TARGET_CROSS=$(CROSS_COMPILE)
TARGET_CC=$(CROSS_COMPILE)gcc
LINUX_KARCH=$(ARCH)
LINUX_DIR=$(LINUXDIR)
LINUX_VERSION=$(LINUX_KERNEL)
PKG_BUILD_DIR=$(shell pwd)/source
PKG_INSTALL_DIR=$(shell pwd)/install
STAGING_DIR=$(STAGEDIR)

# Define variables for gmp

all: $(PKG_BUILD_DIR)/Makefile
	install -d $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		DESTDIR="$(STAGEDIR)" \
		CC="$(TARGET_CC)" \
		all install

$(PKG_BUILD_DIR)/Makefile:
	$(MAKE) gmp-configure

gmp-configure:
	( cd $(PKG_BUILD_DIR) ; $(CONFIGURE) \
		--program-prefix="" --program-suffix="" --prefix=/usr \
		--exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin \
		--libexecdir=/usr/lib --sysconfdir=/etc --datadir=/usr/share \
		--localstatedir=/var --mandir=/usr/man --infodir=/usr/info \
		--disable-nls --enable-shared --enable-static \
	)

install:
	install -d $(INSTALLDIR)/usr/lib
	install -m 755 $(foreach l,$(wildcard $(STAGEDIR)/usr/lib/libgmp.so.*),$(l)) $(INSTALLDIR)/usr/lib/

clean:
	find $(PKG_BUILD_DIR) -type f -name ".*.o.cmd" \
		-o -name ".*.ko.cmd" \
		-o -name "*.o" \
		-o -name "modules.order" \
		-o -name "*.ko" \
		-o -name ".tmp_versions" \
		-o -name "Module.symvers" \
		-o -name "*.mod.c" | xargs rm -fr

stage:
	$(MAKE) -C $(PKG_BUILD_DIR) DESTDIR=$(STAGEDIR) install
	@touch $@
