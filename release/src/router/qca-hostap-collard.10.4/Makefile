QCAHOSTAP_EXEC=$(wildcard prebuild/*)

# librt.so
CROSS_TOOLCHAIN_DIR=$(TOOLCHAIN)
LIBRT_VERSION=0.9.33.2

all:

install:
	@install -D $(CROSS_TOOLCHAIN_DIR)/lib/librt-$(LIBRT_VERSION).so $(INSTALLDIR)/lib/librt-$(LIBRT_VERSION).so
	@cd $(INSTALLDIR)/lib && ln -sf librt-$(LIBRT_VERSION).so librt.so
	@cd $(INSTALLDIR)/lib && ln -sf librt-$(LIBRT_VERSION).so librt.so.0
	$(STRIP) $(INSTALLDIR)/lib/*
	@[ -d $(INSTALLDIR)/usr/bin ] || install -d $(INSTALLDIR)/usr/bin
	@for i in $(QCAHOSTAP_EXEC); do install -D $$i $(INSTALLDIR)/usr/bin ; done
	@$(STRIP) $(INSTALLDIR)/usr/bin/*

clean:

stage:
