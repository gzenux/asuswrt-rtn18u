include ../common.mak


all:


clean:

install:
ifneq ($(HIVE_LIB),y)
	cp -r prebuild/* .
else
	cp prebuild/libpsService.so .
	cp prebuild/libmcfwdtblwlan2g.so .
	cp prebuild/libmcfwdtblwlan5g.so .
	cp prebuild/libmcfwdtbleswitch.so .
	cp prebuild/libpluginManager.so .
	cp prebuild/liblbcmnlibs.so .
endif
	rm -rf $(INSTALLDIR)
	mkdir -p $(INSTALLDIR)/usr/lib
	cp -rf * $(INSTALLDIR)/usr/lib 
	rm -rf $(INSTALLDIR)/usr/lib/Makefile
	rm -rf $(INSTALLDIR)/usr/lib/prebuild


