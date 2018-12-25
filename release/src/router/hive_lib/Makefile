include ../common.mak


all:

clean:

install:
ifneq ($(HIVE_LIB),y)
	cp -r prebuild/* .
else
	cp prebuild/libpsService.so .
endif
	rm -rf $(INSTALLDIR)
	mkdir -p $(INSTALLDIR)/usr/lib
	cp -rf * $(INSTALLDIR)/usr/lib 
	rm -rf $(INSTALLDIR)/usr/lib/Makefile
	rm -rf $(INSTALLDIR)/usr/lib/prebuild


