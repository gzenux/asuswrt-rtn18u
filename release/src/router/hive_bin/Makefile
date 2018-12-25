include ../common.mak


all:

clean:

install:
ifneq ($(HIVE_BIN),y)
	cp -r prebuild/* .
else
	cp prebuild/hyd .
	cp prebuild/lbd .
endif
	rm -rf $(INSTALLDIR)
	mkdir -p $(INSTALLDIR)/usr/sbin
	cp -rf * $(INSTALLDIR)/usr/sbin 
	mkdir -p $(INSTALLDIR)/sbin
	cp lldpd $(INSTALLDIR)/sbin
	cp lldpcli $(INSTALLDIR)/sbin
	rm -rf $(INSTALLDIR)/usr/sbin/lldpd
	rm -rf $(INSTALLDIR)/usr/sbin/lldpcli
	rm -rf $(INSTALLDIR)/usr/sbin/Makefile
	rm -rf $(INSTALLDIR)/usr/sbin/prebuild
        

