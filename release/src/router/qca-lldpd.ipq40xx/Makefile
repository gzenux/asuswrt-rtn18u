include ../common.mak

QCA_GPL_LIBS=$(wildcard prebuild/*)

all:

install: all
	@[ -d $(INSTALLDIR)/usr/lib ] || install -d $(INSTALLDIR)/usr/lib
	@for i in $(QCA_GPL_LIBS); do install -m 755 -D $$i $(INSTALLDIR)/usr/lib ; done
	@$(STRIP) $(INSTALLDIR)/usr/lib/*

clean:
