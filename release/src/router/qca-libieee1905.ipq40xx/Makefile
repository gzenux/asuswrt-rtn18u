include ../common.mak

PBBINS=$(wildcard prebuild/*)
QCA_GPL_LIBS=$(filter %.so,$(PBBINS))

all:

install: all
	@[ -d $(INSTALLDIR)/usr/lib ] || install -d $(INSTALLDIR)/usr/lib
	@for i in $(QCA_GPL_LIBS); do install -m 755 -D $$i $(INSTALLDIR)/usr/lib ; done
	@$(STRIP) $(INSTALLDIR)/usr/lib/*

clean:
