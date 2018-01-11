include ../common.mak

PBBINS=$(wildcard prebuild/*)
QCA_GPL_LIBS=$(filter %.so,$(PBBINS))
QCA_GPL_SH=$(filter %.sh,$(PBBINS))

all:

install: all
	@[ -d $(INSTALLDIR)/usr/lib ] || install -d $(INSTALLDIR)/usr/lib
	@[ -d $(INSTALLDIR)/lib/functions ] || install -d $(INSTALLDIR)/lib/functions
	@for i in $(QCA_GPL_LIBS); do install -m 755 -D $$i $(INSTALLDIR)/usr/lib ; done
	@for i in $(QCA_GPL_SH); do install -m 755 -D $$i $(INSTALLDIR)/lib/functions ; done
	@$(STRIP) $(INSTALLDIR)/usr/lib/*

clean:
