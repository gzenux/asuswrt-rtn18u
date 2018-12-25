include ../common.mak

PBBINS=$(wildcard prebuild/*)
QCA_GPL_LIBS=$(filter %.so,$(PBBINS))
QCA_GPL_EXEC=$(filter-out %.so,$(PBBINS))

all:

install: all
	@[ -d $(INSTALLDIR)/usr/sbin ] || install -d $(INSTALLDIR)/usr/sbin
	@[ -d $(INSTALLDIR)/usr/lib ] || install -d $(INSTALLDIR)/usr/lib
	@for i in $(QCA_GPL_LIBS); do install -m 755 -D $$i $(INSTALLDIR)/usr/lib ; done
	@for i in $(QCA_GPL_EXEC); do install -m 755 -D $$i $(INSTALLDIR)/usr/sbin ; done
	@$(STRIP) $(INSTALLDIR)/usr/sbin/*
	@$(STRIP) $(INSTALLDIR)/usr/lib/*

clean:
