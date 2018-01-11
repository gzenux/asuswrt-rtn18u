include ../common.mak

PBBINS=$(wildcard prebuild/*)
QCA_GPL_EXEC=$(filter-out ,$(PBBINS))

all:

install: all
	@[ -d $(INSTALLDIR)/usr/sbin ] || install -d $(INSTALLDIR)/usr/sbin
	@for i in $(QCA_GPL_EXEC); do install -m 755 -D $$i $(INSTALLDIR)/usr/sbin ; done
	@$(STRIP) $(INSTALLDIR)/usr/sbin/*

clean:
