include ../common.mak

QCA_GPL_EXEC=$(wildcard prebuild/*)

all:

install: all
	@[ -d $(INSTALLDIR)/usr/sbin ] || install -d $(INSTALLDIR)/usr/sbin
	@for i in $(QCA_GPL_EXEC); do install -m 755 -D $$i $(INSTALLDIR)/usr/sbin ; done
	@$(STRIP) $(INSTALLDIR)/usr/sbin/*

clean:
