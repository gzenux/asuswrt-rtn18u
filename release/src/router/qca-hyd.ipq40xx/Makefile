PBBINS=$(wildcard prebuild/*)
LIBS=$(filter %.so,$(PBBINS))
EXEC=$(filter-out $(LIBS),$(PBBINS))

all:

install:
	@[ -d $(INSTALLDIR)/usr/lib ] || install -d $(INSTALLDIR)/usr/lib
	@for i in $(LIBS); do install -D $$i $(INSTALLDIR)/usr/lib ; done
#	@$(STRIP) $(INSTALLDIR)/usr/lib/*
	@[ -d $(INSTALLDIR)/usr/sbin ] || install -d $(INSTALLDIR)/usr/sbin
	@for i in $(EXEC); do install -D $$i $(INSTALLDIR)/usr/sbin ; done
#	@$(STRIP) $(INSTALLDIR)/usr/sbin/*

clean:

stage:
