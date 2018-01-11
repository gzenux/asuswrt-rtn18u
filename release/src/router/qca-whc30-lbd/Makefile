PBBINS=$(wildcard prebuild/*)
WHC_LBD_LIBS=$(filter %.so,$(PBBINS))
WHC_LBD_SH=$(filtert %.sh,$(PBBINS))
WHC_LBD_EXEC=$(filter-out %.so %.sh,$(PBBINS))

all:

install:
	@[ -d $(INSTALLDIR)/usr/sbin ] || install -d $(INSTALLDIR)/usr/sbin
	@[ -d $(INSTALLDIR)/usr/lib ] || install -d $(INSTALLDIR)/usr/lib
	@[ -d $(INSTALLDIR)/lib/functions ] || install -d $(INSTALLDIR)/lib/functions
	$(if $(WHC_LBD_LIBS),install -m 0755 $(foreach lib,$(WHC_LBD_LIBS),$(lib)) $(INSTALLDIR)/usr/lib)
	@for i in $(WHC_LBD_EXEC); do install -m 755 -D $$i $(INSTALLDIR)/usr/sbin ; done
	@for i in $(WHC_LBD_SH); do install -m 755 -D $$i $(INSTALLDIR)/lib/functions ; done
	@$(STRIP) $(INSTALLDIR)/usr/sbin/*
	@$(STRIP) $(INSTALLDIR)/usr/lib/*

clean:

stage:
