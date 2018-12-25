INSTALLKMODDIR:=$(INSTALLDIR)/lib/modules/$(LINUX_VERSION)
QCMBR_EXEC=$(wildcard prebuild/*)

all:

install:
	@[ -d $(INSTALLDIR)/usr/sbin ] || install -d $(INSTALLDIR)/usr/sbin
	@for i in $(QCMBR_EXEC); do install -D $$i $(INSTALLDIR)/usr/sbin ; done
	@$(STRIP) $(INSTALLDIR)/usr/sbin/*

clean:

stage:
