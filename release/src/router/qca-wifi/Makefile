INSTALLKMODDIR:=$(INSTALLDIR)/lib/modules/$(LINUX_VERSION)
PBBINS=$(wildcard prebuild/*)
QCAWIFI_KMOD=$(filter %.ko,$(PBBINS))
QCAWIFI_EXEC=$(filter-out %.ko,$(PBBINS))

all:

install:
	@[ -d $(INSTALLKMODDIR) ] || install -d $(INSTALLKMODDIR)
	@for i in $(QCAWIFI_KMOD); do install -D $$i $(INSTALLKMODDIR) ; done
	@$(STRIPX) $(INSTALLKMODDIR)/*.ko
	@[ -d $(INSTALLDIR)/sbin ] || install -d $(INSTALLDIR)/sbin
	@for i in $(QCAWIFI_EXEC); do install -D $$i $(INSTALLDIR)/sbin ; done
	@$(STRIP) $(INSTALLDIR)/sbin/*

clean:

stage:
