INSTALLKMODDIR:=$(INSTALLDIR)/lib/modules/$(LINUX_KERNEL)
PBBINS=$(wildcard prebuild/*)
QCAWIFI_KMOD=$(filter %.ko,$(PBBINS))
QCAWIFI_LIBS=$(filter %.so,$(PBBINS))
QCAWIFI_USR_SBIN=$(filter %/athdiag %/athtestcmd,$(PBBINS))
QCAWIFI_EXEC=$(filter-out $(QCAWIFI_KMOD) $(QCAWIFI_LIBS) $(QCAWIFI_USR_SBIN),$(PBBINS))

all:

install:
	@[ -d $(INSTALLKMODDIR) ] || install -d $(INSTALLKMODDIR)
	@for i in $(QCAWIFI_KMOD); do install -D $$i $(INSTALLKMODDIR) ; done
	@$(STRIPX) $(INSTALLKMODDIR)/*.ko
	@[ -d $(INSTALLDIR)/usr/lib ] || install -d $(INSTALLDIR)/usr/lib
	@for i in $(QCAWIFI_LIBS); do install -D $$i $(INSTALLDIR)/usr/lib ; done
	@$(STRIP) $(INSTALLDIR)/usr/lib/*
	@[ -d $(INSTALLDIR)/usr/sbin ] || install -d $(INSTALLDIR)/usr/sbin
	@for i in $(QCAWIFI_USR_SBIN); do install -D $$i $(INSTALLDIR)/usr/sbin ; done
	@$(STRIP) $(INSTALLDIR)/usr/sbin/*
	@[ -d $(INSTALLDIR)/sbin ] || install -d $(INSTALLDIR)/sbin
	@for i in $(QCAWIFI_EXEC); do install -D $$i $(INSTALLDIR)/sbin ; done
	@$(STRIP) $(INSTALLDIR)/sbin/*

clean:

stage:
