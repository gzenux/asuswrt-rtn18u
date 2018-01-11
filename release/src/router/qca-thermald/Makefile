PBBINS=$(wildcard prebuild/*)
THERMALD_CONF=$(filter %.conf,$(PBBINS))
THERMALD_EXEC=$(filter-out %.conf,$(PBBINS))

all:

install:
	@[ -d $(INSTALLDIR)/etc/thermal ] || install -d $(INSTALLDIR)/etc/thermal
	@for i in $(THERMALD_CONF); do install -m 644 -D $$i $(INSTALLDIR)/etc/thermal ; done
	@[ -d $(INSTALLDIR)/usr/sbin ] || install -d $(INSTALLDIR)/usr/sbin
	@for i in $(THERMALD_EXEC); do install -D $$i $(INSTALLDIR)/usr/sbin ; done
	@$(STRIP) $(INSTALLDIR)/usr/sbin/*

clean:

stage:
