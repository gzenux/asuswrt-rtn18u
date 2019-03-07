LIBQCACOMMON_EXEC=$(wildcard $(PREBUILD)/*)

all:

install:
	@[ -d $(INSTALLDIR)/usr/lib ] || install -d $(INSTALLDIR)/usr/lib
	@for i in $(LIBQCACOMMON_EXEC); do install -m 0755 -D $$i $(INSTALLDIR)/usr/lib ; done
	@$(STRIP) $(INSTALLDIR)/usr/lib/*

clean:

stage:
