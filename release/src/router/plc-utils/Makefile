PLCUTILS_EXEC=$(wildcard prebuild/*)

all:

install:
	@[ -d $(INSTALLDIR)/usr/local/bin ] || install -d $(INSTALLDIR)/usr/local/bin
	@for i in $(PLCUTILS_EXEC); do cp -a $$i $(INSTALLDIR)/usr/local/bin ; done

clean:
