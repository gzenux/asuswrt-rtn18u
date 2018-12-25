include ../common.mak

all: 
	@echo "do nothing"

install:
	mkdir -p $(INSTALLDIR)/lib/
ifeq ($(RTCONFIG_ALPINE),y)
	install -D ./serial/rtl8761a/rtl8761a_config $(INSTALLDIR)/rom/etc/rtl8761a_config
	install -D ./serial/rtl8761a/rtl8761at_config $(INSTALLDIR)/rom/etc/rtl8761at_config
else
	ln -sf /var/firmware $(INSTALLDIR)/lib/firmware
	install -D ./serial/rtl8822b/rtl8822b_fw $(INSTALLDIR)/rom/etc/rtl8822b_fw
	install -D ./serial/rtl8822b/rtl8822b_config $(INSTALLDIR)/rom/etc/rtl8822b_config
endif

clean:
	@echo "do nothing"

PHONY += FORCE
FORCE:
