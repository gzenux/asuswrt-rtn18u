include $(LINUXDIR)/.config
include $(TOP)/.config

CFLAGS += -Wall -O
CFLAGS += -DASUS
CRYPTLIB = portingssl
WSCSRC = src


#INSTALL = install

all:
	echo $(INSTALLDIR)
	make -C $(CRYPTLIB)
	make -C $(WSCSRC)

install: all
	install -d $(INSTALLDIR)/usr/sbin
	install src/wscd $(INSTALLDIR)/usr/sbin
	install -D src/wscd.conf $(INSTALLDIR)/rom/etc/wscd.conf
	install -D src/simplecfgservice.xml $(INSTALLDIR)/rom/etc/simplecfgservice.xml
	$(STRIP) $(INSTALLDIR)/usr/sbin/wscd
clean:
	make -C $(CRYPTLIB) clean
	make -C $(WSCSRC) clean

.PHONY: all clean install libs dirs osl
