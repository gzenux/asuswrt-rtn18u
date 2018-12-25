include $(LINUXDIR)/.config
include $(TOP)/.config

CFLAGS += -Wall -O
CFLAGS += -DASUS
CFLAGS += ../openssl/libcrypto.a

all: ftd

ft_main.o : ft_main.c ft_main.h

ftd: ft_main.o
	$(CC) -o ftd ft_main.o $(CFLAGS)

install: all
	install -d $(INSTALLDIR)/usr/sbin
	install ./ftd $(INSTALLDIR)/usr/sbin
	install -D ./ft.conf $(INSTALLDIR)/rom/etc/ft.conf
	
clean:
	rm -f *.o ftd
	
.PHONY: all clean install libs dirs osl