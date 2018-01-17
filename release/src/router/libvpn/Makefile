include ../common.mak
include $(SRCBASE)/.config
include $(SRCBASE)/router/.config
CFLAGS += -Os -Wall $(EXTRACFLAGS) -fPIC
CFLAGS += -I. -I$(TOP)/shared -I$(SRCBASE)/include
CFLAGS += -I$(TOP)/openssl/include
ifeq ($(HND_ROUTER),y)
CFLAGS += -DHND_ROUTER
endif
LDFLAGS += $(EXTRALDFLAGS) -L$(TOP)/nvram${BCMEX}${EX7} -lnvram -L$(TOP)/shared -lshared
LDFLAGS += -lcrypt
LDFLAGS += -L$(TOP)/openssl -lcrypto -lssl

ifeq ($(RTCONFIG_AMAS),y)
LDFLAGS += -L$(TOP)/json-c/.libs -ljson-c
endif

INSTALL = install

OBJS = openvpn_config.o openvpn_control.o

all: libvpn.so

libvpn.so: $(OBJS)
	@echo " [libvpn] LD $@"
	@$(CC) $(LDFLAGS) -shared -o $@ $^


install: all
	@echo " [libvpn] Installing as $(INSTALLDIR)/usr/lib/libvpn.so"
	@install -d $(INSTALLDIR)/usr/lib
	@install -m 755 libvpn.so $(INSTALLDIR)/usr/lib
	@$(STRIP) $(INSTALLDIR)/usr/lib/libvpn.so

clean:
	rm -f *.o *.so *.a .*.depend *.prep

%.o: %.c .%.depend
	@echo " [libvpn] CC $@"
	@$(CC) $(CFLAGS) -o $@ -c $<

.depend: $(OBJS:%.o=%.c)
	@$(CC) $(CFLAGS) -M $^ > .depend

.%.depend: %.c
	@$(CC) $(CFLAGS) -M $< > $@

%.prep: %.c
	@$(CC) $(CFLAGS) -E $< > $@

-include $(OBJS:%.o=.%.depend)
