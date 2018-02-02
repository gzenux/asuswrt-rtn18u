include ../common.mak

CFLAGS += -Os -Wall $(EXTRACFLAGS)
CFLAGS += -I$(SRCBASE) -I$(SRCBASE)/include -I. -I$(TOP)/shared 

ifeq ($(RTCONFIG_FBWIFI),y)
CFLAGS +=-I$(TOP)/openssl/include -I$(TOP)/curl-7.21.7/include
endif

include $(SRCBASE)/.config

LIBS = -L$(TOP)/nvram${BCMEX} -lnvram -L$(TOP)/shared -lshared

ifeq ($(RTCONFIG_FBWIFI),y)
LIBS += -L$(TOP)/fb_wifi -lfbwifi
LIBS += -L$(TOP)/openssl -lcrypto -lssl
LIBS += -L$(TOP)/curl-7.21.7/lib/.libs -lcurl
ifeq ($(RTCONFIG_QCA),y)
LIBS +=  -lm -ldl
endif
endif


OBJS_FB = captive_portal.o

all: httpd_uam #test_apps

#test_apps: apps.c
#	$(CC) -DAPPS $(CFLAGS) $(LIBS) $^ -o $@

httpd_uam: $(OBJS_FB)
	@echo " [httpd_uam] CC $@"
	$(CC) -o $@ $(OBJS_FB) $(LIBS)

	$(SIZECHECK)
	$(CPTMP)


install: all
	@echo " [httpd_uam] Installing to $(INSTALLDIR)"
	@install -D httpd_uam $(INSTALLDIR)/usr/sbin/httpd_uam
	@$(STRIP) $(INSTALLDIR)/usr/sbin/httpd_uam
	@chmod 0500 $(INSTALLDIR)/usr/sbin/httpd_uam
	#@install -m 0755 test_apps $(INSTALLDIR)/usr/sbin
	#@$(STRIP) $(INSTALLDIR)/usr/sbin/test_apps

clean:
	rm -f httpd_uam *.o .*.depend test_apps

size: httpd_uam
	mipsel-uclibc-nm --print-size --size-sort httpd_uam

# handle prebuilt object here
ifneq ($(wildcard, ./prebuild),)
ifeq ($(RTCONFIG_HTTPS),y)
pwenc.o:
	@-cp -f ./prebuild/pwenc.o .
endif
endif

%.o: %.c .%.depend
	@echo " [httpd_uam] CC $@"
	@$(CC) $(CFLAGS) -o $@ -c $<

.%.depend: %.c
	@$(CC) $(CFLAGS) -M $< > $@

-include $(OBJS:%.o=.%.depend)
