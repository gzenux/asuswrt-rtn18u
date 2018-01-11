# $Id: Makefile,v 1.2 2009/01/13 02:50:10 bradhuang Exp $

.SUFFIXES:
.SUFFIXES: .o .c
.PHONY: clean all depend

LIBS = 
#CFLAGS = -g -O2 -Wall
CFLAGS := -Os -Wall $(CFLAGS)
CPPFLAGS =  -I. -I.
DEPEND = .depend
LDFLAGS	= -g -s
CC = $(CROSS_COMPILE)gcc
CPP = gcc -E
AR = $(CROSS_COMPILE)ar

SOURCES = minixml.c, upnphttp.c, upnpreplyparse.c, upnpsoap.c \
	mini_upnp.c		
OBJS = $(SOURCES:.c=.o)

UPNP_DAEMON = mini_upnpd

# For mini_upnp stand alone
STATIC_LIB=1
INSTALL = install
ifeq ($(STATIC_LIB),1)
########## Build Static Library ##################
all: mini_upnp.a	

UPNP_LIB = mini_upnp.a

mini_upnp.a: mini_upnp.o minixml.o upnphttp.o upnpreplyparse.o upnpsoap.o
	$(AR) rcs $@ mini_upnp.o minixml.o upnphttp.o upnpreplyparse.o upnpsoap.o

else
########## Build Shared Library ##################
all: $(UPNP_DAEMON) $(UPNP_LIB)	

UPNP_LIB = mini_upnp.so

CFLAGS += -DUSE_SHARED_DAEMON

minixml.o: minixml.c
	$(CC) -c -o $@ -fpic $(CFLAGS) $(IFLAGS) $<

upnphttp.o: upnphttp.c
	$(CC) -c -o $@ -fpic $(CFLAGS) $(IFLAGS) $<	

upnpreplyparse.o: upnpreplyparse.c
	$(CC) -c -o $@ -fpic $(CFLAGS) $(IFLAGS) $<		
	
upnpsoap.o: upnpsoap.c
	$(CC) -c -o $@ -fpic $(CFLAGS) $(IFLAGS) $<		
	
$(UPNP_LIB): minixml.o upnphttp.o upnpreplyparse.o upnpsoap.o
	$(CC) -s -shared -o $@ minixml.o upnphttp.o upnpreplyparse.o upnpsoap.o

$(UPNP_DAEMON): mini_upnp.o $(UPNP_LIB)
	$(CC) -o $@ $(APMIB_LIB) $^ $(LDFLAGS) $(LIBS)

endif

install:
ifeq ($(STATIC_LIB),1)
	@echo Do nothing here...	
else
	$(INSTALL) -d mini_upnpd $(INSTALLDIR)/usr/bin/mini_upnpd
	$(INSTALL) mini_upnp.so $(INSTALLDIR)/lib/mini_upnp.so
	$(STRIP) $(INSTALLDIR)/usr/bin/mini_upnpd
	$(STRIP) $(INSTALLDIR)/lib/mini_upnp.so
endif

clean:
	rm -f *.o *.so *.a $(UPNP_DAEMON)


# depend stuff
depend: $(SOURCES)
	$(CPP) $(CPPFLAGS) -MM $^ > $(DEPEND)
        
-include $(DEPEND)

# tags
tags:	$(SOURCES)
	ctags -o tags $^ *.h

.c.o:
	${CC} -c -o $@ $(CFLAGS) $(IFLAGS) $<




