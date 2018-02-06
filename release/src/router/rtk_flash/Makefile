# Under Solaris, you need to 
#    CFLAGS += -xO2 -Xc
#    LDLIBS += -lnsl -lsocket
# Some versions of Linux may need
#    CFLAGS += -D_GNU_SOURCE
# To cross-compile
#    CC = arm-linux-gcc

include ../.config

CFLAGS += -Wall -O

CFLAGS += -DASUS
CFLAGS += -I$(TOP)/shared -I$(SRCBASE)/include
LDFLAGS = -L$(TOP)/shared -lshared -L$(TOP)/nvram${BCMEX} -lnvram
ifeq ($(RTCONFIG_BCMARM),y)
CFLAGS += -I$(SRCBASE)/common/include
LDFLAGS += -lgcc_s
endif


INSTALL = install

all: flash

flash: flash.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

install: flash
	$(STRIP) flash
	$(INSTALL) -d $(INSTALLDIR)/usr/sbin 
	$(INSTALL) flash $(INSTALLDIR)/usr/sbin

clean:
	rm -f flash *.o
