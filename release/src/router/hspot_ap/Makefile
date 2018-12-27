#Linux Makefile

#SRCBASE = ../..
WLAN_ComponentsInUse := bcmwifi ppr
include ../../makefiles/WLAN_Common.mk
SRCBASE := $(WLAN_SrcBaseR)

include $(SRCBASE)/router/.config

INCLUDE += -I$(SRCBASE)/hspot/include -I$(SRCBASE)/hspot/dsp -I$(SRCBASE)/hspot/wlan -I$(SRCBASE)/hspot/tcp_srv -I$(SRCBASE)/hspot/pkt -I$(SRCBASE)/hspot/pro
INCLUDE += -I. -I.. -I$(SRCBASE)/include -I$(SRCBASE)/shared -I$(SRCBASE)/router/shared -I$(SRCBASE)/wl/exe
INCLUDE += -I$(SRCBASE)/security/secfrw/include -I$(SRCBASE)/supp/include $(WLAN_ComponentIncPathR)

CFLAGS += $(INCLUDE)
CFLAGS += -DWIFI_ACT_FRAME -DHOTSPOT_AP -DWLTDLS -Wall

CFLAGS  += -s

CFLAGS += -DPPR_API

#CFLAGS += -c -g -m32 -Wextra -Werror
#LDFLAGS += -m32 --cref -lpthread -lrt
#LDFLAGS += -Wl,-Map,hspotap.map

LDFLAGS += -L$(TOP)/nvram -L$(INSTALLDIR)/nvram/usr/lib -lnvram
#LDFLAGS += -L$(TOP)/shared -L$(INSTALLDIR)/shared/usr/lib -lshared


vpath %.c $(SRCBASE)/wl/exe
vpath %.c $(SRCBASE)/shared
vpath %.c $(SRCBASE)/shared/bcmwifi/src
vpath %.c $(SRCBASE)/security/secfrw/tmr
vpath %.c $(SRCBASE)/security/secfrw/utils
vpath %.c $(SRCBASE)/router/hspot_ap
vpath %.c $(SRCBASE)/hspot/util
vpath %.c $(SRCBASE)/hspot/pkt
vpath %.c $(SRCBASE)/hspot/dsp
vpath %.c $(SRCBASE)/hspot/wlan
vpath %.c $(SRCBASE)/hspot/pro
vpath %.c $(SRCBASE)/hspot/tcp_srv
vpath %.c $(WLAN_ComponentSrcDirsR)

OBJS = trace.o
OBJS += pktEncode.o pktDecode.o
OBJS += pktEncodeIe.o pktDecodeIe.o pktDecodeWfd.o
OBJS += pktEncodeGas.o pktDecodeGas.o
OBJS += pktEncodeAnqp.o pktDecodeAnqp.o
OBJS += pktEncodeHspotAnqp.o pktDecodeHspotAnqp.o
OBJS += pktEncodeWnm.o pktDecodeWnm.o
OBJS += dsp_ap.o tmr.o
OBJS += wlu_api.o wlu_linux_api.o
OBJS += wlu.o wlu_common.o wlu_cmd.o wlu_iov.o miniopt.o bcmwifi_channels.o bcmutils.o wlu_rates_matrix.o wlc_ppr.o
OBJS += bcm_app_utils.o bcmseclib_linux_timer.o bcmseclib_timer.o bcm_llist.o
OBJS += proGas.o
OBJS += bcmevent.o
OBJS += hspotap.o
OBJS += tcp_srv.o

all: hspotap

ifneq ($(wildcard ./prebuilt),)
hspotap:
	cp prebuilt/hspotap .
else
hspotap: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
endif

install: all
	install -d $(INSTALLDIR)/bin
	install hspotap $(INSTALLDIR)/bin
	$(STRIP) $(INSTALLDIR)/bin/hspotap

clean:
	rm -f *.o *.map hspotap
