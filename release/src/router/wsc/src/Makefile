# makefile for wscd
#include ../../.config
#include ../../../../realtek/rtl819x/linux-3.10/.config
include $(SRCBASE)/router/.config
include $(LINUXDIR)/.config
#for INBAND_HOST
#include .config
#inband_lib = ../../rtk_inbandLib/inband.a

CC			= $(CROSS_COMPILE)gcc
#COPT		= -O2
COPT		= -Os
CDEF		=
CWARN		= -Wall
#CDBG		= -ggdb
CFLAGS		= ${CWARN} ${COPT} ${CDEF} ${CDBG}
#CFLAGS		+= -DINBAND_WPS_OVER_HOST
#LDFLAGS		= --static -Wl,--gc-sections
LDFLAGS		=

ifeq ($(CONFIG_RTL_8198_NFBI_RTK_INBAND_AP),y)
STATIC_LIB = 1
CFLAGS += -DCONFIG_RTL8196C_AP_HCM -DCONFIG_RTL8198_AP_HCM
LDFLAGS = --static
endif

CFLAGS += -DCONFIG_RTL_REPEATER_WPS_SUPPORT

ifeq ($(RTL8186_KB),1)
	LIBUPNP=1
endif

# For mini_upnp stand alone
LIBUPNP=0
STATIC_LIB=1

ifeq ($(CONFIG_RTL_COMAPI_CFGFILE),y)
CFLAGS		+= -DCONFIG_IWPRIV_INTF
endif

ifeq ($(OFFICIAL_OPENSSL),1)
########## Build with OPENSSL Library ##################
OPENSSLDIR	= ../../openssl-0.9.7i

else
########## Build with porting-SSL Library ##################
OPENSSLDIR	= ../portingssl
CFLAGS		+= -DUSE_PORTING_OPENSSL
endif

#ifdef CONFIG_RTL_P2P_SUPPORT

ifeq ($(CONFIG_RTL_P2P_SUPPORT),y)
CFLAGS		+= -DP2P_SUPPORT
endif


ifeq ($(LIBUPNP),1)
########## Build with libupnp Library ##################
UPNPDIR		= ../../upnpd/libupnp-1.4.1
UPNPINC		= $(UPNPDIR)/upnp/inc
IXMLINC		= $(UPNPDIR)/ixml/inc
UPNPLIB 	= -lpthread $(UPNPDIR)/ixml/.libs/libixml.so.2 \
	$(UPNPDIR)/threadutil/.libs/libthreadutil.so.2 \
	$(UPNPDIR)/upnp/.libs/libupnp.so.2
SOURCES = wsc.c txpkt.c rxpkt.c utils.c sample_util.c simplecfg_upnp_main.c

else
########## Build with MINI-UPNP Library ##################
UPNPDIR		= ../../mini_upnp
UPNPINC		= $(UPNPDIR)
IXMLINC		= ./
CFLAGS		+= -DUSE_MINI_UPNP
SOURCES 	= wsc.c txpkt.c rxpkt.c utils.c simplecfg_mini_upnp_main.c

	ifeq ($(STATIC_LIB),1)
	################# Static Library ##################
		UPNPLIB		= $(UPNPDIR)/mini_upnp.a
		CFLAGS		+= -DSTAND_ALONE_MINIUPNP

	else
	################# Shared Library ##################
	UPNPLIB = $(UPNPDIR)/mini_upnp.so

	endif
endif

ifeq ($(OFFICIAL_OPENSSL),1)
INCS		= -I$(OPENSSLDIR)/include/ -I$(UPNPINC) -I$(IXMLINC)
else
INCS		= -I$(OPENSSLDIR)/crypto/include -I$(UPNPINC) -I$(IXMLINC)
endif

LIBS =  $(OPENSSLDIR)/libcrypto.a 
LIBS += $(UPNPLIB)
LIBS += $(inband_lib)

ifeq ($(RTL8186_KB),1)
CFLAGS		+= -DCONFIG_RTL8186_KB
endif

ifeq ($(RTL8186_TR),1)
CFLAGS		+= -DCONFIG_RTL8186_TR
endif

ifeq ($(RTL865X_AC),1)
CFLAGS		+= -DCONFIG_RTL865X_AC
endif

ifeq ($(CONFIG_RTL_8196C),y)
CFLAGS		+= -DCONFIG_RTL8196C
endif

ifeq ($(CONFIG_RTL_8198),y)
CFLAGS		+= -DCONFIG_RTL8198
endif

ifeq ($(CONFIG_RTL_819XD),y)
CFLAGS		+= -DCONFIG_RTL_819XD
endif

ifeq ($(CONFIG_RTL_8196E),y)
CFLAGS		+= -DCONFIG_RTL_8196E
endif

ifeq ($(CONFIG_RTL_8198B),y)
CFLAGS		+= -DCONFIG_RTL8198B
endif

ifeq ($(CONFIG_RTL_8198C),y)
CFLAGS		+= -DCONFIG_RTL_8198C
endif

ifeq ($(RTL865X_KLD),1)
CFLAGS		+= -DCONFIG_RTL865X_KLD
endif

ifeq ($(CONFIG_RTL865X_SC),1)
CFLAGS		+= -DCONFIG_RTL865X_SC
endif

ifeq ($(OFFICIAL_OPENSSL),1)
CFLAGS		+= $(INCS)
else
CFLAGS		+= -D__linux__ -DRSDK_BUILT -DB_ENDIAN $(INCS)
endif

ifeq ($(NOIWCTL),1)
CFLAGS		+= -DNO_IWCONTROL
endif

ifeq ($(CMO),1)
CFLAGS		+= -DCONFIG_CMO
endif

ifeq ($(TLD),1)
CFLAGS		+= -DDET_WPS_SPEC
endif


ifeq ($(CONFIG_MESH_ENABLE),y)
CFLAGS		+= -DCONFIG_RTK_MESH
endif	

SHELL		= /bin/sh
STRIP		= $(CROSS_COMPILE)strip

PROGS=wscd

ifeq ($(SLINK),1)
CFLAGS += -ffunction-sections -fdata-sections
LDFLAGS += --static -Wl,--gc-sections
endif


#CONFIG_RTL_DUAL_PCIESLOT_BIWLAN_D
ifeq ($(CONFIG_RTL_DUAL_PCIESLOT_BIWLAN_D),y)
CFLAGS += -DFOR_DUAL_BAND
endif

ifeq ($(CONFIG_RTL_92D_DMDP),y)
CFLAGS += -DFOR_DUAL_BAND
endif

ifeq ($(CONFIG_RTL_WPS2_SUPPORT),y)
CFLAGS += -DWPS2DOTX
endif


all:	BUILT_TIME $(PROGS)

clean:
	rm -f $(PROGS) core tags ID *.o *.d *~ *.bak built_time

sources = $(SOURCES)

#include $(sources:.c=.d)

BUILT_TIME:
	@echo  \#define BUILT_TIME \"`TZ=UTC date -u "+%Y.%m.%d-%H:%M%z" `\" > ./built_time	

$(PROGS):	$(sources:.c=.o)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)
	$(STRIP) $@

%.d: %.c
	@$(SHELL) -ec '$(CC) -MM $(CFLAGS) $< \
		      | sed '\''s/\($*\)\.o[ :]*/\1.o $@ : /g'\'' > $@; \
		      [ -s $@ ] || rm -f $@'
