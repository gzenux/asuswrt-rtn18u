include ../common.mak

srcdir=source

#CFLAGS += $(EXTRACFLAGS) -Os -ffunction-sections -fdata-sections
#LDFLAGS += -ffunction-sections -fdata-sections -Wl,--gc-sections

ifneq ($(CONFIG_LINUX26),y)
CFLAGS += -DMAX_DEBUG_LEVEL="-1"
endif

ifeq ($(RTCONFIG_RECVFILE), y)
CFLAGS += -DHAVE_BCM_RECVFILE
endif

#ifeq ($(RTCONFIG_BCMARM), y)
#SMBLDFLAGS += -lgcc_s
#endif

ifeq ($(RTCONFIG_BCMARM), y)
HOST = arm
else
HOST = mips
endif

ifeq ($(RTCONFIG_HND_ROUTER), y)
CFLAGS += -fstack-protector-all
LDFLAGS += -L$(INSTALLDIR)/lib -lssp
endif


all: apps

apps: .conf
	mkdir -p $(srcdir)/bin
	$(MAKE) -C $(srcdir) all

.conf:
	cd $(srcdir) && \
	SMB_BUILD_CC_NEGATIVE_ENUM_VALUES=no \
	linux_getgrouplist_ok=no \
	samba_cv_have_longlong=yes \
	samba_cv_HAVE_IFACE_IFCONF=yes \
	samba_cv_USE_SETRESUID=yes \
	$(CONFIGURE) \
		--target=$(HOST)-linux \
		--disable-developer \
		--enable-cups=no \
		--enable-fam=no \
		--enable-shared=yes \
		--enable-iprint=no \
		--enable-pie=no \
		--without-ldap \
		--without-cifsupcall \
		--without-cifsmount \
		--without-cluster-support \
		--without-acl-support \
		--with-privatedir=/etc/samba \
		--with-lockdir=/var/samba/locks \
		--with-configdir=/etc \
		--with-piddir=/var/run/samba \
		--with-logfilebase=/var/samba
	touch .conf
	mkdir -p $(srcdir)/bin

clean:
	-$(MAKE) -C $(srcdir) distclean
	@rm -f .conf

distclean: clean
	@find $(srcdir) -name config.h | xargs rm -f
	@find $(srcdir) -name Makefile | xargs rm -f
	@find $(srcdir) -name config.status | xargs rm -f
	@find $(srcdir) -name config.cache | xargs rm -f

install: all
	@install -d $(INSTALLDIR)/usr/bin/
	@install -d $(INSTALLDIR)/usr/sbin/
	@install -d $(INSTALLDIR)/usr/lib/
	@install -D $(srcdir)/bin/smbd $(INSTALLDIR)/usr/sbin/smbd
	@install -D $(srcdir)/bin/nmbd $(INSTALLDIR)/usr/sbin/nmbd
	@install -D $(srcdir)/bin/smbpasswd $(INSTALLDIR)/usr/bin/smbpasswd
	$(STRIP) -s $(INSTALLDIR)/usr/sbin/smbd
	$(STRIP) -s $(INSTALLDIR)/usr/sbin/nmbd
	$(STRIP) -s $(INSTALLDIR)/usr/bin/smbpasswd

