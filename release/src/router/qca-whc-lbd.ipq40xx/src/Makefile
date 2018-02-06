TOP_SRCDIR = ..
include $(TOP_SRCDIR)/Makefile.defs

LIBS += -lpthread

TARTGET_OBJECTS = lbdMain.$(OBJEXT)

LBD_LIBS = -llbcmnlibs -llbdcore -lwlanif_bsa -lsteerexec_bsa -lbandmon_bsa -lstamon_bsa -lsteeralg_bsa -lestimator_bsa

LBD_OPTIMIZE := -Wl,--gc-sections -fwhole-program -Wl,--sort-section,alignment -Wl,--sort-common

LIBS += $(LBD_LIBS)

all: lbd$(EXEEXT) install

lbd$(EXEEXT): $(TARTGET_OBJECTS)
	$(LINK) -L$(STAGEDIR)/usr/lib -L$(TOP)/qca-whc-lbd.ipq40xx/ipkg-ipq806x/qca-whc-lbd/lib -o $@ $(TARTGET_OBJECTS) -Xlinker --start-group $(LIBS) -lm -ljansson -Xlinker --end-group

.c.o:
	$(COMPILE) -c $<

install:
#	@cp lbd$(EXEEXT) $(INSTALL_ROOT)/sbin
	[ -d $(INSTALLDIR)/qca-whc-lbd.ipq40xx/usr/sbin ] || install -d $(INSTALLDIR)/qca-whc-lbd.ipq40xx/usr/sbin
	install -m 755 lbd$(EXEEXT) $(INSTALLDIR)/qca-whc-lbd.ipq40xx/usr/sbin
	$(STRIP) $(INSTALLDIR)/qca-whc-lbd.ipq40xx/usr/sbin/*

clean:
	@rm -f *.o *~ lbd$(EXEEXT)


.PHONY: all clean install

