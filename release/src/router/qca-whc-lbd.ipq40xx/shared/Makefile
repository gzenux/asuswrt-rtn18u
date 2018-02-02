TOP_SRCDIR := ../
include $(TOP_SRCDIR)/Makefile.defs

TARGET_LIB := liblbcmnlibs.so
TARGET_OBJECTS := -lwlanif -lsteerexec -lstadb -lbandmon -lsteeralg -lstamon -lestimator -ldiaglog -llbcmn -lpersist

EXTRA_CFLAGS += -fPIC

all: $(TARGET_LIB) install

$(TARGET_LIB): $(TARGET_OBJECTS)
	$(CC) -L$(STAGEDIR)/usr/lib -L$(LBLIB_STATIC) -shared -o $@ -Wl,-whole-archive $(TARGET_OBJECTS) -ljansson -Wl,-no-whole-archive

install: $(TARGET_LIB)
	[ -d $(INSTALLDIR)/qca-whc-lbd.ipq40xx/usr/lib ] || install -d $(INSTALLDIR)/qca-whc-lbd.ipq40xx/usr/lib
	install -m 755 $(TARGET_LIB) $(INSTALLDIR)/qca-whc-lbd.ipq40xx/usr/lib
	$(STRIP) $(INSTALLDIR)/qca-whc-lbd.ipq40xx/usr/lib/*

clean:
	@rm -f *.o *.d $(TARGET_LIB) *~

.PHONY: all clean install
