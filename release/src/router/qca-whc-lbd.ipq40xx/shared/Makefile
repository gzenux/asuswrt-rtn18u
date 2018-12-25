TOP_SRCDIR := ../
include $(TOP_SRCDIR)/Makefile.defs

TARGET_LIB := liblbcmnlibs.so
TARGET_OBJECTS := -lwlanif -lsteerexec -lstadb -lbandmon -lsteeralg -lstamon -lestimator -ldiaglog -llbcmn -lpersist

EXTRA_CFLAGS += -fPIC

all: $(TARGET_LIB) install

$(TARGET_LIB): $(TARGET_OBJECTS)
	$(CC) -L$(STAGEDIR)/usr/lib -L$(LBLIB_STATIC) -shared -o $@ -Wl,-whole-archive $(TARGET_OBJECTS) -ljansson -Wl,-no-whole-archive

install: $(TARGET_LIB)
	cp -a -f $(TARGET_LIB) $(TOP)/hive_lib

clean:
	@rm -f *.o *.d $(TARGET_LIB) *~

.PHONY: all clean install
