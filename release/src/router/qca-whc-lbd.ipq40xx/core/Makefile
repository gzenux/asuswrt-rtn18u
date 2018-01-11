TOP_SRCDIR = ../
include $(TOP_SRCDIR)/Makefile.defs

TARGET_LIB = liblbdcore.a
TARGET_SOURCES = module.c config.c profile.c
TARGET_OBJECTS = $(patsubst %.c,%.$(OBJEXT),$(TARGET_SOURCES))

CMN_TARGET_LIB = liblbcmn.a
CMN_TARGET_SOURCES = lb_common.c
CMN_TARGET_OBJECTS = $(patsubst %.c,%.$(OBJEXT),$(CMN_TARGET_SOURCES))

INSTALLHEADERS := $(shell ls *.h 2> /dev/null)

SHARED_CFLAGS = -fPIC

all: $(TARGET_LIB) install

$(TARGET_LIB): $(TARGET_OBJECTS)
	rm -f $(TARGET_LIB)
	$(AR) $(ARFLAGS) $(TARGET_LIB) $(TARGET_OBJECTS)
	$(RANLIB) $(TARGET_LIB)

$(CMN_TARGET_LIB): $(CMN_TARGET_OBJECTS)
	rm -f $(CMN_TARGET_LIB)
	$(AR) $(ARFLAGS) $(CMN_TARGET_LIB) $(CMN_TARGET_OBJECTS)
	$(RANLIB) $(CMN_TARGET_LIB)

$(TARGET_OBJECTS): $(TARGET_SOURCES)
	$(COMPILE) $(CFLAGS) -c $?

$(CMN_TARGET_OBJECTS): $(CMN_TARGET_SOURCES)
	$(COMPILE) $(CFLAGS) $(SHARED_CFLAGS) -c $?

install: $(TARGET_LIB) $(CMN_TARGET_LIB)
	cp -a -f $(TARGET_LIB) $(LBLIB_STATIC)/.
	cp -a -f $(CMN_TARGET_LIB) $(LBLIB_STATIC)/.
	for file in $(INSTALLHEADERS) ; do ln -s -f `pwd`/$$file $(LBINCLUDE)/. ; done

clean:
	rm -rf *.o $(TARGET_LIB) *~ *.d

.PHONY: all clean

