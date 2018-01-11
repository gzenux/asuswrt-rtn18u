TOP_SRCDIR = ../../
include $(TOP_SRCDIR)/Makefile.defs

INSTALLHEADERS = bandmon.h bandmonCmn.h

# These are shared and exported for other daemons to use.
TARGET_LIB = libbandmon.a
TARGET_SOURCES = bandmonCmn.c
TARGET_OBJECTS = $(patsubst %.c,%.$(OBJEXT),$(TARGET_SOURCES))

# These files are not shared/exported to other daemons.
BSA_TARGET_LIB = libbandmon_bsa.a
BSA_TARGET_SOURCES = bandmonBSA.c
BSA_TARGET_OBJECTS = $(patsubst %.c,%.$(OBJEXT),$(BSA_TARGET_SOURCES))

all: $(TARGET_LIB) install

$(TARGET_LIB): $(TARGET_OBJECTS)
	@rm -f $(TARGET_LIB)
	$(AR) $(ARFLAGS) $(TARGET_LIB) $(TARGET_OBJECTS)
	$(RANLIB) $(TARGET_LIB)

$(BSA_TARGET_LIB): $(BSA_TARGET_OBJECTS)
	@rm -f $(BSA_TARGET_LIB)
	$(AR) $(ARFLAGS) $(BSA_TARGET_LIB) $(BSA_TARGET_OBJECTS)
	$(RANLIB) $(BSA_TARGET_LIB)

$(TARGET_OBJECTS): CFLAGS+=-fPIC

%.o: %.c
	$(COMPILE) $(CFLAGS) -c $?

install: $(TARGET_LIB) $(BSA_TARGET_LIB)
	@cp -a -f $(TARGET_LIB) $(LBLIB_STATIC)/.
	@cp -a -f $(BSA_TARGET_LIB) $(LBLIB_STATIC)/.
	@for file in $(INSTALLHEADERS) ; do ln -s -f `pwd`/$$file $(LBINCLUDE)/. ; done

clean:
	@rm -f *.o $(TARGET_LIB) *~
	@rm -f *.o $(BSA_TARGET_LIB) *~

.PHONY: all clean
