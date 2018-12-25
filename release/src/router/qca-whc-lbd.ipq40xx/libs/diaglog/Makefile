TOP_SRCDIR = ../../
include $(TOP_SRCDIR)/Makefile.defs

INSTALLHEADERS = diaglog.h
TARGET_LIB = libdiaglog.a
TARGET_OBJECTS = diaglog.$(OBJEXT)

SHARED_CFLAGS += -fPIC

all: $(TARGET_LIB) install

$(TARGET_LIB): $(TARGET_OBJECTS)  
	@rm -f $(TARGET_LIB)
	$(AR) $(ARFLAGS) $(TARGET_LIB) $(TARGET_OBJECTS) 
	$(RANLIB) $(TARGET_LIB)

.c.o:
	@$(COMPILE) $(SHARED_CFLAGS) -c $<

install: $(TARGET_LIB)
	@cp -a -f $(TARGET_LIB) $(LBLIB_STATIC)/.
	@for file in $(INSTALLHEADERS) ; do ln -s -f `pwd`/$$file $(LBINCLUDE)/. ; done

clean:
	@rm -f *.o *.d $(TARGET_LIB) *~

.PHONY: all clean

