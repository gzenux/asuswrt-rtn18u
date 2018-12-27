TOPDIR=../..
SRCDIR=$(TOPDIR)/src

override CFLAGS += -MMD -Wall -Wno-pointer-sign $(EXTRA_CFLAGS)

HOSTARCH ?= $(shell uname -m)

override LDLIBS += -ldl -lc -lrt -lpthread

override CPPFLAGS += \
	-DSSH_BUILD_IPSEC \
	-DRETSIGTYPE=void \
        -DQUICKSEC_DIST_VPNCLIENT \
	-DSSH_IPSEC_UNIFIED_ADDRESS_SPACE \
	-DUSERMODE_ENGINE \
        -DSSH_USERMODE_DEFAULT_FLAGS=0 \
        -DSSH_USERMODE_INTERCEPTOR_DISABLE_TESTS \
	-DINTERCEPTOR_PROVIDES_INTERFACE_INFORMATION \
	-DINTERCEPTOR_PROVIDES_IP_ROUTING \
	-DINTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS \
        -DINTERCEPTOR_HAS_VIRTUAL_ADAPTERS \
        -DINTERCEPTOR_HAS_ENABLE_INTERCEPTION \
	-DSSH_MP_INTEGER_BIT_SIZE_STATIC=0 \
	-DLINUX_HAS_RTM_SETLINK

ifeq ($(DEBUG), 1)
override CPPFLAGS += -DDEBUG_LIGHT
endif


all: kbuild

-include Makefile.inc
-include Makefile.internal


kbuild:
	cp -Rsf $$PWD/$(SRCDIR)/ interceptor-gpl
	cat Kbuild_head > tmp
	(cd interceptor-gpl; ls *.c | sed 's/\.c$$/.o\\/') >> tmp
	cat Kbuild_tail >> tmp
	mv tmp interceptor-gpl/Kbuild
	cp Makefile.kbuild interceptor-gpl/Makefile
	+${MAKE} -C interceptor-gpl

kbuild_clean:
	rm -fr interceptor-gpl

%.a:
	$(AR) rcs $@ $^

depend:
	echo "Updated depend."
	cat *.d >Makefile.depend

nodepend:
	rm -f Makefile.depend

clean: kbuild_clean
	rm -f *.o *.d *.a Makefile.depend

-include Makefile.depend
