BUILDTYPE=$(shell if test -d ../../../src/lib/; then echo distro; else echo devel; fi)

ifeq ($(BUILDTYPE),devel)
QUICKSEC_SRCDIR ?= ../../../src
TOOLKIT_SRCDIR ?= ../../../../toolkit-trunk/src
TOOLKIT_EXTERNALSRCDIR ?= ../../../../toolkit-trunk/external-src
QUICKSEC_ABSSRC = $(shell cd $(QUICKSEC_SRCDIR); pwd)
TOOLKIT_ABSSRC = $(shell cd $(TOOLKIT_SRCDIR); pwd)
TOOLKIT_ABSEXTERNALSRC = $(shell cd $(TOOLKIT_EXTERNALSRCDIR); pwd)
else
QUICKSEC_SRCDIR ?= ../../../src
TOOLKIT_SRCDIR ?= ../../../src/lib
TOOLKIT_EXTERNALSRCDIR ?= ../../../external-src
QUICKSEC_ABSSRC = $(shell cd $(QUICKSEC_SRCDIR); pwd)
TOOLKIT_ABSSRC = $(shell cd $(TOOLKIT_SRCDIR); pwd)
TOOLKIT_ABSEXTERNALSRC = $(shell cd $(TOOLKIT_EXTERNALSRCDIR); pwd)
endif

all: initialize
	$(if $(KDIR),,\
	    $(eval KDIR := /lib/modules/$(shell uname -r)/build)\
	    $(warning defaulting KDIR to $(KDIR)))
	$(MAKE) -C "$(KDIR)" M="`pwd`" modules

initialize:
	rm -rf obj
	mkdir obj
	cd $(QUICKSEC_SRCDIR)
	( cd $(QUICKSEC_SRCDIR) && find * -type d ) | sort | \
	while read d; do mkdir "obj/$$d"; done
	( cd $(QUICKSEC_SRCDIR) && find * -type f -name '*.[chS]' ) | \
	while read f; do ln -s "$(QUICKSEC_ABSSRC)/$$f" "obj/$$f"; done
	touch $@
	cd $(TOOLKIT_ABSSRC)
	( cd $(TOOLKIT_SRCDIR) && find * -type d ) | sort | \
	while read d; do mkdir "obj/$$d"; done
	( cd $(TOOLKIT_SRCDIR) && find * -type f -name '*.[chS]' ) | \
	while read f; do ln -s "$(TOOLKIT_ABSSRC)/$$f" "obj/$$f"; done
	touch $@
	cd $(TOOLKIT_ABSEXTERNALSRC)
	( cd $(TOOLKIT_EXTERNALSRCDIR) && find * -type d ) | sort | \
	while read d; do mkdir "obj/$$d"; done
	( cd $(TOOLKIT_EXTERNALSRCDIR) && find * -type f -name '*.[chS]' ) | \
	while read f; do ln -s "$(TOOLKIT_ABSEXTERNALSRC)/$$f" "obj/$$f"; done
	touch $@

clean:
	rm -f initialize
	rm -rf obj quicksec* .quicksec* .tmp_versions [Mm]odule*

-include Makefile.inc
-include Makefile.internal
