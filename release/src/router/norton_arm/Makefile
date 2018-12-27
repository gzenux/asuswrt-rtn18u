#
# Norton Gateway Apps Content
#
#  Copyright (c) 2012 Symantec Corporation. All rights reserved.
# 
# THIS SOFTWARE CONTAINS CONFIDENTIAL INFORMATION AND TRADE SECRETS OF SYMANTEC
# CORPORATION.  USE, DISCLOSURE OR REPRODUCTION IS PROHIBITED WITHOUT THE PRIOR
# EXPRESS WRITTEN PERMISSION OF SYMANTEC CORPORATION.
# 
# The Licensed Software and Documentation are deemed to be commercial computer
# software as defined in FAR 12.212 and subject to restricted rights as defined in
# FAR Section 52.227-19 "Commercial Computer Software - Restricted Rights" and
# DFARS 227.7202, "Rights in Commercial Computer Software or Commercial Computer
# Software Documentation", as applicable, and any successor regulations.  Any use,
# modification, reproduction release, performance, display or disclosure of the
# Licensed Software and Documentation by the U.S. Government shall be solely in
# accordance with the terms of this Agreement.
# 

all: pages.mk libs.mk bins.mk configs.mk inits.mk

# Build our list of pages
PAGES := ./www/apolloLoader.gif
PAGES += ./www/favicon.ico
PAGES += ./www/index.asp
PAGES += ./www/jquery-1.8.2.min.js
PAGES += ./www/loading_page_sprite.jpg
PAGES += ./www/status.asp

# Build our list of libs
LIBS := ./lib/libcx_lib.so
LIBS += ./lib/liblux.so.1

# Build our list of binaries
BINS := ./bin/bootstrap

# Build our list of scripts
INITS := ./init/bootstrap.sh
INITS += ./init/service.sh

# Build our list of dat files
CONFIGS := ./config/luxds.dat
CONFIGS += ./config/ngads.dat

# Build our list of docs
DOCS := ./LICENSE

ifneq ($(WIND_HOST_TYPE),x86-win32)
ifdef BCM_NETBSD
pages.mk:
	echo PAGES := $(PAGES) > $@
libs.mk:
	echo LIBS := $(LIBS) > $@
bins.mk:
	echo BINS := $(BINS) > $@
inits.mk:
	echo INITS := $(INITS) > $@
configs.mk:
	echo CONFIGS := $(CONFIGS) > $@
docs.mk:
	echo DOCS := $(DOCS) > $@
else
# Linux
pages.mk:
	echo "PAGES := $(PAGES)" > $@
libs.mk:
	echo "LIBS := $(LIBS)" > $@
bins.mk:
	echo "BINS := $(BINS)" > $@
inits.mk:
	echo "INITS := $(INITS)" > $@
configs.mk:
	echo "CONFIGS := $(CONFIGS)" > $@
docs.mk:
	echo "DOCS := $(DOCS)" > $@
endif
else
# VxWorks
pages.mk:
	echo PAGES := $(PAGES) > $@
libs.mk:
	echo LIBS := $(LIBS) > $@
bins.mk:
	echo BINS := $(BINS) > $@
inits.mk:
	echo INITS := $(INITS) > $@
configs.mk:
	echo CONFIGS := $(CONFIGS) > $@
docs.mk:
	echo DOCS := $(DOCS) > $@
endif

install:
	install -d $(INSTALLDIR)/opt
	install -d $(INSTALLDIR)/opt/nga
	install -d $(INSTALLDIR)/opt/nga/bin
	install -d $(INSTALLDIR)/opt/nga/lib
	install -d $(INSTALLDIR)/opt/nga/content
	install -d $(INSTALLDIR)/opt/nga/content/www
	install -d $(INSTALLDIR)/opt/nga/init
	install -m 644 $(PAGES) $(INSTALLDIR)/opt/nga/content/www
	install -m 644 $(CONFIGS) $(INSTALLDIR)/opt/nga/content
	install -m 644 $(LIBS) $(INSTALLDIR)/opt/nga/lib
	install -m 755 $(BINS) $(INSTALLDIR)/opt/nga/bin
	install -m 755 $(INITS) $(INSTALLDIR)/opt/nga/init
	install -m 644 $(DOCS) $(INSTALLDIR)/opt/nga

clean:
	rm -f pages.mk libs.mk bins.mk inits.mk configs.mk docs.mk
