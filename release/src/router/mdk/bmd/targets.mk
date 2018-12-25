# $Id: targets.mk,v 1.3 Broadcom SDK $
# $Copyright: (c) 2006 Broadcom Corp.
# All Rights Reserved.$
#
# BMD default targets.
#
# This file may be included from the application makefile as well.
#

BMD_DEFAULT_TARGETS = shell api pkgsrc shared

ifndef BMD_TARGETS
BMD_TARGETS = $(BMD_DEFAULT_TARGETS)
endif

BMD_LIBNAMES = $(addprefix libbmd,$(BMD_TARGETS))

# CONFIG_MDK_BCA_BEGIN
ifndef LINUX_SHARED_LIBRARY
ifndef BMD_LIBSUFFIX
BMD_LIBSUFFIX = a
endif
else
ifndef BMD_LIBSUFFIX
BMD_LIBSUFFIX = so
endif
endif
export BMD_LIBSUFFIX
BMD_LIBRARIES = $(addprefix -lbmd,$(BMD_TARGETS))
# CONFIG_MDK_BCA_END

BMD_LIBS = $(addsuffix .$(BMD_LIBSUFFIX),$(BMD_LIBNAMES))
