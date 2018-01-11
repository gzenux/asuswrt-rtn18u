# $Id: targets.mk,v 1.4 Broadcom SDK $
# $Copyright: (c) 2006 Broadcom Corp.
# All Rights Reserved.$
#
# PHY Library default targets.
#
# This file may be included from the application makefile as well.
#

PHY_DEFAULT_TARGETS = pkgsrc generic util sym

ifndef PHY_TARGETS
PHY_TARGETS = $(PHY_DEFAULT_TARGETS)
endif

PHY_LIBNAMES = $(addprefix libphy,$(PHY_TARGETS))

# CONFIG_MDK_BCA_BEGIN
ifndef LINUX_SHARED_LIBRARY
ifndef PHY_LIBSUFFIX
PHY_LIBSUFFIX = a
endif
else
ifndef PHY_LIBSUFFIX
PHY_LIBSUFFIX = so
endif
endif
export PHY_LIBSUFFIX
PHY_LIBRARIES = $(addprefix -lphy,$(PHY_TARGETS)) 
# CONFIG_MDK_BCA_END

PHY_LIBS = $(addsuffix .$(PHY_LIBSUFFIX),$(PHY_LIBNAMES))
