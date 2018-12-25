# $Id: targets.mk,v 1.11 Broadcom SDK $
# $Copyright: (c) 2006 Broadcom Corp.
# All Rights Reserved.$
#
# CDK default targets.
#
# This file may be included from the application makefile as well.
#

CDK_DEFAULT_TARGETS = shell main pkgsrc shared sym libc dsym

# CDK_DEFAULT_TARGETS = shell

ifndef CDK_TARGETS
CDK_TARGETS = $(CDK_DEFAULT_TARGETS)
endif

CDK_LIBNAMES = $(addprefix libcdk,$(CDK_TARGETS))

# CONFIG_MDK_BCA_BEGIN
ifndef LINUX_SHARED_LIBRARY
ifndef CDK_LIBSUFFIX
CDK_LIBSUFFIX = a
endif
else
ifndef CDK_LIBSUFFIX
CDK_LIBSUFFIX = so
endif
endif
export CDK_LIBSUFFIX
CDK_LIBRARIES = $(addprefix -lcdk,$(CDK_TARGETS)) 
# CONFIG_MDK_BCA_END

CDK_LIBS = $(addsuffix .$(CDK_LIBSUFFIX),$(CDK_LIBNAMES))
