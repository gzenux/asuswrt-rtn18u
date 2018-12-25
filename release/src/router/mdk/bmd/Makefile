# $Id: Makefile,v 1.12 Broadcom SDK $
# $Copyright: Copyright 2013 Broadcom Corporation.
# This program is the proprietary software of Broadcom Corporation
# and/or its licensors, and may only be used, duplicated, modified
# or distributed pursuant to the terms and conditions of a separate,
# written license agreement executed between you and Broadcom
# (an "Authorized License").  Except as set forth in an Authorized
# License, Broadcom grants no license (express or implied), right
# to use, or waiver of any kind with respect to the Software, and
# Broadcom expressly reserves all rights in and to the Software
# and all intellectual property rights therein.  IF YOU HAVE
# NO AUTHORIZED LICENSE, THEN YOU HAVE NO RIGHT TO USE THIS SOFTWARE
# IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY BROADCOM AND DISCONTINUE
# ALL USE OF THE SOFTWARE.  
#  
# Except as expressly set forth in the Authorized License,
#  
# 1.     This program, including its structure, sequence and organization,
# constitutes the valuable trade secrets of Broadcom, and you shall use
# all reasonable efforts to protect the confidentiality thereof,
# and to use this information only in connection with your use of
# Broadcom integrated circuit products.
#  
# 2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS
# PROVIDED "AS IS" AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES,
# REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY,
# OR OTHERWISE, WITH RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY
# DISCLAIMS ANY AND ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY,
# NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES,
# ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
# CORRESPONDENCE TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING
# OUT OF USE OR PERFORMANCE OF THE SOFTWARE.
# 
# 3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL
# BROADCOM OR ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL,
# INCIDENTAL, SPECIAL, INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER
# ARISING OUT OF OR IN ANY WAY RELATING TO YOUR USE OF OR INABILITY
# TO USE THE SOFTWARE EVEN IF BROADCOM HAS BEEN ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGES; OR (ii) ANY AMOUNT IN EXCESS OF
# THE AMOUNT ACTUALLY PAID FOR THE SOFTWARE ITSELF OR USD 1.00,
# WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
# ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
#
# BMD top-level makefile
#

# CDK variable is required
ifndef CDK
$(warning setting $$CDK automatically)
export CDK=${MDK}/cdk
endif

# Set default BMD directory
ifndef BMD
BMD = $(CURDIR)
export BMD
endif

# Default build directory
ifndef BMD_BLDDIR
BMD_BLDDIR = $(BMD)/build
endif

# Replace original CDK_BLDDIR with updated version
override MAKEOVERRIDES := $(subst CDK_BLDDIR,_BLDDIR,$(MAKEOVERRIDES))
override CDK_BLDDIR = $(BMD_BLDDIR)
export CDK_BLDDIR

# Default include path
BMD_INCLUDE_PATH = -I$(BMD)/include -I$(CDK)/include

# Import preprocessor flags avoiding include duplicates
TMP_BMD_CPPFLAGS := $(filter-out $(BMD_INCLUDE_PATH),$(BMD_CPPFLAGS))
TMP_BMD_CPPFLAGS += $(BMD_INCLUDE_PATH)

# Import compiler flags
TMP_BMD_CFLAGS := $(BMD_CFLAGS)

include $(CDK)/make/config.mk

# Replace original CDK_CPPFLAGS with updated version
override MAKEOVERRIDES := $(subst CDK_CPPFLAGS,_CPPFLAGS,$(MAKEOVERRIDES))
override CDK_CPPFLAGS := $(TMP_BMD_CPPFLAGS)
export CDK_CPPFLAGS

# Replace original CDK_CFLAGS with updated version
override MAKEOVERRIDES := $(subst CDK_CFLAGS,_CFLAGS,$(MAKEOVERRIDES))
override CDK_CFLAGS := $(TMP_BMD_CFLAGS)
export CDK_CFLAGS

include $(BMD)/targets.mk

.PHONY: all instpkgs clean cleanpkgs $(BMD_TARGETS)

ifeq ($(MAKECMDGOALS),clean)
BMD_CLEAN = clean
endif

ifndef BMD_PKG_OPTIONS
BMD_PKG_OPTIONS = $(PKG_OPTIONS)
endif

all:
	$(MAKE) instpkgs
	$(MAKE) bmdlibs

bmdlibs: $(BMD_TARGETS)

$(BMD_TARGETS):
	@${ECHO} Processing BMD subdirectory $@
	$(MAKE) -C $@ $(BMD_CLEAN)

relpkgs:
	@perl $(BMD)/tools/instpkgs.pl -d $(BMD) -r

instpkgs:
	perl $(BMD)/tools/instpkgs.pl -d $(BMD) $(BMD_PKG_OPTIONS)

clean:: $(BMD_TARGETS)

cleanpkgs::
	$(Q)$(RM) $(BMD)/include/bmdi/arch
	$(Q)$(RM) $(BMD)/include/bmdi/bmd_devlist.h
	$(Q)$(RM) $(BMD)/pkgsrc/chip
	$(Q)$(RM) $(BMD)/pkgsrc/arch
	$(Q)$(RM) $(BMD)/pkgsrc/installed-chips
