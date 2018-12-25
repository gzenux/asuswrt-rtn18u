# $Id: Makefile,v 1.10 Broadcom SDK $
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
# PHY top-level makefile
#

# CDK variable is required
ifndef CDK
$(warning setting $$CDK automatically)
export CDK=${MDK}/cdk
endif

# Set default PHY directory
ifndef PHY
PHY = $(CURDIR)
export PHY
endif

# Default build directory
ifndef PHY_BLDDIR
PHY_BLDDIR = $(PHY)/build
endif

# Replace original CDK_BLDDIR with updated version
override MAKEOVERRIDES := $(subst CDK_BLDDIR,_BLDDIR,$(MAKEOVERRIDES))
override CDK_BLDDIR = $(PHY_BLDDIR)
export CDK_BLDDIR

# Default include path
PHY_INCLUDE_PATH = -I$(PHY)/include

# Import preprocessor flags avoiding include duplicates
TMP_PHY_CPPFLAGS := $(filter-out $(PHY_INCLUDE_PATH),$(PHY_CPPFLAGS))
TMP_PHY_CPPFLAGS += $(PHY_INCLUDE_PATH)

# Import compiler flags
TMP_PHY_CFLAGS := $(PHY_CFLAGS)

include $(CDK)/make/config.mk

# Replace original CDK_CPPFLAGS with updated version
override MAKEOVERRIDES := $(subst CDK_CPPFLAGS,_CPPFLAGS,$(MAKEOVERRIDES))
override CDK_CPPFLAGS := $(TMP_PHY_CPPFLAGS)
export CDK_CPPFLAGS

# Replace original CDK_CFLAGS with updated version
override MAKEOVERRIDES := $(subst CDK_CFLAGS,_CFLAGS,$(MAKEOVERRIDES))
override CDK_CFLAGS := $(TMP_PHY_CFLAGS)
export CDK_CFLAGS

include $(PHY)/targets.mk

.PHONY: all instpkgs clean cleanpkgs $(PHY_TARGETS)

ifeq ($(MAKECMDGOALS),clean)
PHY_CLEAN = clean
endif

ifndef PHY_PKG_OPTIONS
PHY_PKG_OPTIONS = $(PKG_OPTIONS)
endif

all:
	$(MAKE) instpkgs
	$(MAKE) phylibs

phylibs: $(PHY_TARGETS)

$(PHY_TARGETS):
	@${ECHO} Processing PHY subdirectory $@
	$(MAKE) -C $@ $(PHY_CLEAN)

relpkgs:
	@perl $(PHY)/tools/instpkgs.pl -d $(PHY) -r

instpkgs:
	perl $(PHY)/tools/instpkgs.pl -d $(PHY) $(PHY_PKG_OPTIONS)

clean:: $(PHY_TARGETS)

cleanpkgs::
	$(Q)$(RM) $(PHY)/pkgsrc/installed-chips
	$(Q)$(RM) $(PHY)/include/phy_config_chips.h
	$(Q)$(RM) $(PHY)/include/phy/chip
	$(Q)$(RM) $(PHY)/include/phy/bus
	$(Q)$(RM) $(PHY)/include/phy/phy_buslist.h
	$(Q)$(RM) $(PHY)/include/phy/phy_devlist.h
	$(Q)$(RM) $(PHY)/pkgsrc/chip
	$(Q)$(RM) $(PHY)/pkgsrc/bus
	$(Q)$(RM) $(PHY)/sym/chip
	$(Q)$(RM) $(PHY)/sym/phy_allsyms.c

