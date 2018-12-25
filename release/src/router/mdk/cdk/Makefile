# $Id: Makefile,v 1.13 Broadcom SDK $
# $Copyright: Copyright 2009 Broadcom Corporation.
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
# CDK top-level makefile
#

# Set default CDK directory
ifndef CDK
CDK = $(CURDIR)
export CDK
endif

include $(CDK)/make/config.mk

include $(CDK)/targets.mk

.PHONY: all instpkgs cdklibs clean cleanpkgs $(CDK_TARGETS)

ifeq ($(MAKECMDGOALS),clean)
CDK_CLEAN = clean
endif

ifndef CDK_PKG_OPTIONS
CDK_PKG_OPTIONS = $(PKG_OPTIONS)
endif

all:
	$(MAKE) instpkgs
	$(MAKE) cdklibs

cdklibs: $(CDK_TARGETS)

$(CDK_TARGETS):
	@${ECHO} Processing CDK subdirectory $@
	$(MAKE) -C $@ $(CDK_CLEAN)

relpkgs:
	@perl $(CDK)/tools/instpkgs.pl -d $(CDK) -r

instpkgs:
	perl $(CDK)/tools/instpkgs.pl -d $(CDK) $(CDK_PKG_OPTIONS)

clean:: $(CDK_TARGETS)

cleanpkgs::
	$(Q)$(RM) $(CDK)/pkgsrc/installed-chips
	$(Q)$(RM) $(CDK)/include/cdk_config_chips.h
	$(Q)$(RM) $(CDK)/include/cdk_config_archs.h
	$(Q)$(RM) $(CDK)/include/cdk_config_phys.h
	$(Q)$(RM) $(CDK)/include/cdk/chip
	$(Q)$(RM) $(CDK)/include/cdk/arch
	$(Q)$(RM) $(CDK)/include/cdk/cdk_devlist.h
	$(Q)$(RM) $(CDK)/pkgsrc/chip
	$(Q)$(RM) $(CDK)/pkgsrc/arch
	$(Q)$(RM) $(CDK)/shell/arch
	$(Q)$(RM) $(CDK)/sym/chip
	$(Q)$(RM) $(CDK)/sym/cdk_allsyms.c
#	$(MAKE) -C $(CDK)/dsym cleangen
#	$(MAKE) -C $(CDK)/tools/dsyms clean

ccver:
	@echo "CC is '$(CC)'"
	$(CC) $(CC_VERFLAGS)

