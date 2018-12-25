# $Id: Makefile,v 1.11 Broadcom SDK $
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

ifndef CDK_MAKE_DSYMS
CDK_MAKE_DSYMS = 0
endif

ifeq ($(CDK_MAKE_DSYMS),0)

# Build and empty library

LOCALDIR = dsym
LIBNAME = libcdkdsym
include $(CDK)/make/lib.mk

cleangen: 

cleantool:

else

DSYMTOOLDIR = $(CDK)/tools/dsyms
DSYMTOOL = $(DSYMTOOLDIR)/dsyms

# Normal cleaning at stage 2
ifneq (,$(findstring clean,$(MAKECMDGOALS)))
STAGE = 2
endif

ifndef STAGE
start:
	@echo Building DSYM Tool...
	$(MAKE) -C $(DSYMTOOLDIR)
	$(MAKE) STAGE=1
endif

ifeq ($(STAGE),1)

start: gentag
	$(MAKE) STAGE=2

endif

ifeq ($(STAGE),2)

LOCALDIR = dsym
LIBNAME = libcdkdsym

VPATH += $(notdir $(wildcard $(CDK)/$(LOCALDIR)/*))
VSRCS = $(wildcard *.c $(addsuffix /*.c,$(VPATH)))
LSRCS = $(notdir $(VSRCS))
LOBJS = $(addsuffix .$(OBJSUFFIX), $(basename $(LSRCS)))
BOBJS = $(addprefix $(BLDDIR)/,$(LOBJS))

include $(CDK)/make/lib.mk

endif

cleangen:
	@find . -name "*.[c,h]" -exec rm {} \; 
	@rm -f gentag

cleantool:
	$(MAKE) -C $(CDK)/tools/dsyms clean

gentag: $(DSYMTOOL)
	@echo Generating Files...
	$(DSYMTOOL) ot=single od=$(CDK) $(DSYM_GENERATION_OPTIONS)
	@echo Done.
	@touch gentag
	$(MAKE) STAGE=2

$(DSYMTOOL):
	$(MAKE) -C $(DSYMTOOLDIR)

.PRECIOUS: gentag

endif

.PHONY: cleangen cleantool
