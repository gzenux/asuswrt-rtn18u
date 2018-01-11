/*
 * $Id: xgsm_shell.h,v 1.1 Broadcom SDK $
 * $Copyright: Copyright 2013 Broadcom Corporation.
 * This program is the proprietary software of Broadcom Corporation
 * and/or its licensors, and may only be used, duplicated, modified
 * or distributed pursuant to the terms and conditions of a separate,
 * written license agreement executed between you and Broadcom
 * (an "Authorized License").  Except as set forth in an Authorized
 * License, Broadcom grants no license (express or implied), right
 * to use, or waiver of any kind with respect to the Software, and
 * Broadcom expressly reserves all rights in and to the Software
 * and all intellectual property rights therein.  IF YOU HAVE
 * NO AUTHORIZED LICENSE, THEN YOU HAVE NO RIGHT TO USE THIS SOFTWARE
 * IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY BROADCOM AND DISCONTINUE
 * ALL USE OF THE SOFTWARE.  
 *  
 * Except as expressly set forth in the Authorized License,
 *  
 * 1.     This program, including its structure, sequence and organization,
 * constitutes the valuable trade secrets of Broadcom, and you shall use
 * all reasonable efforts to protect the confidentiality thereof,
 * and to use this information only in connection with your use of
 * Broadcom integrated circuit products.
 *  
 * 2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS
 * PROVIDED "AS IS" AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES,
 * REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY,
 * OR OTHERWISE, WITH RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY
 * DISCLAIMS ANY AND ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY,
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES,
 * ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING
 * OUT OF USE OR PERFORMANCE OF THE SOFTWARE.
 * 
 * 3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL
 * BROADCOM OR ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL,
 * INCIDENTAL, SPECIAL, INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER
 * ARISING OUT OF OR IN ANY WAY RELATING TO YOUR USE OF OR INABILITY
 * TO USE THE SOFTWARE EVEN IF BROADCOM HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES; OR (ii) ANY AMOUNT IN EXCESS OF
 * THE AMOUNT ACTUALLY PAID FOR THE SOFTWARE ITSELF OR USD 1.00,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 */

#ifndef __CDK_XGSM_SHELL_H__
#define __CDK_XGSM_SHELL_H__

/*******************************************************************************
 *
 * Various utility functions needed by different parts of the shell. 
 *
 * These are all declared her in this header, but implemented in separate, 
 * individual source files. 
 *
 * As such, if any utility function is unused in a given configuration, its 
 * code will just get dropped by the linker. 
 *
 ******************************************************************************/

#include <cdk/cdk_assert.h>
#include <cdk/cdk_stdlib.h>
#include <cdk/cdk_string.h>
#include <cdk/cdk_printf.h>
#include <cdk/cdk_symbols.h>
#include <cdk/cdk_chip.h>
#include <cdk/cdk_shell.h>
#include <cdk/cdk_debug.h>
#include <cdk/cdk_field.h>

#include <cdk/arch/xgsm_chip.h>
#include <cdk/arch/xgsm_reg.h>
#include <cdk/arch/xgsm_mem.h>
#include <cdk/arch/xgsm_miim.h>

/*******************************************************************************
 *
 * Register and Memory Output Functions (cdk_xgsm_shell_memregs.c)
 *
 *
 ******************************************************************************/

extern int
cdk_xgsm_shell_regops(int unit, const cdk_symbol_t *symbol, cdk_shell_id_t *sid, 
		      uint32_t size, uint32_t *and_masks, uint32_t *or_masks); 

extern int
cdk_xgsm_shell_memops(int unit, const cdk_symbol_t *symbol, cdk_shell_id_t *sid, 
		      uint32_t size, uint32_t *and_masks, uint32_t *or_masks); 

/*******************************************************************************
 *
 * Symbolic Register and Memory operations (cdk_xgsm_shell_symops.c)
 *
 *
 ******************************************************************************/

extern int 
cdk_xgsm_shell_symop(int unit, const cdk_symbol_t *symbol, cdk_shell_id_t *sid, 
                    uint32_t *and_masks, uint32_t *or_masks);

/*******************************************************************************
 *
 * Block functions (cdk_xgsm_shell_blocks.c)
 * 
 *
 ******************************************************************************/

extern const char *
cdk_xgsm_shell_block_type2name(int unit, int blktype); 

extern int
cdk_xgsm_shell_block_name2type(int unit, const char *name); 

extern char*
cdk_xgsm_shell_block_name(int unit, int block, char *dst); 

/*******************************************************************************
 *
 * Symbol Flags
 *
 *
 ******************************************************************************/

extern const char *
cdk_xgsm_shell_symflag_type2name(int unit, uint32_t flag); 

extern uint32_t
cdk_xgsm_shell_symflag_name2type(int unit, const char *name); 

extern int
cdk_xgsm_shell_symflag_cst2flags(int unit, const cdk_shell_tokens_t *cst,
                                uint32_t *present, uint32_t *absent); 

/*******************************************************************************
 *
 * Input parsing utilities (cdk_xgsm_shell_parse.c)
 *
 ******************************************************************************/

extern int 
cdk_xgsm_shell_parse_args(int argc, char *argv[], cdk_shell_tokens_t *cst, int max);

/*******************************************************************************
 *
 * Field dump with XGSM filtering
 *
 ******************************************************************************/

extern int 
cdk_xgsm_shell_show_fields(int unit, const cdk_symbol_t *symbol,
                          uint32_t *data, int skip_zeros);

/*******************************************************************************
 *
 * Shell macros for XGSM chips
 *
 ******************************************************************************/

/* Iterate over all blocktypes */
#define CDK_SHELL_BLKTYPE_ITER(flags, blktype) \
        for(blktype = CDK_XGSM_BLOCK_START; blktype <= CDK_XGSM_BLOCK_LAST; blktype <<= 1) \
           if(flags & blktype) 


#endif /* __CDK_XGSM_SHELL_H__ */
