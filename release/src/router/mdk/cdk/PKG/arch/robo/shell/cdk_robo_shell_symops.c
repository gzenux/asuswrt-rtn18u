/*
 * $Id: cdk_robo_shell_symops.c,v 1.5 Broadcom SDK $
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
 *
 * CDK Shell Utility: SYMOPS
 *
 * These utility functions provide all of the symbolic
 * register/memory encoding and decoding. 
 *
 */

#include <cdk/arch/robo_shell.h>

/*******************************************************************************
 *
 * Get or set a chip register via S-channel
 *
 *
 ******************************************************************************/

static int
_reg_symop(int unit, const cdk_symbol_t *symbol, cdk_shell_id_t *sid, 
           uint32_t *and_masks, uint32_t *or_masks)
{
    int port; 
    int maxidx;

    CDK_ASSERT(symbol); 
    CDK_ASSERT(symbol->flags & CDK_SYMBOL_FLAG_REGISTER); 

    /* Did the user specify indices? */
    if (sid->addr.start == -1) {
        /* No indices specified, insert limits if any */
        maxidx = CDK_SYMBOL_INDEX_MAX_GET(symbol->index); 
        if (maxidx) {
            sid->addr.start = CDK_SYMBOL_INDEX_MIN_GET(symbol->index); 
            sid->addr.end = maxidx; 
        }
    }
    
    /* Blocks are all setup. Now we need to check ports */
    if (symbol->flags & CDK_SYMBOL_FLAG_PORT) {
        /* This is a port-based register */
        if (!sid->port.valid) {
            /* Ports were not specified, so we'll put them in */
            sid->port.start = 0; 
            sid->port.end = CDK_CONFIG_MAX_PORTS - 1; 
        }
    }
    else {
        /* Ignore port specification if not a port-based register */
        sid->port.start = -1; 
        sid->port.end = -1; 
    }

    /*
     * For ROBO chips block and blocktype are synonymous, i.e. there is 
     * only one block per blocktype. Since such top-level ports can span 
     * different blocks, we will iterate over all of the top-level ports 
     * specified, and handle each specific port within the loop below. 
     */
    for (port = sid->port.start; port <= sid->port.end; port++) {

        int b, size;
        cdk_shell_id_t sid2; 
        int blktype; 
        const cdk_robo_block_t *blkp; 

        /* Need a copy of the SID for this block iteration */
        CDK_MEMCPY(&sid2, sid, sizeof(sid2)); 

        /*
         * Iterate through all blocks of this symbol
         */
        for (blktype = 0; blktype < CDK_ROBO_INFO(unit)->nblktypes; blktype++) {

            if ((symbol->flags & (1 << blktype)) == 0) {
                continue;
            }

            /*
             * Iterate through all blocks in the chip
             */
            for (b = 0; b < CDK_ROBO_INFO(unit)->nblocks; b++) {

                /* Get the block pointer for this block */
                blkp = CDK_ROBO_INFO(unit)->blocks + b;
                CDK_ASSERT(blkp); 

                if (blkp->type != blktype) {
                    continue;
                }

                /* 
                 * See if the current port is actually a part of the
                 * current block. If not, we will just punt. 
                 */
                if (port >= 0) {
                    if (!CDK_PBMP_MEMBER(blkp->pbmps, port)) {
                        continue;
                    }
                    sid2.port.start = sid2.port.end = port; 
                }

                /* Lets get it on */
                size = CDK_SYMBOL_INDEX_SIZE_GET(symbol->index);
                cdk_robo_shell_regops(unit, symbol, &sid2, size, and_masks, or_masks); 
                break;
            }
        
            /*
             * If a block was specified, the ports we happen to be iterating over 
             * are block-based physical ports, which we already processed. 
             * Lets bail out of the outermost for loop. 
             */
            if (sid->block.valid) {
                break;
            }
        }
    }

    return 0;
}


/*******************************************************************************
 *
 * Get or Set a chip memory via S-channel
 *
 *
 ******************************************************************************/

static int
_mem_symop(int unit, const cdk_symbol_t *symbol, cdk_shell_id_t *sid, 
           uint32_t *and_masks, uint32_t *or_masks)
{    
    CDK_ASSERT(symbol); 
    CDK_ASSERT(symbol->flags & CDK_SYMBOL_FLAG_MEMORY); 

    /* Did the user specify indices? */
    if (sid->addr.start == -1) {
        /* No indices specified, insert limits for the memory */
        sid->addr.start = CDK_SYMBOL_INDEX_MIN_GET(symbol->index); 
        sid->addr.end = CDK_SYMBOL_INDEX_MAX_GET(symbol->index); 
    }
    
    return cdk_robo_shell_memops(unit, symbol, sid, CDK_SYMBOL_INDEX_SIZE_GET(symbol->index), 
                                 and_masks, or_masks); 
}


/*******************************************************************************
 *
 * Symbolic register and memory operations.
 *
 *
 ******************************************************************************/

int 
cdk_robo_shell_symop(int unit, const cdk_symbol_t *symbol, cdk_shell_id_t *sid, 
                    uint32_t *and_masks, uint32_t *or_masks)
{
    /* Dispatch according to symbol type */
    if (symbol->flags & CDK_SYMBOL_FLAG_REGISTER) {
        _reg_symop(unit, symbol, sid, and_masks, or_masks);
    }
    else if (symbol->flags & CDK_SYMBOL_FLAG_MEMORY) {
        _mem_symop(unit, symbol, sid, and_masks, or_masks);
    }
    else {
        /* Should never get here */
        CDK_PRINTF("%ssymbol '%s' was not generated correctly\n", 
                   CDK_CONFIG_SHELL_ERROR_STR, symbol->name); 
    }   
    return 0; 
}
