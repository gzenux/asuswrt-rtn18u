/*
 * $Id: xgsm_shell_symops.c,v 1.4 Broadcom SDK $
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

#include <cdk/arch/xgsm_shell.h>


/*******************************************************************************
 *
 * Get or set a CMIC register. 
 *
 *
 ******************************************************************************/

static int 
_cmic_symop(int unit, const cdk_symbol_t *symbol, cdk_shell_id_t *sid, 
            uint32_t *and_masks, uint32_t *or_masks)
{
    uint32_t addr, data, step; 
    int i;

    /* No port/block identifiers on cmic registers */
    if (sid->port.valid || sid->block.valid) {
        return cdk_shell_parse_error("cmic address", sid->id); 
    }

    /* Did the user specify indices? */
    if (sid->addr.start == -1) {
        /* No indices specified, insert limits for the memory */
        sid->addr.start = CDK_SYMBOL_INDEX_MIN_GET(symbol->index); 
        sid->addr.end = CDK_SYMBOL_INDEX_MAX_GET(symbol->index); 
    }

    step = CDK_SYMBOL_INDEX_STEP_GET(symbol->index);
    
    for (i = sid->addr.start; i <= sid->addr.end; i++) {

        /* Index 32 bit addresses */
        addr = symbol->addr + (i * 4 * step);

        /* Read the data */
        CDK_DEV_READ32(unit, addr, &data); 

        /* This is a read-modify-write if masks are specified */
        if (and_masks || or_masks ) {
            if(and_masks) data &= and_masks[0]; 
            if(or_masks) data |= or_masks[0]; 
        
            /* Write the data */
            CDK_DEV_WRITE32(unit, addr, data); 

        } else {
            /* If we're here, it was a read operation and we should output the data */
            CDK_PRINTF("%s", symbol->name); 
            if (CDK_SYMBOL_INDEX_MAX_GET(symbol->index) > 0) {
                CDK_PRINTF("[%d]", i); 
            }
            CDK_PRINTF(".cmic [0x%08"PRIx32"] = 0x%"PRIx32"\n", addr, data); 
    
            /* Output field data if it is available */
#if CDK_CONFIG_INCLUDE_FIELD_INFO == 1
            if (sid->flags & CDK_SHELL_IDF_RAW) {
                continue;
            }
            if (symbol->fields) {
                int skip_zeros = (sid->flags & CDK_SHELL_IDF_NONZERO) ? 1 : 0;
                cdk_xgsm_shell_show_fields(unit, symbol, &data, skip_zeros); 
            }
#endif
        }
    }

    return 0; 
}


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
            sid->addr.start = 0; 
            sid->addr.end = maxidx; 
        }
    }
    
    /*
     * If the user specified a port number, but not block, then the ports as 
     * specified are not block-based. Since such top-level ports can span 
     * different blocks, we will iterate over all of the top-level ports 
     * specified, and handle each specific port within the loop below. 
     */
    for (port = sid->port.start; port <= sid->port.end; port++) {

        int b, match_block, wsize;
        cdk_shell_id_t sid2; 
        int blktype; 
        const cdk_xgsm_block_t *blkp; 

        /*
         * Iterate through all blocks of this symbol
         */
        for (blktype = 0; blktype < CDK_XGSM_INFO(unit)->nblktypes; blktype++) {

            if ((symbol->flags & (1 << blktype)) == 0) {
                continue;
            }

            /* Need a copy of the SID for this block iteration */
            CDK_MEMCPY(&sid2, sid, sizeof(sid2)); 

            /*
             * Set block type filter in case identical block types are
             * not contiguous.
             */
            sid2.block.ext32 = (1 << blktype);

            match_block = 0;

            /*
             * Iterate through all blocks in the chip
             */
            for (b = 0; b < CDK_XGSM_INFO(unit)->nblocks; b++) {

                /* Get the block pointer for this block */
                blkp = CDK_XGSM_INFO(unit)->blocks + b; 
                CDK_ASSERT(blkp); 

                if (blkp->type != blktype) {
                    continue;
                }

                /* Does the ID contain a block specifier? */
                if (!sid2.block.valid) {
                    /* User didn't specify the block, so we'll insert this one */
                    CDK_STRCPY(sid2.block.name, cdk_xgsm_shell_block_type2name(unit, blktype)); 
                
                    /* 
                     * If the user DID specify a top-level port number (port != -1)
                     * we need to see if that port is actually a part of this block. 
                     * If not, we will just punt. 
                     */
                    if (port != -1) {
                        cdk_xgsm_pblk_t pb; 
                        /* Look for this port within this blocktype */
                        if (cdk_xgsm_port_block(unit, port, &pb, blkp->type) == 0 && 
                            pb.block == blkp->blknum) {
                            /* This top-level port is a member of this block */
                            sid2.block.start = sid2.block.end = pb.block; 
                            sid2.port.start = sid2.port.end = pb.bport; 
                        }
                        else {
                            /* This top-level port is not a member of this block */
                            continue;
                        }
                    }
                    else {
                        /* No block and no ports, insert all ports in this block */
                        /* Add all blocks of this type */
                        if (sid2.block.start == -1 || sid2.block.end < blkp->blknum) {
                            sid2.block.end = blkp->blknum; 
                        }
                        if (sid2.block.start == -1 || sid2.block.start > blkp->blknum) {
                            sid2.block.start = blkp->blknum; 
                        }
                    }
                }
                else {
                    /* User specified a block identifier */
                    /* does the block match this one? */
                    if (CDK_STRCMP(sid2.block.name, cdk_xgsm_shell_block_type2name(unit, blktype)) == 0) {
                        /* Block specifier matches */
                        match_block = 1;
                        /* If start and stop were omitted, then we need to put them in */
                        if (sid->block.start == -1) {
                            /* Add all blocks of this type */
                            if (sid2.block.start == -1 || sid2.block.end < blkp->blknum) {
                                sid2.block.end = blkp->blknum; 
                            }
                            if (sid2.block.start == -1 || sid2.block.start > blkp->blknum) {
                                sid2.block.start = blkp->blknum; 
                            }
                        }   
                        else {
                            /* specific blocks were indicated. */
                            /* Need to convert these to physical blocks */
                            sid2.block.start = cdk_xgsm_block_number(unit, blktype, sid->block.start); 
                            sid2.block.end = cdk_xgsm_block_number(unit, blktype, sid->block.end); 
                        }                               
                    }
                    else {                      
                        /* Block specified does not match this one. */
                        /* I guess we're done */
                        continue;
                    }
                }
            
                /* Blocks are all setup. Now we need to check ports */
                if (symbol->flags & CDK_SYMBOL_FLAG_PORT) {
                    /* This is a port-based register */
                    /* Were specific ports specified? */
                    if (!sid2.port.valid) {
                        int p, port_end = -1;

                        /* Ports were not specified, so we'll put them in */
                        sid2.port.start = 0; 
                        CDK_PBMP_ITER(blkp->pbmps, p) {
                            port_end++; 
                        }
                        if (sid2.port.end < port_end) {
                            sid2.port.end = port_end;
                        }
                    }
                }
                else {
                    /* Ignore port specification if not a port-based register */
                    sid2.port.start = -1; 
                    sid2.port.end = -1; 
                }
            }
            
            if (sid2.block.valid && !match_block) {
                continue;
            }

            /* Skip if we don't have a valid block range by now */
            if (sid2.block.start == -1) {
                continue;
            }

            /* Get dual-pipe access type from symbol flags */
            sid2.addr.ext32 = (symbol->flags >> 12) & 0x700;

            /* Lets get it on */
            wsize = CDK_BYTES2WORDS(CDK_SYMBOL_INDEX_SIZE_GET(symbol->index));
            cdk_xgsm_shell_regops(unit, symbol, &sid2, wsize, and_masks, or_masks); 
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
    int b, match_block, wsize; 
    int maxidx, enum_val;
    cdk_shell_id_t sid2; 
    const cdk_xgsm_block_t *blkp; 
    int blktype; 


    CDK_ASSERT(symbol); 
    CDK_ASSERT(symbol->flags & CDK_SYMBOL_FLAG_MEMORY); 

    /* Silently ignore if ports were specified */
    if (sid->port.valid) {
        return 0;
    }

    /* Did the user specify indices? */
    if (sid->addr.start == -1) {
        /* No indices specified, insert limits for the memory */
        sid->addr.start = CDK_SYMBOL_INDEX_MIN_GET(symbol->index); 
        maxidx = CDK_SYMBOL_INDEX_MAX_GET(symbol->index); 
        enum_val = cdk_symbols_index(CDK_XGSM_SYMBOLS(unit), symbol);
        sid->addr.end = cdk_xgsm_mem_maxidx(unit, enum_val, maxidx);
    }
    
    /* 
     * Iterate through all blocks of which this memory is a member 
     */
    for (blktype = 0; blktype < CDK_XGSM_INFO(unit)->nblktypes; blktype++) {

        if ((symbol->flags & (1 << blktype)) == 0) {
            continue;
        }

        /* Need a copy of this SID for this block iteration */
        CDK_MEMCPY(&sid2, sid, sizeof(sid2)); 

        match_block = 0;

        for (b = 0; b < CDK_XGSM_INFO(unit)->nblocks; b++) {

            /* Get the block pointer for this block */
            blkp = CDK_XGSM_INFO(unit)->blocks + b;            
            CDK_ASSERT(blkp); 

            if (blkp->type != blktype){
                continue;
            }
            
            /* Does the SID contain a block specifier? */
            if (!sid2.block.valid) {
                /* If no specific blocks were specified, add all blocks of this type */
                if (sid2.block.start == -1 || sid2.block.end < blkp->blknum) {
                    sid2.block.end = blkp->blknum; 
                }
                if (sid2.block.start == -1 || sid2.block.start > blkp->blknum) {
                    sid2.block.start = blkp->blknum; 
                }
            }
            else {
                /* User specified a block identifier */
                /* does the block match this one? */
                if (CDK_STRCMP(sid2.block.name, cdk_xgsm_shell_block_type2name(unit, blktype)) == 0) {
                    /* Block specifier matches */
                    match_block = 1;
                    /* If start and stop were omitted, then we need to put them in */
                    if (sid->block.start == -1) {
                        /* Add all blocks of this type */
                        if (sid2.block.start == -1 || sid2.block.end < blkp->blknum) {
                            sid2.block.end = blkp->blknum; 
                        }
                        if (sid2.block.start == -1 || sid2.block.start > blkp->blknum) {
                            sid2.block.start = blkp->blknum; 
                        }
                    }   
                    else {
                        /* specific blocks were indicated. */
                        /* Need to convert these to physical blocks */
                        sid2.block.start = cdk_xgsm_block_number(unit, blktype, sid->block.start); 
                        sid2.block.end = cdk_xgsm_block_number(unit, blktype, sid->block.end); 
                    }                               
                }
                else {                      
                    /* Block specified does not match this one. */
                    /* I guess we're done */
                    continue;
                }
            }
        }

        /* Does the specified block match? */
        if (sid2.block.valid && !match_block) {
            continue;
        }
            
        /* We don't handle port numbers on memories */
        CDK_ASSERT((symbol->flags & CDK_SYMBOL_FLAG_PORT) == 0); 

        /* Skip if we don't have a valid block range by now */
        if (sid2.block.start == -1) {
            continue;
        }

        /* Get dual-pipe access type from symbol flags */
        sid2.addr.ext32 = (symbol->flags >> 12) & 0x700;

        wsize = CDK_BYTES2WORDS(CDK_SYMBOL_INDEX_SIZE_GET(symbol->index));
        cdk_xgsm_shell_memops(unit, symbol, &sid2, wsize, and_masks, or_masks); 
    }

    return 0;     
}


/*******************************************************************************
 *
 * Symbolic register and memory operations.
 *
 *
 ******************************************************************************/

int 
cdk_xgsm_shell_symop(int unit, const cdk_symbol_t *symbol, cdk_shell_id_t *sid, 
                    uint32_t *and_masks, uint32_t *or_masks)
{
    int cmic_blktype = cdk_xgsm_shell_block_name2type(unit, "cmic");

    /* Dispatch according to symbol type */
    if (symbol->flags & (1 << cmic_blktype)) {
        _cmic_symop(unit, symbol, sid, and_masks, or_masks);
    }
    else if (symbol->flags & CDK_SYMBOL_FLAG_REGISTER) {
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

