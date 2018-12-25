/*
 * $Id: cdk_xgs_shell_memregs.c,v 1.15 Broadcom SDK $
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
 * This file provides all of the basic register and memory reads and writes. 
 * These functions are shared by both the symbolic and non-symbolic commands. 
 *
 */

#include <cdk/arch/xgs_shell.h>

/*******************************************************************************
 *
 *
 *
 *
 ******************************************************************************/
static int
_paddr(int unit, int aindex, int block, int port, uint32_t addr)
{
    uint32_t paddr = addr; 

    /* Calculate the absolute address */
    
    if (block >= 0 && port >= 0) {
        paddr = cdk_xgs_blockport_addr(unit, block, port, paddr); 
    }
    if (block >= 0 && port < 0) {
        paddr = cdk_xgs_block_addr(unit, block, paddr); 
    }
    if (block < 0 && port >= 0) {
        paddr = cdk_xgs_port_addr(unit, port, paddr); 
    }

    if (aindex >= 0) {
        paddr += aindex; 
    }
    return paddr; 
}

/*******************************************************************************
 *
 * 
 *
 *
 ******************************************************************************/
static void
_print_memreg_op(int unit, const char *prefix, cdk_shell_id_t *sid, 
                 int a, int b, int p, uint32_t paddr, const char *errstr, int rc)
{
    char blockname[32]; 
    char port_str[16]; 

    if (rc < 0) {
        CDK_PRINTF("%s%s ", CDK_CONFIG_SHELL_ERROR_STR, errstr); 
    }
        
    CDK_PRINTF("%s %s", prefix, sid->addr.name); 
    if (a >= 0) CDK_PRINTF("[%d]", a); 
    if (b >= 0) CDK_PRINTF(".%s", cdk_xgs_shell_block_name(unit, b, blockname)); 
    if (p >= 0) {
        int port = cdk_xgs_port_number(unit, b, p);
        cdk_shell_lport(port_str, sizeof(port_str), unit, port);
        CDK_PRINTF(".%s%d (BLOCK %d, PORT %s)", sid->port.name, p, b, port_str); 
    }
    CDK_PRINTF(" [0x%08"PRIx32"]", paddr); 

    if (rc < 0) {
        CDK_PRINTF(" (%d)", rc); 
    }
}

/*******************************************************************************
 *
 * cdk_xgs_shell_regop
 *
 * Read or write shell register operations
 *
 ******************************************************************************/
static int
cdk_xgs_shell_regop(int unit, const cdk_symbol_t *symbol, cdk_shell_id_t *sid, 
                     int aindex, int block, int port, uint32_t size, 
                     uint32_t *and_masks, uint32_t *or_masks)
{       
    int rc = 0; 
    uint32_t i, paddr, step; 
    uint32_t data[2]; 

    if (size > sizeof(data)/sizeof(uint32_t)) {
        CDK_PRINTF("%sentity size (%"PRIx32" words) too big\n", 
                   CDK_CONFIG_SHELL_ERROR_STR, size); 
        return -1;
    }

    step = CDK_SYMBOL_INDEX_STEP_GET(symbol->index);

    /* Calculate the absolute address for this read */
    paddr = _paddr(unit, aindex * step, block, port, sid->addr.name32); 

    /* Read the data */
    if (size == 1) {
        rc = cdk_xgs_reg32_read(unit, paddr, data);
    } else {
        rc = cdk_xgs_reg64_read(unit, paddr, data); 
    }

    /* Print an error message if the read failed */
    if (rc < 0) {
        _print_memreg_op(unit, "register", sid, aindex, block, port, 
                         paddr, "reading", rc); 
        CDK_PRINTF("\n"); 
        return rc; 
    }

    /* If masks are specific, this is a read-modify-write operation */
    if (and_masks || or_masks) {
        for (i = 0; i < size; i++) {
            if (and_masks) data[i] &= and_masks[i]; 
            if (or_masks)  data[i] |= or_masks[i]; 
        }
        
        /* Write the data */
        if (size == 1) {
            rc = cdk_xgs_reg32_write(unit, paddr, data);
        } else {
            rc = cdk_xgs_reg64_write(unit, paddr, data); 
        }
        
        /* Print en error message if the write failed */
        if (rc < 0) {
            _print_memreg_op(unit, "register", sid, aindex, block, port, 
                             paddr, "writing", rc); 
            CDK_PRINTF("\n"); 
            return rc; 
        }

        /* No more to be done if this was a write rather than a read */
        return 0;
    }

    if (sid->flags & CDK_SHELL_IDF_NONZERO) {
        for (i = 0; i < size; i++) {
            if (data[i]) break;
        }
        if (i >= size) return 0;
    }

    /* If we are here, this was a read. Output the register data */
    _print_memreg_op(unit, "register", sid, aindex, block, port, 
                     paddr, "reading", rc); 
    if (size == 1) CDK_PRINTF(" = 0x%08"PRIx32"\n", data[0]); 
    if (size == 2) CDK_PRINTF(" = 0x%08"PRIx32":0x%08"PRIx32"\n", 
                              data[0], data[1]); 

    /* Decode the individual fields if they are available */
#if CDK_CONFIG_INCLUDE_FIELD_INFO == 1
    if (sid->flags & CDK_SHELL_IDF_RAW) {
        return 0;
    }
    if (symbol && symbol->fields) {
        int skip_zeros = (sid->flags & CDK_SHELL_IDF_NONZERO) ? 1 : 0;
        /* Decode the result */
        cdk_xgs_shell_show_fields(unit, symbol, data, skip_zeros); 
    }
#endif
    return 0; 
}

/*******************************************************************************
 *
 * cdk_xgs_shell_regops
 *
 * Iterates over all specified register indices, blocks, and ports in a 
 * given sid, performs the request read or write, and displays necessary info
 *
 *
 ******************************************************************************/
int
cdk_xgs_shell_regops(int unit, const cdk_symbol_t *symbol, cdk_shell_id_t *sid, 
                      uint32_t size, uint32_t *and_masks, uint32_t *or_masks)
{    
    int a, b, bt, p, i; 
    cdk_pbmp_t pbmp;
    const cdk_xgs_block_t *blkp = NULL;
    
    /* Foreach address index */
    for (a = sid->addr.start; a <= sid->addr.end; a++) {
        /* Foreach block number */
        for (b = sid->block.start; b <= sid->block.end; b++) {
            
            if (b != -1) {
                /* If this is not a valid block number for the chip, skip it */
                if (cdk_xgs_block_type(unit, b, &bt, NULL) < 0) {
                    continue;
                }
            
                /* Check that block type is valid for this symbol */
                if (symbol && (symbol->flags & (1 << bt)) == 0) {
                    continue;
                }

                /* Skip this block if its port bitmap is empty.
                 * This is because not all blocks of the same type that exist
                 * on a chip may have ports in them, specially true of GPORTs.
                 */
                for (i = 0; i < CDK_XGS_INFO(unit)->nblocks; i++) {
                    if (CDK_XGS_INFO(unit)->blocks[i].blknum == b) {
                        blkp = CDK_XGS_INFO(unit)->blocks + i;
                        break;
                    }
                }
                CDK_ASSERT(blkp);
                CDK_PBMP_ASSIGN(pbmp, blkp->pbmps);
                CDK_PBMP_AND(pbmp, CDK_XGS_INFO(unit)->valid_pbmps);
                if (CDK_PBMP_IS_NULL(pbmp)) {
                    continue;
                }     
            }
       
            /* Foreach port */
            for (p = sid->port.start; p <= sid->port.end; p++) {

                /* If this is not a valid port for this block number, skip it */
                if (b != -1 && p != -1) {
                    int port, encoding, maxidx;

                    port = cdk_xgs_port_number(unit, b, p);
                    if (port == -1) {
                        /* This combination is not valid for the chip */        
                        continue; 
                    }
                    maxidx = CDK_SYMBOL_INDEX_MAX_GET(symbol->index);
                    encoding = CDK_SYMBOL_INDEX_ENC_GET(symbol->index);
                    if (maxidx || encoding) {
                        if (cdk_xgs_reg_index_valid(unit, port, a < 0 ? 0 : a,
                                                    encoding, maxidx) == 0) {
                            /* This register index is not valid for this port */
                            continue; 
                        }
                    }
                }
                /* Perform the operation on this specific register */
                cdk_xgs_shell_regop(unit, symbol, sid, a, b, p, size, 
                                     and_masks, or_masks); 
            }
        }
    }
    return 0; 
}

/*******************************************************************************
 *
 * cdk_xgs_shell_memop
 *
 *
 ******************************************************************************/
static int
cdk_xgs_shell_memop(int unit, const cdk_symbol_t *symbol, cdk_shell_id_t *sid, 
                     int block, int mindex, uint32_t size, 
                     uint32_t *and_masks, uint32_t *or_masks)
{
    int rc; 
    uint32_t i, paddr; 
    uint32_t data[CDK_MAX_REG_WSIZE]; 
    uint32_t findex = mindex;
    uint32_t aindex = mindex;

    if (size > COUNTOF(data)) {
        CDK_PRINTF("%sentity size (%"PRIx32" words) too big\n", 
                   CDK_CONFIG_SHELL_ERROR_STR, size); 
        return -1;
    }

    /* Calculate the absolute address for this memory read */
    paddr = _paddr(unit, -1, block, -1, sid->addr.name32); 

    if (symbol && (symbol->flags & CDK_XGS_MEM_FLAG_STEP2)) {
        findex |= CDK_XGS_MEM_FLAG_STEP2;
        aindex <<= 1;
    }

    /* Read the data */
    rc = cdk_xgs_mem_read(unit, paddr, findex, data, size); 

    /* If the read failed, output an error */
    if (rc < 0) {
        _print_memreg_op(unit, "memory", sid, mindex, block, -1, 
                         paddr + aindex, "reading", rc); 
        CDK_PRINTF("\n"); 
        return rc; 
    }

    /* If masks are specified, this is a read-modify-write */
    if (and_masks || or_masks) {
        for (i = 0; i < size; i++) {
            if(and_masks) data[i] &= and_masks[i]; 
            if(or_masks) data[i] |= or_masks[i]; 
        }

        /* Write the data */
        rc = cdk_xgs_mem_write(unit, paddr, findex, data, size); 
        
        /* If the write failed, output an error */
        if (rc < 0) {
            _print_memreg_op(unit, "memory", sid, mindex, block, -1, 
                             paddr + aindex, "writing", rc); 
            CDK_PRINTF("\n"); 
            return rc; 
        }
        
        /* Nothing more to be done for writes */
        return rc; 
    }
          
    if (sid->flags & CDK_SHELL_IDF_NONZERO) {
        for (i = 0; i < size; i++) {
            if (data[i]) break;
        }
        if (i >= size) return 0;
    }

    /* If we got here, this was a read. Print out the memory data */
    _print_memreg_op(unit, "memory ", sid, mindex, block, -1, 
                     paddr + aindex, "reading", rc); 
    CDK_PRINTF(" = "); 
    for (i = 0; i < size; i++) {
        CDK_PRINTF("0x%08"PRIx32" ", data[i]); 
    }
    CDK_PRINTF("\n"); 

    /* Decode the individual fields if they are available */
#if CDK_CONFIG_INCLUDE_FIELD_INFO == 1
    if (sid->flags & CDK_SHELL_IDF_RAW) {
        return 0;
    }
    if (symbol && symbol->fields) {
        int skip_zeros = (sid->flags & CDK_SHELL_IDF_NONZERO) ? 1 : 0;
        /* Decode the result */
        cdk_xgs_shell_show_fields(unit, symbol, data, skip_zeros); 
    }
#endif

    return 0; 
}

/*******************************************************************************
 *
 * cdk_xgs_shell_memops
 *
 *
 ******************************************************************************/
int
cdk_xgs_shell_memops(int unit, const cdk_symbol_t *symbol, cdk_shell_id_t *sid, 
                      uint32_t size, uint32_t *and_masks, uint32_t *or_masks)
{
    int b, i; 
    for (b = sid->block.start; b <= sid->block.end; b++) {
        for (i = sid->addr.start; i <= sid->addr.end; i++) {
            cdk_xgs_shell_memop(unit, symbol, sid, b, i, size, 
                                 and_masks, or_masks); 
        }
    }
    return 0; 
}
