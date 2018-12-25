/*
 * $Id: xgsm_port_addr.c,v 1.1 Broadcom SDK $
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
 * Common XGS chip functions.
 *
 */

#include <cdk/arch/xgsm_chip.h>
#include <cdk/cdk_debug.h>

/*
 * Calculate address of port-based register
 */
uint32_t
cdk_xgsm_port_addr(int unit, uint32_t blkacc, int port,
                   uint32_t offset, int idx, uint32_t *adext)
{
    int bdx, p, blk_port = 0;
    int block = -1;
    const cdk_xgsm_block_t *blkp = CDK_XGSM_INFO(unit)->blocks;

    /*
     * Determine which block this port belongs to.
     * Note that if block = CMIC block this may be a register
     * that exists in more than one port block type.
     */
    for (bdx = 0; bdx < CDK_XGSM_INFO(unit)->nblocks; bdx++) {  
        if ((blkacc & (1 << blkp->type)) &&
            CDK_PBMP_MEMBER(blkp->pbmps, port)) {
            block = blkp->blknum;
            break;
        }
        blkp++;
    }

    /* Get the physical port number within this block */
    CDK_PBMP_ITER(blkp->pbmps, p) {
        if (p == port) {
            /* Construct address extension from access type and block */
            *adext = CDK_XGSM_BLKACC2ADEXT(blkacc);
            CDK_XGSM_ADEXT_BLOCK_SET(*adext, block);
            return cdk_xgsm_blockport_addr(unit, block, blk_port, offset, idx);
        }
        blk_port++;
    }

    /*
     * If we get here then something is not right, but we do not 
     * want to assert because we could have been called from the 
     * CLI with a raw address.
     */
    CDK_WARN(("cdk_xgsm_port_addr[%d]: invalid port %d "
              "for offset 0x%08"PRIx32"\n",
              unit, port, offset));

    return offset; 
}

