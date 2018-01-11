/*
 * $Id: xgsm_dump_tx_dcbs.c,v 1.2 Broadcom SDK $
 *
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

#include <bmd/bmd.h>

#ifdef CDK_CONFIG_ARCH_XGSM_INSTALLED

#include <bmd/bmd_device.h>

#include <bmdi/arch/xgsm_dma.h>

#include <cdk/cdk_higig_defs.h>
#include <cdk/cdk_debug.h>

#include <cdk/arch/xgsm_chip.h>

#if CDK_CONFIG_INCLUDE_DEBUG == 1

static void
_dump_words(char *prefix, uint32_t *wdata, int cnt, int offs, int incr)
{
    int idx;

    if (cnt == 0) {
        return;
    }

    CDK_DEBUG_DMA((prefix));
    for (idx = 0; idx < cnt; idx++, offs += incr) {
        CDK_DEBUG_DMA((" %08"PRIx32, wdata[offs]));
    }
    CDK_DEBUG_DMA(("\n"));
}

/*
 * Function:
 *	bmd_xgsm_dump_tx_dcbs
 * Purpose:
 *	Dump Tx DMA control block information
 * Parameters:
 *	unit - BMD device
 *	dcbs - DCBs as sequential word arrays
 *	dcb_cnt - Number of DCBs
 *	dcb_size - Size of each DCB (in words)
 *	mh_size - Size of module header (in words)
 * Returns:
 *      CDK_XXX
 */
int
bmd_xgsm_dump_tx_dcbs(int unit, uint32_t *dcbs, int dcb_cnt,
                     int dcb_size, int mh_size)
{
    /* Dump DMA descriptor */
    _dump_words("Tx DMA ctrl =", dcbs, dcb_cnt, 1, dcb_size);
    _dump_words("Tx DMA stat =", dcbs, dcb_cnt, dcb_size-1, dcb_size);

#if CDK_CONFIG_INCLUDE_FIELD_INFO == 1
    if (CDK_DEBUG_CHECK(CDK_DBG_DMA | CDK_DBG_VVERBOSE)) {
        int idx;
        /* Decode DMA descriptors */
        for (idx = 0; idx < dcb_cnt; idx++) {
            CDK_DEBUG_DMA(("Tx DCB[%d]:\n", idx));
            cdk_symbol_dump("TX_DCB", CDK_XGSM_SYMBOLS(unit),
                            &dcbs[(idx*dcb_size)]);
        }
    }
#endif

    /* Dump module header if supplied */
    _dump_words("Tx DMA mhdr =", dcbs, mh_size, 2, 1);

#if CDK_CONFIG_INCLUDE_FIELD_INFO == 1
    if (mh_size > 0 &&
        ((dcbs[2] >> 24) == 0xfb || (dcbs[2] >> 24) == 0xfc) &&
        CDK_DEBUG_CHECK(CDK_DBG_DMA | CDK_DBG_HIGIG)) {
        char *sym_name = (mh_size == CDK_HIGIG2_WSIZE) ? "HIGIG2" : "HIGIG";
        /* Decode module header */
        CDK_DEBUG_DMA(("%s module header:\n", sym_name));
        cdk_symbol_dump(sym_name, &higig_symbols, &dcbs[6]); 
    }
#endif

    return 0;
}

#endif
#endif /* CDK_CONFIG_ARCH_XGSM_INSTALLED */
