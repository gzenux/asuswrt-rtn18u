#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56685_B0 == 1

/*
 * $Id: bcm56685_b0_bmd_tx.c,v 1.2 Broadcom SDK $
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
#include <bmd/bmd_dma.h>

#include <bmdi/arch/xgs_dma.h>

#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>
#include <cdk/cdk_higig_defs.h>

#include <cdk/chip/bcm56685_b0_defs.h>

#include "bcm56685_b0_bmd.h"

#if BMD_CONFIG_INCLUDE_DMA == 1

static void
_dcb_init(int unit, TX_DCB_t *dcb, const bmd_pkt_t *pkt)
{
    uint32_t *sob;

    TX_DCB_CLR(*dcb); 

    if (pkt->port >= 0) {
        /* Enable stream-of-bytes module header */
        TX_DCB_HGf_SET(*dcb, 1); 

        /* Fill out stream-of-bytes module header */
        sob = TX_DCB_MODULE_HEADERf_PTR(*dcb);
        sob[0] = 0xff000000;
        sob[2] = pkt->port;
    }
}

#endif

int
bcm56685_b0_bmd_tx(int unit, const bmd_pkt_t *pkt)
{
#if BMD_CONFIG_INCLUDE_DMA == 1
    TX_DCB_t *dcb;
    dma_addr_t bdcb;
    int hdr_size, hdr_offset;
    int rv = CDK_E_NONE;

    BMD_CHECK_UNIT(unit);

    if (BMD_PORT_VALID(unit, pkt->port)) {
        /* Silently drop packet if link is down */
        if (!(BMD_PORT_STATUS(unit, pkt->port) & BMD_PST_LINK_UP)) {
            return CDK_E_NONE;
        }
    } else if (pkt->port >= 0) {
        /* Port not valid and not negative */
        return CDK_E_PORT;
    }

    /* Check for valid physical bus address */
    CDK_ASSERT(pkt->baddr);

    /* Allocate DMA descriptors from DMA memory pool */
    dcb = bmd_dma_alloc_coherent(unit, 2 * sizeof(*dcb), &bdcb);
    if (dcb == NULL) {
        return CDK_E_MEMORY;
    }

    /* Optionally strip VLAN tag */
    hdr_offset = 16;
    hdr_size = 16;
    if (BMD_PORT_PROPERTIES(unit, pkt->port) & BMD_PORT_HG) {
#if BMD_CONFIG_INCLUDE_HIGIG == 1
        /* Always strip VLAN tag if HiGig packet */
        if (pkt->data[0] == CDK_HIGIG_SOF) {
            hdr_offset += CDK_HIGIG_SIZE;
            hdr_size += (CDK_HIGIG_SIZE - 4);
        } else if (pkt->data[0] == CDK_HIGIG2_SOF) {
            hdr_offset += CDK_HIGIG2_SIZE;
            hdr_size += (CDK_HIGIG2_SIZE - 4);
        }
#endif
    } else if (pkt->flags & BMD_PKT_F_UNTAGGED) {
        hdr_size = 12; 
    }

    /* Set up first DMA descriptor */
    _dcb_init(unit, &dcb[0], pkt); 
    TX_DCB_ADDRf_SET(dcb[0], pkt->baddr); 
    TX_DCB_BYTE_COUNTf_SET(dcb[0], hdr_size);
    TX_DCB_SGf_SET(dcb[0], 1); 
    TX_DCB_CHAINf_SET(dcb[0], 1); 

    /* Set up second DMA descriptor */
    _dcb_init(unit, &dcb[1], pkt); 
    TX_DCB_ADDRf_SET(dcb[1], pkt->baddr + hdr_offset); 
    TX_DCB_BYTE_COUNTf_SET(dcb[1], pkt->size - hdr_offset); 

    /* Start DMA */
    BMD_DMA_CACHE_FLUSH(dcb, 2 * sizeof(*dcb));
    bmd_xgs_dma_tx_start(unit, bdcb); 

    /* Poll for DMA completion */
    if (bmd_xgs_dma_tx_poll(unit, BMD_CONFIG_DMA_MAX_POLLS) < 0) {
        rv = CDK_E_TIMEOUT;
    }
    BMD_DMA_CACHE_INVAL(dcb, 2 * sizeof(*dcb));
    bmd_xgs_dump_tx_dcbs(unit, (uint32_t *)dcb, 2,
                         CDK_BYTES2WORDS(TX_DCB_SIZE), CDK_HIGIG2_WSIZE);

    /* Free DMA descriptor */
    bmd_dma_free_coherent(unit, 2 * sizeof(*dcb), dcb, bdcb);

    return rv; 
#else
    return CDK_E_UNAVAIL;
#endif
}
#endif /* CDK_CONFIG_INCLUDE_BCM56685_B0 */
