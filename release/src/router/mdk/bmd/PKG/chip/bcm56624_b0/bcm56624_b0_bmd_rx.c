#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56624_B0 == 1

/*
 * $Id: bcm56624_b0_bmd_rx.c,v 1.8 Broadcom SDK $
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

#include <cdk/chip/bcm56624_b0_defs.h>

#include "bcm56624_b0_bmd.h"

#if BMD_CONFIG_INCLUDE_DMA == 1

typedef struct xgs_rx_dscr_s {
    RX_DCB_t *dcb;      /* DMA Control Block */
    dma_addr_t bdcb;    /* RX_DCB bus address */
    bmd_pkt_t *pkt;     /* Packet associated with RX_DCB */
} xgs_rx_dscr_t;

static xgs_rx_dscr_t _rx_dscr[BMD_CONFIG_MAX_UNITS];

static int
_cpu_port_enable_set(int unit, int enable)
{
    int ioerr = 0;
    EPC_LINK_BMAP_64r_t epc_link;
    uint32_t epc_pbm;

    ioerr += READ_EPC_LINK_BMAP_64r(unit, &epc_link);
    CDK_ASSERT(CMIC_PORT < 32);
    epc_pbm = EPC_LINK_BMAP_64r_PORT_BITMAP_LOf_GET(epc_link);
    if (enable) {
        epc_pbm |= LSHIFT32(1, CMIC_PORT);
    } else {
        epc_pbm &= ~LSHIFT32(1, CMIC_PORT);
    }
    EPC_LINK_BMAP_64r_PORT_BITMAP_LOf_SET(epc_link, epc_pbm);
    ioerr += WRITE_EPC_LINK_BMAP_64r(unit, epc_link);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

#endif

int
bcm56624_b0_bmd_rx_start(int unit, bmd_pkt_t *pkt)
{
#if BMD_CONFIG_INCLUDE_DMA == 1
    RX_DCB_t *dcb;
    dma_addr_t bdcb;
    int rv = CDK_E_NONE;

    BMD_CHECK_UNIT(unit);

    /* Check for valid physical bus address */
    CDK_ASSERT(pkt->baddr);

    if (_rx_dscr[unit].dcb != NULL) {
        return CDK_E_RESOURCE;
    }

    /* Allocate DMA descriptor from DMA memory pool */
    dcb = bmd_dma_alloc_coherent(unit, sizeof(*dcb), &bdcb);
    if (dcb == NULL) {
        return CDK_E_MEMORY;
    }

    _rx_dscr[unit].dcb = dcb;
    _rx_dscr[unit].bdcb = bdcb;
    _rx_dscr[unit].pkt = pkt;

    /* Set up DMA descriptor */
    RX_DCB_CLR(*dcb); 
    RX_DCB_ADDRf_SET(*dcb, pkt->baddr); 
    RX_DCB_BYTE_COUNTf_SET(*dcb, pkt->size); 

    /* Start DMA */
    BMD_DMA_CACHE_FLUSH(dcb, sizeof(*dcb));
    bmd_xgs_dma_rx_start(unit, bdcb); 

    rv = _cpu_port_enable_set(unit, 1);

    return rv; 
#else
    return CDK_E_UNAVAIL;
#endif
}

int
bcm56624_b0_bmd_rx_poll(int unit, bmd_pkt_t **ppkt)
{
#if BMD_CONFIG_INCLUDE_DMA == 1
    RX_DCB_t *dcb;
    bmd_pkt_t *pkt;
    int rv = CDK_E_NONE;

    BMD_CHECK_UNIT(unit);

    dcb = _rx_dscr[unit].dcb;
    if (dcb == NULL) {
        return CDK_E_DISABLED;
    }

    /* Poll for DMA completion */
    if (bmd_xgs_dma_rx_poll(unit, 1) < 0) {
        return CDK_E_TIMEOUT;
    }
    BMD_DMA_CACHE_INVAL(dcb, sizeof(*dcb));
    bmd_xgs_dump_rx_dcb(unit, (uint32_t *)dcb,
                        CDK_BYTES2WORDS(RX_DCB_SIZE), CDK_HIGIG2_WSIZE);

    if (RX_DCB_DONEf_GET(*dcb) == 0) {
        return CDK_E_TIMEOUT;
    }

    /* Fill out packet structure */
    pkt = _rx_dscr[unit].pkt;
    pkt->size = RX_DCB_BYTES_TRANSFERREDf_GET(*dcb);
    pkt->port = RX_DCB_SRC_PORTf_GET(*dcb);

    bmd_xgs_parse_higig2(unit, pkt, RX_DCB_MODULE_HEADERf_PTR(*dcb));

    /* Pass packet back to application */
    *ppkt = pkt;

    /* Free DMA descriptor */
    bmd_dma_free_coherent(unit, sizeof(*dcb), dcb, _rx_dscr[unit].bdcb);

    CDK_MEMSET(&_rx_dscr[unit], 0, sizeof(_rx_dscr[unit]));

    return rv; 
#else
    return CDK_E_UNAVAIL;
#endif
}

int
bcm56624_b0_bmd_rx_stop(int unit)
{
#if BMD_CONFIG_INCLUDE_DMA == 1
    RX_DCB_t *dcb;
    int rv = CDK_E_NONE;

    BMD_CHECK_UNIT(unit);

    dcb = _rx_dscr[unit].dcb;
    if (dcb == NULL) {
        return CDK_E_DISABLED;
    }

    rv = _cpu_port_enable_set(unit, 0);
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    rv = bmd_xgs_dma_rx_abort(unit, BMD_CONFIG_DMA_MAX_POLLS);
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    /* Free DMA descriptor */
    bmd_dma_free_coherent(unit, sizeof(*dcb), dcb, _rx_dscr[unit].bdcb);

    CDK_MEMSET(&_rx_dscr[unit], 0, sizeof(_rx_dscr[unit]));

    return rv; 
#else
    return CDK_E_UNAVAIL;
#endif
}
#endif /* CDK_CONFIG_INCLUDE_BCM56624_B0 */
