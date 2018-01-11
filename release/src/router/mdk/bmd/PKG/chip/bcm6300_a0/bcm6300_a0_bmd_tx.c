#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM6300_A0 == 1

/*
 * $Id: bcm6300_a0_bmd_tx.c,v 1.4 Broadcom SDK $
 * 
 * $Copyright: Copyright 2009 Broadcom Corporation.
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
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$1,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 */

#include <bmd/bmd.h>
#include <bmd/bmd_dma.h>

#include <cdk/cdk_device.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>
#include <cdk/cdk_util.h>

#include <cdk/chip/bcm6300_a0_defs.h>

#include "bcm6300_a0_internal.h"
#include "bcm6300_a0_bmd.h"

int
bcm6300_a0_bmd_tx(int unit, const bmd_pkt_t *pkt)
{
#if BMD_CONFIG_INCLUDE_DMA == 1
    int rv;
    int txsize;
    uint8_t *txbuf, *crcbuf, *brcm_hdr;
    dma_addr_t baddr;
    uint32_t crc;

    BMD_CHECK_UNIT(unit);

    if (pkt->port > 4 && pkt->port != 8) {
        return CDK_E_PORT;
    }

    /* Allocate Tx buffer */
    txsize = pkt->size + ROBO_BRCM_HDR_SIZE;
    txbuf = bmd_dma_alloc_coherent(unit, txsize + 4, &baddr);
    if (txbuf == NULL) {
        return CDK_E_MEMORY;
    }

    /* Copy MAC addresses to Tx buffer */
    CDK_MEMCPY(txbuf, pkt->data, 12);

    /* Initialize Broadcom header */
    brcm_hdr = &txbuf[12];
    CDK_MEMSET(brcm_hdr, 0, ROBO_BRCM_HDR_SIZE);

    /* Add Broadcom ROBO type ID */
    brcm_hdr[0] = (ROBO_DEFAULT_BRCMID >> 8);
    brcm_hdr[1] = (ROBO_DEFAULT_BRCMID & 0xff);

    /* Create Broadcom tag */
    if (pkt->port >= 0) {
        brcm_hdr[2] = 0x62;
        if (pkt->port == CPIC_PORT) {
            brcm_hdr[4] = 0x01;
        } else {
            if (pkt->flags & BMD_PKT_F_UNTAGGED) {
                brcm_hdr[2] = 0x61;
            }
            brcm_hdr[5] = 1 << pkt->port;
        }
    }

    /* Copy remainder of packet Tx buffer */
    CDK_MEMCPY(&txbuf[12 + ROBO_BRCM_HDR_SIZE], &pkt->data[12], pkt->size - 12);

    /* Add inner CRC based on original packet */
    crc = ~cdk_util_crc32(~0, pkt->data, pkt->size - 4);
    crcbuf = &txbuf[txsize - 4];
    *crcbuf++ = (uint8_t)(crc >> 24);
    *crcbuf++ = (uint8_t)(crc >> 16);
    *crcbuf++ = (uint8_t)(crc >> 8);
    *crcbuf++ = (uint8_t)(crc);

    CDK_VVERB(("Tx inner CRC   = %08"PRIx32"\n", crc));
    CDK_VVERB(("Tx BRCM header = %02x%02x %02x%02x%02x%02x\n",
               brcm_hdr[0], brcm_hdr[1], brcm_hdr[2], 
               brcm_hdr[3], brcm_hdr[4], brcm_hdr[5]));

    /* Pass buffer to Ethernet driver */
    rv = cdk_dev_write(unit, CDK_DEV_ADDR_ETH, txbuf, txsize);

    /* Free Tx buffer */
    bmd_dma_free_coherent(unit, txsize, txbuf, baddr);

    return rv;
#else
    return CDK_E_UNAVAIL;
#endif
}
#endif /* CDK_CONFIG_INCLUDE_BCM6300_A0 */
