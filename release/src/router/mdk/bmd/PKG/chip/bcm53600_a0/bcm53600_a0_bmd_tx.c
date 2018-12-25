#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53600_A0 == 1

/*
 * $Id: bcm53600_a0_bmd_tx.c,v 1.1 Broadcom SDK $
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

#include <cdk/cdk_device.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>
#include <cdk/cdk_util.h>

#include <cdk/chip/bcm53600_a0_defs.h>

#include "bcm53600_a0_internal.h"
#include "bcm53600_a0_bmd.h"

int
bcm53600_a0_bmd_tx(int unit, const bmd_pkt_t *pkt)
{
#if BMD_CONFIG_INCLUDE_DMA == 1
    int rv;
    int txsize;
    uint8_t *txbuf, *brcm_hdr;
    uint8_t temp_vlan[2];
    
    dma_addr_t baddr;

    BMD_CHECK_UNIT(unit);

    if (pkt->port > 28) {
        return CDK_E_PORT;
    }

    /* Allocate Tx buffer */
    /* txsize - 4 due to TB will remove vlan tag manually */
    /* There is no untag opcode */
    txsize = pkt->size + ROBO_BRCM_HDR_SIZE;
    txbuf = bmd_dma_alloc_coherent(unit, txsize - 4, &baddr);
    if (txbuf == NULL) {
        return CDK_E_MEMORY;
    }

    /* Initialize Broadcom header */
    brcm_hdr = &txbuf[0];
    CDK_MEMSET(brcm_hdr, 0, ROBO_BRCM_HDR_SIZE);

    /* Create Broadcom tag */
    if (pkt->port >= 0) {
        /* opcode = 0001, TC = 0000 */
        brcm_hdr[0] = 0x10;
        /* DP = 00, Filter_ByPass[7:2] = 111111 */
        brcm_hdr[1] = 0x3f;
        /* Filter_ByPass[1:0] = 11, R = 0, DST_ID[12:11] = 00, DST_ID[10:8] = 000 */
        brcm_hdr[2] = 0xc0;
        /* DST_ID[7:5] = 000, DST_ID[4:0] = port_id */
        brcm_hdr[3] = pkt->port;
        /* R = 01000000, 1 = DoNotModify bit for EVM */
        brcm_hdr[4] = 0x40;
        /* VLAN_ID[11:0], Flow_ID[11:8] = 0 */
        if (pkt->flags & BMD_PKT_F_UNTAGGED) {
            /* set vid to default vlan 1 */
            brcm_hdr[5] = 0;
            brcm_hdr[6] = 0x10;
        } else {
            temp_vlan[0] = pkt->data[14];
            temp_vlan[1] = pkt->data[15];
            brcm_hdr[5] = ((temp_vlan[0] << 4) & 0xf0) | ((temp_vlan[1] >> 4) & 0x0f);
            brcm_hdr[6] = (temp_vlan[1] << 4) & 0xf0;
        }
        /* Flow_ID[7:0] = 0 */
        brcm_hdr[7] = 0;
    }
    CDK_VVERB(("Tx BRCM header = %02x%02x %02x%02x %02x%02x %02x%02x\n",
               brcm_hdr[0], brcm_hdr[1], brcm_hdr[2], brcm_hdr[3],  
               brcm_hdr[4], brcm_hdr[5], brcm_hdr[6], brcm_hdr[7]));

    /* Copy packet to Tx buffer, starting address is following brcm header */
    CDK_MEMCPY(&txbuf[ROBO_BRCM_HDR_SIZE], pkt->data, 12);

    /* Copy remainder of packet Tx buffer */
    /* TB need to manual remove vlan-tag from packet */
    CDK_MEMCPY(&txbuf[12 + ROBO_BRCM_HDR_SIZE], &pkt->data[16], pkt->size - 16);

    /* Pass buffer to Ethernet driver */
    rv = cdk_dev_write(unit, CDK_DEV_ADDR_ETH, txbuf, txsize - 8);
    /* Free Tx buffer */
    bmd_dma_free_coherent(unit, txsize, txbuf, baddr);
    return rv;
#else
    return CDK_E_UNAVAIL;
#endif
}
#endif /* CDK_CONFIG_INCLUDE_BCM53600_A0 */

