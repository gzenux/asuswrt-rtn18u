#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53115_A0 == 1
/*
 * $Id: bcm53115_a0_bmd_port_pause_capability_set.c,v 1.2 Broadcom SDK $
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
#include <cdk/chip/bcm53115_a0_defs.h>
#include <cdk/cdk_device.h>
#include <bmd/bmd_phy_ctrl.h>
#if BMD_CONFIG_INCLUDE_PHY == 1
#include <phy/phy.h>
#endif

int 
bcm53115_a0_bmd_port_pause_capability_set(
    int unit, 
    int port, 
    bmd_pause_t value)
{
    int ioerr = 0, tx_pause_pmap, rx_pause_pmap, ana_cfg = 0;
    PAUSE_CAPr_t pause_cap;
#if BMD_CONFIG_INCLUDE_PHY == 1
    int phypbmp;
    phy_ctrl_t *pc;
    uint32_t ctrl, an_adv; 
#endif

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

#if BMD_CONFIG_INCLUDE_PHY == 1
    phypbmp = CDK_DEV_PHY_PBMP(unit);
    pc = BMD_PORT_PHY_CTRL(unit, port);
#endif

    ioerr += READ_PAUSE_CAPr(unit, &pause_cap);
    tx_pause_pmap = PAUSE_CAPr_TX_PAUSE_CAPf_GET(pause_cap);
    rx_pause_pmap = PAUSE_CAPr_RX_PAUSE_CAPf_GET(pause_cap);  

    /* resolve pause mode and advertisement. */ 
    /* Please refer to Table 28B-3 of the 802.3ab-1999 spec */
    switch (value) {
        case bmdPauseAuto:
        case bmdPauseBoth:
            ana_cfg = (MII_ANA_ASYM_PAUSE| MII_ANA_PAUSE);
            tx_pause_pmap |= (1 << port);
            rx_pause_pmap |= (1 << port);
            break;

        case bmdPauseTx:
            ana_cfg = (MII_ANA_ASYM_PAUSE);
            tx_pause_pmap |= (1 << port);
            rx_pause_pmap &= ~(1 << port);
            break;

        case bmdPauseRx:
            ana_cfg = (MII_ANA_PAUSE);
            tx_pause_pmap &= ~(1 << port);
            rx_pause_pmap |= (1 << port);
            break;

        case bmdPauseNone:
        default:
            tx_pause_pmap &= ~(1 << port);
            rx_pause_pmap &= ~(1 << port);
        break;
    }

#if BMD_CONFIG_INCLUDE_PHY == 1
    if ((phypbmp & (1 << port)) && (pc)) {
        ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
        if (ctrl & MII_CTRL_AE) {
            ioerr += PHY_BUS_READ(pc, MII_ANA_REG, &an_adv);
            an_adv &= ~(MII_ANA_ASYM_PAUSE| MII_ANA_PAUSE);
            an_adv |= ana_cfg;
            ioerr += PHY_BUS_WRITE(pc, MII_ANA_REG, an_adv);
            ioerr += PHY_AUTONEG_SET(pc, 1);
        } else {
            PAUSE_CAPr_EN_OVERRIDEf_SET(pause_cap, 1);
        }
    } else 
#endif
    if (tx_pause_pmap || rx_pause_pmap) {
        PAUSE_CAPr_EN_OVERRIDEf_SET(pause_cap, 1);
    }

    PAUSE_CAPr_TX_PAUSE_CAPf_SET(pause_cap, tx_pause_pmap);
    PAUSE_CAPr_RX_PAUSE_CAPf_SET(pause_cap, rx_pause_pmap);
    ioerr += WRITE_PAUSE_CAPr(unit, pause_cap);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}
#endif /* CDK_CONFIG_INCLUDE_BCM53115_A0 == 1 */
