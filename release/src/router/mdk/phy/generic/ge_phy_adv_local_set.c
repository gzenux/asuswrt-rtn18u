/*
 * $Id: ge_phy_adv_local_set.c,v 1.1 Broadcom SDK $
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
 * Generic PHY driver.
 *
 */

#include <phy/phy.h>
#include <phy/ge_phy.h>

/*
 * Function:    
 *      ge_phy_adv_local_set
 * Purpose:     
 *      Set the advertised speed capabilities
 * Parameters:
 *      pc - PHY control structure
 *      abil - abilities to be advertised
 * Returns:     
 *      CDK_E_xxx
 */
int 
ge_phy_adv_local_set(phy_ctrl_t *pc, uint32_t abil)
{
    int ioerr = 0;
    uint32_t ctrl, adv;

    /* 
     * Set advertised Gigabit capabilities.
     */
    ioerr += PHY_BUS_READ(pc, MII_GB_CTRL_REG, &ctrl);

    ctrl &= ~(MII_GB_CTRL_ADV_1000HD | MII_GB_CTRL_ADV_1000FD);
    if (abil & PHY_ABIL_1000MB_HD) ctrl |= MII_GB_CTRL_ADV_1000HD;
    if (abil & PHY_ABIL_1000MB_FD) ctrl |= MII_GB_CTRL_ADV_1000FD;

    ioerr += PHY_BUS_WRITE(pc, MII_GB_CTRL_REG, ctrl);

    /*
     * Set advertised 10/100 capabilities.
     */
    adv = MII_ANA_ASF_802_3;
    if (abil & PHY_ABIL_10MB_HD)  adv |= MII_ANA_HD_10;
    if (abil & PHY_ABIL_10MB_FD)  adv |= MII_ANA_FD_10;
    if (abil & PHY_ABIL_100MB_HD) adv |= MII_ANA_HD_100;
    if (abil & PHY_ABIL_100MB_FD) adv |= MII_ANA_FD_100;

    if ((abil & PHY_ABIL_PAUSE) == PHY_ABIL_PAUSE) {
        /* Advertise symmetric pause */
        adv |= MII_ANA_PAUSE;
    } else {
        /*
         * For Asymmetric pause, 
         *   if (Bit 10)
         *       then pause frames flow toward the transceiver
         *       else pause frames flow toward link partner.
         */
        if (abil & PHY_ABIL_PAUSE_TX) {
            adv |= MII_ANA_ASYM_PAUSE;
        } else if (abil & PHY_ABIL_PAUSE_RX) {
            adv |= MII_ANA_ASYM_PAUSE;
            adv |= MII_ANA_PAUSE;
        }
    }

    ioerr += PHY_BUS_WRITE(pc, MII_ANA_REG, adv);

    /* Restart auto-neg if enabled */

    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);

    if (ctrl & MII_CTRL_AE) {
        ctrl |= MII_CTRL_RAN;
        ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

