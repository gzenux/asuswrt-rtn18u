/*
 * $Id: ge_phy_adv_local_get.c,v 1.2 Broadcom SDK $
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
 *      ge_phy_adv_local_get
 * Purpose:     
 *      Set the advertised speed capabilities
 * Parameters:
 *      pc - PHY control structure
 *      *abil - abilities advertised
 * Returns:     
 *      CDK_E_xxx
 */
int 
ge_phy_adv_local_get(phy_ctrl_t *pc, uint32_t *abil)
{
    int ioerr = 0;
    uint32_t ctrl, adv;

    *abil = 0;

    /* 
     * Get advertised Gigabit capabilities.
     */
    ioerr += PHY_BUS_READ(pc, MII_GB_CTRL_REG, &ctrl);

    if (ctrl & MII_GB_CTRL_ADV_1000HD) *abil |= PHY_ABIL_1000MB_HD;
    if (ctrl & MII_GB_CTRL_ADV_1000FD) *abil |= PHY_ABIL_1000MB_FD;

    ioerr += PHY_BUS_READ(pc, MII_ANA_REG, &adv);

    /*
     * Get advertised 10/100 capabilities.
     */

    if (adv & MII_ANA_HD_10)  *abil |= PHY_ABIL_10MB_HD;
    if (adv & MII_ANA_FD_10)  *abil |= PHY_ABIL_10MB_FD;
    if (adv & MII_ANA_HD_100) *abil |= PHY_ABIL_100MB_HD;
    if (adv & MII_ANA_FD_100) *abil |= PHY_ABIL_100MB_FD;

    switch (adv & (MII_ANA_PAUSE | MII_ANA_ASYM_PAUSE)) {
        case MII_ANA_PAUSE:
            *abil |= PHY_ABIL_PAUSE_TX | PHY_ABIL_PAUSE_RX;
            break;
        case MII_ANA_ASYM_PAUSE:
            *abil |= PHY_ABIL_PAUSE_TX;
            break;
        case MII_ANA_PAUSE | MII_ANA_ASYM_PAUSE:
            *abil |= PHY_ABIL_PAUSE_RX;
            break;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

