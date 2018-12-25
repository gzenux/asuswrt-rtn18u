/*
 * $Id: ge_phy_speed_get.c,v 1.6 Broadcom SDK $
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
 *      phy_speed_get
 * Purpose:     
 *      Get the current operating speed. If autoneg is enabled, then
 *      operating mode is returned, otherwise forced mode is returned.
 * Parameters:
 *      pc - PHY control structure
 *      speed - (OUT) current link speed
 * Returns:     
 *      CDK_E_xxx
 * Notes: 
 *      Returns a speed of 0 if autonegotiation is not complete.
 */
int
ge_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int ioerr = 0;
    uint32_t ctrl, stat, misc;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
    ioerr += PHY_BUS_READ(pc, MII_STAT_REG, &stat);

    if (ioerr) {
        return CDK_E_IO;
    }

    if (ctrl & MII_CTRL_AE) {
        /* Auto-negotiation enabled */
        if (!(stat & MII_STAT_AN_DONE)) {
            /* Auto-neg NOT complete */
            *speed = 0;
            return CDK_E_NONE;
        }

        ioerr += ge_phy_autoneg_gcd(pc, speed, NULL);
        if (*speed == 1000) {

            // check if ethernet@wirespeed is enabled, reg 0x18, shodow 0b'111, bit4
            ioerr += PHY_BUS_WRITE(pc, 0x18, 0x7007);
            ioerr += PHY_BUS_READ(pc, 0x18, &misc);
            if(misc & 0x0010) {

                // get link speed from ASR if ethernet@wirespeed is enabled
                ioerr += PHY_BUS_READ(pc, 0x19, &ctrl);
#define MII_ASR_1000(r) (((r & 0x0700) == 0x0700) || ((r & 0x0700) == 0x0600))
#define MII_ASR_100(r)  (((r & 0x0700) == 0x0500) || ((r & 0x0700) == 0x0300))
#define MII_ASR_10(r)   (((r & 0x0700) == 0x0200) || ((r & 0x0700) == 0x0100))

                if (MII_ASR_100(ctrl))
                    *speed = 100;
                else if (MII_ASR_10(ctrl))
                    *speed=10;
            }
        }
        if (ioerr) {
            return CDK_E_IO;
        }
        
    } else {
        /* 
         * Auto-negotiation disabled.
         * Simply pick up the values we force in CTRL register.
         */
        switch (MII_CTRL_SS(ctrl)) {
        case MII_CTRL_SS_10:
            *speed = 10;
            break;
        case MII_CTRL_SS_100:
            *speed = 100;
            break;
        case MII_CTRL_SS_1000:
            *speed = 1000;
            break;
        default:
            return CDK_E_UNAVAIL;
        }
    }

    return CDK_E_NONE;
}
