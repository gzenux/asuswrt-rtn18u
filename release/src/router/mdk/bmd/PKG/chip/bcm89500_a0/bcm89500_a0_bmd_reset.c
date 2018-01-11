#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM89500_A0 == 1

/*
 * $Id: bcm89500_a0_bmd_reset.c,v 1.7 Broadcom SDK $
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

#include <cdk/chip/bcm89500_a0_defs.h>
#include <cdk/cdk_debug.h>

#include "bcm89500_a0_bmd.h"
#include "bcm89500_a0_internal.h"

#define ROBO_SW_RESET_POLL_MAX  100000

int
bcm89500_a0_max_port(int unit)
{
    int bond_pad;
    int max_port = 0;
    BONDING_PAD_STATUSr_t bonding_pad;

    /*
     * 0: RGMIIMII/RvMII through mii3_mode (4 BR-PHY + 3 MII)
     * 1: BR/TX100 PHY. (5 BR-PHY + 2 MII)
     * 2: BR/TX100 PHY and one BR-PHY (2 BR-PHY + 2 MII)
     * 3: Unused
     */
    READ_BONDING_PAD_STATUSr(unit, &bonding_pad);
    bond_pad = BONDING_PAD_STATUSr_BOND_PADf_GET(bonding_pad);
    switch (bond_pad) {
    case 0:
        /* bcm89500, br phy port max to port 3 (start from 0) */
        max_port = 3;
        break;
    case 1:
        /* bcm89501, br phy port max to port 4 (start from 0) */
        max_port = 4;
        break;
    case 2:
        /* bcm89200, br phy port 0, 4 */
        max_port = 4;
        break;
    default:
        return CDK_E_PARAM;
    }
    return max_port;    
}

int
bcm89500_a0_bmd_reset(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    uint32_t cnt;
    uint32_t model;
    WATCH_DOG_CTRLr_t wd_ctrl;
    MODEL_IDr_t model_id;

    BMD_CHECK_UNIT(unit);

    WATCH_DOG_CTRLr_CLR(wd_ctrl);
    WATCH_DOG_CTRLr_EN_SW_RESETf_SET(wd_ctrl, 1);
    WATCH_DOG_CTRLr_SOFTWARE_RESETf_SET(wd_ctrl, 1);
    ioerr += WRITE_WATCH_DOG_CTRLr(unit, wd_ctrl);

    /* Wait for chip reset complete */
    for (cnt = 0; cnt < ROBO_SW_RESET_POLL_MAX; cnt++) {
        ioerr += READ_WATCH_DOG_CTRLr(unit, &wd_ctrl);
        if (ioerr) {
            break;
        } 
        if (WATCH_DOG_CTRLr_SOFTWARE_RESETf_GET(wd_ctrl) == 0) {
            /* Reset is complete */
            break;
        }
    }
    if (cnt >= ROBO_SW_RESET_POLL_MAX) {
        rv = CDK_E_TIMEOUT;
    } else {
        /* Wait for internal CPU to boot up completely */
        do {
            ioerr += READ_MODEL_IDr(unit, &model_id);
            model = MODEL_IDr_GET(model_id);
            model &= 0xffff0;
        } while (model != 0x89500);
    }

    return ioerr ? CDK_E_IO : rv;
}


#endif /* CDK_CONFIG_INCLUDE_BCM89500_A0 */
