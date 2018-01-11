/*
 * $Id: bmd_port_mode_from_phy.c,v 1.13 Broadcom SDK $
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
#include <bmd/bmd_device.h>

#include <bmdi/bmd_port_mode.h>

#include <cdk/cdk_assert.h>

/*
 * Function:
 *	bmd_port_mode_from_phy
 * Purpose:
 *	Determine BMD port mode based on PHY status/configuration.
 * Parameters:
 *	unit - BMD device
 *	port - port number
 *	mode - (OUT) BMD port mode
 *	flags - (OUT) BMD port mode flags
 * Returns:
 *      CDK_XXX
 * Notes:
 *      This is a helper function for the bmd_port_mode_get API.
 *      The flags parameter is assumed to have been initialized
 *      by the caller.
 */
int
bmd_port_mode_from_phy(int unit, int port,
                       bmd_port_mode_t *mode, uint32_t *flags)
{
    int rv = CDK_E_NONE;
    int an, lb, duplex, eee_mode;
    uint32_t speed;

    rv += bmd_phy_loopback_get(unit, port, &lb);
    if (CDK_SUCCESS(rv) && lb) {
        *flags |= BMD_PORT_MODE_F_PHY_LOOPBACK;
    }

    rv += bmd_phy_remote_loopback_get(unit, port, &lb);
    if (CDK_SUCCESS(rv) && lb) {
        *flags |= BMD_PORT_MODE_F_REMOTE_LOOPBACK;
    }

    rv += bmd_phy_autoneg_get(unit, port, &an);
    if (CDK_SUCCESS(rv) && an) {
        *flags |= BMD_PORT_MODE_F_AUTONEG;
    }

    rv += bmd_phy_speed_get(unit, port, &speed);
    if (CDK_SUCCESS(rv)) {
        if (an && (BMD_PORT_STATUS(unit, port) & BMD_PST_LINK_UP) == 0) {
            speed = 0;
        }
        rv += bmd_phy_duplex_get(unit, port, &duplex);
        if (CDK_SUCCESS(rv)) {
            rv += bmd_port_mode_from_speed_duplex(speed, duplex, mode);
        }
    }

    rv += bmd_phy_eee_get(unit, port, &eee_mode);
    if (CDK_SUCCESS(rv)) {
        if (eee_mode == BMD_PHY_M_EEE_AUTO) {
            *flags |= BMD_PORT_MODE_F_AUTOGREEEN;
        } else if (eee_mode == BMD_PHY_M_EEE_802_3) {
            *flags |= BMD_PORT_MODE_F_EEE;
        }
    }

    return rv;
}
