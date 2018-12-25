/*
 * $Id: bmd_port_mode_to_phy.c,v 1.5 Broadcom SDK $
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
 *	bmd_port_mode_to_phy
 * Purpose:
 *	Apply PHY settings according to BMD port mode and flags.
 * Parameters:
 *	unit - BMD device
 *	port - port number
 *	mode - BMD port mode
 *	flags - BMD port mode flags
 *	speed - speed resolved from BMD port mode
 *	duplex - duplex resolved from BMD port mode
 * Returns:
 *      CDK_XXX
 * Notes:
 *      This is a helper function for the bmd_port_mode_set API.
 *      The speed and duplex parameters are provided since they
 *      usually have been derived by the bmd_port_mode_set API
 *      prior to calling this function.
 */
int
bmd_port_mode_to_phy(int unit, int port, bmd_port_mode_t mode,
                     uint32_t flags, uint32_t speed, int duplex)
{
    int rv = CDK_E_NONE;
    int phy_lb = (flags & BMD_PORT_MODE_F_PHY_LOOPBACK) ? 1 : 0;
    int rem_lb = (flags & BMD_PORT_MODE_F_REMOTE_LOOPBACK) ? 1 : 0;
    int autoneg = (mode == bmdPortModeAuto) ? 1 : 0;

    if ((flags & BMD_PORT_MODE_F_INTERNAL) == 0) {

        /* Force a link change event */
        BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_UPDATE);

        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_autoneg_set(unit, port, autoneg);
        }
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_loopback_set(unit, port, phy_lb);
        }
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_remote_loopback_set(unit, port, rem_lb);
        }
        if (CDK_SUCCESS(rv)) {
            int eee_mode = BMD_PHY_M_EEE_OFF;
            if (flags & BMD_PORT_MODE_F_AUTOGREEEN) {
                /* Enable AutoGrEEEn mode */
                eee_mode = BMD_PHY_M_EEE_AUTO;
            } else if (flags & BMD_PORT_MODE_F_EEE) {
                /* Enable native EEE mode */
                eee_mode = BMD_PHY_M_EEE_802_3;
            }
            rv = bmd_phy_eee_set(unit, port, eee_mode);
        }
    }
    /* Read from PHY in case autoneg is not supported */
    if (CDK_SUCCESS(rv) && autoneg) {
        rv = bmd_phy_autoneg_get(unit, port, &autoneg);
    }
    if (!autoneg) {
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_speed_set(unit, port, speed);
        }
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_duplex_set(unit, port, duplex);
        }
    }

    return rv;
}
