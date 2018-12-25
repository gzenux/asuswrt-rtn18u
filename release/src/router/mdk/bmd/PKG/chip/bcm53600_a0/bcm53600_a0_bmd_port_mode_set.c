#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53600_A0 == 1

/*
 * $Id: bcm53600_a0_bmd_port_mode_set.c,v 1.1 Broadcom SDK $
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

#include <cdk/chip/bcm53600_a0_defs.h>
#include <cdk/arch/robo_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm53600_a0_bmd.h"
#include "bcm53600_a0_internal.h"

#define CDK_ROBO_FLAGS(unit) (CDK_ROBO_INFO(unit)->flags)

int
bcm53600_a0_bmd_port_mode_set(int unit, int port, 
                              bmd_port_mode_t mode, uint32_t flags)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int mac_lb = (flags & BMD_PORT_MODE_F_MAC_LOOPBACK) ? 1 : 0;
    int phy_lb = (flags & BMD_PORT_MODE_F_PHY_LOOPBACK) ? 1 : 0;
    int duplex = 1;
    int speed = 1000;
    int sp_sel = SPDSTS_SPEED_1000;
    int mac_disabled;
    STS_OVERRIDE_Pr_t sts_override_p;
    STS_OVERRIDE_GPr_t sts_override_gp;
    G_PCTLr_t g_pctl;
    TH_PCTLr_t th_pctl;
    
    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    if (port == CPIC_PORT) {
        return (mode == bmdPortModeAuto) ? CDK_E_NONE : CDK_E_PARAM;
    }

    switch (mode) {
    case bmdPortMode10hd:
    case bmdPortMode100hd:
    case bmdPortMode1000hd:
        duplex = 0;
        break;
    default:
        break;
    }
    switch (mode) {
    case bmdPortMode10fd:
    case bmdPortMode10hd:
        speed = 10;
        sp_sel = SPDSTS_SPEED_10;
        break;
    case bmdPortMode100fd:
    case bmdPortMode100hd:
        speed = 100;
        sp_sel = SPDSTS_SPEED_100;
        break;
    case bmdPortMode1000fd:
    case bmdPortMode1000hd:
        if (BMD_PORT_PROPERTIES(unit, port) == BMD_PORT_FE) {
            return CDK_E_PARAM;
        }
        break;
    case bmdPortModeAuto:
    case bmdPortModeDisabled:
        break;
    default:
        return CDK_E_PARAM;
    }

    /* MAC loopback unsupported */
    if (mac_lb) {
        return CDK_E_PARAM;
    }
   
    /* Update PHYs before MAC */
    if (CDK_SUCCESS(rv)) {
        rv = bmd_port_mode_to_phy(unit, port, mode, flags, speed, duplex);
    }

    /* Configure the MAC */
    if (BMD_PORT_PROPERTIES(unit, port) == BMD_PORT_FE) {
        ioerr += READ_STS_OVERRIDE_Pr(unit, port, &sts_override_p);
        STS_OVERRIDE_Pr_SW_OVERRIDEf_SET(sts_override_p, 1);
        STS_OVERRIDE_Pr_SPEEDf_SET(sts_override_p, sp_sel);
        STS_OVERRIDE_Pr_DUPLX_MODEf_SET(sts_override_p, duplex);
        ioerr += WRITE_STS_OVERRIDE_Pr(unit, port, sts_override_p);
    } else {
        ioerr += READ_STS_OVERRIDE_GPr(unit, port, &sts_override_gp);
        STS_OVERRIDE_GPr_SW_OVERRIDEf_SET(sts_override_gp, 1);
        STS_OVERRIDE_GPr_SPEEDf_SET(sts_override_gp, sp_sel);
        STS_OVERRIDE_GPr_DUPLX_MODEf_SET(sts_override_gp, duplex);
        ioerr += WRITE_STS_OVERRIDE_GPr(unit, port, sts_override_gp);
    }

    /* Get MAC state */
    if (BMD_PORT_PROPERTIES(unit, port) == BMD_PORT_FE) {
        ioerr += READ_TH_PCTLr(unit, port, &th_pctl);
        mac_disabled = TH_PCTLr_RX_DISf_GET(th_pctl);
    } else {    
        ioerr += READ_G_PCTLr(unit, port, &g_pctl);
        mac_disabled = G_PCTLr_RX_DISf_GET(g_pctl);
    }
    
    if (mode == bmdPortModeDisabled) {
        /* Disable MAC if enabled */
        if (!mac_disabled) {
            if (BMD_PORT_PROPERTIES(unit, port) == BMD_PORT_FE) {
                TH_PCTLr_RX_DISf_SET(th_pctl, 1);
                TH_PCTLr_TX_DISf_SET(th_pctl, 1);
                ioerr += WRITE_TH_PCTLr(unit, port, th_pctl);
            } else { 
                G_PCTLr_RX_DISf_SET(g_pctl, 1);
                G_PCTLr_TX_DISf_SET(g_pctl, 1);
                ioerr += WRITE_G_PCTLr(unit, port, g_pctl);
            }
        }
        BMD_PORT_STATUS_CLR(unit, port, BMD_PST_LINK_UP);
        BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_LINK);
    } else {
        /* Enable MAC if disabled */
        if (mac_disabled) {
            if (BMD_PORT_PROPERTIES(unit, port) == BMD_PORT_FE) {
                TH_PCTLr_RX_DISf_SET(th_pctl, 0);
                TH_PCTLr_TX_DISf_SET(th_pctl, 0);
                ioerr += WRITE_TH_PCTLr(unit, port, th_pctl);
            } else {
                G_PCTLr_RX_DISf_SET(g_pctl, 0);
                G_PCTLr_TX_DISf_SET(g_pctl, 0);
                ioerr += WRITE_G_PCTLr(unit, port, g_pctl);
            }
        }
        
        /* Update link status */
        if (phy_lb) {
            BMD_PORT_STATUS_SET(unit, port, BMD_PST_LINK_UP | BMD_PST_FORCE_LINK);
        } else {
            BMD_PORT_STATUS_CLR(unit, port, BMD_PST_FORCE_LINK);
        }
    }

    /* Force a link change event */
    BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_UPDATE);

    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM53600_A0 */
