#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53010_A0 == 1

/*
 * $Id: bcm53010_a0_bmd_port_mode_set.c,v 1.3 Broadcom SDK $
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

#include <cdk/chip/bcm53010_a0_defs.h>
#include <cdk/arch/robo_chip.h>

#include "bcm53010_a0_bmd.h"
#include "bcm53010_a0_internal.h"

int
bcm53010_a0_bmd_port_mode_set(int unit, int port, 
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
    STS_OVERRIDE_GMIIPr_t sts_override_gp;
    STS_OVERRIDE_P5r_t sts_override_p5;
    STS_OVERRIDE_P7r_t sts_override_p7;
    STS_OVERRIDE_IMPr_t sts_override_imp;
    G_PCTLr_t g_pctl;
    P7_CTLr_t p7_ctl;
    IMP_CTLr_t imp_ctl;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    if ((port == CPIC_PORT) || (port == 7) || (port == 5)) {
        if (mode == bmdPortModeAuto) {
            return CDK_E_NONE;
        }
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
    case bmdPortMode2000fd:
	    if ((port == 5) || (port == 7) || (port == CPIC_PORT)) {
            sp_sel = SPDSTS_SPEED_2000;
        } else {
            return CDK_E_PARAM;
        }
        break;
    case bmdPortMode1000fd:
    case bmdPortMode1000hd:
    case bmdPortModeAuto:
        break;
    case bmdPortModeDisabled:
        break;
    default:
        return CDK_E_PARAM;
    }

    /* MAC loopback unsupported */
    if (mac_lb) {
        return CDK_E_PARAM;
    }

    /* PHY loopback unsupported on some ports */
    if (phy_lb) {
        if ((port == 5) || (port == 7) || (port == CPIC_PORT)) {
            return CDK_E_PARAM;
	    }
    }

    /* Update PHYs before MAC */
    if ((port != 5) && (port != 7) && (port != CPIC_PORT)) {
        if (CDK_SUCCESS(rv)) {
            rv = bmd_port_mode_to_phy(unit, port, mode, flags, speed, duplex);
        }
    }

    if (port == 5) {
        /* Configure the MAC */
        ioerr += READ_STS_OVERRIDE_P5r(unit, &sts_override_p5);
        STS_OVERRIDE_P5r_SW_OVERRIDEf_SET(sts_override_p5, 1);
        if (sp_sel == SPDSTS_SPEED_2000) {
            STS_OVERRIDE_P5r_SPEEDf_SET(sts_override_p5, SPDSTS_SPEED_1000);
            STS_OVERRIDE_P5r_GMII_SPEED_UP_2Gf_SET(sts_override_p5, 1);
        } else {
            STS_OVERRIDE_P5r_SPEEDf_SET(sts_override_p5, sp_sel);
            STS_OVERRIDE_P5r_GMII_SPEED_UP_2Gf_SET(sts_override_p5, 0);
        }
        STS_OVERRIDE_P5r_DUPLX_MODEf_SET(sts_override_p5, duplex);
        ioerr += WRITE_STS_OVERRIDE_P5r(unit, sts_override_p5);
    
        /* Get MAC state */
        ioerr += READ_G_PCTLr(unit, port, &g_pctl);
        mac_disabled = G_PCTLr_RX_DISf_GET(g_pctl);
        if (mode == bmdPortModeDisabled) {
            /* Disable MAC if enabled */
            if (!mac_disabled) {
                G_PCTLr_RX_DISf_SET(g_pctl, 1);
                G_PCTLr_TX_DISf_SET(g_pctl, 1);
                ioerr += WRITE_G_PCTLr(unit, port, g_pctl);
            }
            BMD_PORT_STATUS_CLR(unit, port, BMD_PST_LINK_UP);
            BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_LINK);
        } else {
            /* Enable MAC if disabled */
            if (mac_disabled) {
                G_PCTLr_RX_DISf_SET(g_pctl, 0);
                G_PCTLr_TX_DISf_SET(g_pctl, 0);
                ioerr += WRITE_G_PCTLr(unit, port, g_pctl);
            }
        }
    } else if (port == 7) {
        /* Configure the MAC */
        ioerr += READ_STS_OVERRIDE_P7r(unit, &sts_override_p7);
        STS_OVERRIDE_P7r_SW_OVERRIDEf_SET(sts_override_p7, 1);
        if (sp_sel == SPDSTS_SPEED_2000) {
            STS_OVERRIDE_P7r_SPEEDf_SET(sts_override_p7, SPDSTS_SPEED_1000);
            STS_OVERRIDE_P7r_GMII_SPEED_UP_2Gf_SET(sts_override_p7, 1);
        } else {
            STS_OVERRIDE_P7r_SPEEDf_SET(sts_override_p7, sp_sel);
            STS_OVERRIDE_P7r_GMII_SPEED_UP_2Gf_SET(sts_override_p7, 0);
        }
        STS_OVERRIDE_P7r_DUPLX_MODEf_SET(sts_override_p7, duplex);
        ioerr += WRITE_STS_OVERRIDE_P7r(unit, sts_override_p7);
    
        /* Get MAC state */
        ioerr += READ_P7_CTLr(unit, &p7_ctl);
        mac_disabled = P7_CTLr_RX_DISf_GET(p7_ctl);
        if (mode == bmdPortModeDisabled) {
            /* Disable MAC if enabled */
            if (!mac_disabled) {
                P7_CTLr_RX_DISf_SET(p7_ctl, 1);
                P7_CTLr_TX_DISf_SET(p7_ctl, 1);
                ioerr += WRITE_P7_CTLr(unit, p7_ctl);
            }
            BMD_PORT_STATUS_CLR(unit, port, BMD_PST_LINK_UP);
            BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_LINK);
        } else {
            /* Enable MAC if disabled */
            if (mac_disabled) {
                P7_CTLr_RX_DISf_SET(p7_ctl, 0);
                P7_CTLr_TX_DISf_SET(p7_ctl, 0);
                ioerr += WRITE_P7_CTLr(unit, p7_ctl);
            }
        }
    } else if (port == CPIC_PORT) {
        /* Configure the MAC */
        ioerr += READ_STS_OVERRIDE_IMPr(unit, &sts_override_imp);
		STS_OVERRIDE_IMPr_MII_SW_ORf_SET(sts_override_imp, 1);
        if (sp_sel == SPDSTS_SPEED_2000) {
			STS_OVERRIDE_IMPr_SPEEDf_SET(sts_override_imp, SPDSTS_SPEED_1000);  
			STS_OVERRIDE_IMPr_GMII_SPEED_UP_2Gf_SET(sts_override_imp, 1);	
        } else {
			STS_OVERRIDE_IMPr_SPEEDf_SET(sts_override_imp, sp_sel);  
			STS_OVERRIDE_IMPr_GMII_SPEED_UP_2Gf_SET(sts_override_imp, 0);	
        }
		STS_OVERRIDE_IMPr_DUPLX_MODEf_SET(sts_override_imp, duplex);
        ioerr += WRITE_STS_OVERRIDE_IMPr(unit, sts_override_imp);
    
        /* Get MAC state */
        ioerr += READ_IMP_CTLr(unit, &imp_ctl);
        mac_disabled = IMP_CTLr_RX_DISf_GET(imp_ctl);
        if (mode == bmdPortModeDisabled) {
            /* Disable MAC if enabled */
            if (!mac_disabled) {
                IMP_CTLr_RX_DISf_SET(imp_ctl, 1);
                IMP_CTLr_TX_DISf_SET(imp_ctl, 1);
                ioerr += WRITE_IMP_CTLr(unit, imp_ctl);
            }
            BMD_PORT_STATUS_CLR(unit, port, BMD_PST_LINK_UP);
            BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_LINK);
        } else {
            /* Enable MAC if disabled */
            if (mac_disabled) {
                IMP_CTLr_RX_DISf_SET(imp_ctl, 0);
                IMP_CTLr_TX_DISf_SET(imp_ctl, 0);
                ioerr += WRITE_IMP_CTLr(unit, imp_ctl);
            }
        }
    } else { /* Port 0~4 */
        /* Configure the MAC */
        ioerr += READ_STS_OVERRIDE_GMIIPr(unit, port, &sts_override_gp);
        STS_OVERRIDE_GMIIPr_SW_OVERRIDEf_SET(sts_override_gp, 1);
        STS_OVERRIDE_GMIIPr_SPEEDf_SET(sts_override_gp, sp_sel);
        STS_OVERRIDE_GMIIPr_DUPLX_MODEf_SET(sts_override_gp, duplex);
        ioerr += WRITE_STS_OVERRIDE_GMIIPr(unit, port, sts_override_gp);
    
        /* Get MAC state */
        ioerr += READ_G_PCTLr(unit, port, &g_pctl);
        mac_disabled = G_PCTLr_RX_DISf_GET(g_pctl);
        if (mode == bmdPortModeDisabled) {
            /* Disable MAC if enabled */
            if (!mac_disabled) {
                G_PCTLr_RX_DISf_SET(g_pctl, 1);
                G_PCTLr_TX_DISf_SET(g_pctl, 1);
                ioerr += WRITE_G_PCTLr(unit, port, g_pctl);
            }
            BMD_PORT_STATUS_CLR(unit, port, BMD_PST_LINK_UP);
            BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_LINK);
        } else {
            EEE_EN_CTRLr_t eee_en_ctrl;
            int eee_en;
            cdk_pbmp_t eee_en_pbmp;
            cdk_pbmp_t pbmp;
    
            CDK_ROBO_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPIC, &pbmp);
    		if (CDK_PBMP_MEMBER(pbmp, port)) {
                /* Configure EEE */
                ioerr += READ_EEE_EN_CTRLr(unit, &eee_en_ctrl);
                eee_en = EEE_EN_CTRLr_EN_EEEf_GET(eee_en_ctrl);
                CDK_PBMP_WORD_SET(eee_en_pbmp, 0, eee_en);
                CDK_PBMP_PORT_REMOVE(eee_en_pbmp, port);
                eee_en = CDK_PBMP_WORD_GET(eee_en_pbmp, 0);
                EEE_EN_CTRLr_EN_EEEf_SET(eee_en_ctrl, eee_en);
                ioerr += WRITE_EEE_EN_CTRLr(unit, eee_en_ctrl);
        
                if (flags & BMD_PORT_MODE_F_EEE) {
                    /* Enable IEEE 802.3az EEE */
                    CDK_PBMP_PORT_ADD(eee_en_pbmp, port);
                    eee_en = CDK_PBMP_WORD_GET(eee_en_pbmp, 0);
                    EEE_EN_CTRLr_EN_EEEf_SET(eee_en_ctrl, eee_en);
                    ioerr += WRITE_EEE_EN_CTRLr(unit, eee_en_ctrl);							
                }
            }

            /* Enable MAC if disabled */
            if (mac_disabled) {
                G_PCTLr_RX_DISf_SET(g_pctl, 0);
                G_PCTLr_TX_DISf_SET(g_pctl, 0);
                ioerr += WRITE_G_PCTLr(unit, port, g_pctl);
            }
            if (phy_lb) {
                BMD_PORT_STATUS_SET(unit, port, BMD_PST_LINK_UP | BMD_PST_FORCE_LINK);
            } else {
                BMD_PORT_STATUS_CLR(unit, port, BMD_PST_FORCE_LINK);
            }
        }
    }    

    if ((port != 5) && (port != 7) && (port != CPIC_PORT)) {
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_loopback_set(unit, port, phy_lb);
        }
    }
    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM53010_A0 */
