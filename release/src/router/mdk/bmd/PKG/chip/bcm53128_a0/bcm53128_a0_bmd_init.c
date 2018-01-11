#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53128_A0 == 1

/*
 * $Id: bcm53128_a0_bmd_init.c,v 1.6 Broadcom SDK $
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

#include <cdk/chip/bcm53128_a0_defs.h>
#include <cdk/arch/robo_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm53128_a0_bmd.h"
#include "bcm53128_a0_internal.h"

static int
_gpic_init(int unit, int port)
{
    int ioerr = 0;
    G_PCTLr_t g_pctl;
    STS_OVERRIDE_GMIIPr_t sts_override_gp;

    /* Clear link status */
    ioerr += READ_STS_OVERRIDE_GMIIPr(unit, port, &sts_override_gp);
    STS_OVERRIDE_GMIIPr_LINK_STSf_SET(sts_override_gp, 0);
    ioerr += WRITE_STS_OVERRIDE_GMIIPr(unit, port, sts_override_gp);

    /* Set forwarding state */
    ioerr += READ_G_PCTLr(unit, port, &g_pctl);
    G_PCTLr_G_MISTP_STATEf_SET(g_pctl, 5);
    /* change back from 8051 to re-write RX-discard */
    G_PCTLr_RX_DISf_SET(g_pctl, 0);
    ioerr += WRITE_G_PCTLr(unit, port, g_pctl);

    return ioerr;
}

int
bcm53128_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    VLAN_CTRL0r_t vlan_ctrl0;
    VLAN_CTRL4r_t vlan_ctrl4;
    MST_CONr_t mst_con;
    LED_FUNC1_CTLr_t led_func1_ctl;
    SWMODEr_t swmode;
    GMNGCFGr_t gmngcfg;
    BRCM_HDR_CTRLr_t hdrctrl;
    STS_OVERRIDE_IMPr_t stsoviimp;
    IMP_CTLr_t impstl;
    STRAP_PIN_STATUSr_t strap_value;
    IMP_RGMII_CTL_GPr_t imp_rgmii_ctl; 
    PORT7_RGMII_CTL_GPr_t p7_rgmii_ctl;
    
    int port;
    cdk_pbmp_t pbmp;
    uint32_t rgmii, imp1_rgmii;

    BMD_CHECK_UNIT(unit);

    /* Enable VLANs */
    ioerr += READ_VLAN_CTRL0r(unit, &vlan_ctrl0);
    VLAN_CTRL0r_VLAN_ENf_SET(vlan_ctrl0, 1);
    ioerr += WRITE_VLAN_CTRL0r(unit, vlan_ctrl0);

    /* Drop packet if VLAN mismatch */
    ioerr += READ_VLAN_CTRL4r(unit, &vlan_ctrl4);
    VLAN_CTRL4r_INGR_VID_CHKf_SET(vlan_ctrl4, 1);
    ioerr += WRITE_VLAN_CTRL4r(unit, vlan_ctrl4);

    /* Enable spanning tree */
    ioerr += READ_MST_CONr(unit, &mst_con);
    MST_CONr_EN_802_1Sf_SET(mst_con, 1);
    ioerr += WRITE_MST_CONr(unit, mst_con);

    /* Configure LEDs */
    LED_FUNC1_CTLr_SET(led_func1_ctl, 0x4320);
    ioerr += WRITE_LED_FUNC1_CTLr(unit, led_func1_ctl);

    /* Configure GPICs */
    CDK_ROBO_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPIC, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _gpic_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }
    /* Enable management port */
    ioerr += READ_GMNGCFGr(unit, &gmngcfg);
    GMNGCFGr_FRM_MNGPf_SET(gmngcfg, 2);
    ioerr += WRITE_GMNGCFGr(unit, gmngcfg);

    /* Enable frame forwarding */
    ioerr += READ_SWMODEr(unit, &swmode);
    SWMODEr_SW_FWDG_MODEf_SET(swmode, 1);
    SWMODEr_SW_FWDG_ENf_SET(swmode, 1);
    ioerr += WRITE_SWMODEr(unit, swmode);

    /* force enabling the BRCM header tag */
    ioerr += READ_BRCM_HDR_CTRLr(unit, &hdrctrl);
    BRCM_HDR_CTRLr_BRCM_HDR_ENf_SET(hdrctrl, 1);
    ioerr += WRITE_BRCM_HDR_CTRLr(unit, hdrctrl);

    ioerr += READ_STRAP_PIN_STATUSr(unit, &strap_value);
    /* check if IMP0 is RGMII mode */
    /* Check IMP status */
    rgmii = 0;
    if (STRAP_PIN_STATUSr_IMP_MODEf_GET(strap_value) == 0) {
        rgmii = 1;
    }
    /* Check IMP1 status */
    imp1_rgmii = 0;
    if (STRAP_PIN_STATUSr_GMII_MODEf_GET(strap_value) == 0) {
        imp1_rgmii = 1;
    }

    if (rgmii) {
        /* Enable RGMII tx/rx clock delay mode */
        ioerr += READ_IMP_RGMII_CTL_GPr(unit, &imp_rgmii_ctl);
        IMP_RGMII_CTL_GPr_EN_IMP_RGMII_DLL_RXCf_SET(imp_rgmii_ctl, 1); 
        IMP_RGMII_CTL_GPr_EN_IMP_RGMII_DLL_TXCf_SET(imp_rgmii_ctl, 1); 
        ioerr += WRITE_IMP_RGMII_CTL_GPr(unit, imp_rgmii_ctl);
    }

    if (imp1_rgmii) {
        /* Enable RGMII tx/rx clock delay mode */
        ioerr += READ_PORT7_RGMII_CTL_GPr(unit, &p7_rgmii_ctl);
        PORT7_RGMII_CTL_GPr_EN_RGMII_DLL_RXCf_SET(p7_rgmii_ctl, 1);
        PORT7_RGMII_CTL_GPr_EN_RGMII_DLL_TXCf_SET(p7_rgmii_ctl, 1);
        ioerr += WRITE_PORT7_RGMII_CTL_GPr(unit, p7_rgmii_ctl);
    }
    
    /* force enabling the BRCM header tag */
    ioerr += READ_STS_OVERRIDE_IMPr(unit, &stsoviimp);
    STS_OVERRIDE_IMPr_MII_SW_ORf_SET(stsoviimp, 1);
    STS_OVERRIDE_IMPr_DUPLX_MODEf_SET(stsoviimp, 1);
    STS_OVERRIDE_IMPr_LINK_STSf_SET(stsoviimp, 1);  
    if (rgmii) {
        /* Speed 1000MB */
        STS_OVERRIDE_IMPr_SPEEDf_SET(stsoviimp, 2);  
    } else {
        STS_OVERRIDE_IMPr_SPEEDf_SET(stsoviimp, 0);  
    }          
    ioerr += WRITE_STS_OVERRIDE_IMPr(unit, stsoviimp);

    /* force enabling the BRCM header tag */
    ioerr += READ_IMP_CTLr(unit, &impstl);
    IMP_CTLr_RX_UCST_ENf_SET(impstl, 1);
    IMP_CTLr_RX_MCST_ENf_SET(impstl, 1);
    IMP_CTLr_RX_BCST_ENf_SET(impstl, 1);
    /* back from 8051, need to disable tx/rx discard */
    IMP_CTLr_RX_DISf_SET(impstl, 0);
    IMP_CTLr_TX_DISf_SET(impstl, 0);
    ioerr += WRITE_IMP_CTLr(unit, impstl);

    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM53128_A0 */
