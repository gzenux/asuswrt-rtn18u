#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53084_A0 == 1

/*
 * $Id: bcm53084_a0_bmd_init.c,v 1.10 Broadcom SDK $
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

#include <cdk/chip/bcm53084_a0_defs.h>
#include <cdk/arch/robo_chip.h>
#include <cdk/cdk_debug.h>
#include <cdk/cdk_device.h>

#include "bcm53084_a0_bmd.h"
#include "bcm53084_a0_internal.h"

static int
_gpic_init(int unit, int port)
{
    int ioerr = 0;
    G_PCTLr_t g_pctl;
    STS_OVERRIDE_GMIIPr_t sts_override_gp;
    P5_CTLr_t p5_ctl;
    STS_OVERRIDE_P5r_t stsovip5;

    if (port == 5) {
        /* Clear link status */
        ioerr += READ_STS_OVERRIDE_P5r(unit, &stsovip5);
        STS_OVERRIDE_P5r_LINK_STSf_SET(stsovip5, 0);
        STS_OVERRIDE_P5r_TXFLOW_CNTLf_SET(stsovip5, 0);
        STS_OVERRIDE_P5r_RXFLOW_CNTLf_SET(stsovip5, 0);
        ioerr += WRITE_STS_OVERRIDE_P5r(unit, stsovip5);

        /* Set forwarding state */
        ioerr += READ_P5_CTLr(unit, &p5_ctl);
        P5_CTLr_G_MISTP_STATEf_SET(p5_ctl, 5);
        ioerr += WRITE_P5_CTLr(unit, p5_ctl);
    } else {
        /* Clear link status */
        ioerr += READ_STS_OVERRIDE_GMIIPr(unit, port, &sts_override_gp);
        STS_OVERRIDE_GMIIPr_LINK_STSf_SET(sts_override_gp, 0);
        STS_OVERRIDE_GMIIPr_TXFLOW_CNTLf_SET(sts_override_gp, 0);
        STS_OVERRIDE_GMIIPr_RXFLOW_CNTLf_SET(sts_override_gp, 0);
        ioerr += WRITE_STS_OVERRIDE_GMIIPr(unit, port, sts_override_gp);

        /* Set forwarding state */
        ioerr += READ_G_PCTLr(unit, port, &g_pctl);
        G_PCTLr_G_MISTP_STATEf_SET(g_pctl, 5);
        ioerr += WRITE_G_PCTLr(unit, port, g_pctl);
    }

    return ioerr;
}

int 
bcm53084_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    VLAN_CTRL0r_t vlan_ctrl0;
    VLAN_CTRL4r_t vlan_ctrl4;
    MST_CONr_t mst_con;
    SWMODEr_t swmode;
    GMNGCFGr_t gmngcfg;
    BRCM_HDR_CTRLr_t hdrctrl;
    STS_OVERRIDE_IMPr_t stsoviimp;
    IMP_CTLr_t impctl;
    PORT5_RGMII_CTL_GPr_t port5_rgmii_ctl;
    STS_OVERRIDE_P5r_t stsovip5;
	LED_FUNC1_CTLr_t led_func1_ctl;
    STRAP_PIN_STATUSr_t strap_value;
    MACSEC_GLOBAL_CTRLr_t macsec_global_ctrl;
    int port;
    cdk_pbmp_t pbmp;
    uint32_t rgmii = 0;
    
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

    /* Enable MACSEC Bypass bit by default */
    /* MACSEC driver will handle this bit: clear it if BMACSEC_SUPPORT */
    ioerr += READ_MACSEC_GLOBAL_CTRLr(unit, &macsec_global_ctrl);
    MACSEC_GLOBAL_CTRLr_MACSEC_BYPASS_ENf_SET(macsec_global_ctrl, 1);
    ioerr += WRITE_MACSEC_GLOBAL_CTRLr(unit, macsec_global_ctrl);

    /* Configure GPICs */
    CDK_ROBO_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPIC, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _gpic_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            /* port 5 don't have GPHY */
            if (port != 5) {
                rv = bmd_phy_attach(unit, port);
            }
        }
    }

    /* Enable management port (IMP port(IMP0) only for port8) */
    ioerr += READ_GMNGCFGr(unit, &gmngcfg);
    GMNGCFGr_FRM_MNGPf_SET(gmngcfg, 2);
    GMNGCFGr_RXBPDU_ENf_SET(gmngcfg, 1);
    ioerr += WRITE_GMNGCFGr(unit, gmngcfg);

    /* Enable frame forwarding */
    ioerr += READ_SWMODEr(unit, &swmode);
    SWMODEr_SW_FWDG_MODEf_SET(swmode, 1);
    SWMODEr_SW_FWDG_ENf_SET(swmode, 1);
    ioerr += WRITE_SWMODEr(unit, swmode);

    /* Enable the BRCM header */
    ioerr += READ_BRCM_HDR_CTRLr(unit, &hdrctrl);
    /* Enable the BRCM header for port8 only if interface is secured USB access */
    if (CDK_CHIP_CONFIG(unit) & DCFG_MBUS_SEC_USB) {
        BRCM_HDR_CTRLr_BRCM_HDR_ENf_SET(hdrctrl, 1);
    } else {
        /* Enable the BRCM header for both port8 and port5 if interface is others */
        BRCM_HDR_CTRLr_BRCM_HDR_ENf_SET(hdrctrl, 3);
    }
    ioerr += WRITE_BRCM_HDR_CTRLr(unit, hdrctrl);


    /**** Configure for IMP0 (port8) ****/

    /* Only configure Fource Link for port8 */
    ioerr += READ_STS_OVERRIDE_IMPr(unit, &stsoviimp);
    STS_OVERRIDE_IMPr_MII_SW_ORf_SET(stsoviimp, 1);
    STS_OVERRIDE_IMPr_LINK_STSf_SET(stsoviimp, 1);
    ioerr += WRITE_STS_OVERRIDE_IMPr(unit, stsoviimp);

    /* Enable All flow (unicast, multicast, broadcast) in MII port of mgmt chip */
    ioerr += READ_IMP_CTLr(unit, &impctl);
    IMP_CTLr_RX_UCST_ENf_SET(impctl, 1);
    IMP_CTLr_RX_MCST_ENf_SET(impctl, 1);
    IMP_CTLr_RX_BCST_ENf_SET(impctl, 1);
    ioerr += WRITE_IMP_CTLr(unit, impctl);

    /**** Configure for IMP1 (port5) ****/

    /* check if IMP1 (port 5) is RGMII mode */
    ioerr += READ_STRAP_PIN_STATUSr(unit, &strap_value);

    if (STRAP_PIN_STATUSr_GMII_MODEf_GET(strap_value) == IMP_MODE_RGMII) {
        rgmii = 1;
    }

    if (rgmii) {
        /* Enable RGMII tx/rx clock delay mode */
        ioerr += READ_PORT5_RGMII_CTL_GPr(unit, &port5_rgmii_ctl);
        PORT5_RGMII_CTL_GPr_EN_RGMII_DLL_RXCf_SET(port5_rgmii_ctl, 1);
        PORT5_RGMII_CTL_GPr_EN_RGMII_DLL_TXCf_SET(port5_rgmii_ctl, 1);
        ioerr += WRITE_PORT5_RGMII_CTL_GPr(unit, port5_rgmii_ctl);
    }

    /* Force MII Software Override, set 100 Full Link up in MII port of mgnt chip */
    ioerr += READ_STS_OVERRIDE_P5r(unit, &stsovip5);
    STS_OVERRIDE_P5r_SW_OVERRIDEf_SET(stsovip5, 1);
    STS_OVERRIDE_P5r_DUPLX_MODEf_SET(stsovip5, 1);
    STS_OVERRIDE_P5r_LINK_STSf_SET(stsovip5, 1);  
    
    if (rgmii) {
        /* Speed 1000MB */
        STS_OVERRIDE_P5r_SPEEDf_SET(stsovip5, SPDSTS_SPEED_1000);
    } else {
        STS_OVERRIDE_P5r_SPEEDf_SET(stsovip5, SPDSTS_SPEED_100);
    }

    ioerr += WRITE_STS_OVERRIDE_P5r(unit, stsovip5);

    return ioerr ? CDK_E_IO : rv;
}

#endif /* CDK_CONFIG_INCLUDE_BCM53084_A0 */
