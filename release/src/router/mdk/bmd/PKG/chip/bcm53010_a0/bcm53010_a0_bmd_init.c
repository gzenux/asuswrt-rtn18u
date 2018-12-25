#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53010_A0 == 1

/*
 * $Id: bcm53010_a0_bmd_init.c,v 1.5 Broadcom SDK $
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

#include <cdk/chip/bcm53010_a0_defs.h>
#include <cdk/arch/robo_chip.h>
#include <cdk/cdk_debug.h>
#include <cdk/arch/robo_miim.h>

#include "bcm53010_a0_bmd.h"
#include "bcm53010_a0_internal.h"

static int
_gpic_init(int unit, int port)
{
    int ioerr = 0;
    P7_CTLr_t p7_pctl;
    G_PCTLr_t g_pctl;
    STS_OVERRIDE_P5r_t sts_override_p5;
    STS_OVERRIDE_P7r_t sts_override_p7;
    STS_OVERRIDE_GMIIPr_t sts_override_gp;

    if (port == 5) {
        /* Clear link status */
        ioerr += READ_STS_OVERRIDE_P5r(unit, &sts_override_p5);
        STS_OVERRIDE_P5r_LINK_STSf_SET(sts_override_p5, 0);
        STS_OVERRIDE_P5r_TXFLOW_CNTLf_SET(sts_override_p5, 0);
        STS_OVERRIDE_P5r_RXFLOW_CNTLf_SET(sts_override_p5, 0);
        ioerr += WRITE_STS_OVERRIDE_P5r(unit, sts_override_p5);
    
        /* Set forwarding state */
        ioerr += READ_G_PCTLr(unit, port, &g_pctl);
        G_PCTLr_G_MISTP_STATEf_SET(g_pctl, 5);
        ioerr += WRITE_G_PCTLr(unit, port, g_pctl);
    } else if (port == 7) {
        /* Clear link status */
        ioerr += READ_STS_OVERRIDE_P7r(unit, &sts_override_p7);
        STS_OVERRIDE_P7r_LINK_STSf_SET(sts_override_p7, 0);
        STS_OVERRIDE_P7r_TXFLOW_CNTLf_SET(sts_override_p7, 0);
        STS_OVERRIDE_P7r_RXFLOW_CNTLf_SET(sts_override_p7, 0);
        ioerr += WRITE_STS_OVERRIDE_P7r(unit, sts_override_p7);
    
        /* Set forwarding state */
        ioerr += READ_P7_CTLr(unit, &p7_pctl);
        P7_CTLr_G_MISTP_STATEf_SET(p7_pctl, 5);
        ioerr += WRITE_P7_CTLr(unit, p7_pctl);
        
        
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
bcm53010_a0_bmd_init(int unit)
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
    STS_OVERRIDE_P7r_t stsovip7;
    STS_OVERRIDE_P5r_t stsovip5;
    IMP_CTLr_t impstl;
    int port;
    cdk_pbmp_t pbmp;

    BMD_CHECK_UNIT(unit);

    /* Enable VLANs */
    READ_VLAN_CTRL0r(unit, &vlan_ctrl0);
    VLAN_CTRL0r_VLAN_ENf_SET(vlan_ctrl0, 1);
    WRITE_VLAN_CTRL0r(unit, vlan_ctrl0);

    /* Drop packet if VLAN mismatch */
    READ_VLAN_CTRL4r(unit, &vlan_ctrl4);
    VLAN_CTRL4r_INGR_VID_CHKf_SET(vlan_ctrl4, 1);
    WRITE_VLAN_CTRL4r(unit, vlan_ctrl4);

    /* Enable spanning tree */
    READ_MST_CONr(unit, &mst_con);
    MST_CONr_EN_802_1Sf_SET(mst_con, 1);
    WRITE_MST_CONr(unit, mst_con);

    /* Configure LEDs */
    LED_FUNC1_CTLr_SET(led_func1_ctl, 0x4320);
    WRITE_LED_FUNC1_CTLr(unit, led_func1_ctl);

    /* Configure GPICs */
    CDK_ROBO_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPIC, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {

        ioerr += _gpic_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }

    /* Enable frame forwarding */
    READ_SWMODEr(unit, &swmode);
    SWMODEr_SW_FWDG_MODEf_SET(swmode, 1);
    SWMODEr_SW_FWDG_ENf_SET(swmode, 1);
    WRITE_SWMODEr(unit, swmode);

    /* Enable BRCM header tag on port 8 */
    READ_BRCM_HDR_CTRLr(unit, &hdrctrl);
    BRCM_HDR_CTRLr_BRCM_HDR_ENf_SET(hdrctrl, BRCM_HDR_IMP0);
    WRITE_BRCM_HDR_CTRLr(unit, hdrctrl);

    /* Port 8 configuration*/
    READ_STS_OVERRIDE_IMPr(unit, &stsoviimp);
    STS_OVERRIDE_IMPr_MII_SW_ORf_SET(stsoviimp, 1);
    STS_OVERRIDE_IMPr_DUPLX_MODEf_SET(stsoviimp, 1);
    STS_OVERRIDE_IMPr_LINK_STSf_SET(stsoviimp, 1);  
    /* Default speed at 2G */
    STS_OVERRIDE_IMPr_SPEEDf_SET(stsoviimp, 2);  
    WRITE_STS_OVERRIDE_IMPr(unit, stsoviimp);

    /* Port 7 configuration*/
    READ_STS_OVERRIDE_P7r(unit, &stsovip7);
    /* Default speed at 2G */
    STS_OVERRIDE_P7r_SPEEDf_SET(stsovip7, 2);
    STS_OVERRIDE_P7r_SW_OVERRIDEf_SET(stsovip7, 1);
    STS_OVERRIDE_P7r_DUPLX_MODEf_SET(stsovip7, 1);
    STS_OVERRIDE_P7r_LINK_STSf_SET(stsovip7, 1);
    STS_OVERRIDE_P7r_TXFLOW_CNTLf_SET(stsovip7, 1);
    STS_OVERRIDE_P7r_RXFLOW_CNTLf_SET(stsovip7, 1);
    WRITE_STS_OVERRIDE_P7r(unit, stsovip7);

    /* Port 5 configuration*/
    READ_STS_OVERRIDE_P5r(unit, &stsovip5);
    /* Default speed at 2G */
    STS_OVERRIDE_P5r_SPEEDf_SET(stsovip5, 2);
    STS_OVERRIDE_P5r_SW_OVERRIDEf_SET(stsovip5, 1);
    STS_OVERRIDE_P5r_DUPLX_MODEf_SET(stsovip5, 1);
    STS_OVERRIDE_P5r_LINK_STSf_SET(stsovip5, 1);
    STS_OVERRIDE_P5r_TXFLOW_CNTLf_SET(stsovip5, 1);
    STS_OVERRIDE_P5r_RXFLOW_CNTLf_SET(stsovip5, 1);
    WRITE_STS_OVERRIDE_P5r(unit, stsovip5);

    /*
     * Enable All flow (unicast, multicast, broadcast)
     * in MII port of mgmt chip
     */
    ioerr += READ_IMP_CTLr(unit, &impstl);
    IMP_CTLr_RX_UCST_ENf_SET(impstl, 1);
    IMP_CTLr_RX_MCST_ENf_SET(impstl, 1);
    IMP_CTLr_RX_BCST_ENf_SET(impstl, 1);
    ioerr += WRITE_IMP_CTLr(unit, impstl);

    /* Enable management port */
    READ_GMNGCFGr(unit, &gmngcfg);
    GMNGCFGr_FRM_MNGPf_SET(gmngcfg, 2);
    GMNGCFGr_RXBPDU_ENf_SET(gmngcfg, 1);
    WRITE_GMNGCFGr(unit, gmngcfg);

    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM53010_A0 */
