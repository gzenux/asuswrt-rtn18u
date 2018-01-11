#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53101_A0 == 1

/*
 * $Id: bcm53101_a0_bmd_init.c,v 1.2 2009/09/24 08:22:27 hchang Exp $
 * 
 * $Copyright: Copyright 2008 Broadcom Corporation.
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
 * THE AMOUNT ACTUALLY PAID FOR THE SOFTWARE ITSELF OR U.S. $1,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 */

#include <bmd/bmd.h>
#include <bmd/bmd_device.h>

#include <cdk/chip/bcm53101_a0_defs.h>
#include <cdk/arch/robo_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm53101_a0_bmd.h"
#include "bcm53101_a0_internal.h"

#define PBMAP_MIPS              0x100

static int
_epic_init(int unit, int port)
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
    ioerr += WRITE_G_PCTLr(unit, port, g_pctl);

    return ioerr;
}

int
bcm53101_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
//    VLAN_CTRL0r_t vlan_ctrl0;
//    VLAN_CTRL4r_t vlan_ctrl4;
//    MST_CONr_t mst_con;
//    LED_FUNC1_CTLr_t led_func1_ctl;
    SWMODEr_t swmode;
    GMNGCFGr_t gmngcfg;
    BRCM_HDR_CTRLr_t hdrctrl;
    STRAP_VALUEr_t strap_value;
    SWITCH_CTRLr_t switch_ctrl;
    IMP_RGMII_CTL_GPr_t imp_rgmii_ctl_gp;
    STS_OVERRIDE_IMPr_t stsoviimp;
    IMP_CTLr_t impstl;
    uint32_t temp, rgmii = 0;
    CTRL_REGr_t ctrl_reg;
    ULF_DROP_MAPr_t ulf_map;
    MLF_DROP_MAPr_t mlf_map;
    MLF_IPMC_FWD_MAPr_t ipmc_map;
    NEW_CTRLr_t newctrl;        
    DIS_LEARNr_t dis_learn;
    int port, val;
    cdk_pbmp_t pbmp;

    BMD_CHECK_UNIT(unit);

#if 0
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
#endif

    /* Fixed for port 5 with external phy */
    READ_CTRL_REGr(unit, &ctrl_reg);
    CTRL_REGr_MDC_TIMING_ENHf_SET(ctrl_reg, 1);
    WRITE_CTRL_REGr(unit, ctrl_reg);

    /* Configure GPICs */
    CDK_ROBO_BLKTYPE_PBMP_GET(unit, BLKTYPE_EPIC, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _epic_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }
    /* Enable management port */
    READ_GMNGCFGr(unit, &gmngcfg);
    GMNGCFGr_FRM_MNGPf_SET(gmngcfg, 2);
    GMNGCFGr_RXBPDU_ENf_SET(gmngcfg, 1);
    WRITE_GMNGCFGr(unit, gmngcfg);

    /* Enable frame forwarding */
    READ_SWMODEr(unit, &swmode);
    SWMODEr_SW_FWDG_MODEf_SET(swmode, 1);
    SWMODEr_SW_FWDG_ENf_SET(swmode, 1);
    WRITE_SWMODEr(unit, swmode);

    /* force enabling the BRCM header tag */
    READ_BRCM_HDR_CTRLr(unit, &hdrctrl);
    BRCM_HDR_CTRLr_BRCM_HDR_ENf_SET(hdrctrl, 1);
    WRITE_BRCM_HDR_CTRLr(unit, hdrctrl);

    READ_STRAP_VALUEr(unit, &strap_value);
    temp = STRAP_VALUEr_FINAL_MII1_MODEf_GET(strap_value);

    /* check if RGMII mode */
    if (temp == 0x5) {
        CDK_PRINTF("rgmii mode\n");
        rgmii = 1;
    }

    if (rgmii) {
        /* Select 2.5V as MII voltage */
        READ_SWITCH_CTRLr(unit, &switch_ctrl);
        temp = 1; /* 2.5V */
        SWITCH_CTRLr_MII1_VOL_SELf_SET(switch_ctrl, temp);
        WRITE_SWITCH_CTRLr(unit, switch_ctrl);
    
        /* Enable RGMII tx/rx clock delay mode */
        READ_IMP_RGMII_CTL_GPr(unit, &imp_rgmii_ctl_gp); 
        IMP_RGMII_CTL_GPr_RXC_DLL_DLY_ENf_SET(imp_rgmii_ctl_gp, 1); 
        IMP_RGMII_CTL_GPr_TXC_DLL_DLY_ENf_SET(imp_rgmii_ctl_gp, 1); 
        WRITE_IMP_RGMII_CTL_GPr(unit, imp_rgmii_ctl_gp);
                
    }
    /* Set IMP port state using override */
    READ_STS_OVERRIDE_IMPr(unit, &stsoviimp);
    STS_OVERRIDE_IMPr_MII_SW_ORf_SET(stsoviimp, 1);
    STS_OVERRIDE_IMPr_DUPLX_MODEf_SET(stsoviimp, 1);
    STS_OVERRIDE_IMPr_LINK_STSf_SET(stsoviimp, 1);  
    
    if (rgmii) {
        /* Speed 1000MB */
        STS_OVERRIDE_IMPr_SPEEDf_SET(stsoviimp, 2);  
    } else {
        STS_OVERRIDE_IMPr_SPEEDf_SET(stsoviimp, 1);  
    }          
    WRITE_STS_OVERRIDE_IMPr(unit, stsoviimp);

    /* Enable IMP Rx of ucast/mcast/bcast packets */
    READ_IMP_CTLr(unit, &impstl);
    IMP_CTLr_RX_UCST_ENf_SET(impstl, 1);
    IMP_CTLr_RX_MCST_ENf_SET(impstl, 1);
    IMP_CTLr_RX_BCST_ENf_SET(impstl, 1);
    WRITE_IMP_CTLr(unit, impstl);

    READ_NEW_CTRLr(unit, &newctrl);
    NEW_CTRLr_UC_FWD_ENf_SET(newctrl, 1);
    NEW_CTRLr_MC_FWD_ENf_SET(newctrl, 1);
    WRITE_NEW_CTRLr(unit, newctrl);

    /* Forward unlearned unicast and unresolved mcast to the MIPS */
    ULF_DROP_MAPr_SET(ulf_map, PBMAP_MIPS);
    WRITE_ULF_DROP_MAPr(unit, ulf_map);
    MLF_DROP_MAPr_SET(mlf_map, PBMAP_MIPS);
    WRITE_MLF_DROP_MAPr(unit, mlf_map);
    MLF_IPMC_FWD_MAPr_SET(ipmc_map, PBMAP_MIPS);
    WRITE_MLF_IPMC_FWD_MAPr(unit, ipmc_map);

    /* Disable learning on MIPS */
    READ_DIS_LEARNr(unit, &dis_learn);
    val = DIS_LEARNr_DIS_LEARNf_GET(dis_learn);
    DIS_LEARNr_DIS_LEARNf_SET(dis_learn, val | PBMAP_MIPS);
    WRITE_DIS_LEARNr(unit, dis_learn);

    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM53101_A0 */
