#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53115_A0 == 1

/*
 * $Id: bcm53115_a0_bmd_init.c,v 1.1 Broadcom SDK $
 * 
 * $Copyright: Copyright 2009 Broadcom Corporation.
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
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$1,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 */

#include <bmd/bmd.h>
#include <bmd/bmd_device.h>

#include <cdk/chip/bcm53115_a0_defs.h>
#include <cdk/arch/robo_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm53115_a0_bmd.h"
#include "bcm53115_a0_internal.h"

#define PBMAP_MIPS              0x100
#define PBMAP_ALL               0x1FF
#define SWITCH_LAN_PORTS        8

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

    ioerr += READ_G_PCTLr(unit, port, &g_pctl);
    /* Set forwarding state */
    G_PCTLr_G_MISTP_STATEf_SET(g_pctl, 5);
    ioerr += WRITE_G_PCTLr(unit, port, g_pctl);

    return ioerr;
}

int
bcm53115_a0_bmd_init(int unit)
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
    STS_OVERRIDE_IMPr_t stsoviimp;
    IMP_CTLr_t impstl;
    NEW_CTRLr_t new_ctrl;
    ULF_DROP_MAPr_t ulf_map;
    MLF_DROP_MAPr_t mlf_map;
    MLF_IPMC_FWD_MAPr_t ipmc_map;
    DIS_LEARNr_t dis_learn;
    TC2COS_MAPr_t tc2cos;
    QOS_TX_CTRLr_t txqctl;
#if defined(CONFIG_BCM_MCAST_SNOOP)
    HL_PRTC_CTRLr_t hlprtcctrl;
#endif

#if defined(CONFIG_BCM_JUMBO_FRAME)
    JUMBO_PORT_MASKr_t jumbo_msk;
#endif /* CONFIG_BCM_JUMBO_FRAME */

    int val, port;
    cdk_pbmp_t pbmp;
    uint32_t config_pbmp, phy_pbmp, nophy_pbmp;
    STS_OVERRIDE_GMIIPr_t sts_override_gp;
    
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
    config_pbmp = CDK_DEV_CONFIG_PBMP(unit);
    phy_pbmp = CDK_DEV_PHY_PBMP(unit);

    /* Configure GPICs */
    CDK_ROBO_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPIC, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _gpic_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }

    /* Enable IMP port, and Rx of BPDUs */
    READ_GMNGCFGr(unit, &gmngcfg);
    GMNGCFGr_FRM_MNGPf_SET(gmngcfg, 2);
    GMNGCFGr_RXBPDU_ENf_SET(gmngcfg, 1);
    WRITE_GMNGCFGr(unit, gmngcfg);

#if defined(CONFIG_BCM_MCAST_SNOOP)
    /* Enable IGMP and MLD snooping, forward to IMP only*/
    READ_HL_PRTC_CTRLr(unit, &hlprtcctrl);
    HL_PRTC_CTRLr_IGMP_RPTLVE_ENf_SET(hlprtcctrl, 1);
    HL_PRTC_CTRLr_IGMP_RPTLVE_FWD_MODEf_SET(hlprtcctrl, 1);
    HL_PRTC_CTRLr_MLD_RPTDONE_ENf_SET(hlprtcctrl, 1);
    HL_PRTC_CTRLr_MLD_RPTDONE_FWD_MODEf_SET(hlprtcctrl, 1);
    WRITE_HL_PRTC_CTRLr(unit, hlprtcctrl);
#endif    

    /* Enable frame forwarding */
    READ_SWMODEr(unit, &swmode);
    SWMODEr_SW_FWDG_MODEf_SET(swmode, 1);
    SWMODEr_SW_FWDG_ENf_SET(swmode, 1);
    WRITE_SWMODEr(unit, swmode);

    /* force enabling the BRCM header tag */
    READ_BRCM_HDR_CTRLr(unit, &hdrctrl);
    BRCM_HDR_CTRLr_BRCM_HDR_ENf_SET(hdrctrl, 1);
    WRITE_BRCM_HDR_CTRLr(unit, hdrctrl);

    /* force 1000FD on IMP port */
    READ_STS_OVERRIDE_IMPr(unit, &stsoviimp);
    STS_OVERRIDE_IMPr_MII_SW_ORf_SET(stsoviimp, 1);
    STS_OVERRIDE_IMPr_DUPLX_MODEf_SET(stsoviimp, 1);
    STS_OVERRIDE_IMPr_LINK_STSf_SET(stsoviimp, 1);  
    STS_OVERRIDE_IMPr_SPEED_Rf_SET(stsoviimp, 2);  
    WRITE_STS_OVERRIDE_IMPr(unit, stsoviimp);

    /* Enable unicast/mcast/bcast rx on IMP port */
    READ_IMP_CTLr(unit, &impstl);
    IMP_CTLr_RX_UCST_ENf_SET(impstl, 1);
    IMP_CTLr_RX_MCST_ENf_SET(impstl, 1);
    IMP_CTLr_RX_BCST_ENf_SET(impstl, 1);
    WRITE_IMP_CTLr(unit, impstl);
    /* Forward lookup failure to use ULF/MLF/IPMC lookup fail registers */
    NEW_CTRLr_CLR(new_ctrl);
    NEW_CTRLr_MC_FWD_ENf_SET(new_ctrl, 1);
    NEW_CTRLr_UC_FWD_ENf_SET(new_ctrl, 1);
    NEW_CTRLr_IP_MCf_SET(new_ctrl, 1);
    WRITE_NEW_CTRLr(unit, new_ctrl);
    /* Forward unlearned unicast and unresolved mcast to the MIPS */
    ULF_DROP_MAPr_CLR(ulf_map);
    ULF_DROP_MAPr_SET(ulf_map, PBMAP_MIPS);
    WRITE_ULF_DROP_MAPr(unit, ulf_map);
    MLF_DROP_MAPr_CLR(mlf_map);
    MLF_DROP_MAPr_SET(mlf_map, PBMAP_MIPS);
    WRITE_MLF_DROP_MAPr(unit, mlf_map);
    MLF_IPMC_FWD_MAPr_CLR(ipmc_map);
    MLF_IPMC_FWD_MAPr_SET(ipmc_map, PBMAP_MIPS);
    WRITE_MLF_IPMC_FWD_MAPr(unit, ipmc_map);
    
    /* Disable learning on MIPS */
    READ_DIS_LEARNr(unit, &dis_learn);
    val = DIS_LEARNr_DIS_LEARNf_GET(dis_learn);
    DIS_LEARNr_DIS_LEARNf_SET(dis_learn, val | PBMAP_MIPS);
    WRITE_DIS_LEARNr(unit, dis_learn);

    /* QoS: Map priority ID to Tx queue ID as:
     *      P0 to Q0, P1 to Q1, P2 to Q2, P3 to Q3
     *      P4, P5, P6, P7 to Q3
     */
    TC2COS_MAPr_CLR(tc2cos);
    TC2COS_MAPr_SET(tc2cos, 0xffe4);
    WRITE_TC2COS_MAPr(unit, tc2cos);
    
    /* QoS: Set Tx queues to strict priority.
     *      The priority is COS3 > COS2 > COS1 > COS0
     */
    QOS_TX_CTRLr_CLR(txqctl);
    QOS_TX_CTRLr_SET(txqctl, 0x3);
    WRITE_QOS_TX_CTRLr(unit, txqctl);

#if defined(CONFIG_BCM_JUMBO_FRAME)

    /* Enable Jumpbo frame */
    JUMBO_PORT_MASKr_SET(jumbo_msk, PBMAP_ALL);
    WRITE_JUMBO_PORT_MASKr(unit, jumbo_msk);

#endif /* CONFIG_BCM_JUMBO_FRAME */

    nophy_pbmp = (~phy_pbmp) & config_pbmp;
    printf("[53115] Switch MDK: unit = %d; phy_pbmp = 0x%x; config_pbmp = 0x%x \n", 
        unit, phy_pbmp, config_pbmp);
    /* Force link up for non-phy ports; Correct speed is set by
     * swmdk polling function based on board paramenters. */
    for (port = 0; port < SWITCH_LAN_PORTS; port++) {
        if (nophy_pbmp & (1 << port)) {
            READ_STS_OVERRIDE_GMIIPr(unit, port, &sts_override_gp);
            STS_OVERRIDE_GMIIPr_LINK_STSf_SET(sts_override_gp, 1);
            WRITE_STS_OVERRIDE_GMIIPr(unit, port, sts_override_gp);
        } 
    }

    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM53115_A0 */
