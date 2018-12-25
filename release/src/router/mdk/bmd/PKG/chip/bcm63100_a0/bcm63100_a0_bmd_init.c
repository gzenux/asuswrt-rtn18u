#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM63100_A0 == 1

/*
 * $Id: bcm63100_a0_bmd_init.c,v 1.1 Broadcom SDK $
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

#include <cdk/chip/bcm63100_a0_defs.h>
#include <cdk/arch/robo_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm63100_a0_bmd.h"
#include "bcm63100_a0_internal.h"

#define PBMAP_MIPS              0x100
#define PBMAP_ALL               0x1FF
#define SWITCH_LAN_PORTS        8

static int
_gpic_init(int unit, int port)
{
    int ioerr = 0;
    G_PCTLr_t g_pctl;
//    STS_OVERRIDE_GMIIPr_t sts_override_gp;

#if 0
    /* Clear link status */
    ioerr += READ_STS_OVERRIDE_GMIIPr(unit, port, &sts_override_gp);
    STS_OVERRIDE_GMIIPr_LINK_STSf_SET(sts_override_gp, 0);
    ioerr += WRITE_STS_OVERRIDE_GMIIPr(unit, port, sts_override_gp);
#endif

    ioerr += READ_G_PCTLr(unit, port, &g_pctl);
    /* Set forwarding state */
    G_PCTLr_G_MISTP_STATEf_SET(g_pctl, 5);
    ioerr += WRITE_G_PCTLr(unit, port, g_pctl);

    return ioerr;
}

int
bcm63100_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    TC2COS_MAPr_t tc2cos;
    QOS_TX_CTRLr_t txqctl;
#if !defined(CONFIG_BCM_ENET_MULTI_IMP_SUPPORT)
    SWMODEr_t swmode;
    GMNGCFGr_t gmngcfg;
    BRCM_HDR_CTRLr_t hdrctrl;
    STS_OVERRIDE_IMPr_t stsoviimp;
    DIS_LEARNr_t dis_learn;
    NEW_CTRLr_t new_ctrl;
    ULF_DROP_MAPr_t ulf_map;
    MLF_DROP_MAPr_t mlf_map;
    MLF_IPMC_FWD_MAPr_t ipmc_map;
    IMP_CTLr_t impstl;
    int val;
#endif
#if defined(CONFIG_BCM_MCAST_SNOOP)
    HL_PRTC_CTRLr_t hlprtcctrl;
#endif

#if defined(CONFIG_BCM_JUMBO_FRAME)
    JUMBO_PORT_MASKr_t jumbo_msk;
#endif /* CONFIG_BCM_JUMBO_FRAME */

    int port;
    cdk_pbmp_t pbmp;
    uint32_t config_pbmp, phy_pbmp, nophy_pbmp;
    STS_OVERRIDE_GMIIPr_t sts_override_gp;

    BMD_CHECK_UNIT(unit);

    config_pbmp = CDK_DEV_CONFIG_PBMP(unit);
    phy_pbmp = CDK_DEV_PHY_PBMP(unit);

    /* Configure GPICs */
    CDK_ROBO_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPIC, &pbmp);

    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _gpic_init(unit, port);
        /* Configure ports with PHY */
        if (phy_pbmp & (1 << port)) {
            /* Only need to probe the PHY; 
             * bmd_phy_attach would probe, reset and init the PHY - not needed */
            rv = bmd_phy_probe(unit, port);
        }
    }


#if defined(CONFIG_BCM_MCAST_SNOOP)
    /* Enable IGMP and MLD snooping, forward to IMP only*/
    /* NOTE : We are not tying this register setting to MULTI_IMP_SUPPORT.
     * Reason : Switch takes this decision about these execption packets much later in forwarding tree
     * and overrides the earlier decisions; So even if some of the ports may not be grouped 
     * with P8, switch will be overriding the PBVLAN decision. As per VLSI team. */
    READ_HL_PRTC_CTRLr(unit, &hlprtcctrl);
    HL_PRTC_CTRLr_IGMP_RPTLVE_ENf_SET(hlprtcctrl, 1);
    HL_PRTC_CTRLr_IGMP_RPTLVE_FWD_MODEf_SET(hlprtcctrl, 1);
    HL_PRTC_CTRLr_MLD_RPTDONE_ENf_SET(hlprtcctrl, 1);
    HL_PRTC_CTRLr_MLD_RPTDONE_FWD_MODEf_SET(hlprtcctrl, 1);
    WRITE_HL_PRTC_CTRLr(unit, hlprtcctrl);
#endif    

#if !defined(CONFIG_BCM_ENET_MULTI_IMP_SUPPORT)
    /* When multiple IMP Ports are used, configuration is done by Ethernet Driver */

    /* Enable IMP port, and Rx of BPDUs */
    READ_GMNGCFGr(unit, &gmngcfg);
    GMNGCFGr_FRM_MNGPf_SET(gmngcfg, 3);
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

    /* force 1000FD on IMP port */
    READ_STS_OVERRIDE_IMPr(unit, &stsoviimp);
    STS_OVERRIDE_IMPr_MII_SW_ORf_SET(stsoviimp, 1);
    STS_OVERRIDE_IMPr_DUPLX_MODEf_SET(stsoviimp, 1);
    STS_OVERRIDE_IMPr_LINK_STSf_SET(stsoviimp, 1);  
    STS_OVERRIDE_IMPr_SPEED_Rf_SET(stsoviimp, 2);  
    STS_OVERRIDE_IMPr_GMII_SPEED_UP_2Gf_SET(stsoviimp,1); /* Set IMP port towards SF2 at 2G */
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
#endif /* !defined(CONFIG_BCM_ENET_MULTI_IMP_SUPPORT) */

    /*
     * QOS: For each port, MAP Traffic Class n 
     *      to queue id n -- one-one.
     *      n runs from 0 .. 7.
     */
     
    for (port = 0; port <= SWITCH_LAN_PORTS; port++) {
        TC2COS_MAPr_CLR(tc2cos, port);
        TC2COS_MAPr_SET(tc2cos, port, 0xfac688);
        WRITE_TC2COS_MAPr(unit, port, tc2cos);
        
        /* QoS: For each port, Set Tx queues q7 .. q4 
         * to strict priority.
         * COS is synonymous with q.
         * The priority is COS7 > COS6 > COS5 ...  COS1 > COS0
         */
        QOS_TX_CTRLr_CLR(txqctl, port);

        // Q7-Q4 SP, rest WDRR/WRR. 
        // Also make WRR the default on Q3 - Q0.

        QOS_TX_CTRLr_SET(txqctl, port, (0x4 | (1 << 3)));
        WRITE_QOS_TX_CTRLr(unit, port, txqctl);
    }

#if defined(CONFIG_BCM_JUMBO_FRAME)

    /* Enable Jumpbo frame */
    JUMBO_PORT_MASKr_SET(jumbo_msk, PBMAP_ALL);
    WRITE_JUMBO_PORT_MASKr(unit, jumbo_msk);

#endif /* CONFIG_BCM_JUMBO_FRAME */

    nophy_pbmp = (~phy_pbmp) & config_pbmp;
    printf("[63100] Switch MDK: unit = %d; phy_pbmp = 0x%x; config_pbmp = 0x%x nophy_pbmp = 0x%x\n", 
        unit, phy_pbmp, config_pbmp,nophy_pbmp);
    /* Force link up for non-phy ports; Correct speed is set by
     * swmdk polling function based on board paramenters. */
    for (port = 0; port < SWITCH_LAN_PORTS; port++) {
        if (nophy_pbmp & (1 << port)) {
            READ_STS_OVERRIDE_GMIIPr(unit, port, &sts_override_gp);
            STS_OVERRIDE_GMIIPr_LINK_STSf_SET(sts_override_gp, 1);
            WRITE_STS_OVERRIDE_GMIIPr(unit, port, sts_override_gp);
            printf("unit = %d; port=%d force MAC link up \n", unit, port);
        } 
    }


    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM63100_A0 */
