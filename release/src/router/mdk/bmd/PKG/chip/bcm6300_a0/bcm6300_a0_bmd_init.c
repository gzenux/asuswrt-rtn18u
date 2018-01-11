#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM6300_A0 == 1

/*
 * $Id: bcm6300_a0_bmd_init.c,v 1.7 Broadcom SDK $
 * 
 * $Copyright: Copyright 2009 Broadcom Corporation.
 */

/*
* <:label-BRCM:2011:proprietary:standard
* 
*  This program is the proprietary software of Broadcom and/or its
*  licensors, and may only be used, duplicated, modified or distributed pursuant
*  to the terms and conditions of a separate, written license agreement executed
*  between you and Broadcom (an "Authorized License").  Except as set forth in
*  an Authorized License, Broadcom grants no license (express or implied), right
*  to use, or waiver of any kind with respect to the Software, and Broadcom
*  expressly reserves all rights in and to the Software and all intellectual
*  property rights therein.  IF YOU HAVE NO AUTHORIZED LICENSE, THEN YOU HAVE
*  NO RIGHT TO USE THIS SOFTWARE IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY
*  BROADCOM AND DISCONTINUE ALL USE OF THE SOFTWARE.
* 
*  Except as expressly set forth in the Authorized License,
* 
*  1. This program, including its structure, sequence and organization,
*     constitutes the valuable trade secrets of Broadcom, and you shall use
*     all reasonable efforts to protect the confidentiality thereof, and to
*     use this information only in connection with your use of Broadcom
*     integrated circuit products.
* 
*  2. TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
*     AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES, REPRESENTATIONS OR
*     WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
*     RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY DISCLAIMS ANY AND
*     ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT,
*     FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR
*     COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE
*     TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING OUT OF USE OR
*     PERFORMANCE OF THE SOFTWARE.
* 
*  3. TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL BROADCOM OR
*     ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL, INCIDENTAL, SPECIAL,
*     INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER ARISING OUT OF OR IN ANY
*     WAY RELATING TO YOUR USE OF OR INABILITY TO USE THE SOFTWARE EVEN
*     IF BROADCOM HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES;
*     OR (ii) ANY AMOUNT IN EXCESS OF THE AMOUNT ACTUALLY PAID FOR THE
*     SOFTWARE ITSELF OR U.S. $1, WHICHEVER IS GREATER. THESE LIMITATIONS
*     SHALL APPLY NOTWITHSTANDING ANY FAILURE OF ESSENTIAL PURPOSE OF ANY
*     LIMITED REMEDY.
* :>
*/


#include <bmd/bmd.h>
#include <bmd/bmd_device.h>

#include <cdk/chip/bcm6300_a0_defs.h>
#include <cdk/arch/robo_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm6300_a0_bmd.h"
#include "bcm6300_a0_internal.h"
#include "cms_boardcmds.h"
#include "cms_boardioctl.h"

#define SWITCH_LAN_PORTS        8
#if defined(CHIP_63268)
#define NUM_RGMII_PORTS         4
#elif defined(CHIP_6328)
#define NUM_RGMII_PORTS         1
#else
#define NUM_RGMII_PORTS         2
#endif
#define IMP_PORT_ID             8
#define PBMAP_MIPS              0x100
#define PBMAP_ALL               0x1FF
#define LINK_OVRD_1000FD        0x4B
#define LINK_OVRD_DOWN          0x40
#define LINK_1000FD_DOWN        0x4A
/* Tx: 0->0, 1->1, 2->2, 3->3. */
#define DEFAULT_IUDMA_QUEUE_SEL 0x688

#define RGMII2_PORT             5

#define DEFAULT_FC_CTRL_VAL                    0x1F
#if defined(CHIP_63268)
/* These FC thresholds are based on 0x200 buffers available in the switch */
#define DEFAULT_TOTAL_DROP_THRESHOLD           0x1FF
#define DEFAULT_TOTAL_PAUSE_THRESHOLD          0x1FF
#define DEFAULT_TOTAL_HYSTERESIS_THRESHOLD     0x1F0 
#define DEFAULT_TXQHI_DROP_THRESHOLD           0x78
#define DEFAULT_TXQHI_PAUSE_THRESHOLD          0x6c
#define DEFAULT_TXQHI_HYSTERESIS_THRESHOLD     0x60
#else
/* These FC thresholds are based on 0x100 buffers available in the switch */
#define DEFAULT_TOTAL_DROP_THRESHOLD           0xFF
#define DEFAULT_TOTAL_PAUSE_THRESHOLD          0xD0
#define DEFAULT_TOTAL_HYSTERESIS_THRESHOLD     0xA0
#define DEFAULT_TXQHI_DROP_THRESHOLD           0x3D
#define DEFAULT_TXQHI_PAUSE_THRESHOLD          0x2D
#define DEFAULT_TXQHI_HYSTERESIS_THRESHOLD     0x1D
#endif

#if 0
static int
_gpic_init(int unit, int port)
{
    int ioerr = 0;
//    G_PCTLr_t g_pctl;
    STS_OVERRIDE_GPr_t sts_override_gp;

    /* Clear link status */
    ioerr += READ_STS_OVERRIDE_GPr(unit, port, &sts_override_gp);
    STS_OVERRIDE_GPr_LINK_STSf_SET(sts_override_gp, 0);
    ioerr += WRITE_STS_OVERRIDE_GPr(unit, port, sts_override_gp);


    /* Set forwarding state */
    ioerr += READ_G_PCTLr(unit, port, &g_pctl);
    G_PCTLr_G_MISTP_STATEf_SET(g_pctl, 5);
    ioerr += WRITE_G_PCTLr(unit, port, g_pctl);

    return ioerr;
}
#endif

#if defined(CHIP_6328)
//#define PBMAP_PORT0_N_EPON_PORT (0x1 | (1 << CDK_DEV_GET_EPON_PORT(0)))
#define ALL_PORTS_FORWARDING 0x05B6DB6D
#endif

int
bcm6300_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    SWMODEr_t swmode;
    GMNGCFGr_t gmngcfg;
    G_PCTLr_t pctl;
    RGMII_CTL_GPr_t rgmii_ctl;
    MII_PCTLr_t imp_ctl;
    IUDMA_CTRLr_t dma_ctl;
#if defined(CONFIG_BCM_JUMBO_FRAME)
    JUMBO_PORT_MASKr_t jumbo_msk;
#endif /* CONFIG_BCM_JUMBO_FRAME */
    NEW_CONTROLr_t new_ctrl;
    QOS_TX_CTRLr_t qos_tx_ctrl;
    DIS_LEARNr_t dis_learn;
    FC_PAUSE_DROP_CTRLr_t fc_pause_drop;
    STS_OVERRIDE_GPr_t sts_override_gp;
    QOS_CTLr_t qos_ctrl;
    int i, port, val;
    uint32_t config_pbmp, phy_pbmp, nophy_pbmp;
    IUDMA_QUEUE_CTRLr_t iudmaq_ctrl;
    GARLCFGr_t garl_cfg;
    FC_TXQ_TH_RSRV_Qr_t txq_hyst;
    FC_TXQ_TH_PAUSE_Qr_t txq_pause;
    FC_TXQ_TH_DROP_Qr_t txq_drop;
    FC_TOTAL_TH_HYST_Qr_t total_hyst;
    FC_TOTAL_TH_PAUSE_Qr_t total_pause;
    FC_TOTAL_TH_DROP_Qr_t total_drop;
#if defined(CHIP_6328)
    MST_CONr_t mst_con;
    MST_TBLr_t mst_tbl;
#endif

    BMD_CHECK_UNIT(unit);

    /* Disable unused switch ethernet ports */
    G_PCTLr_CLR(pctl);
    config_pbmp = CDK_DEV_CONFIG_PBMP(unit);
    for (port = 0; port < SWITCH_LAN_PORTS; port++) {
        if (!(config_pbmp & (1 << port))) {
            G_PCTLr_MIRX_DISf_SET(pctl, 1);
            G_PCTLr_MITX_DISf_SET(pctl, 1);
        } else {
            G_PCTLr_MIRX_DISf_SET(pctl, 0);
            G_PCTLr_MITX_DISf_SET(pctl, 0);
        }
        WRITE_G_PCTLr(unit, port, pctl);
    }

    /* RGMII delay programming: Enable ID mode and GMII(RGMII) TXCLK*/ 
    for (port = 0; port < NUM_RGMII_PORTS; port++) {
        READ_RGMII_CTL_GPr(unit, port, &rgmii_ctl);
#if defined(BRCM_PORTS_ON_INT_EXT_SW)
        RGMII_CTL_GPr_TIM_SELf_SET(rgmii_ctl, 1);
        RGMII_CTL_GPr_GMII_CLKENf_SET(rgmii_ctl, 1);
#else
        RGMII_CTL_GPr_GMII_CLKENf_SET(rgmii_ctl, 1);
#if !defined(CHIP_63268)
        RGMII_CTL_GPr_TIM_SELf_SET(rgmii_ctl, 1);
#endif
#endif
        RGMII_CTL_GPr_GMII_CLKENf_SET(rgmii_ctl, 1);
        WRITE_RGMII_CTL_GPr(unit, port, rgmii_ctl);
    }

    /* Enable IMP port, IGMP snooping, and Rx of BPDUs */
    READ_GMNGCFGr(unit, &gmngcfg);
    GMNGCFGr_FRM_MNGPf_SET(gmngcfg, 2);
    GMNGCFGr_IGMPIP_SNOP_ENf_SET(gmngcfg, 1);
    GMNGCFGr_RXBPDU_ENf_SET(gmngcfg, 1);
    WRITE_GMNGCFGr(unit, gmngcfg);

    /* Put switch in managed mode. */
    READ_SWMODEr(unit, &swmode);
    SWMODEr_SW_FWDG_MODEf_SET(swmode, 1);
    SWMODEr_SW_FWDG_ENf_SET(swmode, 1);
    WRITE_SWMODEr(unit, swmode);

    /* Configure the IMP port control */
    MII_PCTLr_CLR(imp_ctl);
    MII_PCTLr_STP_STSf_SET(imp_ctl, 5);
    MII_PCTLr_MIRX_UC_ENf_SET(imp_ctl, 1);
    MII_PCTLr_MIRX_MC_ENf_SET(imp_ctl, 1);
    MII_PCTLr_MIRX_BC_ENf_SET(imp_ctl, 1);
    WRITE_MII_PCTLr(unit, imp_ctl);

    /* Configure the switch to use Desc priority */
    READ_IUDMA_CTRLr(unit, &dma_ctl);
    IUDMA_CTRLr_RXBD_PRIOf_SET(dma_ctl, 1);
    WRITE_IUDMA_CTRLr(unit, dma_ctl);

#if defined(CONFIG_BCM_JUMBO_FRAME)

    /* Enable Jumpbo frame */
    JUMBO_PORT_MASKr_SET(jumbo_msk, PBMAP_ALL);
    WRITE_JUMBO_PORT_MASKr(unit, jumbo_msk);

#endif /* CONFIG_BCM_JUMBO_FRAME */
    QOS_TX_CTRLr_CLR(qos_tx_ctrl);
#if defined(CHIP_6328)
    /* Enable multiple queues and SP scheduling */
    QOS_TX_CTRLr_HQ_PREEMPTf_SET(qos_tx_ctrl, 1);
    QOS_TX_CTRLr_QOS_MODEf_SET(qos_tx_ctrl, 1);
    WRITE_QOS_TX_CTRLr(unit, qos_tx_ctrl);
#else
    {
        QOS_WEIGHTr_t wrr_weight;
        /* Enable SP+WRR (Q3 & Q2 in SP and Q1 & Q0 in WRR)scheduling */
        QOS_TX_CTRLr_HQ_PREEMPTf_SET(qos_tx_ctrl, 1);
        QOS_TX_CTRLr_QOS_MODEf_SET(qos_tx_ctrl, 2);
        WRITE_QOS_TX_CTRLr(unit, qos_tx_ctrl);
        /* Set the WRR weights of all 4 queues to 1 */
        for(i=0; i< NUM_EGRESS_QUEUES; i++) {
            QOS_WEIGHTr_SET(wrr_weight, 1);
            WRITE_QOS_WEIGHTr(unit, i, wrr_weight);
        }
    }
#endif

    /* Disable the auto set of queue buffer thresholds */
    QOS_CTLr_CLR(qos_ctrl);
    WRITE_QOS_CTLr(unit, qos_ctrl);

    /* Set the default flow control value as desired */
    FC_PAUSE_DROP_CTRLr_SET(fc_pause_drop, DEFAULT_FC_CTRL_VAL);
    WRITE_FC_PAUSE_DROP_CTRLr(unit, fc_pause_drop);
    /* Configure Buffer Thresholds */
    for (i = 0; i < NUM_EGRESS_QUEUES; i++) {
        FC_TXQ_TH_RSRV_Qr_SET(txq_hyst, DEFAULT_TXQHI_HYSTERESIS_THRESHOLD);
        ioerr += WRITE_FC_TXQ_TH_RSRV_Qr(unit, i, txq_hyst);
        FC_TXQ_TH_PAUSE_Qr_SET(txq_pause, DEFAULT_TXQHI_PAUSE_THRESHOLD);
        ioerr += WRITE_FC_TXQ_TH_PAUSE_Qr(unit, i, txq_pause);
        FC_TXQ_TH_DROP_Qr_SET(txq_drop, DEFAULT_TXQHI_DROP_THRESHOLD);
        ioerr += WRITE_FC_TXQ_TH_DROP_Qr(unit, i, txq_drop);
        FC_TOTAL_TH_HYST_Qr_SET(total_hyst, DEFAULT_TOTAL_HYSTERESIS_THRESHOLD);
        ioerr += WRITE_FC_TOTAL_TH_HYST_Qr(unit, i, total_hyst);
        FC_TOTAL_TH_PAUSE_Qr_SET(total_pause, DEFAULT_TOTAL_PAUSE_THRESHOLD);
        ioerr += WRITE_FC_TOTAL_TH_PAUSE_Qr(unit, i, total_pause);
        FC_TOTAL_TH_DROP_Qr_SET(total_drop, DEFAULT_TOTAL_DROP_THRESHOLD);
        ioerr += WRITE_FC_TOTAL_TH_DROP_Qr(unit, i, total_drop);
    }

    /* Forward lookup failure to use ULF/MLF/IPMC lookup fail registers */
    NEW_CONTROLr_CLR(new_ctrl);
    NEW_CONTROLr_MC_DLF_FWDf_SET(new_ctrl, 1);
    NEW_CONTROLr_UC_DROP_ENf_SET(new_ctrl, 1);
    NEW_CONTROLr_IP_MULTICASTf_SET(new_ctrl, 1);
    WRITE_NEW_CONTROLr(unit, new_ctrl);

    {
        ULF_DROP_MAPr_t ulf_map;
        MLF_DROP_MAPr_t mlf_map;
        MLF_IMPC_FWD_MAPr_t ipmc_map;
        VLAN_CTRL5r_t vlan_ctl5;

        /* Forward unlearned unicast and unresolved mcast to the MIPS */
        ULF_DROP_MAPr_SET(ulf_map, PBMAP_MIPS);
        WRITE_ULF_DROP_MAPr(unit, ulf_map);
        MLF_DROP_MAPr_SET(mlf_map, PBMAP_MIPS);
        WRITE_MLF_DROP_MAPr(unit, mlf_map);
        MLF_IMPC_FWD_MAPr_SET(ipmc_map, PBMAP_MIPS);
        WRITE_MLF_IMPC_FWD_MAPr(unit, ipmc_map);

        /* Disable tag_status_preserve */
        VLAN_CTRL5r_CLR(vlan_ctl5);
        WRITE_VLAN_CTRL5r(unit, vlan_ctl5);
    }

#if defined(CHIP_6328)
#if defined(EPON_SDK_BUILD)
    {
        unsigned int ret, num_uni_ports, fe_ports, ge_ports;
        ret = devCtl_getNumFePorts(&fe_ports);
        if (ret != 0) {
            printf("ERROR: eponapp not able to get the Number of EPON FE ports. Assuming 4 \n");
            fe_ports = 4;
        }
        ret = devCtl_getNumGePorts(&ge_ports);
        if (ret != 0) {
            printf("ERROR: eponapp not able to get the Number of EPON GE ports. Assuming 0 \n");
            ge_ports = 0;
        }
        num_uni_ports = fe_ports + ge_ports;

        if (num_uni_ports == 1) {
            int epon_port = CDK_DEV_GET_EPON_PORT(0);
            COMM_IRC_CONr_t ctrl;
            PORT_IRC_CONr_t port_ctrl;
            ULF_DROP_MAPr_t ulf_map;
            MLF_DROP_MAPr_t mlf_map;
            MLF_IMPC_FWD_MAPr_t ipmc_map;


            /* EPON 1+1 design work-around for IGMP */
            ULF_DROP_MAPr_SET(ulf_map, config_pbmp | PBMAP_MIPS);
            WRITE_ULF_DROP_MAPr(unit, ulf_map);
            MLF_DROP_MAPr_SET(mlf_map, config_pbmp | PBMAP_MIPS);
            WRITE_MLF_DROP_MAPr(unit, mlf_map);
            MLF_IMPC_FWD_MAPr_SET(ipmc_map, config_pbmp | PBMAP_MIPS);
            WRITE_MLF_IMPC_FWD_MAPr(unit, ipmc_map);

            /* RSTP work-around to avoid MIPS getting loaded by reserved mcast traffic from port-0*/
            for (port = 0; port < SWITCH_LAN_PORTS; port++) {
                if (( port != epon_port) && config_pbmp & (1 << port)) {
                    /* Enable bucket1 rate limiting (250pps) for reserved mcast traffic */
                    READ_COMM_IRC_CONr(unit, &ctrl);
                    COMM_IRC_CONr_PKT_MSK1f_SET(ctrl, 0x10);
                    WRITE_COMM_IRC_CONr(unit, ctrl);
                    READ_PORT_IRC_CONr(unit, port, &port_ctrl);
                    PORT_IRC_CONr_REF_CNT1f_SET(port_ctrl, 0x2);
                    PORT_IRC_CONr_ING_RC_EN1f_SET(port_ctrl, 1);
                    WRITE_PORT_IRC_CONr(unit, port, port_ctrl);
                }
            }
        }
    }
#endif

    /* Enable spanning tree */
    READ_MST_CONr(unit, &mst_con);
    MST_CONr_EN_802_1Sf_SET(mst_con, 1);
    WRITE_MST_CONr(unit, mst_con);

    MST_TBLr_SET(mst_tbl, ALL_PORTS_FORWARDING);
    WRITE_MST_TBLr(unit, 0, mst_tbl);
#endif

    /* Configure the iudma to egress-queue default mapping */
    READ_IUDMA_QUEUE_CTRLr(unit, &iudmaq_ctrl);
    IUDMA_QUEUE_CTRLr_TXQ_SELf_SET(iudmaq_ctrl, DEFAULT_IUDMA_QUEUE_SEL);
    WRITE_IUDMA_QUEUE_CTRLr(unit, iudmaq_ctrl);

    /* Enable Mcast ARL table */
    READ_GARLCFGr(unit, &garl_cfg);
    GARLCFGr_MCAST_ARL_ENf_SET(garl_cfg, 1);
    WRITE_GARLCFGr(unit, garl_cfg);

    /* Disable learning on MIPS */
    READ_DIS_LEARNr(unit, &dis_learn);
    val = DIS_LEARNr_DIS_LEARNf_GET(dis_learn);
    DIS_LEARNr_DIS_LEARNf_SET(dis_learn, (val |PBMAP_MIPS));
#if defined(CHIP_6362) && defined(BRCM_PORTS_ON_INT_EXT_SW)
    DIS_LEARNr_DIS_LEARNf_SET(dis_learn, PBMAP_ALL);
#endif
    WRITE_DIS_LEARNr(unit, dis_learn);

    /* Configure ports with PHY */
    phy_pbmp = CDK_DEV_PHY_PBMP(unit);
    for (port = 0; port < SWITCH_LAN_PORTS; port++) {
        if (phy_pbmp & (1 << port)) {
            rv = bmd_phy_probe(unit, port);
        }
    }

#if defined(CHIP_6362) && defined(BRCM_PORTS_ON_INT_EXT_SW)
    for (port = 0; port <= SWITCH_LAN_PORTS; port++) {
        BCM6300_A0_PORT_VLAN_CTLr_t r;
        if (port == SWITCH_LAN_PORTS)
        {
            PORT_VLAN_CTLr_SET(r, 0x1ff);
        }
        else
        {
            PORT_VLAN_CTLr_SET(r, 0x100);
        }
        // write the register
        WRITE_PORT_VLAN_CTLr(0, port, r);
    }
#endif
    nophy_pbmp = (~phy_pbmp) & config_pbmp;
    printf("[6300] Switch MDK: unit = %d; phy_pbmp = 0x%x; config_pbmp = 0x%x \n", 
        unit, phy_pbmp, config_pbmp);
    for (port = 0; port < SWITCH_LAN_PORTS; port++) {
        if (nophy_pbmp & (1 << port)) {
            STS_OVERRIDE_GPr_SET(sts_override_gp, LINK_OVRD_1000FD);
            WRITE_STS_OVERRIDE_GPr(unit, port, sts_override_gp);
        } else {
            STS_OVERRIDE_GPr_SET(sts_override_gp, LINK_OVRD_DOWN);
#if defined(CHIP_63268)
            if (port == RGMII2_PORT)
                STS_OVERRIDE_GPr_SET(sts_override_gp, LINK_1000FD_DOWN);
#endif
            WRITE_STS_OVERRIDE_GPr(unit, port, sts_override_gp);
        }
    }

    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM6300_A0 */
