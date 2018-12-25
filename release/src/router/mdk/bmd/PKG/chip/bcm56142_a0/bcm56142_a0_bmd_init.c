/*
 * $Id: bcm56142_a0_bmd_init.c,v 1.10 Broadcom SDK $
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
#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56142_A0 == 1

#include <bmd/bmd.h>
#include <bmd/bmd_device.h>
#include <bmdi/arch/xgs_dma.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>
#include <cdk/chip/bcm56142_a0_defs.h>
#include <phy/phy.h>
#include <bmd/bmd_phy_ctrl.h>
#include "bcm56142_a0_bmd.h"
#include "bcm56142_a0_internal.h"

#define PIPE_RESET_TIMEOUT_MSEC         5

#define JUMBO_MAXSZ                     0x3fe8
#define MMU_NUM_COS                     8
static uint8_t tdm[75] = {2,14,26,27,28,29,
                  3,15,26,27,28,29,
                  4,16,26,27,28,29,
                  5,17,26,27,28,29,
                  0,
                  6,18,26,27,28,29,
                  7,19,26,27,28,29,
                  8,20,26,27,28,29,
                  9,21,26,27,28,29,
                  0,
                  10,22,26,27,28,29,
                  11,23,26,27,28,29,
                  12,24,26,27,28,29,
                  13,25,26,27,28,29,
                  30};

static int
_mmu_init(int unit)
{
    int ioerr = 0;
    int port, i;
    cdk_pbmp_t pbmp, mmu_pbmp;
    uint32_t pbm;
    CFAPCONFIGr_t cfapconfig;
    HOLCOSPKTSETLIMITr_t holcospktsetlimit;
    PKTAGINGTIMERr_t pktagingtimer;
    PKTAGINGLIMITr_t pktaginglimit;
    MMUPORTENABLEr_t mmu_port_en;

    /* Ports to configure */
    CDK_PBMP_CLEAR(mmu_pbmp);
    CDK_PBMP_ADD(mmu_pbmp, CMIC_PORT);
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XQPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);

    ioerr += READ_CFAPCONFIGr(unit, &cfapconfig);
    CFAPCONFIGr_CFAPPOOLSIZEf_SET(cfapconfig, BCM56142_A0_MMU_CFAPm_MAX);
    ioerr += WRITE_CFAPCONFIGr(unit, cfapconfig);

    HOLCOSPKTSETLIMITr_SET(holcospktsetlimit, (BCM56142_A0_MMU_XQ0m_MAX+1) / MMU_NUM_COS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        for (i = 0; i < MMU_NUM_COS; i++) {
            ioerr += WRITE_HOLCOSPKTSETLIMITr(unit, port, i, holcospktsetlimit);
        }
    }

    /* Disable packet aging on all COSQs */
    PKTAGINGTIMERr_CLR(pktagingtimer);
    ioerr += WRITE_PKTAGINGTIMERr(unit, pktagingtimer);
    PKTAGINGLIMITr_CLR(pktaginglimit);
    ioerr += WRITE_PKTAGINGLIMITr(unit, pktaginglimit);

    MMUPORTENABLEr_CLR(mmu_port_en);
    pbm = CDK_PBMP_WORD_GET(mmu_pbmp, 0);
    MMUPORTENABLEr_MMUPORTENABLEf_SET(mmu_port_en, pbm);
    ioerr += WRITE_MMUPORTENABLEr(unit, mmu_port_en);

    return ioerr;
}

static int
_port_init(int unit, int port)
{
    int ioerr = 0;
    EGR_ENABLEr_t egr_enable;
    EGR_PORTr_t egr_port;
    EGR_VLAN_CONTROL_1r_t egr_vlan_ctrl1;
    PORT_TABm_t port_tab;

    /* Default port VLAN and tag action, enable L2 HW learning */
    PORT_TABm_CLR(port_tab);
    PORT_TABm_PORT_VIDf_SET(port_tab, 1);
    PORT_TABm_FILTER_ENABLEf_SET(port_tab, 1);
    PORT_TABm_OUTER_TPID_ENABLEf_SET(port_tab, 1);
    PORT_TABm_CML_FLAGS_NEWf_SET(port_tab, 8);
    PORT_TABm_CML_FLAGS_MOVEf_SET(port_tab, 8);
    ioerr += WRITE_PORT_TABm(unit, port, port_tab);

    /* Filter VLAN on egress */
    ioerr += READ_EGR_PORTr(unit, port, &egr_port);
    EGR_PORTr_EN_EFILTERf_SET(egr_port, 1);
    ioerr += WRITE_EGR_PORTr(unit, port, egr_port);

    /* Configure egress VLAN for backward compatibility */
    ioerr += READ_EGR_VLAN_CONTROL_1r(unit, port, &egr_vlan_ctrl1);
    EGR_VLAN_CONTROL_1r_VT_MISS_UNTAGf_SET(egr_vlan_ctrl1, 0);
    EGR_VLAN_CONTROL_1r_REMARK_OUTER_DOT1Pf_SET(egr_vlan_ctrl1, 1);
    ioerr += WRITE_EGR_VLAN_CONTROL_1r(unit, port, egr_vlan_ctrl1);

    /* Egress enable */
    ioerr += READ_EGR_ENABLEr(unit, port, &egr_enable);
    EGR_ENABLEr_PRT_ENABLEf_SET(egr_enable, 1);
    ioerr += WRITE_EGR_ENABLEr(unit, port, egr_enable);

    return ioerr;
}

static int
_gport_init(int unit, int port)
{
    int ioerr = 0;
    COMMAND_CONFIGr_t command_cfg;
    TX_IPG_LENGTHr_t tx_ipg;

    ioerr += _port_init(unit, port);  

    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
    COMMAND_CONFIGr_SW_RESETf_SET(command_cfg, 1);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);

    /* Ensure that MAC (Rx) and loopback mode is disabled */
    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
    COMMAND_CONFIGr_LOOP_ENAf_SET(command_cfg, 0);
    COMMAND_CONFIGr_RX_ENAf_SET(command_cfg, 0);
    COMMAND_CONFIGr_TX_ENAf_SET(command_cfg, 1);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);

    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
    COMMAND_CONFIGr_SW_RESETf_SET(command_cfg, 0);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);

    TX_IPG_LENGTHr_SET(tx_ipg, 12);
    WRITE_TX_IPG_LENGTHr(unit, port, tx_ipg);

    return ioerr;
}

int
bcm56142_a0_xport_init(int unit, int port)
{
    int ioerr = 0;
    XPORT_CONFIGr_t xport_cfg;
    XQPORT_XGXS_NEWCTL_REGr_t xqport_newctl;
    XQPORT_MODE_REGr_t xqport_mode;
    MAC_TXCTRLr_t txctrl;
    MAC_RXCTRLr_t rxctrl;
    MAC_TXMAXSZr_t txmaxsz;
    MAC_RXMAXSZr_t rxmaxsz;
    MAC_CTRLr_t mac_ctrl;

    /* Common GPORT initialization */
    ioerr += _gport_init(unit, port);  
 
    /* Enable XPORT by default if 10G port */
    XPORT_CONFIGr_CLR(xport_cfg);                      
    XPORT_CONFIGr_XPORT_ENf_SET(xport_cfg, 1);
    if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) { 
        XPORT_CONFIGr_HIGIG_MODEf_SET(xport_cfg, 1);
     } else {
        XPORT_CONFIGr_HIGIG_MODEf_SET(xport_cfg, 0);
    }

    ioerr += WRITE_XPORT_CONFIGr(unit, port, xport_cfg); 

    /* Set XPORT mode to 10G by default */
    ioerr += READ_XQPORT_MODE_REGr(unit, port, &xqport_mode);
    XQPORT_MODE_REGr_XQPORT_MODE_BITSf_SET(xqport_mode, 2);
    ioerr += WRITE_XQPORT_MODE_REGr(unit, port, xqport_mode);

    /* Ensure that MAC (Rx) and loopback mode is disabled */
    MAC_CTRLr_CLR(mac_ctrl);
    MAC_CTRLr_TXENf_SET(mac_ctrl, 1);
    ioerr += WRITE_MAC_CTRLr(unit, port, mac_ctrl);

    /* Enable 1G Tx clocks */
    ioerr += READ_XQPORT_XGXS_NEWCTL_REGr(unit, port, &xqport_newctl);
    XQPORT_XGXS_NEWCTL_REGr_TXD1G_FIFO_RSTBf_SET(xqport_newctl, 0xf);
    ioerr += WRITE_XQPORT_XGXS_NEWCTL_REGr(unit, port, xqport_newctl);

    /* Configure Tx (Inter-Packet-Gap, recompute CRC mode, IEEE header) */
    MAC_TXCTRLr_CLR(txctrl);
    MAC_TXCTRLr_AVGIPGf_SET(txctrl, 0xc);
    MAC_TXCTRLr_CRC_MODEf_SET(txctrl, 0x2);
    MAC_TXCTRLr_THROTDENOMf_SET(txctrl, 0x2);
    ioerr += WRITE_MAC_TXCTRLr(unit, port, txctrl);

    /* Configure Rx (strip CRC, strict preamble, IEEE header) */
    MAC_RXCTRLr_CLR(rxctrl);
    MAC_RXCTRLr_STRICTPRMBLf_SET(rxctrl, 1);
    ioerr += WRITE_MAC_RXCTRLr(unit, port, rxctrl);

    /* Set max Tx frame size */
    MAC_TXMAXSZr_CLR(txmaxsz);
    MAC_TXMAXSZr_SZf_SET(txmaxsz, JUMBO_MAXSZ);
    ioerr += WRITE_MAC_TXMAXSZr(unit, port, txmaxsz);

    /* Set max Rx frame size */
    MAC_RXMAXSZr_CLR(rxmaxsz);
    MAC_RXMAXSZr_SZf_SET(rxmaxsz, JUMBO_MAXSZ);
    ioerr += WRITE_MAC_RXMAXSZr(unit, port, rxmaxsz);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

int
bcm56142_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    uint8_t *tdm_table;
    int tdm_size;
    IARB_TDM_TABLEm_t iarb_tdm;
    MMU_ARB_TDM_TABLEm_t mmu_arb_tdm;
    IARB_TDM_CONTROLr_t iarb_tdm_ctrl;
    ING_HW_RESET_CONTROL_1r_t ing_rst_ctl_1;
    ING_HW_RESET_CONTROL_2r_t ing_rst_ctl_2;
    EGR_HW_RESET_CONTROL_0r_t egr_rst_ctl_0;
    EGR_HW_RESET_CONTROL_1r_t egr_rst_ctl_1;
    MISCCONFIGr_t misc_cfg;
    CMIC_RATE_ADJUSTr_t rate_adjust;
    CMIC_RATE_ADJUST_INT_MDIOr_t rate_adjust_int_mdio;
    CMIC_RATE_ADJUST_STDMAr_t rate_adjust_stdma;
    RDBGC0_SELECTr_t rdbgc0_select;
    VLAN_PROFILE_TABm_t vlan_profile;
    ING_VLAN_TAG_ACTION_PROFILEm_t vlan_action;
    EGR_VLAN_TAG_ACTION_PROFILEm_t egr_action;
    GPORT_RSV_MASKr_t gport_rsv_mask;
    GPORT_CONFIGr_t gport_cfg;
    QPORT_CONFIGr_t qport_cfg;
    cdk_pbmp_t pbmp;
    int port;
    int idx;

    BMD_CHECK_UNIT(unit);

    /* Reset the IPIPE block */
    ING_HW_RESET_CONTROL_1r_CLR(ing_rst_ctl_1);
    ioerr += WRITE_ING_HW_RESET_CONTROL_1r(unit, ing_rst_ctl_1);
    ING_HW_RESET_CONTROL_2r_CLR(ing_rst_ctl_2);
    ING_HW_RESET_CONTROL_2r_RESET_ALLf_SET(ing_rst_ctl_2, 1);
    ING_HW_RESET_CONTROL_2r_VALIDf_SET(ing_rst_ctl_2, 1);
    ING_HW_RESET_CONTROL_2r_COUNTf_SET(ing_rst_ctl_2, 0x8000);
    ioerr += WRITE_ING_HW_RESET_CONTROL_2r(unit, ing_rst_ctl_2);

    /* Reset the EPIPE block */
    EGR_HW_RESET_CONTROL_0r_CLR(egr_rst_ctl_0);
    EGR_HW_RESET_CONTROL_1r_CLR(egr_rst_ctl_1);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_0r(unit, egr_rst_ctl_0);
    EGR_HW_RESET_CONTROL_1r_RESET_ALLf_SET(egr_rst_ctl_1, 1);
    EGR_HW_RESET_CONTROL_1r_VALIDf_SET(egr_rst_ctl_1, 1);
    EGR_HW_RESET_CONTROL_1r_COUNTf_SET(egr_rst_ctl_1, 0x4000);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_1r(unit, egr_rst_ctl_1);

    for (idx = 0; idx < PIPE_RESET_TIMEOUT_MSEC; idx++) {
        ioerr += READ_ING_HW_RESET_CONTROL_2r(unit, &ing_rst_ctl_2);
        if (ING_HW_RESET_CONTROL_2r_DONEf_GET(ing_rst_ctl_2)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (idx >= PIPE_RESET_TIMEOUT_MSEC) {
        CDK_WARN(("bcm56142_a0_bmd_init[%d]: IPIPE reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }
        
    for (; idx < PIPE_RESET_TIMEOUT_MSEC; idx++) {
        ioerr += READ_EGR_HW_RESET_CONTROL_1r(unit, &egr_rst_ctl_1);
        if (EGR_HW_RESET_CONTROL_1r_DONEf_GET(egr_rst_ctl_1)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (idx >= PIPE_RESET_TIMEOUT_MSEC) {
        CDK_WARN(("bcm56142_a0_bmd_init[%d]: EPIPE reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }

    /* Clear pipe reset registers */
    ING_HW_RESET_CONTROL_2r_CLR(ing_rst_ctl_2);
    ioerr += WRITE_ING_HW_RESET_CONTROL_2r(unit, ing_rst_ctl_2);
    EGR_HW_RESET_CONTROL_1r_CLR(egr_rst_ctl_1);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_1r(unit, egr_rst_ctl_1);

    /* XQPORT and GPORT configuration determines which TDM table to use */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPORT, &pbmp);
    tdm_table = tdm;
    tdm_size = COUNTOF(tdm);

    /* Initialize TDM arbiter table */
    CDK_XGS_MEM_CLEAR(unit, IARB_TDM_TABLEm);
    CDK_XGS_MEM_CLEAR(unit, MMU_ARB_TDM_TABLEm);
    for (idx = 0; idx < tdm_size; idx++) {
        IARB_TDM_TABLEm_CLR(iarb_tdm);
        MMU_ARB_TDM_TABLEm_CLR(mmu_arb_tdm);
        IARB_TDM_TABLEm_PORT_NUMf_SET(iarb_tdm, tdm_table[idx]);
        MMU_ARB_TDM_TABLEm_PORT_NUMf_SET(mmu_arb_tdm, tdm_table[idx]);
        if (idx == (tdm_size - 1)) {
            MMU_ARB_TDM_TABLEm_WRAP_ENf_SET(mmu_arb_tdm, 1);
        }
        ioerr += WRITE_IARB_TDM_TABLEm(unit, idx, iarb_tdm);
        ioerr += WRITE_MMU_ARB_TDM_TABLEm(unit, idx, mmu_arb_tdm);
    }

    /* Enable arbiter */
    ioerr += READ_IARB_TDM_CONTROLr(unit, &iarb_tdm_ctrl);
    IARB_TDM_CONTROLr_DISABLEf_SET(iarb_tdm_ctrl, 0);
    ioerr += WRITE_IARB_TDM_CONTROLr(unit, iarb_tdm_ctrl);

    /* Enable Field Processor metering clock */
    ioerr += READ_MISCCONFIGr(unit, &misc_cfg);
    MISCCONFIGr_METERING_CLK_ENf_SET(misc_cfg, 1);
    ioerr += WRITE_MISCCONFIGr(unit, misc_cfg);

    /*
     * Set reference clock (based on 200MHz core clock)
     * to be 200MHz * (1/40) = 5MHz
     */
    CMIC_RATE_ADJUSTr_CLR(rate_adjust);
    CMIC_RATE_ADJUSTr_DIVISORf_SET(rate_adjust, 40);
    CMIC_RATE_ADJUSTr_DIVIDENDf_SET(rate_adjust, 1);
    ioerr += WRITE_CMIC_RATE_ADJUSTr(unit, rate_adjust);

    /* Match the Internal MDC freq with above for External MDC */
    CMIC_RATE_ADJUST_INT_MDIOr_CLR(rate_adjust_int_mdio);
    CMIC_RATE_ADJUST_INT_MDIOr_DIVISORf_SET(rate_adjust_int_mdio, 40);
    CMIC_RATE_ADJUST_INT_MDIOr_DIVIDENDf_SET(rate_adjust_int_mdio, 1);
    ioerr += WRITE_CMIC_RATE_ADJUST_INT_MDIOr(unit, rate_adjust_int_mdio);

    /*
     * Set reference clock (based on 200MHz core clock)
     * to be 200MHz * (1/8) = 25MHz
     */
    CMIC_RATE_ADJUST_STDMAr_CLR(rate_adjust_stdma);
    CMIC_RATE_ADJUST_STDMAr_DIVISORf_SET(rate_adjust_stdma, 8);
    CMIC_RATE_ADJUST_STDMAr_DIVIDENDf_SET(rate_adjust_stdma, 1);
    ioerr += WRITE_CMIC_RATE_ADJUST_STDMAr(unit, rate_adjust_stdma);

    /* Configure discard counter */
    RDBGC0_SELECTr_CLR(rdbgc0_select);
    RDBGC0_SELECTr_BITMAPf_SET(rdbgc0_select, 0x0400ad11);
    ioerr += WRITE_RDBGC0_SELECTr(unit, rdbgc0_select);

    /* Initialize MMU */
    ioerr += _mmu_init(unit);

    /* Default VLAN profile */
    VLAN_PROFILE_TABm_CLR(vlan_profile);
    VLAN_PROFILE_TABm_L2_PFMf_SET(vlan_profile, 1);
    VLAN_PROFILE_TABm_L3_IPV4_PFMf_SET(vlan_profile, 1);
    VLAN_PROFILE_TABm_L3_IPV6_PFMf_SET(vlan_profile, 1);
    VLAN_PROFILE_TABm_IPMCV6_ENABLEf_SET(vlan_profile, 1);
    VLAN_PROFILE_TABm_IPMCV4_ENABLEf_SET(vlan_profile, 1);
    VLAN_PROFILE_TABm_IPMCV6_L2_ENABLEf_SET(vlan_profile, 1);
    VLAN_PROFILE_TABm_IPMCV4_L2_ENABLEf_SET(vlan_profile, 1);
    VLAN_PROFILE_TABm_IPV6L3_ENABLEf_SET(vlan_profile, 1);
    VLAN_PROFILE_TABm_IPV4L3_ENABLEf_SET(vlan_profile, 1);
    ioerr += WRITE_VLAN_PROFILE_TABm(unit, VLAN_PROFILE_TABm_MAX, vlan_profile);

    /* Ensure that all incoming packets get tagged appropriately */
    ING_VLAN_TAG_ACTION_PROFILEm_CLR(vlan_action);
    ING_VLAN_TAG_ACTION_PROFILEm_UT_OTAG_ACTIONf_SET(vlan_action, 1);
    ING_VLAN_TAG_ACTION_PROFILEm_SIT_PITAG_ACTIONf_SET(vlan_action, 3);
    ING_VLAN_TAG_ACTION_PROFILEm_SIT_OTAG_ACTIONf_SET(vlan_action, 1);
    ING_VLAN_TAG_ACTION_PROFILEm_SOT_POTAG_ACTIONf_SET(vlan_action, 2);
    ING_VLAN_TAG_ACTION_PROFILEm_DT_POTAG_ACTIONf_SET(vlan_action, 2);
    ioerr += WRITE_ING_VLAN_TAG_ACTION_PROFILEm(unit, 0, vlan_action);

    /* Create special egress action profile for HiGig ports */
    EGR_VLAN_TAG_ACTION_PROFILEm_CLR(egr_action);
    EGR_VLAN_TAG_ACTION_PROFILEm_SOT_OTAG_ACTIONf_SET(egr_action, 3);
    EGR_VLAN_TAG_ACTION_PROFILEm_DT_OTAG_ACTIONf_SET(egr_action, 3);
    ioerr += WRITE_EGR_VLAN_TAG_ACTION_PROFILEm(unit, 1, egr_action);

    /* Fixup packet purge filtering */
    GPORT_RSV_MASKr_SET(gport_rsv_mask, 0x70);
    ioerr += WRITE_GPORT_RSV_MASKr(unit, gport_rsv_mask, -1);

    /* Enable GPORTs and clear counters */
    ioerr += READ_GPORT_CONFIGr(unit, &gport_cfg, -1);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 1);
    ioerr += WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);
    GPORT_CONFIGr_GPORT_ENf_SET(gport_cfg, 1);
    ioerr += WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 0);
    ioerr += WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);

    /* Configure GPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _gport_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }

    /* Configure XQPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XQPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        /* Clears GPORT counters in XQPORT */
        ioerr += READ_QPORT_CONFIGr(unit, port, &qport_cfg);
        QPORT_CONFIGr_CLR_CNTf_SET(qport_cfg, 1);
        ioerr += WRITE_QPORT_CONFIGr(unit, port, qport_cfg);
        /* give a delay, with extra reads */
        ioerr += READ_QPORT_CONFIGr(unit, port, &qport_cfg);
        ioerr += READ_QPORT_CONFIGr(unit, port, &qport_cfg);
        QPORT_CONFIGr_CLR_CNTf_SET(qport_cfg, 0);
        ioerr += WRITE_QPORT_CONFIGr(unit, port, qport_cfg);

        ioerr += bcm56142_a0_xport_init(unit, port);

        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_probe(unit, port);
        }
        
        if ((CDK_XGS_FLAGS(unit) & CHIP_FLAG_FE_ONLY)){
            if (CDK_SUCCESS(rv)) {
                rv = bmd_phy_mode_set(unit, port, "hypercore",
                                        BMD_PHY_MODE_2LANE, 1);
            }
        } else if ((CDK_XGS_FLAGS(unit) & CHIP_FLAG_HD25_HD127)){
            rv = bmd_phy_mode_set(unit, port, "hypercore",
                                        BMD_PHY_MODE_2LANE, 1);
#if BMD_CONFIG_INCLUDE_PHY == 1
            if (CDK_SUCCESS(rv)) {
                phy_ctrl_t *pc;
                CMIC_MISC_STATUSr_t misc_stat;
                ioerr += READ_CMIC_MISC_STATUSr(unit, &misc_stat);
                if (CMIC_MISC_STATUSr_DUAL_XGXS_MODE_SELf_GET(misc_stat) == 0) {
                    if ((port == 28) || (port == 29)) {
                        pc = BMD_PORT_PHY_CTRL(unit, port);
                        /* indicate as dxgxs ports */
                        PHY_CTRL_FLAGS(pc) |= PHY_F_R2_MODE; /* indicate as dxgxs ports */
                    }
                } else {
                    if ((port == 26) || (port == 27)) {
                        pc = BMD_PORT_PHY_CTRL(unit, port);
                        /* indicate as dxgxs ports */
                        PHY_CTRL_FLAGS(pc) |= PHY_F_R2_MODE; /* indicate as dxgxs ports */
                    }
                }
            }
#endif
        } else {
            if (port > 27 && port < 30){
                rv = bmd_phy_mode_set(unit, port, "hypercore",
                                        BMD_PHY_MODE_2LANE, 1);
#if BMD_CONFIG_INCLUDE_PHY == 1
                if (CDK_SUCCESS(rv)) {
                    phy_ctrl_t *pc;

                    pc = BMD_PORT_PHY_CTRL(unit, port);
                    /* indicate as dxgxs ports */
                    PHY_CTRL_FLAGS(pc) |= PHY_F_R2_MODE; /* indicate as dxgxs ports */
                }
#endif
             }
        }
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_init(unit, port);
        }
    }
#if BMD_CONFIG_INCLUDE_DMA
    /* Common port initialization for CPU port */
    ioerr += _port_init(unit, CMIC_PORT);

    if (CDK_SUCCESS(rv)) {
        rv = bmd_xgs_dma_init(unit);
    }
#endif
    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56142_A0 */
