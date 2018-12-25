#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56624_A0 == 1

/*
 * $Id: bcm56624_a0_bmd_init.c,v 1.19 Broadcom SDK $
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

#include <bmdi/arch/xgs_dma.h>

#include <cdk/chip/bcm56624_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56624_a0_bmd.h"
#include "bcm56624_a0_internal.h"

#define PIPE_RESET_TIMEOUT_MSEC         5

#define JUMBO_MAXSZ                     0x3fe8

#define MMU_NUM_COS                     8

#define MMU_ETH_FRAME_CELLS             12
#define MMU_JUMBO_FRAME_CELLS           128

#define MMU_PORT_MIN_CELLS              72
#define MMU_PORT_MIN_PACKETS            1

#define MMU_OP_PORT_MIN_CELLS           12
#define MMU_OP_PORT_MIN_PACKETS         1

static int
_mmu_init(int unit)
{
    int ioerr = 0;
    int port, i, port_min, q_min, obs_limit;
    cdk_pbmp_t pbmp, mmu_pbmp;
    uint32_t pbm;
    PORT_MIN_CELLr_t port_min_cell;
    TOTAL_SHARED_LIMIT_CELLr_t ts_limit_cell;
    PORT_SHARED_LIMIT_CELLr_t port_shared_limit_cell;
    PORT_MAX_PKT_SIZEr_t port_max_pkt_size;
    PORT_MIN_PACKETr_t port_min_packet;
    TOTAL_SHARED_LIMIT_PACKETr_t ts_limit_packet;
    OP_QUEUE_CONFIG_CELLr_t op_q_cfg_cell;
    OP_BUFFER_SHARED_LIMIT_CELLr_t obs_limit_cell;
    OP_PORT_CONFIG_CELLr_t op_port_cfg_cell;
    OP_QUEUE_CONFIG_PACKETr_t op_q_cfg_pkt;
    OP_BUFFER_SHARED_LIMIT_PACKETr_t obs_limit_packet;
    OP_PORT_CONFIG_PACKETr_t op_port_cfg_pkt;
    INPUT_PORT_RX_ENABLE_64r_t inp_rx_enable;
    OUTPUT_PORT_RX_ENABLE_64r_t outp_rx_enable;
    IESMIF_CONTROLr_t iesmif_ctrl;
    uint32_t total_cells = 32L * 1024;
    uint32_t total_pkts = 11L * 1024;

    /* Ports to configure */
    CDK_PBMP_CLEAR(mmu_pbmp);
    CDK_PBMP_ADD(mmu_pbmp, CMIC_PORT);
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_SPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XGPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);
#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GXPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);
#endif

    /*
     * Ingress limits and thresholds.
     *
     * Note that no cells or packets are reserved for
     * priority groups (PGs).
     */

    /* Minimum cells per port */
    port_min = 0;
    PORT_MIN_CELLr_SET(port_min_cell, MMU_PORT_MIN_CELLS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_MIN_CELLr(unit, port, port_min_cell);
        port_min += MMU_PORT_MIN_CELLS;
    }

    /* Use remaining cells for shared cells */
    TOTAL_SHARED_LIMIT_CELLr_SET(ts_limit_cell, total_cells - port_min);
    ioerr += WRITE_TOTAL_SHARED_LIMIT_CELLr(unit, ts_limit_cell);

    /* Use dynamic limit with alpha = 8 */
    PORT_SHARED_LIMIT_CELLr_CLR(port_shared_limit_cell);
    PORT_SHARED_LIMIT_CELLr_PORT_SHARED_DYNAMICf_SET(port_shared_limit_cell, 1);
    PORT_SHARED_LIMIT_CELLr_PORT_SHARED_LIMITf_SET(port_shared_limit_cell, 7);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_SHARED_LIMIT_CELLr(unit, port, port_shared_limit_cell);
    }

    /* Max packet size (in cells) */
    PORT_MAX_PKT_SIZEr_SET(port_max_pkt_size, MMU_JUMBO_FRAME_CELLS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_MAX_PKT_SIZEr(unit, port, port_max_pkt_size);
    }

    /* Minimum packets per port */
    port_min = 0;
    PORT_MIN_PACKETr_SET(port_min_packet, MMU_PORT_MIN_PACKETS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_MIN_PACKETr(unit, port, port_min_packet);
        port_min += MMU_PORT_MIN_PACKETS;
    }

    /* Use remaining packets for shared packets */
    TOTAL_SHARED_LIMIT_PACKETr_SET(ts_limit_packet, total_pkts - port_min);
    ioerr += WRITE_TOTAL_SHARED_LIMIT_PACKETr(unit, ts_limit_packet);

    /*
     * Egress limits and thresholds.
     *
     * Note that no cells or packets are reserved for
     * priority groups (PGs).
     */

    /* Minimum cells per port, use dynamic limit with alpha = 4 */
    q_min = 0;
    OP_QUEUE_CONFIG_CELLr_CLR(op_q_cfg_cell);
    OP_QUEUE_CONFIG_CELLr_Q_MIN_CELLf_SET(op_q_cfg_cell, MMU_OP_PORT_MIN_CELLS);
    OP_QUEUE_CONFIG_CELLr_Q_LIMIT_ENABLE_CELLf_SET(op_q_cfg_cell, 1);
    OP_QUEUE_CONFIG_CELLr_Q_LIMIT_DYNAMIC_CELLf_SET(op_q_cfg_cell, 1);
    OP_QUEUE_CONFIG_CELLr_Q_SHARED_LIMIT_CELLf_SET(op_q_cfg_cell, 6);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        for (i = 0; i < MMU_NUM_COS; i++) {
            ioerr += WRITE_OP_QUEUE_CONFIG_CELLr(unit, port, i, op_q_cfg_cell);
            q_min += MMU_OP_PORT_MIN_CELLS;
        }
    }

    /* Use remaining cells for shared cells */
    obs_limit = total_cells - q_min;
    OP_BUFFER_SHARED_LIMIT_CELLr_SET(obs_limit_cell, obs_limit);
    ioerr += WRITE_OP_BUFFER_SHARED_LIMIT_CELLr(unit, obs_limit_cell);

    /* Configure limit/reset thresholds as 3/4 and 1/2 of shared limit */
    OP_PORT_CONFIG_CELLr_CLR(op_port_cfg_cell);
    OP_PORT_CONFIG_CELLr_OP_SHARED_LIMIT_CELLf_SET(op_port_cfg_cell, 
                                                   (obs_limit * 3) / 4);
    OP_PORT_CONFIG_CELLr_OP_SHARED_RESET_VALUE_CELLf_SET(op_port_cfg_cell, 
                                                         obs_limit / 2);
    OP_PORT_CONFIG_CELLr_PORT_LIMIT_ENABLE_CELLf_SET(op_port_cfg_cell, 1);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_OP_PORT_CONFIG_CELLr(unit, port, op_port_cfg_cell);
    }

    /* Minimum packets per port, use dynamic limit with alpha = 4 */
    q_min = 0;
    OP_QUEUE_CONFIG_PACKETr_CLR(op_q_cfg_pkt);
    OP_QUEUE_CONFIG_PACKETr_Q_MIN_PACKETf_SET(op_q_cfg_pkt, 
                                              MMU_OP_PORT_MIN_PACKETS);
    OP_QUEUE_CONFIG_PACKETr_Q_LIMIT_ENABLE_PACKETf_SET(op_q_cfg_pkt, 1);
    OP_QUEUE_CONFIG_PACKETr_Q_LIMIT_DYNAMIC_PACKETf_SET(op_q_cfg_pkt, 1);
    OP_QUEUE_CONFIG_PACKETr_Q_SHARED_LIMIT_PACKETf_SET(op_q_cfg_pkt, 6);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        for (i = 0; i < MMU_NUM_COS; i++) {
            ioerr += WRITE_OP_QUEUE_CONFIG_PACKETr(unit, port, i, op_q_cfg_pkt);
        }
    }

    /* Use remaining packets for shared packets */
    obs_limit = total_pkts - q_min;
    OP_BUFFER_SHARED_LIMIT_PACKETr_SET(obs_limit_packet, obs_limit);
    ioerr += WRITE_OP_BUFFER_SHARED_LIMIT_PACKETr(unit, obs_limit_packet);

    /* Configure limit/reset thresholds as 3/4 and 1/2 of shared limit */
    OP_PORT_CONFIG_PACKETr_CLR(op_port_cfg_pkt);
    OP_PORT_CONFIG_PACKETr_OP_SHARED_LIMIT_PACKETf_SET(op_port_cfg_pkt, 
                                                       (obs_limit * 3) / 4);
    OP_PORT_CONFIG_PACKETr_OP_SHARED_RESET_VALUE_PACKETf_SET(op_port_cfg_pkt, 
                                                      obs_limit / 2);
    OP_PORT_CONFIG_PACKETr_PORT_LIMIT_ENABLE_PACKETf_SET(op_port_cfg_pkt, 1);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_OP_PORT_CONFIG_PACKETr(unit, port, op_port_cfg_pkt);
    }

    /* Port enable */
    INPUT_PORT_RX_ENABLE_64r_CLR(inp_rx_enable);
    pbm = CDK_PBMP_WORD_GET(mmu_pbmp, 0);
    INPUT_PORT_RX_ENABLE_64r_INPUT_PORT_RX_ENABLE_LOf_SET(inp_rx_enable, pbm);
    pbm = CDK_PBMP_WORD_GET(mmu_pbmp, 1);
    INPUT_PORT_RX_ENABLE_64r_INPUT_PORT_RX_ENABLE_HIf_SET(inp_rx_enable, pbm);
    ioerr += WRITE_INPUT_PORT_RX_ENABLE_64r(unit, inp_rx_enable);

    OUTPUT_PORT_RX_ENABLE_64r_CLR(outp_rx_enable);
    pbm = CDK_PBMP_WORD_GET(mmu_pbmp, 0);
    OUTPUT_PORT_RX_ENABLE_64r_OUTPUT_PORT_RX_ENABLE_LOf_SET(outp_rx_enable, pbm);
    pbm = CDK_PBMP_WORD_GET(mmu_pbmp, 1);
    OUTPUT_PORT_RX_ENABLE_64r_OUTPUT_PORT_RX_ENABLE_HIf_SET(outp_rx_enable, pbm);
    ioerr += WRITE_OUTPUT_PORT_RX_ENABLE_64r(unit, outp_rx_enable);

    /* Disable external ESM searches */
    ioerr += READ_IESMIF_CONTROLr(unit, &iesmif_ctrl);
    IESMIF_CONTROLr_EN_EXT_SEARCH_REQf_SET(iesmif_ctrl, 0);
    ioerr += WRITE_IESMIF_CONTROLr(unit, iesmif_ctrl);

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

    /* Common port initialization */
    ioerr += _port_init(unit, port);

    /* Ensure that MAC (Rx) and loopback mode is disabled */
    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
    COMMAND_CONFIGr_LOOP_ENAf_SET(command_cfg, 0);
    COMMAND_CONFIGr_RX_ENAf_SET(command_cfg, 0);
    COMMAND_CONFIGr_TX_ENAf_SET(command_cfg, 1);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);

    return ioerr;
}

int
bcm56624_a0_xport_init(int unit, int port)
{
    int ioerr = 0;
    XPORT_CONFIGr_t xport_cfg;
    XPORT_MODE_REGr_t xport_mode;
    XPORT_XGXS_NEWCTL_REGr_t xport_newctl;
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
    ioerr += WRITE_XPORT_CONFIGr(unit, port, xport_cfg);

    /* Set XPORT mode to 10G by default */
    ioerr += READ_XPORT_MODE_REGr(unit, port, &xport_mode);
    XPORT_MODE_REGr_XPORT_MODE_BITSf_SET(xport_mode, 1);
    ioerr += WRITE_XPORT_MODE_REGr(unit, port, xport_mode);

    /* Ensure that MAC (Rx) and loopback mode is disabled */
    MAC_CTRLr_CLR(mac_ctrl);
    MAC_CTRLr_TXENf_SET(mac_ctrl, 1);
    ioerr += WRITE_MAC_CTRLr(unit, port, mac_ctrl);

    /* Enable 1G Tx clocks */
    ioerr += READ_XPORT_XGXS_NEWCTL_REGr(unit, port, &xport_newctl);
    XPORT_XGXS_NEWCTL_REGr_TXD1G_FIFO_RSTBf_SET(xport_newctl, 0xf);
    ioerr += WRITE_XPORT_XGXS_NEWCTL_REGr(unit, port, xport_newctl);

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

    return ioerr;
}

int
bcm56624_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    IARB_TDM_CONTROLr_t iarb_tdm_ctrl;
    ESTDMCONFIGr_t estdmconfig;
    ING_HW_RESET_CONTROL_1r_t ing_rst_ctl_1;
    ING_HW_RESET_CONTROL_2r_t ing_rst_ctl_2;
    EGR_HW_RESET_CONTROL_0r_t egr_rst_ctl_0;
    EGR_HW_RESET_CONTROL_1r_t egr_rst_ctl_1;
    MISCCONFIGr_t misc_cfg;
    CMIC_RATE_ADJUSTr_t rate_adjust;
    CMIC_RATE_ADJUST_INT_MDIOr_t rate_adjust_int_mdio;
    RDBGC0_SELECTr_t rdbgc0_select;
    SPORT_CTL_REGr_t sport_ctl;
    XGPORT_MODE_REGr_t xgport_mode;
    XGPORT_XGXS_NEWCTL_REGr_t xgport_newctl;
    XGPORT_EXTRA_XGXS_NEWCTL_REGr_t xgport_enewctl;
    VLAN_PROFILE_TABm_t vlan_profile;
    ING_VLAN_TAG_ACTION_PROFILEm_t vlan_action;
    EGR_VLAN_TAG_ACTION_PROFILEm_t egr_action;
    GPORT_RSV_MASKr_t gport_rsv_mask;
    GPORT_CONFIGr_t gport_cfg;
    cdk_pbmp_t pbmp;
    int xg_xports[] = { 2, 14, 26, 27 };
    int xg_modes[] = { 1, 1, 1, 1 };
    int hc_extra_ports[] = { 6, 35 };
    int mdio_div;
    int port;
    int idx;

    BMD_CHECK_UNIT(unit);

    ioerr += READ_IARB_TDM_CONTROLr(unit, &iarb_tdm_ctrl);
    IARB_TDM_CONTROLr_DISABLEf_SET(iarb_tdm_ctrl, 0);
    ioerr += WRITE_IARB_TDM_CONTROLr(unit, iarb_tdm_ctrl);

    /* Configure egress scheduler for 16 Gbps */
    ioerr += READ_ESTDMCONFIGr(unit, &estdmconfig);
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XG01_16G) {
        ESTDMCONFIGr_GROUP0_MODEf_SET(estdmconfig, 2);
        ESTDMCONFIGr_GROUP1_MODEf_SET(estdmconfig, 2);
        xg_modes[0] = 2;
        xg_modes[1] = 2;
    }
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XG23_16G) {
        ESTDMCONFIGr_GROUP2_MODEf_SET(estdmconfig, 2);
        ESTDMCONFIGr_GROUP3_MODEf_SET(estdmconfig, 2);
        xg_modes[2] = 2;
        xg_modes[3] = 2;
    }
    ioerr += WRITE_ESTDMCONFIGr(unit, estdmconfig);

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
        CDK_WARN(("bcm56624_a0_bmd_init[%d]: IPIPE reset timeout\n", unit));
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
        CDK_WARN(("bcm56624_a0_bmd_init[%d]: EPIPE reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }

    /* Clear pipe reset registers */
    ING_HW_RESET_CONTROL_2r_CLR(ing_rst_ctl_2);
    ioerr += WRITE_ING_HW_RESET_CONTROL_2r(unit, ing_rst_ctl_2);
    EGR_HW_RESET_CONTROL_1r_CLR(egr_rst_ctl_1);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_1r(unit, egr_rst_ctl_1);

    /* Enable Field Processor metering clock */
    ioerr += READ_MISCCONFIGr(unit, &misc_cfg);
    MISCCONFIGr_METERING_CLK_ENf_SET(misc_cfg, 1);
    ioerr += WRITE_MISCCONFIGr(unit, misc_cfg);

    /*
     * Set MDIO reference clocks based on core clock:
     * mdio_refclk = coreclk * (1/divisor)
     *
     * Actual MDIO clock is reference clock divided by 2:
     * mdio_clk = mdio_refclk/2
     */

    /* mdio_refclk = 200 MHz * (1/40) = 5 MHz */
    mdio_div = 40;

    /* Configure internal MDC (refclk/2 = 2.5 MHz) */
    CMIC_RATE_ADJUST_INT_MDIOr_CLR(rate_adjust_int_mdio);
    CMIC_RATE_ADJUST_INT_MDIOr_DIVISORf_SET(rate_adjust_int_mdio, mdio_div);
    CMIC_RATE_ADJUST_INT_MDIOr_DIVIDENDf_SET(rate_adjust_int_mdio, 1);
    ioerr += WRITE_CMIC_RATE_ADJUST_INT_MDIOr(unit, rate_adjust_int_mdio);

    /* Configure external MDC (1/2 * refclk/2 = 1.25 MHz) */
    CMIC_RATE_ADJUSTr_CLR(rate_adjust);
    CMIC_RATE_ADJUSTr_DIVISORf_SET(rate_adjust, 2 * mdio_div);
    CMIC_RATE_ADJUSTr_DIVIDENDf_SET(rate_adjust, 1);
    ioerr += WRITE_CMIC_RATE_ADJUSTr(unit, rate_adjust);

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
    VLAN_PROFILE_TABm_MPLS_ENABLEf_SET(vlan_profile, 1);
    WRITE_VLAN_PROFILE_TABm(unit, VLAN_PROFILE_TABm_MAX, vlan_profile);

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

    /* Clear GPORT counters */
    ioerr += READ_GPORT_CONFIGr(unit, &gport_cfg, -1);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 1);
    ioerr += WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 0);
    ioerr += WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);

    /* Enable SPORT */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_SPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += READ_SPORT_CTL_REGr(unit, port, &sport_ctl);
        SPORT_CTL_REGr_SPORT_EN_BITf_SET(sport_ctl, 1);
        ioerr += WRITE_SPORT_CTL_REGr(unit, port, sport_ctl);
    }

    /* Enable XGPORTs */
    for (idx = 0; idx < COUNTOF(xg_xports); idx++) {
        port = xg_xports[idx];
        if (!CDK_XGS_PORT_VALID(unit, port)) {
            continue;
        }
        ioerr += READ_XGPORT_MODE_REGr(unit, &xgport_mode, port);
        XGPORT_MODE_REGr_XGPORT_MODE_BITSf_SET(xgport_mode, xg_modes[idx]);
        ioerr += WRITE_XGPORT_MODE_REGr(unit, xgport_mode, port);
    }

    /* Configure SPORT */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_SPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _gport_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }

    /* Configure XGPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XGPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _gport_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }

    /* Enable Hypercore Tx clocks */
    for (idx = 0; idx < COUNTOF(xg_xports); idx++) {
        port = xg_xports[idx];
        if (!CDK_XGS_PORT_VALID(unit, port)) {
            continue;
        }
        ioerr += READ_XGPORT_XGXS_NEWCTL_REGr(unit, &xgport_newctl, port);
        XGPORT_XGXS_NEWCTL_REGr_TXD1G_FIFO_RSTBf_SET(xgport_newctl, 0xf);
        ioerr += WRITE_XGPORT_XGXS_NEWCTL_REGr(unit, xgport_newctl, port);
    }
    for (idx = 0; idx < COUNTOF(hc_extra_ports); idx++) {
        port = hc_extra_ports[idx];
        if (!CDK_XGS_PORT_VALID(unit, port)) {
            continue;
        }
        ioerr += READ_XGPORT_EXTRA_XGXS_NEWCTL_REGr(unit, &xgport_enewctl, port);
        XGPORT_EXTRA_XGXS_NEWCTL_REGr_TXD1G_FIFO_RSTBf_SET(xgport_enewctl, 0xf);
        ioerr += WRITE_XGPORT_EXTRA_XGXS_NEWCTL_REGr(unit, xgport_enewctl, port);
    }

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    /* Configure GXPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GXPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += bcm56624_a0_xport_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XG01_16G) {
        ioerr += bcm56624_a0_xport_init(unit, 2);
        ioerr += bcm56624_a0_xport_init(unit, 14);
    }
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XG23_16G) {
        ioerr += bcm56624_a0_xport_init(unit, 26);
        ioerr += bcm56624_a0_xport_init(unit, 27);
    }
#endif

#if BMD_CONFIG_INCLUDE_DMA
    /* Common port initialization for CPU port */
    ioerr += _port_init(unit, CMIC_PORT);

    if (CDK_SUCCESS(rv)) {
        rv = bmd_xgs_dma_init(unit);
    }
#endif

    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56624_A0 */
