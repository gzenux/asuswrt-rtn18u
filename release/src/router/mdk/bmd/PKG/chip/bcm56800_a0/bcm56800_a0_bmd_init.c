#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56800_A0 == 1

/*
 * $Id: bcm56800_a0_bmd_init.c,v 1.10 Broadcom SDK $
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

#include <cdk/chip/bcm56800_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56800_a0_bmd.h"
#include "bcm56800_a0_internal.h"

#define PIPE_RESET_TIMEOUT_MSEC         5

#define JUMBO_MAXSZ                     0x3fe8

/* Number of COS queues */
#define MMU_NUM_COS                     8

/* Number of priority groups */
#define MMU_NUM_PG                      3

/* Total number of cell available */
#define MMU_TOTAL_CELLS                 (12 * 1024)

/* Standard Ethernet MTU (1 cell = 128 bytes) */
#define MMU_MTU_CELLS                   12

/* Jumbo Frame MTU (1 cell = 128 bytes) */
#define MMU_JUMBO_CELLS                 80

/* The following number of cells is based on packet simulations */
#define MMU_PORT_MIN                    72
#define MMU_SC_MIN                      12
#define MMU_QM_MIN                      12

/* Enough to absorb in-flight data during PAUSE response */
#define MMU_PG2_HDRM_LIMIT              32

/* Alternative disabling method b/c PORT_LIMIT_ENABLE bit is broken */
#define LIMIT_DISABLE                   0x3000

/* CFAP adjustments */
#define MMU_CFAP_FULL_SET_OFFSET        0x100
#define MMU_CFAP_FULL_RESET_OFFSET      0x1b0

static int
_mmu_init(int unit)
{
    int ioerr = 0;
    int port, i;
    int num_ports;
    cdk_pbmp_t pbmp, mmu_pbmp;
    uint32_t pbm;
    uint32_t total_shared_limit;
    uint32_t global_hdrm_limit;
    uint32_t q_min;
    uint32_t op_buffer_shared_limit;
    uint32_t cfap_offset;
    TOTAL_SHARED_LIMITr_t ts_limit;
    GLOBAL_HDRM_LIMITr_t gh_limit;
    PORT_MINr_t port_min;
    PORT_MAX_PKT_SIZEr_t p_max_pkt_sz;
    PORT_SHARED_LIMITr_t p_shared_limit;
    PG_THRESH_SELr_t pg_thresh_sel;
    PG_RESET_SELr_t pg_reset_sel;
    PG_RESET_FLOORr_t pg_reset_floor;
    PG_MINr_t pg_min;
    PG_HDRM_LIMITr_t pg_hdrm_limit;
    PORT_PRI_GRPr_t port_pri_grp;
    PORT_SC_MINr_t port_sc_min;
    PORT_QM_MINr_t port_qm_min;
    OP_BUFFER_SHARED_LIMITr_t obs_limit;
    OP_PORT_CONFIGr_t op_port_config;
    OP_QUEUE_CONFIGr_t op_queue_config;
    OP_THR_CONFIGr_t op_thr_config;
    CFAPCONFIGr_t cfapconfig;
    CFAPFULLTHRESHOLDr_t cfapfullthreshold;
    PORT_PRI_XON_ENABLEr_t port_pri_xon_enable;
    INPUT_PORT_RX_ENABLEr_t input_port_rx_enable;
    OUTPUT_PORT_RX_ENABLEr_t output_port_rx_enable;

    /* Ports to configure */
    CDK_PBMP_CLEAR(mmu_pbmp);
    CDK_PBMP_ADD(mmu_pbmp, CMIC_PORT);
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GXPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);

    num_ports = 0;
    CDK_PBMP_ITER(mmu_pbmp, port) {
        num_ports++;
    }

    /*
     * Ingress based threshholds
     */

    /* Per-device limit: 1 Ethernet MTU per port */
    global_hdrm_limit = num_ports * MMU_MTU_CELLS;

    /* Use whatever is left over for shared cells */
    total_shared_limit = MMU_TOTAL_CELLS;
    total_shared_limit -= global_hdrm_limit;
    total_shared_limit -= ((num_ports - 1) * MMU_PG2_HDRM_LIMIT);
    total_shared_limit -= (num_ports * MMU_PORT_MIN);
    total_shared_limit -= (num_ports * MMU_SC_MIN);
    total_shared_limit -= (num_ports * MMU_QM_MIN);

    TOTAL_SHARED_LIMITr_SET(ts_limit, total_shared_limit);
    ioerr += WRITE_TOTAL_SHARED_LIMITr(unit, ts_limit);

    GLOBAL_HDRM_LIMITr_SET(gh_limit, global_hdrm_limit);
    ioerr += WRITE_GLOBAL_HDRM_LIMITr(unit, gh_limit);

    PORT_MINr_SET(port_min, MMU_PORT_MIN);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_MINr(unit, port, port_min);
    }

    PORT_MAX_PKT_SIZEr_SET(p_max_pkt_sz, MMU_JUMBO_CELLS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_MAX_PKT_SIZEr(unit, port, p_max_pkt_sz);
    }

    PORT_SHARED_LIMITr_CLR(p_shared_limit);
    /* The following values may change when link is established */
    PORT_SHARED_LIMITr_PORT_SHARED_LIMITf_SET(p_shared_limit, LIMIT_DISABLE);
    PORT_SHARED_LIMITr_PORT_SHARED_DYNAMICf_SET(p_shared_limit, 0);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_SHARED_LIMITr(unit, port, p_shared_limit);
    }

    PG_THRESH_SELr_CLR(pg_thresh_sel);
    PG_THRESH_SELr_PG0_THRESH_SELf_SET(pg_thresh_sel, 0x6);
    PG_THRESH_SELr_PG1_THRESH_SELf_SET(pg_thresh_sel, 0x7);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PG_THRESH_SELr(unit, port, pg_thresh_sel);
    }

    PG_RESET_SELr_CLR(pg_reset_sel);
    PG_RESET_SELr_PG0_RESET_SELf_SET(pg_reset_sel, 0x7);
    PG_RESET_SELr_PG1_RESET_SELf_SET(pg_reset_sel, 0x7);
    PG_RESET_SELr_PG2_RESET_SELf_SET(pg_reset_sel, 0x7);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PG_RESET_SELr(unit, port, pg_reset_sel);
    }

    /* Currently everything is zero, but keep code for reference */
    PG_RESET_FLOORr_CLR(pg_reset_floor);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        for (i = 0; i <= MMU_NUM_PG - 1; i++) {
            ioerr += WRITE_PG_RESET_FLOORr(unit, port, i, pg_reset_floor);
        }
    }

    /* With only one PG in use PORT_MIN should be sufficient */
    PG_MINr_CLR(pg_min);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        for (i = 0; i <= MMU_NUM_PG - 1; i++) {
            ioerr += WRITE_PG_MINr(unit, port, i, pg_min);
        }
    }

    /* Note that only PG-max is being used */
    PG_HDRM_LIMITr_CLR(pg_hdrm_limit);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        for (i = 0; i <= MMU_NUM_PG - 1; i++) {
            ioerr += WRITE_PG_HDRM_LIMITr(unit, port, i, pg_hdrm_limit);
        }
    }
    PG_HDRM_LIMITr_PG_HDRM_LIMITf_SET(pg_hdrm_limit, MMU_PG2_HDRM_LIMIT);
    PG_HDRM_LIMITr_PG_GEf_SET(pg_hdrm_limit, 1);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (port == CMIC_PORT) {
            continue;
        }
        ioerr += WRITE_PG_HDRM_LIMITr(unit, port, MMU_NUM_PG - 1, pg_hdrm_limit);
    }

    PORT_PRI_GRPr_CLR(port_pri_grp);
    PORT_PRI_GRPr_PG0_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    PORT_PRI_GRPr_PG1_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    PORT_PRI_GRPr_PG2_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    PORT_PRI_GRPr_PG3_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    PORT_PRI_GRPr_PG4_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    PORT_PRI_GRPr_PG5_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    PORT_PRI_GRPr_PG6_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    PORT_PRI_GRPr_PG7_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    PORT_PRI_GRPr_PG8_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    PORT_PRI_GRPr_PG9_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    PORT_PRI_GRPr_PG10_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    PORT_PRI_GRPr_PG11_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    PORT_PRI_GRPr_PG12_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    PORT_PRI_GRPr_PG13_GRPf_SET(port_pri_grp, MMU_NUM_PG - 1);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_PRI_GRPr(unit, port, port_pri_grp);
    }

    PORT_SC_MINr_SET(port_sc_min, MMU_SC_MIN);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_SC_MINr(unit, port, port_sc_min);
    }

    PORT_QM_MINr_SET(port_qm_min, MMU_QM_MIN);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_QM_MINr(unit, port, port_qm_min);
    }

    /* 
     * Output queue threshold settings
     */

    q_min = MMU_MTU_CELLS;

    op_buffer_shared_limit = MMU_TOTAL_CELLS;
    op_buffer_shared_limit -= (q_min * num_ports * MMU_NUM_COS);

    OP_BUFFER_SHARED_LIMITr_SET(obs_limit, op_buffer_shared_limit);
    ioerr += WRITE_OP_BUFFER_SHARED_LIMITr(unit, obs_limit);

    /*
     * OP_SHARED_LIMIT should be ((op_buffer_shared_limit * 3) / 4)
     * OP_SHARED_RESET_VALUE should be (op_buffer_shared_limit / 4)
     *
     * Since PORT_LIMIT_ENABLE does not work, the above limits
     * can be disabled by configuring values larger than the
     * OP_BUFFER_SHARED_LIMIT value.
     */
    OP_PORT_CONFIGr_CLR(op_port_config);
    OP_PORT_CONFIGr_OP_SHARED_LIMITf_SET(op_port_config, LIMIT_DISABLE);
    OP_PORT_CONFIGr_OP_SHARED_RESET_VALUEf_SET(op_port_config, LIMIT_DISABLE);
    OP_PORT_CONFIGr_PORT_LIMIT_ENABLEf_SET(op_port_config, 0);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        WRITE_OP_PORT_CONFIGr(unit, port, op_port_config);
    }
    /* Use fixed buffer size for CPU port */
    OP_PORT_CONFIGr_OP_SHARED_LIMITf_SET(op_port_config, LIMIT_DISABLE);
    OP_PORT_CONFIGr_OP_SHARED_RESET_VALUEf_SET(op_port_config, 0x733);
    OP_PORT_CONFIGr_PORT_LIMIT_ENABLEf_SET(op_port_config, 0);
    WRITE_OP_PORT_CONFIGr(unit, CMIC_PORT, op_port_config);

    OP_QUEUE_CONFIGr_CLR(op_queue_config);
    /* Make it 87.5 % of original threshold */
    OP_QUEUE_CONFIGr_Q_RESET_SELf_SET(op_queue_config, 0x7);
    OP_QUEUE_CONFIGr_Q_MINf_SET(op_queue_config, q_min);
    OP_QUEUE_CONFIGr_Q_LIMIT_ENABLEf_SET(op_queue_config, 0x1);
    /* Use dynamic threshold limits */
    OP_QUEUE_CONFIGr_Q_LIMIT_DYNAMICf_SET(op_queue_config, 0x1);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (port == CMIC_PORT) {
            /* Dynamic threshold limit is alpha of 1/2 */
            OP_QUEUE_CONFIGr_Q_SHARED_LIMITf_SET(op_queue_config, 0x3);
        } else {
            /* Dynamic threshold limit is alpha of 4 */
            OP_QUEUE_CONFIGr_Q_SHARED_LIMITf_SET(op_queue_config, 0x7);
        }
        for (i = 0; i < MMU_NUM_COS; i++) {
            ioerr += WRITE_OP_QUEUE_CONFIGr(unit, port, i, op_queue_config);
        }
        for (i = 8; i <= 9; i++) {
            ioerr += WRITE_OP_QUEUE_CONFIGr(unit, port, i, op_queue_config);
        }
    }

    OP_THR_CONFIGr_CLR(op_thr_config);
    OP_THR_CONFIGr_ASF_PKT_SIZEf_SET(op_thr_config, 0x3);
    OP_THR_CONFIGr_ASF_QUEUE_SIZEf_SET(op_thr_config, 0x3);
    OP_THR_CONFIGr_MOP_POLICYf_SET(op_thr_config, 0x7);
    OP_THR_CONFIGr_SOP_POLICYf_SET(op_thr_config, 0);
    ioerr += WRITE_OP_THR_CONFIGr(unit, op_thr_config);

    CFAPCONFIGr_CLR(cfapconfig);
    CFAPCONFIGr_CFAPPOOLSIZEf_SET(cfapconfig, MMU_TOTAL_CELLS - 1);
    ioerr += WRITE_CFAPCONFIGr(unit, cfapconfig);

    CFAPFULLTHRESHOLDr_CLR(cfapfullthreshold);
    cfap_offset = MMU_TOTAL_CELLS - MMU_CFAP_FULL_SET_OFFSET;
    CFAPFULLTHRESHOLDr_CFAPFULLSETPOINTf_SET(cfapfullthreshold, cfap_offset);
    cfap_offset = MMU_TOTAL_CELLS - MMU_CFAP_FULL_RESET_OFFSET;
    CFAPFULLTHRESHOLDr_CFAPFULLRESETPOINTf_SET(cfapfullthreshold, cfap_offset);
    ioerr += WRITE_CFAPFULLTHRESHOLDr(unit, cfapfullthreshold);

    /* No flow control for COS 0-7 */
    PORT_PRI_XON_ENABLEr_SET(port_pri_xon_enable, 0);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_PRI_XON_ENABLEr(unit, port, port_pri_xon_enable);
    }

    /* Port enable */
    pbm = CDK_PBMP_WORD_GET(mmu_pbmp, 0);
    INPUT_PORT_RX_ENABLEr_SET(input_port_rx_enable, pbm);
    ioerr += WRITE_INPUT_PORT_RX_ENABLEr(unit, input_port_rx_enable);
    OUTPUT_PORT_RX_ENABLEr_SET(output_port_rx_enable, pbm);
    ioerr += WRITE_OUTPUT_PORT_RX_ENABLEr(unit, output_port_rx_enable);

    return ioerr;
}

static int
_port_init(int unit, int port)
{
    int ioerr = 0;
    EGR_ENABLEr_t egr_enable;
    EGR_PORTr_t egr_port;
    PORT_TABm_t port_tab;

    /* Default port VLAN */
    PORT_TABm_CLR(port_tab);
    PORT_TABm_PORT_VIDf_SET(port_tab, 1);
    PORT_TABm_FILTER_ENABLEf_SET(port_tab, 1);
    PORT_TABm_OUTER_TPIDf_SET(port_tab, 0x8100);
    ioerr += WRITE_PORT_TABm(unit, port, port_tab);

    /* Filter VLAN on egress */
    ioerr += READ_EGR_PORTr(unit, port, &egr_port);
    EGR_PORTr_EN_EFILTERf_SET(egr_port, 1);
    ioerr += WRITE_EGR_PORTr(unit, port, egr_port);

    /* Egress enable */
    ioerr += READ_EGR_ENABLEr(unit, port, &egr_enable);
    EGR_ENABLEr_PRT_ENABLEf_SET(egr_enable, 1);
    ioerr += WRITE_EGR_ENABLEr(unit, port, egr_enable);

    return ioerr;
}

int
bcm56800_a0_gxport_init(int unit, int port)
{
    int ioerr = 0;
    GPCSCr_t gpcsc;
    GMACC0r_t gmacc0;
    FE_IPGRr_t fe_ipgr;
    FE_IPGTr_t fe_ipgt;
    FE_MAXFr_t maxf;
    GPORT_CONFIGr_t gport_cfg;
    XPORT_CONFIGr_t xport_cfg;
    MAC_CTRLr_t mac_ctrl;
    MAC_TXCTRLr_t txctrl;
    MAC_RXCTRLr_t rxctrl;
    MAC_TXMAXSZr_t txmaxsz;
    MAC_RXMAXSZr_t rxmaxsz;

    /* Common port initialization */
    ioerr += _port_init(unit, port);

    /* Enable GPORT and clear counters */
    ioerr += READ_GPORT_CONFIGr(unit, port, &gport_cfg);
    if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
        /* Do not enable GPORT if 10G port */
        GPORT_CONFIGr_GPORT_ENf_SET(gport_cfg, 0);
    } else {
        GPORT_CONFIGr_GPORT_ENf_SET(gport_cfg, 1);
    }
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 1);
    ioerr += WRITE_GPORT_CONFIGr(unit, port, gport_cfg);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 0);
    ioerr += WRITE_GPORT_CONFIGr(unit, port, gport_cfg);

    /* Select GMII */
    ioerr += READ_GMACC0r(unit, port, &gmacc0);
    GMACC0r_TMDSf_SET(gmacc0, 1);
    ioerr += WRITE_GMACC0r(unit, port, gmacc0);

    /* Run GMII at 125 MHz */
    ioerr += READ_GPCSCr(unit, port, &gpcsc);
    GPCSCr_RCSELf_SET(gpcsc, 1);
    ioerr += WRITE_GPCSCr(unit, port, gpcsc);

    /* Set minimum 10/100 Inter-Packet-Gap */
    ioerr += READ_FE_IPGRr(unit, port, &fe_ipgr);
    FE_IPGRr_IPGR1f_SET(fe_ipgr, 0x6);
    FE_IPGRr_IPGR2f_SET(fe_ipgr, 0xf);
    ioerr += WRITE_FE_IPGRr(unit, port, fe_ipgr);
    ioerr += READ_FE_IPGTr(unit, port, &fe_ipgt);
    FE_IPGTr_IPGTf_SET(fe_ipgt, 0x15);
    ioerr += WRITE_FE_IPGTr(unit, port, fe_ipgt);

    /* Adjust 10/100 max frame size */
    FE_MAXFr_CLR(maxf);
    FE_MAXFr_MAXFRf_SET(maxf, 0x5ef);
    ioerr += WRITE_FE_MAXFr(unit, port, maxf);

    /* Enable XPORT by default if 10G port */
    XPORT_CONFIGr_CLR(xport_cfg);
    if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
        XPORT_CONFIGr_XPORT_ENf_SET(xport_cfg, 1);
    }
    ioerr += WRITE_XPORT_CONFIGr(unit, port, xport_cfg);

    /* Ensure that MAC (Rx) and loopback mode is disabled */
    MAC_CTRLr_CLR(mac_ctrl);
    MAC_CTRLr_TXENf_SET(mac_ctrl, 1);
    ioerr += WRITE_MAC_CTRLr(unit, port, mac_ctrl);

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
bcm56800_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    ING_HW_RESET_CONTROL_1r_t ing_rst_ctl_1;
    ING_HW_RESET_CONTROL_2r_t ing_rst_ctl_2;
    ING_HW_RESET_CONTROL_2_Xr_t ing_rst_ctl_2_x;
    ING_HW_RESET_CONTROL_2_Yr_t ing_rst_ctl_2_y;
    EGR_HW_RESET_CONTROL_0r_t egr_rst_ctl_0;
    EGR_HW_RESET_CONTROL_1r_t egr_rst_ctl_1;
    MISCCONFIGr_t misc_cfg;
    CMIC_XGXS0_PLL_CONTROL_2r_t pll0_ctrl2;
    CMIC_RATE_ADJUSTr_t rate_adjust;
    L2_AGE_DEBUGr_t l2_age_debug;
    RDBGC0_SELECTr_t rdbgc0_select;
    XPORT_CONFIGr_t xport_cfg;
    cdk_pbmp_t pbmp;
    int idx;
    int port;

    BMD_CHECK_UNIT(unit);

    /* Reset the IPIPE block */
    ING_HW_RESET_CONTROL_1r_CLR(ing_rst_ctl_1);
    ioerr += WRITE_ING_HW_RESET_CONTROL_1r(unit, ing_rst_ctl_1);
    ING_HW_RESET_CONTROL_2r_CLR(ing_rst_ctl_2);
    ING_HW_RESET_CONTROL_2r_RESET_ALLf_SET(ing_rst_ctl_2, 1);
    ING_HW_RESET_CONTROL_2r_VALIDf_SET(ing_rst_ctl_2, 1);
    ING_HW_RESET_CONTROL_2r_COUNTf_SET(ing_rst_ctl_2, 0x4000);
    ioerr += WRITE_ING_HW_RESET_CONTROL_2r(unit, ing_rst_ctl_2);
    CDK_MEMCPY(&ing_rst_ctl_2_x, &ing_rst_ctl_2, sizeof(ing_rst_ctl_2_x));
    ioerr += WRITE_ING_HW_RESET_CONTROL_2_Xr(unit, ing_rst_ctl_2_x);
    CDK_MEMCPY(&ing_rst_ctl_2_y, &ing_rst_ctl_2, sizeof(ing_rst_ctl_2_y));
    ioerr += WRITE_ING_HW_RESET_CONTROL_2_Yr(unit, ing_rst_ctl_2_y);

    /* Reset the EPIPE block */
    EGR_HW_RESET_CONTROL_0r_CLR(egr_rst_ctl_0);
    EGR_HW_RESET_CONTROL_1r_CLR(egr_rst_ctl_1);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_0r(unit, egr_rst_ctl_0);
    EGR_HW_RESET_CONTROL_1r_RESET_ALLf_SET(egr_rst_ctl_1, 1);
    EGR_HW_RESET_CONTROL_1r_VALIDf_SET(egr_rst_ctl_1, 1);
    EGR_HW_RESET_CONTROL_1r_COUNTf_SET(egr_rst_ctl_1, 0x2000);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_1r(unit, egr_rst_ctl_1);

    for (idx = 0; idx < PIPE_RESET_TIMEOUT_MSEC; idx++) {
        ioerr += READ_ING_HW_RESET_CONTROL_2r(unit, &ing_rst_ctl_2);
        if (ING_HW_RESET_CONTROL_2r_DONEf_GET(ing_rst_ctl_2)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    for (; idx < PIPE_RESET_TIMEOUT_MSEC; idx++) {
        ioerr += READ_ING_HW_RESET_CONTROL_2_Xr(unit, &ing_rst_ctl_2_x);
        if (ING_HW_RESET_CONTROL_2_Xr_DONEf_GET(ing_rst_ctl_2_x)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    for (; idx < PIPE_RESET_TIMEOUT_MSEC; idx++) {
        ioerr += READ_ING_HW_RESET_CONTROL_2_Yr(unit, &ing_rst_ctl_2_y);
        if (ING_HW_RESET_CONTROL_2_Yr_DONEf_GET(ing_rst_ctl_2_y)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (idx >= PIPE_RESET_TIMEOUT_MSEC) {
        CDK_WARN(("bcm56800_a0_bmd_init[%d]: IPIPE reset timeout\n", unit));
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
        CDK_WARN(("bcm56800_a0_bmd_init[%d]: EPIPE reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }

    /* Clear pipe reset registers */
    ING_HW_RESET_CONTROL_2r_CLR(ing_rst_ctl_2);
    ioerr += WRITE_ING_HW_RESET_CONTROL_2r(unit, ing_rst_ctl_2);
    ING_HW_RESET_CONTROL_2_Xr_CLR(ing_rst_ctl_2_x);
    ioerr += WRITE_ING_HW_RESET_CONTROL_2_Xr(unit, ing_rst_ctl_2_x);
    ING_HW_RESET_CONTROL_2_Yr_CLR(ing_rst_ctl_2_y);
    ioerr += WRITE_ING_HW_RESET_CONTROL_2_Yr(unit, ing_rst_ctl_2_y);
    EGR_HW_RESET_CONTROL_1r_CLR(egr_rst_ctl_1);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_1r(unit, egr_rst_ctl_1);

    /* Enable Field Processor metering clock */
    ioerr += READ_MISCCONFIGr(unit, &misc_cfg);
    MISCCONFIGr_METERING_CLK_ENf_SET(misc_cfg, 1);
    ioerr += WRITE_MISCCONFIGr(unit, misc_cfg);

    /* Enable 125MHz clock */
    ioerr += READ_CMIC_XGXS0_PLL_CONTROL_2r(unit, &pll0_ctrl2);
    CMIC_XGXS0_PLL_CONTROL_2r_XGPLL_EN125f_SET(pll0_ctrl2, 1);
    ioerr += WRITE_CMIC_XGXS0_PLL_CONTROL_2r(unit, pll0_ctrl2);

    /*
     * Set reference clock (based on 180MHz core clock)
     * to be 180MHz * (1/36) = 5MHz
     * so MDC output frequency is 0.5 * 5MHz = 2.5MHz
     */
    CMIC_RATE_ADJUSTr_CLR(rate_adjust);
    CMIC_RATE_ADJUSTr_DIVISORf_SET(rate_adjust, 36);
    CMIC_RATE_ADJUSTr_DIVIDENDf_SET(rate_adjust, 1);
    ioerr += WRITE_CMIC_RATE_ADJUSTr(unit, rate_adjust);

    /* Fixup incorrect reset value */
    ioerr += READ_L2_AGE_DEBUGr(unit, &l2_age_debug);
    L2_AGE_DEBUGr_AGE_COUNTf_SET(l2_age_debug, 0x7ff);
    ioerr += WRITE_L2_AGE_DEBUGr(unit, l2_age_debug);

    /* Configure discard counter */
    RDBGC0_SELECTr_CLR(rdbgc0_select);
    RDBGC0_SELECTr_BITMAPf_SET(rdbgc0_select, 0x0400ad11);
    ioerr += WRITE_RDBGC0_SELECTr(unit, rdbgc0_select);

    /* Initialize MMU */
    ioerr += _mmu_init(unit);

    /* 
     * Ensure that unused XPORTs are enabled for correct LED operation.
     * This must be done before the active ports are initialized.
     */
    XPORT_CONFIGr_CLR(xport_cfg);
    XPORT_CONFIGr_XPORT_ENf_SET(xport_cfg, 1);
    /* Loop over both active and inactive ports */
    for (port = 0; port < CMIC_PORT; port++) {
        ioerr += WRITE_XPORT_CONFIGr(unit, port, xport_cfg);
    }

    /* Configure GXPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GXPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += bcm56800_a0_gxport_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
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
#endif /* CDK_CONFIG_INCLUDE_BCM56800_A0 */
