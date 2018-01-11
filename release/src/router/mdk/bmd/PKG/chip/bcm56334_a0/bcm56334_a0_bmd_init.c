#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56334_A0 == 1

/*
 * $Id: bcm56334_a0_bmd_init.c,v 1.17 Broadcom SDK $
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

#include <cdk/chip/bcm56334_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56334_a0_bmd.h"
#include "bcm56334_a0_internal.h"

#define PIPE_RESET_TIMEOUT_MSEC         5

#define JUMBO_MAXSZ                     0x3fe8

#define MMU_NUM_COS                     8
#define MMU_NUM_PG                      8

#define MMU_ETH_FRAME_CELLS             12
#define MMU_JUMBO_FRAME_CELLS           72

/* MAX Frame MTU, 16384 (1 cell = 128 bytes) */
#define MMU_MAX_FRAME_CELLS  128

#define MMU_PORT_MIN_CELLS              72
#define MMU_PORT_MIN_PACKETS            1

#define MMU_PG_HDRM_LIMIT_CELLS  36
#define MMU_PG_HDRM_LIMIT_PKTS   36

#define MMU_RESET_OFFSET_CELLS  24
#define MMU_RESET_OFFSET_PKTS   2

#define MMU_GLOBAL_HDRM_LIMIT_CELLS     636

#define MMU_OP_PORT_MIN_CELLS           12
#define MMU_OP_PORT_MIN_PACKETS         1

#define MMU_MOP_POLICY  7
#define MMU_SOP_POLICY  0

static uint8_t tdm[84] = {2,10,18,26,27,28,29,
                  3,11,19,26,27,28,29,
                  4,12,20,26,27,28,29,
                  5,13,21,26,27,28,29,
                  6,14,22,26,27,28,29,
                  7,15,23,26,27,28,29,
                  8,16,24,26,27,28,29,
                  9,17,25,26,27,28,29,
                  1,30,30,26,27,28,29,
                  1,30,30,26,27,28,29,
                  1,30,30,26,27,28,29,
                  0,30,30,26,27,28,29};

static int
_mmu_init(int unit)
{
    int ioerr = 0;
    int port, i, port_min, q_min, obs_limit, idx;
    int b_shr_limit;
    cdk_pbmp_t pbmp, mmu_pbmp;
    uint32_t pbm, tm;
    PORT_MIN_CELLr_t port_min_cell;
    PG_MIN_CELLr_t pg_min_cell;
    PG_MIN_PACKETr_t pg_min_packet;
    PG_HDRM_LIMIT_CELLr_t lm_cell;
    PG_HDRM_LIMIT_PACKETr_t lm_pkt;       
    PG_RESET_OFFSET_CELLr_t rs_cell;
    PG_RESET_FLOOR_CELLr_t pg_reset_floor_cell;    
    PORT_SC_MIN_CELLr_t port_sc_min_cell;
    PORT_QM_MIN_CELLr_t port_qm_min_cell;
    PORT_SC_MIN_PACKETr_t port_sc_min_packet;
    PORT_QM_MIN_PACKETr_t port_qm_min_packet;
    PORT_PAUSE_ENABLEr_t port_pause_en;
    PORT_PRI_GRP0r_t port_pri_grp0;
    PORT_PRI_GRP1r_t port_pri_grp1;
    PG_THRESH_SELr_t pg_thresh_sel;
    PG_RESET_OFFSET_PACKETr_t rs_pkt;
    GLOBAL_HDRM_LIMITr_t global_hl;
    TOTAL_SHARED_LIMIT_CELLr_t ts_limit_cell;
    PORT_SHARED_LIMIT_CELLr_t ps_limit_cell;
    PORT_SHARED_LIMIT_PACKETr_t ps_lm_pkt;
    PORT_MAX_PKT_SIZEr_t port_max_pkt_size;
    PORT_MIN_PACKETr_t port_min_packet;
    TOTAL_SHARED_LIMIT_PACKETr_t ts_limit_packet;
    OP_QUEUE_CONFIG_CELLr_t op_q_cfg_cell;
    OP_BUFFER_SHARED_LIMIT_CELLr_t obs_limit_cell;
    OP_PORT_CONFIG_CELLr_t op_port_cfg_cell;
    OP_QUEUE_CONFIG_PACKETr_t op_q_cfg_pkt;
    OP_BUFFER_SHARED_LIMIT_PACKETr_t obs_limit_packet;
    OP_PORT_CONFIG_PACKETr_t op_port_cfg_pkt;
    OP_QUEUE_RESET_OFFSET_CELLr_t q_reset_cell;    
    OP_QUEUE_RESET_OFFSET_PACKETr_t q_reset_pkt;
    OP_THR_CONFIGr_t op_thr_cfg;
    PORT_PRI_XON_ENABLEr_t port_pri_xon_en;
    CELLLINKMEMDEBUGr_t celllinkmemdebug;
    SW2_RAM_CONTROL_4r_t sw2_ram_control_4;
    EFP_RAM_CONTROLr_t efp_ram_control;
    FP_CAM_CONTROL_TM_7_THRU_0r_t fpcamtm7;
    VLAN_SUBNET_CAM_DBGCTRLr_t vlan_subnet_cam_dbgctrl;
    L2_USER_ENTRY_CAM_DBGCTRLr_t l2_user_entry_cam_dbgctrl;
    L3_DEFIP_128_CAM_DBGCTRLr_t l3_defip_128_cam_dbgctrl;
    L3_DEFIP_CAM_DBGCTRL0r_t l3_defip_cam_dbgctrl0;
    L3_DEFIP_CAM_DBGCTRL1r_t l3_defip_cam_dbgctrl1;
    L3_DEFIP_CAM_DBGCTRL2r_t l3_defip_cam_dbgctrl2;
    L3_TUNNEL_CAM_DBGCTRLr_t l3_tunnel_cam_dbgctrl;
    MPLS_STATION_CAM_DBGCTRLr_t mpls_station_cam_dbgctrl;
    VFP_CAM_CONTROL_TM_7_THRU_0r_t vfp_cam_tm_7;
    
    INPUT_PORT_RX_ENABLEr_t inp_rx_enable;
    OUTPUT_PORT_RX_ENABLEr_t outp_rx_enable;
    /* mmu init*/
    int total_cells = 16 * 1024;
    int total_pkts = 6 * 1024;
    
    /* Ports to configure */
    CDK_PBMP_CLEAR(mmu_pbmp);
    CDK_PBMP_ADD(mmu_pbmp, CMIC_PORT);
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XQPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);

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

    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_XE) {
            for (idx = 0; idx < MMU_NUM_PG; idx++) {
                ioerr += WRITE_PG_MIN_CELLr(unit, port, idx, pg_min_cell);
            }
        } else if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) {
            for (idx = 0; idx < MMU_NUM_PG; idx++) {
                ioerr += WRITE_PG_MIN_CELLr(unit, port, idx, pg_min_cell);
            }
        } else if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_GE) {
            ioerr += WRITE_PG_MIN_CELLr(unit, port, 0, pg_min_cell);
        }
    }

    /* 
     * Leave input port per-PG minimum at default value (0).
     * With only one PG in use PORT_MIN should be sufficient.
     *
     * Configure input port per-PG headroom (cells and packets).
     * Use only 1 PG (highest priority PG for the port).
     */
    PG_HDRM_LIMIT_CELLr_CLR(lm_cell);
    PG_HDRM_LIMIT_CELLr_PG_HDRM_LIMITf_SET(lm_cell, MMU_PG_HDRM_LIMIT_CELLS);
    PG_HDRM_LIMIT_CELLr_PG_GEf_SET(lm_cell, 1);
    PG_HDRM_LIMIT_PACKETr_CLR(lm_pkt);
    PG_HDRM_LIMIT_PACKETr_PG_HDRM_LIMITf_SET(lm_pkt, MMU_PG_HDRM_LIMIT_PKTS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_CPU | BMD_PORT_GE)) {
            idx = 0;
            /* Leave CPU and GE port at default value (0) */
        } else {
            idx = MMU_NUM_PG - 1;
        }
        ioerr += WRITE_PG_HDRM_LIMIT_CELLr(unit, port, idx, lm_cell);
        ioerr += WRITE_PG_HDRM_LIMIT_PACKETr(unit, port, idx, lm_pkt);
    }

    /* Input port per-device headroom (cells) */
    GLOBAL_HDRM_LIMITr_SET(global_hl, MMU_GLOBAL_HDRM_LIMIT_CELLS);
    ioerr += WRITE_GLOBAL_HDRM_LIMITr(unit, global_hl);

    /* Use remaining cells for shared cells */
    TOTAL_SHARED_LIMIT_CELLr_SET(ts_limit_cell, total_cells - port_min);
    ioerr += WRITE_TOTAL_SHARED_LIMIT_CELLr(unit, ts_limit_cell);

    /* Use dynamic limit with alpha = 8 */
    PORT_SHARED_LIMIT_CELLr_CLR(ps_limit_cell);
    PORT_SHARED_LIMIT_CELLr_PORT_SHARED_DYNAMICf_SET(ps_limit_cell, 1);
    PORT_SHARED_LIMIT_CELLr_PORT_SHARED_LIMITf_SET(ps_limit_cell, 7);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_SHARED_LIMIT_CELLr(unit, port, ps_limit_cell);
    }

    /* Max packet size (in cells) */
    PORT_MAX_PKT_SIZEr_SET(port_max_pkt_size, MMU_MAX_FRAME_CELLS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_MAX_PKT_SIZEr(unit, port, port_max_pkt_size);
    }

    /*
     * Input port per-PG reset offset.
     * Use only 1 PG (highest priority PG for the port).
     */
    PG_RESET_OFFSET_CELLr_CLR(rs_cell);
    PG_RESET_OFFSET_CELLr_SET(rs_cell, MMU_RESET_OFFSET_CELLS);
    PG_RESET_OFFSET_PACKETr_CLR(rs_pkt);
    PG_RESET_OFFSET_PACKETr_SET(rs_pkt, MMU_RESET_OFFSET_PKTS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_CPU | BMD_PORT_GE)) {
            /* Leave CPU and GE ports at default value (0) */
            continue;
        }
        for (idx = 1; idx < MMU_NUM_PG; idx++) {
            if (idx == (MMU_NUM_PG - 1)) {
                ioerr += WRITE_PG_RESET_OFFSET_CELLr(unit, port, idx, rs_cell);
                ioerr += WRITE_PG_RESET_OFFSET_PACKETr(unit, port, idx, rs_pkt);
            } else {
                ioerr += WRITE_PG_RESET_OFFSET_CELLr(unit, port, 0, rs_cell);
            }
        }
    }

    /* Currently everything is zero, but keep code for reference */
    PG_RESET_FLOOR_CELLr_CLR(pg_reset_floor_cell);
    PG_RESET_FLOOR_CELLr_SET(pg_reset_floor_cell, 0);

    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_XE | BMD_PORT_HG)) {
            for (idx = 0; idx < MMU_NUM_PG; idx++) {
                ioerr += WRITE_PG_RESET_FLOOR_CELLr(unit, port, idx, 
                                                    pg_reset_floor_cell);
            }
        }
    }

    PORT_SC_MIN_CELLr_CLR(port_sc_min_cell);
    PORT_SC_MIN_CELLr_SET(port_sc_min_cell, 0);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_SC_MIN_CELLr(unit, port, port_sc_min_cell);
    }
    
    PORT_QM_MIN_CELLr_CLR(port_qm_min_cell);
    PORT_QM_MIN_CELLr_SET(port_qm_min_cell, 0);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_QM_MIN_CELLr(unit, port, port_qm_min_cell);
    }

    /* Minimum packets per port */
    port_min = 0;
    PORT_MIN_PACKETr_SET(port_min_packet, MMU_PORT_MIN_PACKETS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_MIN_PACKETr(unit, port, port_min_packet);
        port_min += MMU_PORT_MIN_PACKETS;
    }

    /* Per-PG minimum. With only one PG in use PORT_MIN should be sufficient */
    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_XE | BMD_PORT_HG)) {
            for (idx = 0; idx < MMU_NUM_PG; idx++) {
                ioerr += WRITE_PG_MIN_PACKETr(unit, port, idx, pg_min_packet);
            }
        }
    }

    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_GE) {
            ioerr += WRITE_PG_MIN_PACKETr(unit, port, 0, pg_min_packet);
        }
    }

    /* Use remaining packets for shared packets */
    TOTAL_SHARED_LIMIT_PACKETr_SET(ts_limit_packet, total_pkts - port_min);
    ioerr += WRITE_TOTAL_SHARED_LIMIT_PACKETr(unit, ts_limit_packet);

    PORT_SHARED_LIMIT_PACKETr_CLR(ps_lm_pkt);
    PORT_SHARED_LIMIT_PACKETr_PORT_SHARED_DYNAMICf_SET(ps_lm_pkt, 1);
    PORT_SHARED_LIMIT_PACKETr_PORT_SHARED_LIMITf_SET(ps_lm_pkt, 7);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_SHARED_LIMIT_PACKETr(unit, port, ps_lm_pkt);
    }

    PORT_SC_MIN_PACKETr_CLR(port_sc_min_packet);
    PORT_SC_MIN_PACKETr_PORT_SC_MINf_SET(port_sc_min_packet, 0);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_SC_MIN_PACKETr(unit, port, port_sc_min_packet);
    }
    
    PORT_QM_MIN_PACKETr_CLR(port_qm_min_packet);
    PORT_QM_MIN_PACKETr_PORT_QM_MINf_SET(port_qm_min_packet, 0);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_QM_MIN_PACKETr(unit, port, port_qm_min_packet);
    }

    /* Input port per-PG threshold */
    PG_THRESH_SELr_CLR(pg_thresh_sel);
    PG_THRESH_SELr_PG0_THRESH_SELf_SET(pg_thresh_sel, 0x8);
    PG_THRESH_SELr_PG1_THRESH_SELf_SET(pg_thresh_sel, 0x8);
    PG_THRESH_SELr_PG2_THRESH_SELf_SET(pg_thresh_sel, 0x8);
    PG_THRESH_SELr_PG3_THRESH_SELf_SET(pg_thresh_sel, 0x8);
    PG_THRESH_SELr_PG4_THRESH_SELf_SET(pg_thresh_sel, 0x8);
    PG_THRESH_SELr_PG5_THRESH_SELf_SET(pg_thresh_sel, 0x8);
    PG_THRESH_SELr_PG6_THRESH_SELf_SET(pg_thresh_sel, 0x8);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) {
            WRITE_PG_THRESH_SELr(unit, port, pg_thresh_sel);
        }
    }
    
    idx = MMU_NUM_PG - 1;
    PORT_PRI_GRP0r_CLR(port_pri_grp0);
    PORT_PRI_GRP0r_PRI0_GRPf_SET(port_pri_grp0, idx);
    PORT_PRI_GRP0r_PRI1_GRPf_SET(port_pri_grp0, idx);
    PORT_PRI_GRP0r_PRI2_GRPf_SET(port_pri_grp0, idx);
    PORT_PRI_GRP0r_PRI3_GRPf_SET(port_pri_grp0, idx);
    PORT_PRI_GRP0r_PRI4_GRPf_SET(port_pri_grp0, idx);
    PORT_PRI_GRP0r_PRI5_GRPf_SET(port_pri_grp0, idx);
    PORT_PRI_GRP0r_PRI6_GRPf_SET(port_pri_grp0, idx);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_XE | BMD_PORT_HG)) {
            WRITE_PORT_PRI_GRP0r(unit, port, port_pri_grp0);
        }
    }

    PORT_PRI_GRP1r_CLR(port_pri_grp1);
    PORT_PRI_GRP1r_PRI7_GRPf_SET(port_pri_grp1, idx);
    PORT_PRI_GRP1r_PRI8_GRPf_SET(port_pri_grp1, idx);
    PORT_PRI_GRP1r_PRI9_GRPf_SET(port_pri_grp1, idx);
    PORT_PRI_GRP1r_PRI10_GRPf_SET(port_pri_grp1, idx);
    PORT_PRI_GRP1r_PRI11_GRPf_SET(port_pri_grp1, idx);
    PORT_PRI_GRP1r_PRI12_GRPf_SET(port_pri_grp1, idx);
    PORT_PRI_GRP1r_PRI13_GRPf_SET(port_pri_grp1, idx);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_XE | BMD_PORT_HG)) {
            WRITE_PORT_PRI_GRP1r(unit, port, port_pri_grp1);
        }
    }

    /* Input port pause enable */
    PORT_PAUSE_ENABLEr_CLR(port_pause_en);
    pbm = CDK_PBMP_WORD_GET(mmu_pbmp, 0);
    PORT_PAUSE_ENABLEr_PORT_PAUSE_ENABLEf_SET(port_pause_en, pbm);
    ioerr += WRITE_PORT_PAUSE_ENABLEr(unit, port_pause_en);
    
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

    /* CELL THRESHOLDS */
    q_min = MMU_ETH_FRAME_CELLS;
    b_shr_limit = total_cells;
    CDK_PBMP_ITER(mmu_pbmp, port) {
        b_shr_limit -= (q_min * MMU_NUM_COS);
    }    

    /* Output port per-port per-COS reset offset */
    OP_QUEUE_RESET_OFFSET_CELLr_SET(q_reset_cell, MMU_RESET_OFFSET_CELLS);
    OP_QUEUE_RESET_OFFSET_PACKETr_SET(q_reset_pkt, MMU_RESET_OFFSET_PKTS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        for (idx = 0; idx < MMU_NUM_COS; idx++) {
            ioerr += WRITE_OP_QUEUE_RESET_OFFSET_CELLr(unit, port, idx,
                                                       q_reset_cell);
            ioerr += WRITE_OP_QUEUE_RESET_OFFSET_PACKETr(unit, port, idx,
                                                         q_reset_pkt);
        }
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
                                                      obs_limit / 4);
    OP_PORT_CONFIG_PACKETr_PORT_LIMIT_ENABLE_PACKETf_SET(op_port_cfg_pkt, 1);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_OP_PORT_CONFIG_PACKETr(unit, port, op_port_cfg_pkt);
    }

    /* Output port configuration */
    OP_THR_CONFIGr_CLR(op_thr_cfg);
    OP_THR_CONFIGr_MOP_POLICYf_SET(op_thr_cfg, MMU_MOP_POLICY);
    OP_THR_CONFIGr_SOP_POLICYf_SET(op_thr_cfg, MMU_SOP_POLICY);
    ioerr += WRITE_OP_THR_CONFIGr(unit, op_thr_cfg);

    /* Apply TM setting on MMU_CELLLINK */
    CELLLINKMEMDEBUGr_SET(celllinkmemdebug, 0x20);
    ioerr += WRITE_CELLLINKMEMDEBUGr(unit, celllinkmemdebug);

    /* Apply TM=0x10 setting for all CAMs */
    tm=0x10;
    ioerr += READ_SW2_RAM_CONTROL_4r(unit, &sw2_ram_control_4);
    SW2_RAM_CONTROL_4r_CPU_COS_MAP_TCAM_TMf_SET(sw2_ram_control_4, tm);
    ioerr += WRITE_SW2_RAM_CONTROL_4r(unit, sw2_ram_control_4);

    ioerr += READ_EFP_RAM_CONTROLr(unit, &efp_ram_control);
    EFP_RAM_CONTROLr_EFP_CAM_TM_7_THRU_0f_SET(efp_ram_control, tm);
    ioerr += WRITE_EFP_RAM_CONTROLr(unit, efp_ram_control);

    ioerr += READ_FP_CAM_CONTROL_TM_7_THRU_0r(unit, &fpcamtm7);
    FP_CAM_CONTROL_TM_7_THRU_0r_ALL_TCAMS_TM_7_0f_SET(fpcamtm7, tm);
    FP_CAM_CONTROL_TM_7_THRU_0r_ALL_GLOBAL_MASK_TCAMS_TM_7_0f_SET(fpcamtm7, tm);
    ioerr += WRITE_FP_CAM_CONTROL_TM_7_THRU_0r(unit, fpcamtm7);

    ioerr += READ_VLAN_SUBNET_CAM_DBGCTRLr(unit, &vlan_subnet_cam_dbgctrl);
    VLAN_SUBNET_CAM_DBGCTRLr_TMf_SET(vlan_subnet_cam_dbgctrl, tm);
    ioerr += WRITE_VLAN_SUBNET_CAM_DBGCTRLr(unit, vlan_subnet_cam_dbgctrl);

    ioerr += READ_L2_USER_ENTRY_CAM_DBGCTRLr(unit, &l2_user_entry_cam_dbgctrl);
    L2_USER_ENTRY_CAM_DBGCTRLr_TMf_SET(l2_user_entry_cam_dbgctrl, tm);
    ioerr += WRITE_L2_USER_ENTRY_CAM_DBGCTRLr(unit, l2_user_entry_cam_dbgctrl);

    ioerr += READ_L3_DEFIP_128_CAM_DBGCTRLr(unit, &l3_defip_128_cam_dbgctrl);
    L3_DEFIP_128_CAM_DBGCTRLr_CAM0_TMf_SET(l3_defip_128_cam_dbgctrl, tm);
    L3_DEFIP_128_CAM_DBGCTRLr_CAM1_TMf_SET(l3_defip_128_cam_dbgctrl, tm);
    ioerr += WRITE_L3_DEFIP_128_CAM_DBGCTRLr(unit, l3_defip_128_cam_dbgctrl);

    ioerr += READ_L3_DEFIP_CAM_DBGCTRL0r(unit, &l3_defip_cam_dbgctrl0);
    L3_DEFIP_CAM_DBGCTRL0r_CAM0_TMf_SET(l3_defip_cam_dbgctrl0, tm);
    L3_DEFIP_CAM_DBGCTRL0r_CAM1_TMf_SET(l3_defip_cam_dbgctrl0, tm);
    ioerr += WRITE_L3_DEFIP_CAM_DBGCTRL0r(unit, l3_defip_cam_dbgctrl0);

    ioerr += READ_L3_DEFIP_CAM_DBGCTRL1r(unit, &l3_defip_cam_dbgctrl1);
    L3_DEFIP_CAM_DBGCTRL1r_CAM2_TMf_SET(l3_defip_cam_dbgctrl1, tm);
    L3_DEFIP_CAM_DBGCTRL1r_CAM3_TMf_SET(l3_defip_cam_dbgctrl1, tm);
    ioerr += WRITE_L3_DEFIP_CAM_DBGCTRL1r(unit, l3_defip_cam_dbgctrl1);

    ioerr += READ_L3_DEFIP_CAM_DBGCTRL2r(unit, &l3_defip_cam_dbgctrl2);
    L3_DEFIP_CAM_DBGCTRL2r_CAM4_TMf_SET(l3_defip_cam_dbgctrl2, tm);
    L3_DEFIP_CAM_DBGCTRL2r_CAM5_TMf_SET(l3_defip_cam_dbgctrl2, tm);
    ioerr += WRITE_L3_DEFIP_CAM_DBGCTRL2r(unit, l3_defip_cam_dbgctrl2);
    
    ioerr += READ_L3_TUNNEL_CAM_DBGCTRLr(unit, &l3_tunnel_cam_dbgctrl);
    L3_TUNNEL_CAM_DBGCTRLr_TMf_SET(l3_tunnel_cam_dbgctrl, tm);
    ioerr += WRITE_L3_TUNNEL_CAM_DBGCTRLr(unit, l3_tunnel_cam_dbgctrl);

    ioerr += READ_MPLS_STATION_CAM_DBGCTRLr(unit, &mpls_station_cam_dbgctrl);
    MPLS_STATION_CAM_DBGCTRLr_CAM0_TMf_SET(mpls_station_cam_dbgctrl, tm);
    ioerr += WRITE_MPLS_STATION_CAM_DBGCTRLr(unit, mpls_station_cam_dbgctrl);

    ioerr += READ_VFP_CAM_CONTROL_TM_7_THRU_0r(unit, &vfp_cam_tm_7);
    VFP_CAM_CONTROL_TM_7_THRU_0r_TMf_SET(vfp_cam_tm_7, tm);
    ioerr += WRITE_VFP_CAM_CONTROL_TM_7_THRU_0r(unit, vfp_cam_tm_7);

    /* No flow control for COS 0-7 */
    PORT_PRI_XON_ENABLEr_CLR(port_pri_xon_en);
    PORT_PRI_XON_ENABLEr_SET(port_pri_xon_en, 0);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
            ioerr += WRITE_PORT_PRI_XON_ENABLEr(unit, port, port_pri_xon_en);
        }
    }

    /* Port enable */
    INPUT_PORT_RX_ENABLEr_CLR(inp_rx_enable);
    pbm = CDK_PBMP_WORD_GET(mmu_pbmp, 0);
    INPUT_PORT_RX_ENABLEr_SET(inp_rx_enable, pbm);
    ioerr += WRITE_INPUT_PORT_RX_ENABLEr(unit, inp_rx_enable);

    OUTPUT_PORT_RX_ENABLEr_CLR(outp_rx_enable);
    pbm = CDK_PBMP_WORD_GET(mmu_pbmp, 0);
    OUTPUT_PORT_RX_ENABLEr_SET(outp_rx_enable, pbm);
    ioerr += WRITE_OUTPUT_PORT_RX_ENABLEr(unit, outp_rx_enable);

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
bcm56334_a0_xport_init(int unit, int port)
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

    return ioerr;
}

int
bcm56334_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    uint8_t *tdm_table;
    int tdm_size;
    IARB_TDM_TABLEm_t iarb_tdm;
    ARB_TDM_TABLEm_t arb_tdm;
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
        CDK_WARN(("bcm56634_a0_bmd_init[%d]: IPIPE reset timeout\n", unit));
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
        CDK_WARN(("bcm56634_a0_bmd_init[%d]: EPIPE reset timeout\n", unit));
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
    CDK_XGS_MEM_CLEAR(unit, ARB_TDM_TABLEm);
    for (idx = 0; idx < tdm_size; idx++) {
        IARB_TDM_TABLEm_CLR(iarb_tdm);
        ARB_TDM_TABLEm_CLR(arb_tdm);
        IARB_TDM_TABLEm_PORT_NUMf_SET(iarb_tdm, tdm_table[idx]);
        ARB_TDM_TABLEm_PORT_NUMf_SET(arb_tdm, tdm_table[idx]);
        if (idx == (tdm_size - 1)) {
            ARB_TDM_TABLEm_WRAP_ENf_SET(arb_tdm, 1);
        }
        ioerr += WRITE_IARB_TDM_TABLEm(unit, idx, iarb_tdm);
        ioerr += WRITE_ARB_TDM_TABLEm(unit, idx, arb_tdm);
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

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    /* Configure XQPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XQPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += bcm56334_a0_xport_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
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
#endif /* CDK_CONFIG_INCLUDE_BCM56334_A0 */
