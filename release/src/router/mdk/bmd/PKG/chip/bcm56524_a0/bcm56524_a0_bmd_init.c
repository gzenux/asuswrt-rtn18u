#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56524_A0 == 1

/*
 * $Id: bcm56524_a0_bmd_init.c,v 1.16 Broadcom SDK $
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

#include <cdk/chip/bcm56524_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56524_a0_bmd.h"
#include "bcm56524_a0_internal.h"

#define PIPE_RESET_TIMEOUT_MSEC         5

#define JUMBO_MAXSZ                     0x3fe8

#define MMU_NUM_COS                     8
#define MMU_NUM_PG                      8

#define MMU_ETH_FRAME_CELLS             12
#define MMU_JUMBO_FRAME_CELLS           128

#define MMU_PORT_MIN_CELLS              72
#define MMU_PORT_MIN_PACKETS            1

#define MMU_GLOBAL_HDRM_LIMIT_CELLS     636

#define MMU_PG_HDRM_LIMIT_CELLS         36
#define MMU_PG_HDRM_LIMIT_PKTS          36
#define MMU_PG_RESET_OFFSET_CELLS       24
#define MMU_PG_RESET_OFFSET_PKTS        1

#define MMU_OP_PORT_MIN_CELLS           12
#define MMU_OP_PORT_MIN_PKTS            1
#define MMU_OP_RESET_OFFSET_CELLS       24
#define MMU_OP_RESET_OFFSET_PKTS        2

#define MMU_SOP_POLICY                  0
#define MMU_MOP_POLICY                  7

static uint8_t tdmb524a[114] = {
    30, 26, 54, 27, 34, 28, 29, 26, 27, 38, 28, 
    29, 26, 42, 27, 28, 29, 26, 46, 27, 28, 29, 
    50, 26, 27, 54, 28, 29, 31, 26, 27, 28, 35, 
    29, 54, 26, 27, 39, 28, 29, 26, 43, 27, 28, 
    29, 26, 47, 54, 27, 28, 51, 29, 26, 27, 28, 
    29,  1, 32, 26, 54, 27, 36, 28, 29, 26, 27, 
    40, 28, 29, 26, 44, 27, 28, 29, 26, 48, 27, 
    28, 29, 52, 26, 27, 54, 28, 29, 33, 26, 27, 
    28, 37, 29, 54, 26, 27, 41, 28, 29, 26, 45, 
    27, 28, 29, 26, 49, 54, 27, 28, 53, 29, 26, 
    27, 28, 29, 0 };

static int
_mmu_init(int unit)
{
    int ioerr = 0;
    int port, idx;
    cdk_pbmp_t pbmp, mmu_pbmp, pbmp_2pg, pbmp_8pg;
    uint32_t pbm;
    PORT_MIN_CELLr_t port_min_cell;
    PORT_MIN_PACKETr_t port_min_packet;
    PG_HDRM_LIMIT_CELLr_t pg_hl_cell;
    PG_HDRM_LIMIT_PACKETr_t pg_hl_pkt;
    GLOBAL_HDRM_LIMITr_t global_hl;
    PG_RESET_OFFSET_CELLr_t pg_reset_cell;
    PG_RESET_OFFSET_PACKETr_t pg_reset_pkt;
    PORT_MAX_PKT_SIZEr_t port_max_pkt_size;
    PG_THRESH_SELr_t pg_thresh_sel;
    PORT_PRI_GRP0r_t port_pri_grp0;
    PORT_PRI_GRP1r_t port_pri_grp1;
    PORT_PAUSE_ENABLE_64r_t port_pause_en;
    OP_QUEUE_CONFIG_CELLr_t op_q_cfg_cell;
    OP_QUEUE_CONFIG_PACKETr_t op_q_cfg_pkt;
    OP_QUEUE_RESET_OFFSET_CELLr_t q_reset_cell;
    OP_QUEUE_RESET_OFFSET_PACKETr_t q_reset_pkt;
    BUFFER_CELL_LIMIT_SPr_t cell_limit_sp;
    BUFFER_PACKET_LIMIT_SPr_t packet_limit_sp;
    PORT_SHARED_LIMIT_CELLr_t ps_limit_cell;
    PORT_SHARED_LIMIT_PACKETr_t ps_limit_pkt;
    OP_BUFFER_SHARED_LIMIT_CELLr_t obs_limit_cell;
    OP_BUFFER_SHARED_LIMIT_PACKETr_t obs_limit_packet;
    OP_PORT_CONFIG_CELLr_t op_port_cfg_cell;
    OP_PORT_CONFIG_PACKETr_t op_port_cfg_pkt;
    OP_THR_CONFIGr_t op_thr_cfg;
    INPUT_PORT_RX_ENABLE_64r_t inp_rx_enable;
    OUTPUT_PORT_RX_ENABLE_64r_t outp_rx_enable;
    IESMIF_CONTROLr_t iesmif_ctrl;
    int in_reserved_cells, in_reserved_pkts;
    int out_reserved_cells, out_reserved_pkts;
    int shared_cells, shared_pkts;
    int total_cells = 24 * 1024;
    int total_pkts = 11 * 1024;

    /* Ports to configure */
    CDK_PBMP_CLEAR(mmu_pbmp);
    CDK_PBMP_ADD(mmu_pbmp, CMIC_PORT);
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XQPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);
#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GXPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);
#endif

    /* Ports with 8 PGs */
    CDK_PBMP_CLEAR(pbmp_8pg);
    CDK_PBMP_WORD_SET(pbmp_8pg, 0, 0x7c000000); /* ports 26-30 */
    CDK_PBMP_WORD_SET(pbmp_8pg, 1, 0x00444444); /* ports 34, 38, 42, 46, 50, 54 */
    CDK_PBMP_AND(pbmp_8pg, mmu_pbmp);

    /* 2 PGs for other ports */
    CDK_PBMP_ASSIGN(pbmp_2pg, mmu_pbmp);
    CDK_PBMP_REMOVE(pbmp_2pg, pbmp_8pg);

    /*
     * Reserved space calculation:
     *   Input port:
     *     per-port minimum
     *     per-PG minimum (config to 0)
     *     per-PG headroom
     *     per-device headroom
     *     per-port minimum for SC and QM traffic (config to 0)
     *   Output port:
     *     per-port per-COS minimum space
     * Shared space calculation:
     *   Input port: total - input port reserved - output port reserved
     *   Output port: total - output port reserved
     */
    in_reserved_cells = 0;
    in_reserved_pkts = 0;
    out_reserved_cells = 0;
    out_reserved_pkts = 0;

    /*
     * Reserved ingress limits and thresholds.
     */

    /* Minimum cells and packets per input port */
    PORT_MIN_CELLr_SET(port_min_cell, MMU_PORT_MIN_CELLS);
    PORT_MIN_PACKETr_SET(port_min_packet, MMU_PORT_MIN_PACKETS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_MIN_CELLr(unit, port, port_min_cell);
        ioerr += WRITE_PORT_MIN_PACKETr(unit, port, port_min_packet);
        in_reserved_cells += MMU_PORT_MIN_CELLS;
        in_reserved_pkts += MMU_PORT_MIN_PACKETS;
    }

    /* 
     * Leave input port per-PG minimum at default value (0).
     * With only one PG in use PORT_MIN should be sufficient.
     *
     * Configure input port per-PG headroom (cells and packets).
     * Use only 1 PG (highest priority PG for the port).
     */
    PG_HDRM_LIMIT_CELLr_CLR(pg_hl_cell);
    PG_HDRM_LIMIT_CELLr_PG_HDRM_LIMITf_SET(pg_hl_cell, MMU_PG_HDRM_LIMIT_CELLS);
    PG_HDRM_LIMIT_CELLr_PG_GEf_SET(pg_hl_cell, 1);
    PG_HDRM_LIMIT_PACKETr_CLR(pg_hl_pkt);
    PG_HDRM_LIMIT_PACKETr_PG_HDRM_LIMITf_SET(pg_hl_pkt, MMU_PG_HDRM_LIMIT_PKTS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (port == CMIC_PORT) {
            /* Leave CPU port at default value (0) */
            continue;
        }
        idx = CDK_PBMP_MEMBER(pbmp_8pg, port) ? MMU_NUM_PG - 1 : 0;
        ioerr += WRITE_PG_HDRM_LIMIT_CELLr(unit, port, idx, pg_hl_cell);
        ioerr += WRITE_PG_HDRM_LIMIT_PACKETr(unit, port, idx, pg_hl_pkt);
        in_reserved_cells += MMU_PG_HDRM_LIMIT_CELLS;
        in_reserved_pkts += MMU_PG_HDRM_LIMIT_PKTS;
    }

    /* Input port per-device headroom (cells) */
    GLOBAL_HDRM_LIMITr_SET(global_hl, MMU_GLOBAL_HDRM_LIMIT_CELLS);
    ioerr += WRITE_GLOBAL_HDRM_LIMITr(unit, global_hl);
    in_reserved_cells += MMU_GLOBAL_HDRM_LIMIT_CELLS;


    /*
     * Input port per-PG reset offset.
     * Use only 1 PG (highest priority PG for the port).
     */
    PG_RESET_OFFSET_CELLr_CLR(pg_reset_cell);
    PG_RESET_OFFSET_CELLr_PG_RESET_OFFSETf_SET(pg_reset_cell,
                                               MMU_PG_RESET_OFFSET_CELLS);
    PG_RESET_OFFSET_PACKETr_CLR(pg_reset_pkt);
    PG_RESET_OFFSET_PACKETr_PG_RESET_OFFSETf_SET(pg_reset_pkt,
                                                 MMU_PG_RESET_OFFSET_PKTS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (port == CMIC_PORT) {
            /* Leave CPU port at default value (0) */
            continue;
        }
        idx = CDK_PBMP_MEMBER(pbmp_8pg, port) ? MMU_NUM_PG - 1 : 0;
        ioerr += WRITE_PG_RESET_OFFSET_CELLr(unit, port, idx, pg_reset_cell);
        ioerr += WRITE_PG_RESET_OFFSET_PACKETr(unit, port, idx, pg_reset_pkt);
    }

    /* Max packet size (in cells) */
    PORT_MAX_PKT_SIZEr_SET(port_max_pkt_size, MMU_JUMBO_FRAME_CELLS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_MAX_PKT_SIZEr(unit, port, port_max_pkt_size);
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

    idx = MMU_NUM_PG - 1;
    PORT_PRI_GRP0r_CLR(port_pri_grp0);
    PORT_PRI_GRP0r_PRI0_GRPf_SET(port_pri_grp0, idx);
    PORT_PRI_GRP0r_PRI1_GRPf_SET(port_pri_grp0, idx);
    PORT_PRI_GRP0r_PRI2_GRPf_SET(port_pri_grp0, idx);
    PORT_PRI_GRP0r_PRI3_GRPf_SET(port_pri_grp0, idx);
    PORT_PRI_GRP0r_PRI4_GRPf_SET(port_pri_grp0, idx);
    PORT_PRI_GRP0r_PRI5_GRPf_SET(port_pri_grp0, idx);
    PORT_PRI_GRP0r_PRI6_GRPf_SET(port_pri_grp0, idx);
    PORT_PRI_GRP0r_PRI7_GRPf_SET(port_pri_grp0, idx);

    PORT_PRI_GRP1r_CLR(port_pri_grp1);
    PORT_PRI_GRP1r_PRI8_GRPf_SET(port_pri_grp1, idx);
    PORT_PRI_GRP1r_PRI9_GRPf_SET(port_pri_grp1, idx);
    PORT_PRI_GRP1r_PRI10_GRPf_SET(port_pri_grp1, idx);
    PORT_PRI_GRP1r_PRI11_GRPf_SET(port_pri_grp1, idx);
    PORT_PRI_GRP1r_PRI12_GRPf_SET(port_pri_grp1, idx);
    PORT_PRI_GRP1r_PRI13_GRPf_SET(port_pri_grp1, idx);
    PORT_PRI_GRP1r_PRI14_GRPf_SET(port_pri_grp1, idx);
    PORT_PRI_GRP1r_PRI15_GRPf_SET(port_pri_grp1, idx);

    CDK_PBMP_ITER(pbmp_8pg, port) {
        ioerr += WRITE_PG_THRESH_SELr(unit, port, pg_thresh_sel);
        ioerr += WRITE_PORT_PRI_GRP0r(unit, port, port_pri_grp0);
        ioerr += WRITE_PORT_PRI_GRP1r(unit, port, port_pri_grp1);
    }

    /*
     * Reserved egress limits and thresholds.
     */

    /* Minimum cells and packets per port, use dynamic limit with alpha = 1/4 */
    OP_QUEUE_CONFIG_CELLr_CLR(op_q_cfg_cell);
    OP_QUEUE_CONFIG_CELLr_Q_MIN_CELLf_SET(op_q_cfg_cell, MMU_OP_PORT_MIN_CELLS);
    OP_QUEUE_CONFIG_CELLr_Q_LIMIT_ENABLE_CELLf_SET(op_q_cfg_cell, 1);
    OP_QUEUE_CONFIG_CELLr_Q_LIMIT_DYNAMIC_CELLf_SET(op_q_cfg_cell, 1);
    OP_QUEUE_CONFIG_CELLr_Q_SHARED_LIMIT_CELLf_SET(op_q_cfg_cell, 2);

    OP_QUEUE_CONFIG_PACKETr_CLR(op_q_cfg_pkt);
    OP_QUEUE_CONFIG_PACKETr_Q_MIN_PACKETf_SET(op_q_cfg_pkt, MMU_OP_PORT_MIN_PKTS);
    OP_QUEUE_CONFIG_PACKETr_Q_LIMIT_ENABLE_PACKETf_SET(op_q_cfg_pkt, 1);
    OP_QUEUE_CONFIG_PACKETr_Q_LIMIT_DYNAMIC_PACKETf_SET(op_q_cfg_pkt, 1);
    OP_QUEUE_CONFIG_PACKETr_Q_SHARED_LIMIT_PACKETf_SET(op_q_cfg_pkt, 2);

    CDK_PBMP_ITER(mmu_pbmp, port) {
        for (idx = 0; idx < MMU_NUM_COS; idx++) {
            ioerr += WRITE_OP_QUEUE_CONFIG_CELLr(unit, port, idx, op_q_cfg_cell);
            ioerr += WRITE_OP_QUEUE_CONFIG_PACKETr(unit, port, idx, op_q_cfg_pkt);
            out_reserved_cells += MMU_OP_PORT_MIN_CELLS;
            out_reserved_pkts += MMU_OP_PORT_MIN_PKTS;
        }
    }

    /* Output port per-port per-COS reset offset */
    OP_QUEUE_RESET_OFFSET_CELLr_SET(q_reset_cell, MMU_OP_RESET_OFFSET_CELLS);
    OP_QUEUE_RESET_OFFSET_PACKETr_SET(q_reset_pkt, MMU_OP_RESET_OFFSET_PKTS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        for (idx = 0; idx < MMU_NUM_COS; idx++) {
            ioerr += WRITE_OP_QUEUE_RESET_OFFSET_CELLr(unit, port, idx,
                                                       q_reset_cell);
            ioerr += WRITE_OP_QUEUE_RESET_OFFSET_PACKETr(unit, port, idx,
                                                         q_reset_pkt);
        }
    }

    /*
     * Shared limits and thresholds.
     */

    /* Use remaining input cells for shared pool */
    shared_cells = total_cells - in_reserved_cells - out_reserved_cells;
    BUFFER_CELL_LIMIT_SPr_SET(cell_limit_sp, shared_cells);
    ioerr += WRITE_BUFFER_CELL_LIMIT_SPr(unit, 0, cell_limit_sp);

    /* Use remaining input packets for shared pool */
    shared_pkts = total_pkts - in_reserved_pkts - out_reserved_pkts;
    BUFFER_PACKET_LIMIT_SPr_SET(packet_limit_sp, shared_pkts);
    ioerr += WRITE_BUFFER_PACKET_LIMIT_SPr(unit, 0, packet_limit_sp);

    /* No limit for shared cells and packets */
    PORT_SHARED_LIMIT_CELLr_CLR(ps_limit_cell);
    PORT_SHARED_LIMIT_CELLr_PORT_SHARED_LIMITf_SET(ps_limit_cell,
                                                   total_cells - 1);
    PORT_SHARED_LIMIT_PACKETr_CLR(ps_limit_pkt);
    PORT_SHARED_LIMIT_PACKETr_PORT_SHARED_LIMITf_SET(ps_limit_pkt,
                                                     total_pkts - 1);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_SHARED_LIMIT_CELLr(unit, port, ps_limit_cell);
        ioerr += WRITE_PORT_SHARED_LIMIT_PACKETr(unit, port, ps_limit_pkt);
    }

    /* Use remaining cells for shared cells */
    shared_cells = total_cells - out_reserved_cells;
    OP_BUFFER_SHARED_LIMIT_CELLr_SET(obs_limit_cell, shared_cells);
    ioerr += WRITE_OP_BUFFER_SHARED_LIMIT_CELLr(unit, obs_limit_cell);

    /* Use remaining output packets for shared pool */
    shared_pkts = total_pkts - out_reserved_pkts;
    OP_BUFFER_SHARED_LIMIT_PACKETr_SET(obs_limit_packet, shared_pkts);
    ioerr += WRITE_OP_BUFFER_SHARED_LIMIT_PACKETr(unit, obs_limit_packet);

    /* Configure limit/reset thresholds as 3/4 and 1/2 of shared limit */
    OP_PORT_CONFIG_CELLr_CLR(op_port_cfg_cell);
    OP_PORT_CONFIG_CELLr_OP_SHARED_LIMIT_CELLf_SET(op_port_cfg_cell, 
                                                   (shared_cells * 3) / 4);
    OP_PORT_CONFIG_CELLr_OP_SHARED_RESET_VALUE_CELLf_SET(op_port_cfg_cell, 
                                                         shared_cells / 2);
    OP_PORT_CONFIG_CELLr_PORT_LIMIT_ENABLE_CELLf_SET(op_port_cfg_cell, 1);

    OP_PORT_CONFIG_PACKETr_CLR(op_port_cfg_pkt);
    OP_PORT_CONFIG_PACKETr_OP_SHARED_LIMIT_PACKETf_SET(op_port_cfg_pkt, 
                                                       (shared_pkts * 3) / 4);
    OP_PORT_CONFIG_PACKETr_OP_SHARED_RESET_VALUE_PACKETf_SET(op_port_cfg_pkt, 
                                                             shared_pkts / 2);
    OP_PORT_CONFIG_PACKETr_PORT_LIMIT_ENABLE_PACKETf_SET(op_port_cfg_pkt, 1);

    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_OP_PORT_CONFIG_CELLr(unit, port, op_port_cfg_cell);
        ioerr += WRITE_OP_PORT_CONFIG_PACKETr(unit, port, op_port_cfg_pkt);
    }

    /*
     * Enable MMU ports
     */

    /* Input port pause enable */
    PORT_PAUSE_ENABLE_64r_CLR(port_pause_en);
    pbm = CDK_PBMP_WORD_GET(mmu_pbmp, 0);
    PORT_PAUSE_ENABLE_64r_PORT_PAUSE_ENABLE_LOf_SET(port_pause_en, pbm);
    pbm = CDK_PBMP_WORD_GET(mmu_pbmp, 1);
    PORT_PAUSE_ENABLE_64r_PORT_PAUSE_ENABLE_HIf_SET(port_pause_en, pbm);
    ioerr += WRITE_PORT_PAUSE_ENABLE_64r(unit, port_pause_en);

    /* Output port configuration */
    OP_THR_CONFIGr_CLR(op_thr_cfg);
    OP_THR_CONFIGr_MOP_POLICYf_SET(op_thr_cfg, MMU_MOP_POLICY);
    OP_THR_CONFIGr_SOP_POLICYf_SET(op_thr_cfg, MMU_SOP_POLICY);
    ioerr += WRITE_OP_THR_CONFIGr(unit, op_thr_cfg);

    /* Input port enable */
    INPUT_PORT_RX_ENABLE_64r_CLR(inp_rx_enable);
    pbm = CDK_PBMP_WORD_GET(mmu_pbmp, 0);
    INPUT_PORT_RX_ENABLE_64r_INPUT_PORT_RX_ENABLE_LOf_SET(inp_rx_enable, pbm);
    pbm = CDK_PBMP_WORD_GET(mmu_pbmp, 1);
    INPUT_PORT_RX_ENABLE_64r_INPUT_PORT_RX_ENABLE_HIf_SET(inp_rx_enable, pbm);
    ioerr += WRITE_INPUT_PORT_RX_ENABLE_64r(unit, inp_rx_enable);

    /* Output port enable */
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
    EGR_PORT_64r_t egr_port;
    EGR_VLAN_CONTROL_1r_t egr_vlan_ctrl1;
    PORT_TABm_t port_tab;
    SYS_PORTMAPm_t sys_portmap;

    /* Default port VLAN and tag action, enable L2 HW learning */
    PORT_TABm_CLR(port_tab);
    PORT_TABm_SRC_SYS_PORT_IDf_SET(port_tab, port);
    PORT_TABm_PORT_VIDf_SET(port_tab, 1);
    PORT_TABm_FILTER_ENABLEf_SET(port_tab, 1);
    PORT_TABm_OUTER_TPID_ENABLEf_SET(port_tab, 1);
    PORT_TABm_CML_FLAGS_NEWf_SET(port_tab, 8);
    PORT_TABm_CML_FLAGS_MOVEf_SET(port_tab, 8);
    ioerr += WRITE_PORT_TABm(unit, port, port_tab);

    /* Identity mapping for system ports */
    SYS_PORTMAPm_CLR(sys_portmap);
    SYS_PORTMAPm_PHYS_PORT_IDf_SET(sys_portmap, port);
    ioerr += WRITE_SYS_PORTMAPm(unit, port, sys_portmap);

    /* Filter VLAN on egress */
    ioerr += READ_EGR_PORT_64r(unit, port, &egr_port);
    EGR_PORT_64r_EN_EFILTERf_SET(egr_port, 1);
    ioerr += WRITE_EGR_PORT_64r(unit, port, egr_port);

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

    /* Common port initialization */
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
    ioerr += WRITE_TX_IPG_LENGTHr(unit, port, tx_ipg);

    return ioerr;
}

int
bcm56524_a0_xport_init(int unit, int port)
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
bcm56524_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
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
    XQPORT_MODE_REGr_t xqport_mode;
    XQPORT_XGXS_NEWCTL_REGr_t xqport_newctl;
    VLAN_PROFILE_TABm_t vlan_profile;
    ING_VLAN_TAG_ACTION_PROFILEm_t vlan_action;
    EGR_VLAN_TAG_ACTION_PROFILEm_t egr_action;
    GPORT_RSV_MASKr_t gport_rsv_mask;
    GPORT_CONFIGr_t gport_cfg;
    cdk_pbmp_t pbmp;
    int xq_xports[] = { 30, 34, 38, 42, 46, 50 };
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
        CDK_WARN(("bcm56524_a0_bmd_init[%d]: IPIPE reset timeout\n", unit));
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
        CDK_WARN(("bcm56524_a0_bmd_init[%d]: EPIPE reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }

    /* Clear pipe reset registers */
    ING_HW_RESET_CONTROL_2r_CLR(ing_rst_ctl_2);
    ioerr += WRITE_ING_HW_RESET_CONTROL_2r(unit, ing_rst_ctl_2);
    EGR_HW_RESET_CONTROL_1r_CLR(egr_rst_ctl_1);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_1r(unit, egr_rst_ctl_1);

    /* Initialize TDM arbiter table */
    CDK_XGS_MEM_CLEAR(unit, IARB_TDM_TABLEm);
    CDK_XGS_MEM_CLEAR(unit, ARB_TDM_TABLEm);
    for (idx = 0; idx < COUNTOF(tdmb524a); idx++) {
        IARB_TDM_TABLEm_CLR(iarb_tdm);
        ARB_TDM_TABLEm_CLR(arb_tdm);
        IARB_TDM_TABLEm_PORT_NUMf_SET(iarb_tdm, tdmb524a[idx]);
        ARB_TDM_TABLEm_PORT_NUMf_SET(arb_tdm, tdmb524a[idx]);
        if (idx == (COUNTOF(tdmb524a) - 1)) {
            ARB_TDM_TABLEm_WRAP_ENf_SET(arb_tdm, 1);
        }
        ioerr += WRITE_IARB_TDM_TABLEm(unit, idx, iarb_tdm);
        ioerr += WRITE_ARB_TDM_TABLEm(unit, idx, arb_tdm);
    }

    /* Enable arbiter */
    ioerr += READ_IARB_TDM_CONTROLr(unit, &iarb_tdm_ctrl);
    IARB_TDM_CONTROLr_DISABLEf_SET(iarb_tdm_ctrl, 0);
    IARB_TDM_CONTROLr_TDM_WRAP_PTRf_SET(iarb_tdm_ctrl, COUNTOF(tdmb524a) - 1);
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

    /* Clear GPORT counters */
    ioerr += READ_GPORT_CONFIGr(unit, &gport_cfg, -1);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 1);
    ioerr += WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 0);
    ioerr += WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);

    /* Enable XQPORTs */
    for (idx = 0; idx < COUNTOF(xq_xports); idx++) {
        port = xq_xports[idx];
        if (!CDK_XGS_PORT_VALID(unit, port)) {
            continue;
        }
        ioerr += READ_XQPORT_MODE_REGr(unit, &xqport_mode, port);
        XQPORT_MODE_REGr_XQPORT_MODE_BITSf_SET(xqport_mode, 1);
        ioerr += WRITE_XQPORT_MODE_REGr(unit, xqport_mode, port);
    }

    /* Configure XQPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XQPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
            ioerr += bcm56524_a0_xport_init(unit, port);
        } else {
            ioerr += _gport_init(unit, port);
        }
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }

    /* Enable Hypercore Tx clocks */
    for (idx = 0; idx < COUNTOF(xq_xports); idx++) {
        port = xq_xports[idx];
        if (!CDK_XGS_PORT_VALID(unit, port)) {
            continue;
        }
        ioerr += READ_XQPORT_XGXS_NEWCTL_REGr(unit, &xqport_newctl, port);
        XQPORT_XGXS_NEWCTL_REGr_TXD1G_FIFO_RSTBf_SET(xqport_newctl, 0xf);
        ioerr += WRITE_XQPORT_XGXS_NEWCTL_REGr(unit, xqport_newctl, port);
    }

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    /* Configure GXPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GXPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += bcm56524_a0_xport_init(unit, port);
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
#endif /* CDK_CONFIG_INCLUDE_BCM56524_A0 */
