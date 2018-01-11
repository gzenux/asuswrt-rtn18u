#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56820_A0 == 1

/*
 * $Id: bcm56820_a0_bmd_init.c,v 1.17 Broadcom SDK $
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

#include <cdk/chip/bcm56820_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56820_a0_bmd.h"
#include "bcm56820_a0_internal.h"

#define PIPE_RESET_TIMEOUT_MSEC         5

#define JUMBO_MAXSZ                     0x3fe8

/* Number of COS queues */
#define MMU_NUM_COS                     8

/* Number of priority groups */
#define MMU_NUM_PG                      8

/* Total number of cell available */
#define MMU_TOTAL_CELLS                 (16 * 1024)

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
#define LIMIT_DISABLE                   0x3fff

/* CFAP adjustments */
#define MMU_CFAP_FULL_SET_OFFSET        0x100
#define MMU_CFAP_FULL_RESET_OFFSET      0x1b0

static int _tdm_arbiter_table_1x[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    1, 2, 3, 4, 5, 6, 0, 7, 8, 9, 10, 11, 12,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0,
    -1
};

static int _tdm_arbiter_table_1y[] = {
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    13, 14, 15, 16, 17, 18, 25, 19, 20, 21, 22, 23, 24,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    13, 14, 15, 16, 17, 18, 27, 19, 20, 21, 22, 23, 24,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 28,
    -1
};

static int _tdm_arbiter_table_2x[] = {
    1, 5, 2, 6, 3, 7, 4, 8, 1, 9, 2, 10, 3, 5,
    4, 6, 1, 7, 2, 8, 3, 9, 4, 10, 1, 5, 2, 0,
    3, 6, 4, 7, 1, 8, 2, 9, 3, 10, 4, 5, 1, 6,
    2, 7, 3, 8, 4, 9, 1, 10, 2, 5, 3, 6, 4, 0,
    7, 1, 8, 2, 9, 3, 10, 4, 5, 1, 6, 2, 7, 3,
    8, 4, 9, 1, 10, 2, 5, 3, 6, 4, 7, 1, 8, 2, 0,
    9, 3, 10, 4, 5, 1, 6, 2, 7, 3, 8, 4, 9, 1,
    10, 2, 5, 3, 6, 4, 7, 1, 8, 2, 9, 3, 10, 4, 0,
    -1
};

static int _tdm_arbiter_table_2y[] = {
    24, 20, 23, 19, 22, 18, 21, 17, 24, 16, 23, 15, 22, 20,
    21, 19, 24, 18, 23, 17, 22, 16, 21, 15, 24, 20, 23, 25,
    22, 19, 21, 18, 24, 17, 23, 16, 22, 15, 21, 20, 24, 19,
    23, 18, 22, 17, 21, 16, 24, 15, 23, 20, 22, 19, 21, 26,
    18, 24, 17, 23, 16, 22, 15, 21, 20, 24, 19, 23, 18, 22,
    17, 21, 16, 24, 15, 23, 20, 22, 19, 21, 18, 24, 17, 23, 27,
    16, 22, 15, 21, 20, 24, 19, 23, 18, 22, 17, 21, 16, 24,
    15, 23, 20, 22, 19, 21, 18, 24, 17, 23, 16, 22, 15, 21, 28,
    -1
};

static int _tdm_arbiter_table_3x[] = {
    7, 8, 9, 10, 11, 12, 0x1f,
    7, 8, 9, 10, 11, 12, 0x1f,
    7, 8, 9, 10, 11, 12, 0x1f,
    7, 8, 9, 10, 11, 12, 0,
    -1
};

static int _tdm_arbiter_table_3y[] = {
    13, 14, 15, 16, 17, 18, 0x1f,
    13, 14, 15, 16, 17, 18, 0x1f,
    13, 14, 15, 16, 17, 18, 0x1f,
    13, 14, 15, 16, 17, 18, 25,
    13, 14, 15, 16, 17, 18, 0x1f,
    13, 14, 15, 16, 17, 18, 0x1f,
    13, 14, 15, 16, 17, 18, 0x1f,
    13, 14, 15, 16, 17, 18, 26,
    13, 14, 15, 16, 17, 18, 0x1f,
    13, 14, 15, 16, 17, 18, 0x1f,
    13, 14, 15, 16, 17, 18, 0x1f,
    13, 14, 15, 16, 17, 18, 27,
    13, 14, 15, 16, 17, 18, 0x1f,
    13, 14, 15, 16, 17, 18, 0x1f,
    13, 14, 15, 16, 17, 18, 0x1f,
    13, 14, 15, 16, 17, 18, 28,
    -1
};

static int
_tdm_arbiter_init(int unit)
{
    int ioerr = 0;
    int *x_ports, *y_ports;
    int idx, wrap;
    ARB_TDM_TABLEm_t arb_entry;
    X_ARB_TDM_TABLEm_t x_arb_entry;
    Y_ARB_TDM_TABLEm_t y_arb_entry;
    TDM_ENr_t tdm_en;
    X_TDM_ENr_t x_tdm_en;
    Y_TDM_ENr_t y_tdm_en;

    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_TDM3_X) {
        x_ports = _tdm_arbiter_table_3x;
    } else if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_TDM2_X) {
        x_ports = _tdm_arbiter_table_2x;
    } else {
        x_ports = _tdm_arbiter_table_1x;
    }

    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_TDM3_Y) {
        y_ports = _tdm_arbiter_table_3y;
    } else if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_TDM2_Y) {
        y_ports = _tdm_arbiter_table_2y;
    } else {
        y_ports = _tdm_arbiter_table_1y;
    }

    /* Ingress pipe select X */
    bcm56820_a0_pipe_select(unit, 0);

    ARB_TDM_TABLEm_CLR(arb_entry);
    X_ARB_TDM_TABLEm_CLR(x_arb_entry);
    wrap = 0;
    for (idx = ARB_TDM_TABLEm_MIN; idx <= ARB_TDM_TABLEm_MAX && !wrap; idx++) {
        if (x_ports[idx + 1] < 0) {
            wrap = 1;
        }
        /* MMU table */
        X_ARB_TDM_TABLEm_PORT_NUMf_SET(x_arb_entry, x_ports[idx]);
        if (wrap) {
            X_ARB_TDM_TABLEm_WRAP_ENf_SET(x_arb_entry, 1);
        }
        ioerr += WRITE_X_ARB_TDM_TABLEm(unit, idx, x_arb_entry);
        /* Ingress (X) table */
        ARB_TDM_TABLEm_PORT_NUMf_SET(arb_entry, x_ports[idx]);
        if (wrap) {
            ARB_TDM_TABLEm_WRAP_ENf_SET(arb_entry, 1);
        }
        ioerr += WRITE_ARB_TDM_TABLEm(unit, idx, arb_entry);
    }

    /* Ingress pipe select Y */
    bcm56820_a0_pipe_select(unit, 1);

    ARB_TDM_TABLEm_CLR(arb_entry);
    Y_ARB_TDM_TABLEm_CLR(y_arb_entry);
    wrap = 0;
    for (idx = ARB_TDM_TABLEm_MIN; idx <= ARB_TDM_TABLEm_MAX && !wrap; idx++) {
        if (y_ports[idx] < 0) {
            wrap = 1;
        }
        /* MMU table */
        Y_ARB_TDM_TABLEm_PORT_NUMf_SET(y_arb_entry, y_ports[idx]);
        if (wrap) {
            Y_ARB_TDM_TABLEm_WRAP_ENf_SET(y_arb_entry, 1);
        }
        ioerr += WRITE_Y_ARB_TDM_TABLEm(unit, idx, y_arb_entry);
        /* Ingress (Y) table */
        ARB_TDM_TABLEm_PORT_NUMf_SET(arb_entry, y_ports[idx]);
        if (wrap) {
            ARB_TDM_TABLEm_WRAP_ENf_SET(arb_entry, 1);
        }
        ioerr += WRITE_ARB_TDM_TABLEm(unit, idx, arb_entry);
    }

    /* Enable TDM for MMU while still in Y pipe */
    TDM_ENr_SET(tdm_en, 1);
    ioerr += WRITE_TDM_ENr(unit, tdm_en);

    /* Switch back to X pipe and enable TDM for MMU */
    bcm56820_a0_pipe_select(unit, 0);
    ioerr += WRITE_TDM_ENr(unit, tdm_en);

    /* Enable TDM for ingress X and Y pipes */
    X_TDM_ENr_SET(x_tdm_en, 1);
    ioerr += WRITE_X_TDM_ENr(unit, x_tdm_en);
    Y_TDM_ENr_SET(y_tdm_en, 1);
    ioerr += WRITE_Y_TDM_ENr(unit, y_tdm_en);

    return ioerr;
}

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
    PG_RESET_OFFSETr_t pg_reset_offset;
    PG_RESET_FLOORr_t pg_reset_floor;
    PG_MINr_t pg_min;
    PG_HDRM_LIMITr_t pg_hdrm_limit;
    PORT_PRI_GRP0r_t port_pri_grp0;
    PORT_PRI_GRP1r_t port_pri_grp1;
    PORT_SC_MINr_t port_sc_min;
    PORT_QM_MINr_t port_qm_min;
    OP_BUFFER_SHARED_LIMITr_t obs_limit;
    OP_PORT_CONFIGr_t op_port_config;
    OP_QUEUE_CONFIGr_t op_queue_config;
    OP_QUEUE_RESET_OFFSETr_t opq_rst_offs;
    OP_THR_CONFIGr_t op_thr_config;
    CFAPCONFIGr_t cfapconfig;
    CFAPFULLTHRESHOLDr_t cfapfullthreshold;
    PORT_PRI_XON_ENABLEr_t port_pri_xon_enable;
    INPUT_PORT_RX_ENABLEr_t input_port_rx_enable;
    OUTPUT_PORT_RX_ENABLEr_t output_port_rx_enable;

    /* Ports to configure */
    CDK_PBMP_CLEAR(mmu_pbmp);
    CDK_PBMP_ADD(mmu_pbmp, CMIC_PORT);
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_QGPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);
#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GXPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);
#endif

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

    PG_RESET_OFFSETr_SET(pg_reset_offset, MMU_MTU_CELLS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        for (i = 0; i < MMU_NUM_PG; i++) {
            ioerr += WRITE_PG_RESET_OFFSETr(unit, port, i, pg_reset_offset);
        }
    }

    /* Currently everything is zero, but keep code for reference */
    PG_RESET_FLOORr_CLR(pg_reset_floor);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        for (i = 0; i < MMU_NUM_PG; i++) {
            ioerr += WRITE_PG_RESET_FLOORr(unit, port, i, pg_reset_floor);
        }
    }

    /* With only one PG in use PORT_MIN should be sufficient */
    PG_MINr_CLR(pg_min);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        for (i = 0; i < MMU_NUM_PG; i++) {
            ioerr += WRITE_PG_MINr(unit, port, i, pg_min);
        }
    }

    /* Note that only PG-max is being used */
    PG_HDRM_LIMITr_CLR(pg_hdrm_limit);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        for (i = 0; i < MMU_NUM_PG; i++) {
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

    PORT_PRI_GRP0r_CLR(port_pri_grp0);
    PORT_PRI_GRP0r_PRI0_GRPf_SET(port_pri_grp0, MMU_NUM_PG - 1);
    PORT_PRI_GRP0r_PRI1_GRPf_SET(port_pri_grp0, MMU_NUM_PG - 1);
    PORT_PRI_GRP0r_PRI2_GRPf_SET(port_pri_grp0, MMU_NUM_PG - 1);
    PORT_PRI_GRP0r_PRI3_GRPf_SET(port_pri_grp0, MMU_NUM_PG - 1);
    PORT_PRI_GRP0r_PRI4_GRPf_SET(port_pri_grp0, MMU_NUM_PG - 1);
    PORT_PRI_GRP0r_PRI5_GRPf_SET(port_pri_grp0, MMU_NUM_PG - 1);
    PORT_PRI_GRP0r_PRI6_GRPf_SET(port_pri_grp0, MMU_NUM_PG - 1);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_PRI_GRP0r(unit, port, port_pri_grp0);
    }
    PORT_PRI_GRP1r_CLR(port_pri_grp1);
    PORT_PRI_GRP1r_PRI7_GRPf_SET(port_pri_grp1, MMU_NUM_PG - 1);
    PORT_PRI_GRP1r_PRI8_GRPf_SET(port_pri_grp1, MMU_NUM_PG - 1);
    PORT_PRI_GRP1r_PRI9_GRPf_SET(port_pri_grp1, MMU_NUM_PG - 1);
    PORT_PRI_GRP1r_PRI10_GRPf_SET(port_pri_grp1, MMU_NUM_PG - 1);
    PORT_PRI_GRP1r_PRI11_GRPf_SET(port_pri_grp1, MMU_NUM_PG - 1);
    PORT_PRI_GRP1r_PRI12_GRPf_SET(port_pri_grp1, MMU_NUM_PG - 1);
    PORT_PRI_GRP1r_PRI13_GRPf_SET(port_pri_grp1, MMU_NUM_PG - 1);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        ioerr += WRITE_PORT_PRI_GRP1r(unit, port, port_pri_grp1);
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

    OP_QUEUE_RESET_OFFSETr_CLR(opq_rst_offs);
    OP_QUEUE_RESET_OFFSETr_Q_RESET_OFFSETf_SET(opq_rst_offs, MMU_MTU_CELLS >> 4);
    OP_QUEUE_CONFIGr_CLR(op_queue_config);
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
            OP_QUEUE_CONFIGr_Q_SHARED_LIMITf_SET(op_queue_config, 0x6);
        }
        for (i = 0; i < MMU_NUM_COS; i++) {
            ioerr += WRITE_OP_QUEUE_CONFIGr(unit, port, i, op_queue_config);
            ioerr += WRITE_OP_QUEUE_RESET_OFFSETr(unit, port, i, opq_rst_offs);
        }
        for (i = 8; i <= 9; i++) {
            ioerr += WRITE_OP_QUEUE_CONFIGr(unit, port, i, op_queue_config);
            ioerr += WRITE_OP_QUEUE_RESET_OFFSETr(unit, port, i, opq_rst_offs);
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
    GPORT_RSV_MASKr_t gport_rsv_mask;
    GPORT_STAT_UPDATE_MASKr_t stat_upd_mask;
    uint32_t rsv_mask;

    /* Common port initialization */
    ioerr += _port_init(unit, port);

    /* Ensure that MAC (Rx) and loopback mode is disabled */
    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
    COMMAND_CONFIGr_LOOP_ENAf_SET(command_cfg, 0);
    COMMAND_CONFIGr_RX_ENAf_SET(command_cfg, 0);
    COMMAND_CONFIGr_TX_ENAf_SET(command_cfg, 1);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);

    /* Fixup packet purge filtering */
    rsv_mask = 0x70;
    GPORT_RSV_MASKr_SET(gport_rsv_mask, rsv_mask);
    ioerr += WRITE_GPORT_RSV_MASKr(unit, port, gport_rsv_mask);
    GPORT_STAT_UPDATE_MASKr_SET(stat_upd_mask, rsv_mask);
    ioerr += WRITE_GPORT_STAT_UPDATE_MASKr(unit, port, stat_upd_mask);

    return ioerr;
}

int
bcm56820_a0_gxport_init(int unit, int port)
{
    int ioerr = 0;
    GPORT_CONFIGr_t gport_cfg;
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

    /* Clear GE counters */
    ioerr += READ_GPORT_CONFIGr(unit, port, &gport_cfg);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 1);
    ioerr += WRITE_GPORT_CONFIGr(unit, port, gport_cfg);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 0);
    ioerr += WRITE_GPORT_CONFIGr(unit, port, gport_cfg);

    /* Enable XPORT by default if 10G port */
    XPORT_CONFIGr_CLR(xport_cfg);
    XPORT_CONFIGr_XPORT_ENf_SET(xport_cfg, 1);
    ioerr += WRITE_XPORT_CONFIGr(unit, port, xport_cfg);

    /* Set XPORT mode to 10G by default */
    ioerr += READ_XPORT_MODE_REGr(unit, port, &xport_mode);
    XPORT_MODE_REGr_XPORT_MODE_BITSf_SET(xport_mode, 1);
    ioerr += WRITE_XPORT_MODE_REGr(unit, port, xport_mode);

    /* Enable 1G Tx clocks */
    ioerr += READ_XPORT_XGXS_NEWCTL_REGr(unit, port, &xport_newctl);
    XPORT_XGXS_NEWCTL_REGr_TXD1G_FIFO_RSTBf_SET(xport_newctl, 0xf);
    ioerr += WRITE_XPORT_XGXS_NEWCTL_REGr(unit, port, xport_newctl);

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
bcm56820_a0_pipe_select(int unit, int select_pipe_y)
{
    int ioerr = 0;
    SBS_CONTROLr_t sbs_ctrl;
    EGR_SBS_CONTROLr_t egr_sbs_ctrl;

    SBS_CONTROLr_SET(sbs_ctrl, select_pipe_y ? 1 : 0);
    ioerr += WRITE_SBS_CONTROLr(unit, sbs_ctrl);

    EGR_SBS_CONTROLr_SET(egr_sbs_ctrl, select_pipe_y ? 1 : 0);
    ioerr += WRITE_EGR_SBS_CONTROLr(unit, egr_sbs_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

int
bcm56820_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    ING_HW_RESET_CONTROL_1r_t ing_rst_ctl_1;
    ING_HW_RESET_CONTROL_2r_t ing_rst_ctl_2;
    EGR_HW_RESET_CONTROL_0r_t egr_rst_ctl_0;
    EGR_HW_RESET_CONTROL_1r_t egr_rst_ctl_1;
    MISCCONFIGr_t misc_cfg;
    CMIC_RATE_ADJUSTr_t rate_adjust;
    CMIC_RATE_ADJUST_INT_MDIOr_t rate_adjust_int_mdio;
    RDBGC0_SELECTr_t rdbgc0_select;
    VLAN_PROFILE_TABm_t vlan_profile;
    ING_VLAN_TAG_ACTION_PROFILEm_t vlan_action;
    EGR_VLAN_TAG_ACTION_PROFILEm_t egr_action;
    QGPORT_CONFIGr_t qgport_cfg;
    cdk_pbmp_t pbmp;
    int mdio_div;
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
        CDK_WARN(("bcm56820_a0_bmd_init[%d]: IPIPE reset timeout\n", unit));
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
        CDK_WARN(("bcm56820_a0_bmd_init[%d]: EPIPE reset timeout\n", unit));
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
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_CLK_225) {
        /* mdio_refclk = 225 MHz * (1/45) = 5 MHz */
        mdio_div = 45;
    } else if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_CLK_245) {
        /* mdio_refclk = 245 MHz * (1/49) = 5 MHz */
        mdio_div = 49;
    } else {
        /* mdio_refclk = 220 MHz * (1/44) = 5 MHz */
        mdio_div = 44;
    }

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

    /* Initialize arbiter */
    ioerr += _tdm_arbiter_init(unit);

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

    /* Enable QGPORT and clear counters */
    ioerr += READ_QGPORT_CONFIGr(unit, &qgport_cfg, -1);
    QGPORT_CONFIGr_GPORT_ENf_SET(qgport_cfg, 1);
    QGPORT_CONFIGr_CLR_CNTf_SET(qgport_cfg, 1);
    ioerr += WRITE_QGPORT_CONFIGr(unit, qgport_cfg, -1);
    QGPORT_CONFIGr_CLR_CNTf_SET(qgport_cfg, 0);
    ioerr += WRITE_QGPORT_CONFIGr(unit, qgport_cfg, -1);

    /* Configure QGPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_QGPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _gport_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    /* Configure GXPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GXPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += bcm56820_a0_gxport_init(unit, port);
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
#endif /* CDK_CONFIG_INCLUDE_BCM56820_A0 */
