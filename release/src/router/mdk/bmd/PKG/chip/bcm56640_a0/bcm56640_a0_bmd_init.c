#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56640_A0 == 1

/*
 * $Id: bcm56640_a0_bmd_init.c,v 1.23 Broadcom SDK $
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

#include <bmdi/arch/xgsm_dma.h>

#include <cdk/chip/bcm56640_a0_defs.h>
#include <cdk/arch/xgsm_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56640_a0_bmd.h"
#include "bcm56640_a0_internal.h"

#define PIPE_RESET_TIMEOUT_MSEC         5
#define LLS_RESET_TIMEOUT_MSEC          50

#define PASSTHRU_MPORT                  58

#define JUMBO_MAXSZ                     0x3fe8

#define MMU_CELLS_RSVD_IP               100

#define MMU_MAX_PKT_BYTES               (10 * 1024L) /* bytes */
#define MMU_PKT_HDR_BYTES               64    /* bytes */
#define MMU_JUMBO_FRAME_BYTES           9216  /* bytes */
#define MMU_DEFAULT_MTU_BYTES           1536  /* bytes */

#define MMU_TOTAL_CELLS_24K             (24 * 1024L) /* 24k cells */
#define MMU_TOTAL_CELLS_19K             (19 * 1024L) /* 19k cells */
#define MMU_IN_PG_HDRM_CELLS            162
#define MMU_OUT_PORT_MIN_CELLS          0

#define MMU_CELL_BYTES                  208
#define MMU_NUM_PG                      8
#define MMU_NUM_POOL                    4

#define MMU_PG_PER_PORT                 1
#define MMU_DEFAULT_PG                  (MMU_NUM_PG - 1)

#define ISM_NUM_STAGES                  4
#define ISM_BANKS_PER_STAGE             5
#define ISM_CHUNKS_PER_STAGE            16

#define ISM_176_CHIP_FLAGS              (CHIP_FLAG_MMU19 | \
                                         CHIP_FLAG_GE28)

#define ISM_80_CHIP_FLAGS               (CHIP_FLAG_NO_DPI)

#define FW_ALIGN_BYTES                  16
#define FW_ALIGN_MASK                   (FW_ALIGN_BYTES - 1)

#define CMIC_NUM_PKT_DMA_CHAN           4

typedef struct _ism_cfg_s {
    int chunk_size;
    int num_chunks[ISM_BANKS_PER_STAGE];
} _ism_cfg_t;

typedef struct _ism_tbl_cfg_s {
    int num_banks;
    const uint8_t *bank_info;
} _ism_tbl_cfg_t;

#define _TBL_CFG(_cfg) { COUNTOF(_cfg), _cfg }

/* Bank info combines 4-bit search stage and 4-bit search bank */
#define BANK_INFO_STAGE_NO(_bank_info) ((_bank_info) >> 4)
#define BANK_INFO_BANK_NO(_bank_info) ((_bank_info) & 0xf)

/* Index of first chunk in each search bank */
static const int _ism_bank_start[ISM_BANKS_PER_STAGE] = { 0, 8, 12, 14, 15 };

/* ISM bank configurations (chunk size and chunks per bank) */
static const _ism_cfg_t _ism_512 = { 2048, { 8, 4, 2, 1, 1 } };
static const _ism_cfg_t _ism_176 = { 1024, { 4, 4, 2, 1, 0 } };
static const _ism_cfg_t _ism_80  = { 1024, { 0, 2, 1, 1, 1 } };

/* ISM table configuration for 512K mode */

/* Bank info for each table, e.g. 0x12 means stage 1 bank 2 */
static const uint8_t _vlan_xlate_512[] = { 0x20 };
static const uint8_t _l2_entry_512[] = { 0x00, 0x10 };
static const uint8_t _l3_entry_512[] = { 0x30, 0x01, 0x11 };
static const uint8_t _ep_vlan_xlate_512[] = { 0x02 };
static const uint8_t _mpls_512[] = { 0x21, 0x31 };

static const _ism_tbl_cfg_t _ism_tbl_cfg_512[] = {
    _TBL_CFG(_vlan_xlate_512),
    _TBL_CFG(_l2_entry_512),
    _TBL_CFG(_l3_entry_512),
    _TBL_CFG(_ep_vlan_xlate_512),
    _TBL_CFG(_mpls_512)
};

/* ISM table configuration for 176K mode */

/* Bank info for each table, e.g. 0x12 means stage 1 bank 2 */
static const uint8_t _vlan_xlate_176[] = { 0x20, 0x13, 0x23 };
static const uint8_t _l2_entry_176[] = { 0x00, 0x10, 0x02, 0x03 };
static const uint8_t _l3_entry_176[] = { 0x30, 0x01, 0x12, 0x33 };
static const uint8_t _ep_vlan_xlate_176[] = { 0x32 };
static const uint8_t _mpls_176[] = { 0x11, 0x23 };

static const _ism_tbl_cfg_t _ism_tbl_cfg_176[] = {
    _TBL_CFG(_vlan_xlate_176),
    _TBL_CFG(_l2_entry_176),
    _TBL_CFG(_l3_entry_176),
    _TBL_CFG(_ep_vlan_xlate_176),
    _TBL_CFG(_mpls_176)
};

/* ISM table configuration for 80K mode */

/* Bank info for each table, e.g. 0x12 means stage 1 bank 2 */
static const uint8_t _vlan_xlate_80[] = { 0x21 };
static const uint8_t _l2_entry_80[] = { 0x01, 0x11, 0x02, 0x12, 0x22, 0x32 };
static const uint8_t _l3_entry_80[] = { 0x31 };
static const uint8_t _ep_vlan_xlate_80[] = { 0x03 };

static const _ism_tbl_cfg_t _ism_tbl_cfg_80[] = {
    _TBL_CFG(_vlan_xlate_80),
    _TBL_CFG(_l2_entry_80),
    _TBL_CFG(_l3_entry_80),
    _TBL_CFG(_ep_vlan_xlate_80)
};

static int
_port_map_init(int unit)
{
    int ioerr = 0;
    int port, lport, mport;
    int num_pport = NUM_PHYS_PORTS;
    int num_lport = NUM_LOGIC_PORTS;
    int num_mport = NUM_MMU_PORTS;
    cdk_pbmp_t pbmp;
    ING_PHYS_TO_LOGIC_MAPm_t ing_p2l;
    EGR_LOGIC_TO_PHYS_MAPr_t egr_l2p;
    MMU_TO_PHYS_MAPr_t mmu_m2p;
    MMU_TO_LOGIC_MAPr_t mmu_m2l;

    bcm56640_a0_xport_pbmp_get(unit, &pbmp);
    CDK_PBMP_PORT_ADD(pbmp, CMIC_PORT);

    /* Ingress physical to logical port mapping */
    ING_PHYS_TO_LOGIC_MAPm_CLR(ing_p2l);
    for (port = 0; port < num_pport; port++) {
        lport = P2L(unit, port);
        if (lport < 0) {
            lport = 0x7f;
        }
        ING_PHYS_TO_LOGIC_MAPm_LOGIC_PORTf_SET(ing_p2l, lport);
        ioerr += WRITE_ING_PHYS_TO_LOGIC_MAPm(unit, port, ing_p2l);
    }

    /* Egress logical to physical port mapping */
    for (lport = 0; lport < num_lport; lport++) {
        port = L2P(unit, lport);
        if (port < 0) {
            port = 0x7f;
        }
        EGR_LOGIC_TO_PHYS_MAPr_PHYS_PORTf_SET(egr_l2p, port);
        ioerr += WRITE_EGR_LOGIC_TO_PHYS_MAPr(unit, lport, egr_l2p);
    }

    /* MMU to physical port mapping and MMU to logical port mapping */
    for (mport = 0; mport < num_mport; mport++) {
        port = M2P(unit, mport);
        if (port < 0) {
            port = 0x7f;
            lport = -1;
        } else {
            lport = P2L(unit, port);
        }
        if (lport < 0) {
            lport = 0x3f;
        }
        MMU_TO_PHYS_MAPr_PHYS_PORTf_SET(mmu_m2p, port);
        ioerr += WRITE_MMU_TO_PHYS_MAPr(unit, mport, mmu_m2p);
        MMU_TO_LOGIC_MAPr_LOGIC_PORTf_SET(mmu_m2l, lport);
        ioerr += WRITE_MMU_TO_LOGIC_MAPr(unit, mport, mmu_m2l);
    }

    return ioerr;
}

static int
_mmu_tdm_init(int unit)
{
    int ioerr = 0;
    IARB_TDM_CONTROLr_t iarb_tdm_ctrl;
    IARB_TDM_TABLEm_t arb_tdm;
    LLS_PORT_TDMm_t lls_tdm;
    LLS_TDM_CAL_CFGr_t tdm_cal_cfg;
    const int *tdm_seq;
    int tdm_seq_len, tdm_max, idx, mdx;
    int port, mport;

    /* Get default TDM sequence for this configuration */
    tdm_seq_len = bcm56640_a0_tdm_default(unit, &tdm_seq);
    if (tdm_seq_len <= 0) {
        return CDK_E_INTERNAL;
    }
    tdm_max = tdm_seq_len - 1;

    /* Disable arbiter while programming TDM tables */
    ioerr += READ_IARB_TDM_CONTROLr(unit, &iarb_tdm_ctrl);
    IARB_TDM_CONTROLr_DISABLEf_SET(iarb_tdm_ctrl, 1);
    IARB_TDM_CONTROLr_TDM_WRAP_PTRf_SET(iarb_tdm_ctrl, tdm_max);
    ioerr += WRITE_IARB_TDM_CONTROLr(unit, iarb_tdm_ctrl);

    IARB_TDM_TABLEm_CLR(arb_tdm);
    for (idx = 0; idx < tdm_seq_len; idx++) {
        port = tdm_seq[idx];
        if (port < 0) {
            port = 0x7f;
            mport = 0x3f;
        } else {
            mport = P2M(unit, port);
        }
        IARB_TDM_TABLEm_PORT_NUMf_SET(arb_tdm, port);
        WRITE_IARB_TDM_TABLEm(unit, idx, arb_tdm);

        if (idx & 1) {
            LLS_PORT_TDMm_PORT_ID_1f_SET(lls_tdm, mport);
            LLS_PORT_TDMm_PORT_ID_1_ENABLEf_SET(lls_tdm, 1);
            mdx = idx >> 1;
            ioerr += WRITE_LLS_PORT_TDMm(unit, mdx, lls_tdm);
            ioerr += WRITE_LLS_PORT_TDMm(unit, mdx + 512, lls_tdm);
        } else {
            LLS_PORT_TDMm_PORT_ID_0f_SET(lls_tdm, mport);
            LLS_PORT_TDMm_PORT_ID_0_ENABLEf_SET(lls_tdm, 1);
        }
    }

    /* Enable arbiter */
    ioerr += READ_IARB_TDM_CONTROLr(unit, &iarb_tdm_ctrl);
    IARB_TDM_CONTROLr_DISABLEf_SET(iarb_tdm_ctrl, 0);
#if BMD_CONFIG_SIMULATION
    IARB_TDM_CONTROLr_DISABLEf_SET(iarb_tdm_ctrl, 1);
#endif
    IARB_TDM_CONTROLr_AUX_CMICM_SLOT_ENf_SET(iarb_tdm_ctrl, 1); 
    IARB_TDM_CONTROLr_AUX_AXP_SLOT_ENf_SET(iarb_tdm_ctrl, 1);
    ioerr += WRITE_IARB_TDM_CONTROLr(unit, iarb_tdm_ctrl);

    LLS_TDM_CAL_CFGr_CLR(tdm_cal_cfg);
    LLS_TDM_CAL_CFGr_END_Af_SET(tdm_cal_cfg, tdm_max);
    LLS_TDM_CAL_CFGr_END_Bf_SET(tdm_cal_cfg, tdm_max);
    LLS_TDM_CAL_CFGr_DEFAULT_PORTf_SET(tdm_cal_cfg, PASSTHRU_MPORT);
    LLS_TDM_CAL_CFGr_ENABLEf_SET(tdm_cal_cfg, 1);
    ioerr += WRITE_LLS_TDM_CAL_CFGr(unit, tdm_cal_cfg);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

static uint32_t
_mmu_port_mc_credits(int unit, int port)
{
    uint32_t speed;
    int mport = P2M(unit, port);

    if (mport == 56) {
        return 2 * 1024;
    }
    if (mport == 58) {
        return 4 * 1024;
    }
    if (mport == 59) {
        return 12 * 1024;
    }
    if (mport == 60 || mport == 61) {
        return 256;
    }

    speed = bcm56640_a0_port_speed_max(unit, port);

    if (speed > 42000) {
        return 20 * 1024;
    }
    if (speed >= 20000) {
        return 4 * 1024;
    }
    if (speed >= 10000) {
        return 1024;
    }
    if (speed >= 1000) {
        return 256;
    }
    return 0;
}

static int
_lls_reset(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    LLS_SOFT_RESETr_t soft_reset;
    LLS_INITr_t lls_init;
    int idx;

    READ_LLS_SOFT_RESETr(unit, &soft_reset);
    LLS_SOFT_RESETr_SOFT_RESETf_SET(soft_reset, 0);
    ioerr  += WRITE_LLS_SOFT_RESETr(unit, soft_reset);

    READ_LLS_INITr(unit, &lls_init);
    LLS_INITr_INITf_SET(lls_init, 1);
    ioerr  += WRITE_LLS_INITr(unit, lls_init);

    for (idx = 0; idx < LLS_RESET_TIMEOUT_MSEC; idx++) {
        READ_LLS_INITr(unit, &lls_init);
        if (LLS_INITr_INIT_DONEf_GET(lls_init)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (idx >= LLS_RESET_TIMEOUT_MSEC) {
        CDK_WARN(("bcm56640_a0_bmd_init[%d]: LLS reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }
    return ioerr ? CDK_E_IO : rv;
}

/*
 *  Linked List Scheduler (LLS)
 *  ===========================
 *
 *   48 CPU (multicast) queues map to single L1/L0 node:
 *
 *   Queue    L1  L0  MMU port
 *  --------------------------
 *   1536      0   0    59
 *   1537      0   0    59
 *       ...
 *
 *   1583      0   0    59
 *
 *
 *   8/10 per-port multicast queues map to 8/10 L1 nodes:
 *
 *   Queue    L1  L0  MMU port
 *  --------------------------
 *   1024      1   1     0
 *   1025      2   1     0
 *       ...
 *
 *   1531      8   1     0
 *   1032      9   2     1
 *   1033     10   2     1
 *       ...
 *
 *   1539     16   2     1
 *       ...
 *
 *
 *   8/10 per-port unicast queues map to 8/10 L1 nodes:
 *   (same L1/L0 nodes as used by multicast)
 *
 *   Queue    L1  L0  MMU port
 *  --------------------------
 *      0      1   1     0
 *      1      2   1     0
 *       ...
 *
 *      7      8   1     0
 *      8      9   2     1
 *      9     10   2     1
 *       ...
 *
 *     15     16   2     1
 *       ...
 *
 */
static int
_lls_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    LLS_L0_CHILD_WEIGHT_CFGm_t l0_weight;
    LLS_L1_CHILD_WEIGHT_CFGm_t l1_weight;
    LLS_L2_CHILD_WEIGHT_CFGm_t l2_weight;
    LLS_PORT_CONFIGm_t lls_pcfg;
    LLS_L0_CONFIGm_t lls_l0cfg;
    LLS_L1_CONFIGm_t lls_l1cfg;
    LLS_L0_PARENTm_t l0_parent;
    LLS_L1_PARENTm_t l1_parent;
    LLS_L2_PARENTm_t l2_parent;
    ING_COS_MODEr_t icos_mode;
    LLS_CONFIG0r_t lls_cfg;
    cdk_pbmp_t mmu_pbmp;
    int port, mport, lport, idx, qx, num_mc_q, num_uc_q;
    int base, lx0, lx1, lx2;

    /* Get front-panel ports */
    bcm56640_a0_xport_pbmp_get(unit, &mmu_pbmp);

    lx0 = 0;
    lx1 = 0;

    /* Default entry values */
    LLS_L0_PARENTm_CLR(l0_parent);
    LLS_L1_PARENTm_CLR(l1_parent);
    LLS_L2_PARENTm_CLR(l2_parent);
    LLS_L0_CHILD_WEIGHT_CFGm_CLR(l0_weight);
    LLS_L1_CHILD_WEIGHT_CFGm_CLR(l1_weight);
    LLS_L2_CHILD_WEIGHT_CFGm_CLR(l2_weight);
    LLS_PORT_CONFIGm_CLR(lls_pcfg);
    LLS_PORT_CONFIGm_L0_LOCK_ON_PACKETf_SET(lls_pcfg, 1);
    LLS_PORT_CONFIGm_L1_LOCK_ON_PACKETf_SET(lls_pcfg, 1);
    LLS_PORT_CONFIGm_L2_LOCK_ON_PACKETf_SET(lls_pcfg, 1);
    LLS_L0_CONFIGm_CLR(lls_l0cfg);
    LLS_L0_CONFIGm_P_CFG_EF_PROPAGATEf_SET(lls_l0cfg, 1);
    LLS_L1_CONFIGm_CLR(lls_l1cfg);
    LLS_L1_CONFIGm_P_CFG_EF_PROPAGATEf_SET(lls_l1cfg, 1);

    /* Configure CPU queues */
    mport = P2M(unit, CMIC_PORT);
    lx2 = MMU_QBASE_CPU;
    num_mc_q = 48;
    LLS_L2_PARENTm_C_PARENTf_SET(l2_parent, lx1);
    /* All CPU queues map to a single L1 node with equal weight */
    LLS_L2_CHILD_WEIGHT_CFGm_C_WEIGHTf_SET(l2_weight, 1);
    for (qx = 0; qx < num_mc_q; qx++) {
        idx = lx2 + qx;
        ioerr += WRITE_LLS_L2_PARENTm(unit, idx, l2_parent);
        ioerr += WRITE_LLS_L2_CHILD_WEIGHT_CFGm(unit, idx, l2_weight);
    }
    /* Enable WRR for L1 node */
    LLS_L1_CONFIGm_P_WRR_IN_USEf_SET(lls_l1cfg, 1);
    LLS_L1_CONFIGm_P_NUM_SPRIf_SET(lls_l1cfg, 0);
    ioerr += WRITE_LLS_L1_CONFIGm(unit, lx1, lls_l1cfg);
    /* Map to single L0 node using strict priority */
    LLS_L1_PARENTm_C_PARENTf_SET(l1_parent, lx0);
    ioerr += WRITE_LLS_L1_PARENTm(unit, lx1, l1_parent);
    ioerr += WRITE_LLS_L1_CHILD_WEIGHT_CFGm(unit, lx1, l1_weight);
    LLS_L0_CONFIGm_P_NUM_SPRIf_SET(lls_l0cfg, 1);
    ioerr += WRITE_LLS_L0_CONFIGm(unit, lx0, lls_l0cfg);
    /* Map L0 node to MMU port using strict priority */
    LLS_L0_PARENTm_C_PARENTf_SET(l0_parent, mport);
    ioerr += WRITE_LLS_L0_PARENTm(unit, lx0, l0_parent);
    ioerr += WRITE_LLS_L0_CHILD_WEIGHT_CFGm(unit, lx0, l0_weight);
    LLS_PORT_CONFIGm_P_NUM_SPRIf_SET(lls_pcfg, 1);
    ioerr += WRITE_LLS_PORT_CONFIGm(unit, mport, lls_pcfg);

    /* Configure front-panel queues */
    lx1 = 10;
    lx0 = 3;
    /* All queues (L2 nodes) map to L1 nodes with equal weight */
    LLS_L2_CHILD_WEIGHT_CFGm_C_WEIGHTf_SET(l2_weight, 1);
    /* All L1 nodes map to L0 nodes with equal weight */
    LLS_L1_CHILD_WEIGHT_CFGm_C_WEIGHTf_SET(l1_weight, 1);
    /* All L0 nodes map to ports with equal weight */
    LLS_L0_CHILD_WEIGHT_CFGm_C_WEIGHTf_SET(l0_weight, 1);
    /* Enable WRR for all queues (L2 nodes )*/
    LLS_L1_CONFIGm_P_WRR_IN_USEf_SET(lls_l1cfg, 1);
    LLS_L1_CONFIGm_P_NUM_SPRIf_SET(lls_l1cfg, 0);
    /* Enable WRR for L1 nodes */
    LLS_L0_CONFIGm_P_WRR_IN_USEf_SET(lls_l0cfg, 1);
    LLS_L0_CONFIGm_P_NUM_SPRIf_SET(lls_l0cfg, 0);
    /* Enable WRR for L0 nodes */
    LLS_PORT_CONFIGm_P_WRR_IN_USEf_SET(lls_pcfg, 1);
    LLS_PORT_CONFIGm_P_NUM_SPRIf_SET(lls_pcfg, 0);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        mport = P2M(unit, port);
        lport = P2L(unit, port);
        num_mc_q = bcm56640_a0_mmu_port_mc_queues(unit, port);
        num_uc_q = bcm56640_a0_mmu_port_uc_queues(unit, port);
        /* Get multicast queue base for this port */
        lx2 = bcm56640_a0_mc_queue_num(unit, port, 0);
        /* Get unicast queue base for this port */
        base = bcm56640_a0_uc_queue_num(unit, port, 0);
        CDK_VVERB(("Port %d (MMU %d): mcq=%d ucq=%d mcbase=%d ucbase=%d\n",
                   port, mport, num_mc_q, num_uc_q, lx2, base));
        for (qx = 0; qx < num_mc_q; qx++) {
            /* Queues 8 and above share the L2 parent */
            if (qx > 8) {
                lx1--;
            }
            /* Map multicast queue to L1 node */
            idx = lx2 + qx;
            LLS_L2_PARENTm_C_PARENTf_SET(l2_parent, lx1);
            ioerr += WRITE_LLS_L2_PARENTm(unit, idx, l2_parent);
            ioerr += WRITE_LLS_L2_CHILD_WEIGHT_CFGm(unit, idx, l2_weight);
            /* Unicast queue uses same L1 node */
            if (qx < num_uc_q) {
                idx = base + qx;
                ioerr += WRITE_LLS_L2_PARENTm(unit, idx, l2_parent);
                ioerr += WRITE_LLS_L2_CHILD_WEIGHT_CFGm(unit, idx, l2_weight);
            }
            /* Map L1 node to L0 node */
            LLS_L1_PARENTm_C_PARENTf_SET(l1_parent, lx0);
            ioerr += WRITE_LLS_L1_PARENTm(unit, lx1, l1_parent);
            /* L2 scheduling mode (equal weight WRR) */
            ioerr += WRITE_LLS_L1_CHILD_WEIGHT_CFGm(unit, lx1, l1_weight);
            ioerr += WRITE_LLS_L1_CONFIGm(unit, lx1, lls_l1cfg);
            /* Map L0 node to MMU port */
            LLS_L0_PARENTm_C_PARENTf_SET(l0_parent, mport);
            ioerr += WRITE_LLS_L0_PARENTm(unit, lx0, l0_parent);
            /* L1 scheduling mode (equal weight WRR) */
            ioerr += WRITE_LLS_L0_CHILD_WEIGHT_CFGm(unit, lx0, l0_weight);
            ioerr += WRITE_LLS_L0_CONFIGm(unit, lx0, lls_l0cfg);
            lx1++;
        }
        lx0++;
        /* L0 scheduling mode */
        ioerr += WRITE_LLS_PORT_CONFIGm(unit, mport, lls_pcfg);
        /* Configure base queue for unicast */
        ING_COS_MODEr_CLR(icos_mode);
        ING_COS_MODEr_BASE_QUEUE_NUM_0f_SET(icos_mode, base);
        ING_COS_MODEr_BASE_QUEUE_NUM_1f_SET(icos_mode, base);
        ioerr += WRITE_ING_COS_MODEr(unit, lport, icos_mode);
    }

    /* Enable LLS */
    LLS_CONFIG0r_CLR(lls_cfg);
    LLS_CONFIG0r_DEQUEUE_ENABLEf_SET(lls_cfg, 1);
    LLS_CONFIG0r_ENQUEUE_ENABLEf_SET(lls_cfg, 1);
    LLS_CONFIG0r_PORT_SCHEDULER_ENABLEf_SET(lls_cfg, 1);
    ioerr += WRITE_LLS_CONFIG0r(unit, lls_cfg);

    return ioerr ? CDK_E_IO : rv;
}

static int
_fifo_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    MCQ_FIFO_BASE_REG_32_35r_t mcq_base32;
    MCQ_FIFO_BASE_REG_36_39r_t mcq_base36;
    MCQ_FIFO_BASE_REGr_t mcq_base;
    MCQ_FIFO_BASE_REG_48_55r_t mcq_base48;
    MCQ_FIFO_BASE_REG_56r_t mcq_base56;
    MCQ_FIFO_BASE_REG_PASSTHRUr_t mcq_base58;
    MCQ_FIFO_BASE_REG_CPUr_t mcq_base59;
    OVQ_MCQ_CREDITSr_t ovq_cred;
    MMU_INTFO_CONGST_STr_t cng_st;
    MCFIFO_CONFIGr_t mcfifo_cfg;
    cdk_pbmp_t mmu_pbmp;
    uint32_t credits, fifo_base;
    uint32_t mode_combine;
    int num_q, total_q;
    int port, mport, idx;

    /* Get MMU ports */
    bcm56640_a0_xport_pbmp_get(unit, &mmu_pbmp);
    CDK_PBMP_PORT_ADD(mmu_pbmp, CMIC_PORT);

    /* Configure multicast FIFO credits */
    CDK_PBMP_ITER(mmu_pbmp, port) {
        mport = P2M(unit, port);
        total_q = (mport >= 40 && mport <= 55) ? 10 : 8;
        num_q = bcm56640_a0_mmu_port_mc_queues(unit, port);
        if (num_q == 0) {
            continue;
        }
        credits = _mmu_port_mc_credits(unit, port) / num_q;
        fifo_base = (credits < 2048) ? credits : 0;
        
        if (mport >= 32 && mport <= 35) {
            for (idx = 0; idx < total_q; idx++) {
                MCQ_FIFO_BASE_REG_32_35r_SET(mcq_base32, idx * fifo_base);
                ioerr += WRITE_MCQ_FIFO_BASE_REG_32_35r(unit, mport,
                                                        idx, mcq_base32);
            }
        } else if (mport >= 36 && mport <= 39) {
            for (idx = 0; idx < total_q; idx++) {
                MCQ_FIFO_BASE_REG_36_39r_SET(mcq_base36, idx * fifo_base);
                ioerr += WRITE_MCQ_FIFO_BASE_REG_36_39r(unit, mport,
                                                        idx, mcq_base36);
            }
        } else if (mport >= 40 && mport <= 47) {
            for (idx = 0; idx < total_q; idx++) {
                MCQ_FIFO_BASE_REGr_SET(mcq_base, idx * fifo_base);
                ioerr += WRITE_MCQ_FIFO_BASE_REGr(unit, mport,
                                                  idx, mcq_base);
            }
        } else if (mport >= 48 && mport <= 55) {
            for (idx = 0; idx < total_q; idx++) {
                MCQ_FIFO_BASE_REG_48_55r_SET(mcq_base48, idx * fifo_base);
                ioerr += WRITE_MCQ_FIFO_BASE_REG_48_55r(unit, mport,
                                                        idx, mcq_base48);
            }
        } else if (mport == 56) {
            for (idx = 0; idx < total_q; idx++) {
                MCQ_FIFO_BASE_REG_56r_SET(mcq_base56, idx * fifo_base);
                ioerr += WRITE_MCQ_FIFO_BASE_REG_56r(unit, mport,
                                                     idx, mcq_base56);
            }
        } else if (mport == 58) {
            for (idx = 0; idx < total_q; idx++) {
                MCQ_FIFO_BASE_REG_PASSTHRUr_SET(mcq_base58, idx * fifo_base);
                ioerr += WRITE_MCQ_FIFO_BASE_REG_PASSTHRUr(unit, mport,
                                                           idx, mcq_base58);
            }
        } else if (mport == 59) {
            for (idx = 0; idx < total_q; idx++) {
                MCQ_FIFO_BASE_REG_CPUr_SET(mcq_base59, idx * fifo_base);
                ioerr += WRITE_MCQ_FIFO_BASE_REG_CPUr(unit, mport,
                                                      idx, mcq_base59);
            }
        }

        for (idx = 0; idx < total_q; idx++) {
            OVQ_MCQ_CREDITSr_SET(ovq_cred, credits);
            if (idx > num_q) {
                OVQ_MCQ_CREDITSr_CLR(ovq_cred);
            }
            ioerr += WRITE_OVQ_MCQ_CREDITSr(unit, mport, idx, ovq_cred);
        }

        MMU_INTFO_CONGST_STr_CLR(cng_st);
        MMU_INTFO_CONGST_STr_ENf_SET(cng_st, 1);
        ioerr += WRITE_MMU_INTFO_CONGST_STr(unit, mport, cng_st);
    }

    /* Configure multicast FIFO mode */
    mode_combine = 0;
    CDK_PBMP_ITER(mmu_pbmp, port) {
        mport = P2M(unit, port);
        if (mport >= 32 && mport < 48) {
            if (bcm56640_a0_port_speed_max(unit, port) > 1000) {
                mode_combine |= LSHIFT32(1, mport - 32);
            }
        }
    }
    MCFIFO_CONFIGr_CLR(mcfifo_cfg);
    MCFIFO_CONFIGr_MODE_COMBINEf_SET(mcfifo_cfg, mode_combine);
    ioerr += WRITE_MCFIFO_CONFIGr(unit, mcfifo_cfg);

    return ioerr ? CDK_E_IO : rv;
}

static int
_mmu_set_limits(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    CFAPFULLTHRESHOLDr_t cfap_full_th;
    PORT_MAX_PKT_SIZEr_t max_pkt_sz;
    PORT_PRI_GRPr_t port_pri_grp;
    PORT_PRI_XON_ENABLEr_t xon_enable;
    THDI_PORT_SP_CONFIGm_t port_sp_config;
    THDI_PORT_PG_CONFIGm_t port_pg_config;
    USE_SP_SHAREDr_t use_sp_shared;
    BUFFER_CELL_LIMIT_SPr_t buf_cell_limit;
    CELL_RESET_LIMIT_OFFSET_SPr_t cell_reset_limit;
    GLOBAL_HDRM_LIMITr_t global_hdrm_limit;
    MMU_THDO_CONFIG_QGROUPm_t cfg_qgrp;
    OP_QUEUE_CONFIG_CELLr_t opq_cfg_cell;
    OP_QUEUE_LIMIT_COLOR_CELLr_t opq_lcol_cell;
    OP_QUEUE_RESET_OFFSET_CELLr_t opq_rsto_cell;
    MMU_THDO_CONFIG_QUEUEm_t cfg_queue;
    MMU_THDO_OFFSET_QUEUEm_t off_queue;
    OP_BUFFER_SHARED_LIMIT_CELLr_t opb_shl_cell;
    OP_BUFFER_LIMIT_YELLOW_CELLr_t opb_lim_y_cell;
    OP_BUFFER_LIMIT_RED_CELLr_t opb_lim_r_cell;
    OP_BUFFER_SHARED_LIMIT_RESUME_CELLr_t opb_shl_rsm_cell;
    OP_BUFFER_LIMIT_RESUME_YELLOW_CELLr_t opb_lim_y_rsm_cell;
    OP_BUFFER_LIMIT_RESUME_RED_CELLr_t opb_lim_r_rsm_cell;
    MMU_THDO_CONFIG_PORTm_t cfg_port;
    OP_PORT_CONFIG_CELLr_t op_cfg_cell;
    OP_PORT_LIMIT_COLOR_CELLr_t op_lim_col_cell;
    OP_PORT_LIMIT_RESUME_COLOR_CELLr_t op_rsm_col_cell;
    cdk_pbmp_t mmu_pbmp;
    uint32_t pg_pbm;
    uint32_t rval, fval;
    uint32_t max_packet_cells, jumbo_frame_cells, default_mtu_cells;
    uint32_t total_cells, in_reserved_cells, out_reserved_cells;
    int num_port, num_q;
    int port, mport, base, idx;

    /* Get front-panel ports */
    bcm56640_a0_xport_pbmp_get(unit, &mmu_pbmp);

    /* Number of front-panel ports */
    num_port = 0;
    CDK_PBMP_ITER(mmu_pbmp, port) {
        num_port++;
    }

    /* Add CPU port to MMU ports */
    CDK_PBMP_PORT_ADD(mmu_pbmp, CMIC_PORT);

    /* Number of output queues */
    num_q = 0;
    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (port == CMIC_PORT) {
            continue;
        }
        mport = P2M(unit, port);
        num_q += bcm56640_a0_mmu_port_mc_queues(unit, port);
        num_q += bcm56640_a0_mmu_port_uc_queues(unit, port);
    }

    max_packet_cells =
        (MMU_MAX_PKT_BYTES + MMU_PKT_HDR_BYTES + MMU_CELL_BYTES - 1) /
        MMU_CELL_BYTES;
    jumbo_frame_cells =
        (MMU_JUMBO_FRAME_BYTES + MMU_PKT_HDR_BYTES + MMU_CELL_BYTES - 1) /
        MMU_CELL_BYTES;
    default_mtu_cells =
        (MMU_DEFAULT_MTU_BYTES + MMU_PKT_HDR_BYTES + MMU_CELL_BYTES - 1) /
        MMU_CELL_BYTES;

    /*
     * Input port pool allocation precedence:
     *   reserved space: per-port per-PG minimum space
     *   reserved space: per-port minimum space (include cpu port)
     *   shared space = total - input port reserved - output port reserved
     *   reserved space: per-port per-PG headroom
     *   reserved space: per-device global headroom
     * Output port:
     *   reserved space: per-port per-queue minimum space
    *   shared space = total - output port reserved
     */
    total_cells = MMU_TOTAL_CELLS_24K;
    if (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_MMU19) {
        total_cells = MMU_TOTAL_CELLS_19K;
    }
    total_cells -= MMU_CELLS_RSVD_IP;
    in_reserved_cells = (num_port + 1) * jumbo_frame_cells
        + num_port * MMU_PG_PER_PORT * MMU_IN_PG_HDRM_CELLS
        + num_port * default_mtu_cells;
    out_reserved_cells = num_q * MMU_OUT_PORT_MIN_CELLS
        + 2 * jumbo_frame_cells;

    pg_pbm = 0;
    for (idx = 8 - MMU_PG_PER_PORT; idx < 8; idx++) {
        pg_pbm |= LSHIFT32(1, idx);
    }

    CFAPFULLTHRESHOLDr_CLR(cfap_full_th);
    CFAPFULLTHRESHOLDr_CFAPFULLSETPOINTf_SET(cfap_full_th, total_cells);
    fval = total_cells - out_reserved_cells;
    CFAPFULLTHRESHOLDr_CFAPFULLRESETPOINTf_SET(cfap_full_th, fval);
    ioerr += WRITE_CFAPFULLTHRESHOLDr(unit, cfap_full_th);

    /* Input port misc per-port setting */
    PORT_MAX_PKT_SIZEr_CLR(max_pkt_sz);
    PORT_MAX_PKT_SIZEr_PORT_MAX_PKT_SIZEf_SET(max_pkt_sz, max_packet_cells);

    /* All priorities use the default priority group */
    rval = 0;
    for (idx = 0; idx < 8; idx++) {
        /* Three bits per priority */
        rval |= MMU_DEFAULT_PG << (3 * idx);
    }
    PORT_PRI_GRPr_SET(port_pri_grp, rval);

    PORT_PRI_XON_ENABLEr_SET(xon_enable, 0xffff);

    CDK_PBMP_ITER(mmu_pbmp, port) {
        mport = P2M(unit, port);
        ioerr += WRITE_PORT_MAX_PKT_SIZEr(unit, mport, max_pkt_sz);
        ioerr += WRITE_PORT_PRI_GRPr(unit, mport, 0, port_pri_grp);
        ioerr += WRITE_PORT_PRI_GRPr(unit, mport, 1, port_pri_grp);
        if (port == CMIC_PORT) {
            continue;
        }
        ioerr += WRITE_PORT_PRI_XON_ENABLEr(unit, mport, xon_enable);
    }

    /* Input port per-port limits */
    THDI_PORT_SP_CONFIGm_CLR(port_sp_config);
    THDI_PORT_SP_CONFIGm_PORT_SP_MAX_LIMITf_SET(port_sp_config, total_cells);
    fval = total_cells - (2 * default_mtu_cells);
    THDI_PORT_SP_CONFIGm_PORT_SP_RESUME_LIMITf_SET(port_sp_config, fval);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        mport = P2M(unit, port);
        idx = mport * MMU_NUM_POOL;
        ioerr += WRITE_THDI_PORT_SP_CONFIGm(unit, idx, port_sp_config);
    }

    /* Input port per-port per-PG limits */
    THDI_PORT_PG_CONFIGm_CLR(port_pg_config);
    THDI_PORT_PG_CONFIGm_PG_RESET_OFFSETf_SET(port_pg_config, 16);
    THDI_PORT_PG_CONFIGm_PG_MIN_LIMITf_SET(port_pg_config, jumbo_frame_cells);
    THDI_PORT_PG_CONFIGm_PG_SHARED_LIMITf_SET(port_pg_config, 7);
    THDI_PORT_PG_CONFIGm_PG_SHARED_DYNAMICf_SET(port_pg_config, 1);
    THDI_PORT_PG_CONFIGm_PG_GBL_HDRM_ENf_SET(port_pg_config, 1);
    THDI_PORT_PG_CONFIGm_PG_HDRM_LIMITf_SET(port_pg_config,
                                            MMU_IN_PG_HDRM_CELLS);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        mport = P2M(unit, port);
        base = mport * MMU_NUM_PG;
        for (idx = base; idx < (base + MMU_NUM_PG); idx++) {
            if (idx < (base + (MMU_NUM_PG - MMU_PG_PER_PORT))) {
                continue;
            }
            ioerr += WRITE_THDI_PORT_PG_CONFIGm(unit, idx, port_pg_config);
        }
    }

    /* Input port shared space (use service pool 0 only) */
    USE_SP_SHAREDr_CLR(use_sp_shared);
    USE_SP_SHAREDr_ENABLEf_SET(use_sp_shared, 1);
    ioerr += WRITE_USE_SP_SHAREDr(unit, use_sp_shared);

    BUFFER_CELL_LIMIT_SPr_CLR(buf_cell_limit);
    fval = total_cells - in_reserved_cells - out_reserved_cells;
    BUFFER_CELL_LIMIT_SPr_LIMITf_SET(buf_cell_limit, fval);
    ioerr += WRITE_BUFFER_CELL_LIMIT_SPr(unit, 0, buf_cell_limit);

    CELL_RESET_LIMIT_OFFSET_SPr_CLR(cell_reset_limit);
    fval = 30 * default_mtu_cells;
    CELL_RESET_LIMIT_OFFSET_SPr_OFFSETf_SET(cell_reset_limit, fval);
    ioerr += WRITE_CELL_RESET_LIMIT_OFFSET_SPr(unit, 0, cell_reset_limit);

    /* Input port per-device global headroom */
    GLOBAL_HDRM_LIMITr_CLR(global_hdrm_limit);
    fval = 2 * jumbo_frame_cells;
    GLOBAL_HDRM_LIMITr_GLOBAL_HDRM_LIMITf_SET(global_hdrm_limit, fval);
    ioerr += WRITE_GLOBAL_HDRM_LIMITr(unit, global_hdrm_limit);

    /* Output Q-groups */
    MMU_THDO_CONFIG_QGROUPm_CLR(cfg_qgrp);
    MMU_THDO_CONFIG_QGROUPm_Q_SHARED_LIMIT_CELLf_SET(cfg_qgrp, total_cells);
    MMU_THDO_CONFIG_QGROUPm_Q_COLOR_LIMIT_DYNAMIC_CELLf_SET(cfg_qgrp, 1);
    fval = (total_cells * 125) / 1000;
    MMU_THDO_CONFIG_QGROUPm_LIMIT_YELLOW_CELLf_SET(cfg_qgrp, fval);
    MMU_THDO_CONFIG_QGROUPm_LIMIT_RED_CELLf_SET(cfg_qgrp, fval);
    for (idx = 0; idx <= MMU_THDO_CONFIG_QGROUPm_MAX; idx++) {
        ioerr += WRITE_MMU_THDO_CONFIG_QGROUPm(unit, idx, cfg_qgrp);
    }

    /* Output Q-groups are off by default */
    ioerr += CDK_XGSM_MEM_CLEAR(unit, MMU_THDO_Q_TO_QGRP_MAPm);

    /* Output multicast queues */
    fval = total_cells - out_reserved_cells;
    OP_QUEUE_CONFIG_CELLr_CLR(opq_cfg_cell);
    OP_QUEUE_CONFIG_CELLr_Q_SHARED_LIMIT_CELLf_SET(opq_cfg_cell, fval);
    fval = total_cells / 8;
    OP_QUEUE_LIMIT_COLOR_CELLr_CLR(opq_lcol_cell);
    OP_QUEUE_LIMIT_COLOR_CELLr_REDf_SET(opq_lcol_cell, fval);
    OP_QUEUE_RESET_OFFSET_CELLr_CLR(opq_rsto_cell);
    OP_QUEUE_RESET_OFFSET_CELLr_Q_RESET_OFFSET_CELLf_SET(opq_rsto_cell, 2);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        mport = P2M(unit, port);
        num_q = bcm56640_a0_mmu_port_mc_queues(unit, port);
        for (idx = 0; idx <= num_q; idx++) {
            ioerr += WRITE_OP_QUEUE_CONFIG_CELLr(unit, mport, idx,
                                                 opq_cfg_cell);
            ioerr += WRITE_OP_QUEUE_LIMIT_COLOR_CELLr(unit, mport, idx,
                                                      opq_lcol_cell);
            ioerr += WRITE_OP_QUEUE_RESET_OFFSET_CELLr(unit, mport, idx,
                                                       opq_rsto_cell);
        }
    }

    /* Output unicast queues */
    MMU_THDO_CONFIG_QUEUEm_CLR(cfg_queue);
    MMU_THDO_CONFIG_QUEUEm_Q_SHARED_LIMIT_CELLf_SET(cfg_queue, total_cells);
    MMU_THDO_CONFIG_QUEUEm_Q_COLOR_LIMIT_DYNAMIC_CELLf_SET(cfg_queue, 1);
    fval = (total_cells * 125) / 1000;
    MMU_THDO_CONFIG_QUEUEm_LIMIT_YELLOW_CELLf_SET(cfg_queue, fval);
    MMU_THDO_CONFIG_QUEUEm_LIMIT_RED_CELLf_SET(cfg_queue, fval);
    MMU_THDO_OFFSET_QUEUEm_CLR(off_queue);
    MMU_THDO_OFFSET_QUEUEm_RESET_OFFSET_CELLf_SET(off_queue, 2);
    MMU_THDO_OFFSET_QUEUEm_RESET_OFFSET_YELLOW_CELLf_SET(off_queue, 2);
    MMU_THDO_OFFSET_QUEUEm_RESET_OFFSET_RED_CELLf_SET(off_queue, 2);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        if (port == CMIC_PORT) {
            continue;
        }
        mport = P2M(unit, port);
        num_q = bcm56640_a0_mmu_port_uc_queues(unit, port);
        for (idx = 0; idx <= num_q; idx++) {
            ioerr += WRITE_MMU_THDO_CONFIG_QUEUEm(unit, idx, cfg_queue);
            ioerr += WRITE_MMU_THDO_OFFSET_QUEUEm(unit, idx, off_queue);
        }
    }

    /* Global limits for service pool 0 */
    fval = total_cells - out_reserved_cells;
    OP_BUFFER_SHARED_LIMIT_CELLr_CLR(opb_shl_cell);
    OP_BUFFER_SHARED_LIMIT_CELLr_SET(opb_shl_cell, fval);
    ioerr += WRITE_OP_BUFFER_SHARED_LIMIT_CELLr(unit, 0, opb_shl_cell);
    OP_BUFFER_SHARED_LIMIT_RESUME_CELLr_CLR(opb_shl_rsm_cell);
    OP_BUFFER_SHARED_LIMIT_RESUME_CELLr_SET(opb_shl_rsm_cell, fval);
    ioerr += WRITE_OP_BUFFER_SHARED_LIMIT_RESUME_CELLr(unit, 0, opb_shl_rsm_cell);
    fval = fval / 8;
    OP_BUFFER_LIMIT_YELLOW_CELLr_CLR(opb_lim_y_cell);
    OP_BUFFER_LIMIT_YELLOW_CELLr_SET(opb_lim_y_cell, fval);
    ioerr += WRITE_OP_BUFFER_LIMIT_YELLOW_CELLr(unit, 0, opb_lim_y_cell);
    OP_BUFFER_LIMIT_RED_CELLr_CLR(opb_lim_r_cell);
    OP_BUFFER_LIMIT_RED_CELLr_SET(opb_lim_r_cell, fval);
    ioerr += WRITE_OP_BUFFER_LIMIT_RED_CELLr(unit, 0, opb_lim_r_cell);
    OP_BUFFER_LIMIT_RESUME_YELLOW_CELLr_CLR(opb_lim_y_rsm_cell);
    OP_BUFFER_LIMIT_RESUME_YELLOW_CELLr_SET(opb_lim_y_rsm_cell, fval);
    ioerr += WRITE_OP_BUFFER_LIMIT_RESUME_YELLOW_CELLr(unit, 0, opb_lim_y_rsm_cell);
    OP_BUFFER_LIMIT_RESUME_RED_CELLr_CLR(opb_lim_r_rsm_cell);
    OP_BUFFER_LIMIT_RESUME_RED_CELLr_SET(opb_lim_r_rsm_cell, fval);
    ioerr += WRITE_OP_BUFFER_LIMIT_RESUME_RED_CELLr(unit, 0, opb_lim_r_rsm_cell);

    /* Per-port multicast limits for service pool 0 */
    fval = total_cells - out_reserved_cells;
    OP_PORT_CONFIG_CELLr_CLR(op_cfg_cell);
    OP_PORT_CONFIG_CELLr_OP_SHARED_LIMIT_CELLf_SET(op_cfg_cell, fval);
    OP_PORT_CONFIG_CELLr_OP_SHARED_RESET_VALUE_CELLf_SET(op_cfg_cell, fval - 16);
    fval = fval / 8;
    OP_PORT_LIMIT_COLOR_CELLr_CLR(op_lim_col_cell);
    OP_PORT_LIMIT_COLOR_CELLr_REDf_SET(op_lim_col_cell, fval);
    OP_PORT_LIMIT_RESUME_COLOR_CELLr_CLR(op_rsm_col_cell);
    OP_PORT_LIMIT_RESUME_COLOR_CELLr_REDf_SET(op_rsm_col_cell, fval - 2);

    CDK_PBMP_ITER(mmu_pbmp, port) {
        mport = P2M(unit, port);
        ioerr += WRITE_OP_PORT_CONFIG_CELLr(unit, mport, 0,
                                            op_cfg_cell);
        ioerr += WRITE_OP_PORT_LIMIT_COLOR_CELLr(unit, mport, 0,
                                                 op_lim_col_cell);
        ioerr += WRITE_OP_PORT_LIMIT_RESUME_COLOR_CELLr(unit, mport, 0,
                                                        op_rsm_col_cell);
    }

    /* Per-port unicast limits for service pool 0 */
    fval = total_cells - out_reserved_cells;
    MMU_THDO_CONFIG_PORTm_CLR(cfg_port);
    MMU_THDO_CONFIG_PORTm_SHARED_LIMITf_SET(cfg_port, fval);
    MMU_THDO_CONFIG_PORTm_SHARED_RESUMEf_SET(cfg_port, fval - 16);
    fval = fval / 8;
    MMU_THDO_CONFIG_PORTm_YELLOW_LIMITf_SET(cfg_port, fval);
    MMU_THDO_CONFIG_PORTm_YELLOW_RESUMEf_SET(cfg_port, fval - 2);
    MMU_THDO_CONFIG_PORTm_RED_LIMITf_SET(cfg_port, fval);
    MMU_THDO_CONFIG_PORTm_RED_RESUMEf_SET(cfg_port, fval - 2);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        mport = P2M(unit, port);
        ioerr += WRITE_MMU_THDO_CONFIG_PORTm(unit, mport * 4, cfg_port);
    }

    return ioerr ? CDK_E_IO : rv;
}

static int
_mmu_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    IP_TO_CMICM_CREDIT_TRANSFERr_t cmic_cred_xfer;
    EGR_EDB_XMIT_CTRLm_t xmit_ctrl;
    OVQ_DROP_THRESHOLD0r_t ovq_drop_thr;
    OVQ_DROP_THRESHOLD_RESET_LIMITr_t ovq_drop_lim;
    OP_THR_CONFIGr_t op_thr_cfg;
    INPUT_PORT_RX_ENABLE_64r_t in_rx_en;
    OUTPUT_PORT_RX_ENABLE0_64r_t out_rx_en;
    PORT_PAUSE_ENABLE_64r_t pause_en;
    int idx, start_cnt;

    /* Reset linked-list scheduler */
    if (CDK_SUCCESS(rv)) {
        rv = _lls_reset(unit);
    }

    /* Setup TDM for MMU */
    if (CDK_SUCCESS(rv)) {
        rv = _mmu_tdm_init(unit);
    }

    /* Configure MMU limits and guarantees */
    if (CDK_SUCCESS(rv)) {
        rv = _mmu_set_limits(unit);
    }

    /* Configure linked-list scheduler */
    if (CDK_SUCCESS(rv)) {
        rv = _lls_init(unit);
    }

    /* Configure multicast FIFO */
    if (CDK_SUCCESS(rv)) {
        rv = _fifo_init(unit);
    }

    /* Enable IP to CMICM credit transfer */
    IP_TO_CMICM_CREDIT_TRANSFERr_CLR(cmic_cred_xfer);
    IP_TO_CMICM_CREDIT_TRANSFERr_TRANSFER_ENABLEf_SET(cmic_cred_xfer, 1);
    IP_TO_CMICM_CREDIT_TRANSFERr_NUM_OF_CREDITSf_SET(cmic_cred_xfer, 32);
    ioerr += WRITE_IP_TO_CMICM_CREDIT_TRANSFERr(unit, cmic_cred_xfer);

    /* Transmit start thresholds */
    EGR_EDB_XMIT_CTRLm_CLR(xmit_ctrl);
    for (idx = 0; idx <= EGR_EDB_XMIT_CTRLm_MAX; idx++) {
        start_cnt = (idx < 53) ? 7 : 2;
        EGR_EDB_XMIT_CTRLm_START_CNTf_SET(xmit_ctrl, start_cnt);
        ioerr += WRITE_EGR_EDB_XMIT_CTRLm(unit, idx, xmit_ctrl);
    }

    /* OVQ settings */
    OVQ_DROP_THRESHOLD0r_SET(ovq_drop_thr, 0x17cf);
    ioerr += WRITE_OVQ_DROP_THRESHOLD0r(unit, ovq_drop_thr);
    OVQ_DROP_THRESHOLD_RESET_LIMITr_SET(ovq_drop_lim, 0x1700);
    ioerr += WRITE_OVQ_DROP_THRESHOLD_RESET_LIMITr(unit, ovq_drop_lim);

    /* Egress policies */
    OP_THR_CONFIGr_CLR(op_thr_cfg);
    OP_THR_CONFIGr_MOP_POLICYf_SET(op_thr_cfg, 7);
    OP_THR_CONFIGr_YELLOW_CELL_DS_SELECTf_SET(op_thr_cfg, 1);
    ioerr += WRITE_OP_THR_CONFIGr(unit, op_thr_cfg);

    /* Enable all ports */
    INPUT_PORT_RX_ENABLE_64r_SET(in_rx_en, 0, 0xffffffff);
    INPUT_PORT_RX_ENABLE_64r_SET(in_rx_en, 1, 0x7fffffff);
    ioerr += WRITE_INPUT_PORT_RX_ENABLE_64r(unit, in_rx_en);
    OUTPUT_PORT_RX_ENABLE0_64r_SET(out_rx_en, 0, 0xffffffff);
    OUTPUT_PORT_RX_ENABLE0_64r_SET(out_rx_en, 1, 0x7fffffff);
    ioerr += WRITE_OUTPUT_PORT_RX_ENABLE0_64r(unit, out_rx_en);

    /* Input port pause enable */
    PORT_PAUSE_ENABLE_64r_SET(pause_en, 0, 0xffffffff);
    PORT_PAUSE_ENABLE_64r_SET(pause_en, 1, 0x7fffffff);
    ioerr += WRITE_PORT_PAUSE_ENABLE_64r(unit, pause_en);

    return ioerr ? CDK_E_IO : rv;
}

static int
_ism_init(int unit)
{
    int ioerr = 0;
    STAGE_BANK_SIZEr_t bank_size;
    TABLE_BANK_CONFIGr_t bank_cfg;
    TABLE0_LOG_TO_PHY_MAPm_t tbl0_map;
    TABLE1_LOG_TO_PHY_MAPm_t tbl1_map;
    TABLE2_LOG_TO_PHY_MAPm_t tbl2_map;
    TABLE3_LOG_TO_PHY_MAPm_t tbl3_map;
    TABLE4_LOG_TO_PHY_MAPm_t tbl4_map;
    STAGE_HASH_OFFSETr_t sho[ISM_NUM_STAGES];
    const _ism_tbl_cfg_t *tbl_cfg;
    const _ism_cfg_t *ism_cfg;
    uint32_t bank_info;
    uint32_t bank_mask[ISM_NUM_STAGES];
    int bank_size_limit[ISM_BANKS_PER_STAGE];
    int num_tbl_cfg;
    int bank, stage, chunk;
    int idx, tdx, bdx, cdx;

    /* Default ISM configuration */
    ism_cfg = &_ism_512;
    tbl_cfg = _ism_tbl_cfg_512;
    num_tbl_cfg = COUNTOF(_ism_tbl_cfg_512);

    /* Check for reduced size ISM configuration */
    if (CDK_XGSM_FLAGS(unit) & ISM_80_CHIP_FLAGS) {
        ism_cfg = &_ism_80;
        tbl_cfg = _ism_tbl_cfg_80;
        num_tbl_cfg = COUNTOF(_ism_tbl_cfg_80);
    } else if (CDK_XGSM_FLAGS(unit) & ISM_176_CHIP_FLAGS) {
        ism_cfg = &_ism_176;
        tbl_cfg = _ism_tbl_cfg_176;
        num_tbl_cfg = COUNTOF(_ism_tbl_cfg_176);
    }

    /* Configure actual bank sizes (mainly for simulation) */
    for (tdx = 0; tdx < ISM_BANKS_PER_STAGE; tdx++) {
        for (idx = 0; idx < 3; idx++) {
            if ((ism_cfg->num_chunks[tdx] << idx) == _ism_512.num_chunks[tdx]) {
                break;
            }
        }
        bank_size_limit[tdx] = idx;
    }
    STAGE_BANK_SIZEr_CLR(bank_size);
    STAGE_BANK_SIZEr_BANK0_SIZE_LIMITf_SET(bank_size, bank_size_limit[0]);
    STAGE_BANK_SIZEr_BANK1_SIZE_LIMITf_SET(bank_size, bank_size_limit[1]);
    STAGE_BANK_SIZEr_BANK2_SIZE_LIMITf_SET(bank_size, bank_size_limit[2]);
    STAGE_BANK_SIZEr_BANK3_SIZE_LIMITf_SET(bank_size, bank_size_limit[3]);
    STAGE_BANK_SIZEr_BANK4_SIZE_LIMITf_SET(bank_size, bank_size_limit[4]);
    /* All stages uses same configuration */
    for (bdx = 0; bdx < ISM_NUM_STAGES; bdx++) {
        ioerr += WRITE_STAGE_BANK_SIZEr(unit, bdx, bank_size);
    }

    /* Read hash offset registers */
    for (stage = 0; stage < ISM_NUM_STAGES; stage++) {
        ioerr += READ_STAGE_HASH_OFFSETr(unit, stage, &sho[stage]);
    }

    for (tdx = 0; tdx < num_tbl_cfg; tdx++, tbl_cfg++) {
        /* Configure which banks that are used for this table */
        CDK_MEMSET(bank_mask, 0, sizeof(bank_mask));
        for (bdx = 0; bdx < tbl_cfg->num_banks; bdx++) {
            bank_info = tbl_cfg->bank_info[bdx];
            stage = BANK_INFO_STAGE_NO(bank_info);
            bank = BANK_INFO_BANK_NO(bank_info);
            bank_mask[stage] |= (1 << bank);
        }
        TABLE_BANK_CONFIGr_CLR(bank_cfg);
        TABLE_BANK_CONFIGr_STAGE0_BANKSf_SET(bank_cfg, bank_mask[0]);
        TABLE_BANK_CONFIGr_STAGE1_BANKSf_SET(bank_cfg, bank_mask[1]);
        TABLE_BANK_CONFIGr_STAGE2_BANKSf_SET(bank_cfg, bank_mask[2]);
        TABLE_BANK_CONFIGr_STAGE3_BANKSf_SET(bank_cfg, bank_mask[3]);
        TABLE_BANK_CONFIGr_HASH_ZERO_OR_LSBf_SET(bank_cfg, 1);
        if (ism_cfg->chunk_size == 1024) {
            /* 256K mode */
            TABLE_BANK_CONFIGr_MAPPING_MODEf_SET(bank_cfg, 1);
        }
        ioerr += WRITE_TABLE_BANK_CONFIGr(unit, tdx, bank_cfg);

        /* Configure logical numbers for physical banks */
        idx = 0;
        for (bdx = 0; bdx < tbl_cfg->num_banks; bdx++) {
            bank_info = tbl_cfg->bank_info[bdx];
            stage = BANK_INFO_STAGE_NO(bank_info);
            bank = BANK_INFO_BANK_NO(bank_info);
            chunk = (stage * ISM_CHUNKS_PER_STAGE) + _ism_bank_start[bank];
            for (cdx = 0; cdx < ism_cfg->num_chunks[bank]; cdx++) {
                if (tdx == 0) {
                    TABLE0_LOG_TO_PHY_MAPm_SET(tbl0_map, chunk + cdx);
                    ioerr += WRITE_TABLE0_LOG_TO_PHY_MAPm(unit, idx, tbl0_map);
                } else if (tdx == 1) {
                    TABLE1_LOG_TO_PHY_MAPm_SET(tbl1_map, chunk + cdx);
                    ioerr += WRITE_TABLE1_LOG_TO_PHY_MAPm(unit, idx, tbl1_map);
                } else if (tdx == 2) {
                    TABLE2_LOG_TO_PHY_MAPm_SET(tbl2_map, chunk + cdx);
                    ioerr += WRITE_TABLE2_LOG_TO_PHY_MAPm(unit, idx, tbl2_map);
                } else if (tdx == 3) {
                    TABLE3_LOG_TO_PHY_MAPm_SET(tbl3_map, chunk + cdx);
                    ioerr += WRITE_TABLE3_LOG_TO_PHY_MAPm(unit, idx, tbl3_map);
                } else if (tdx == 4) {
                    TABLE4_LOG_TO_PHY_MAPm_SET(tbl4_map, chunk + cdx);
                    ioerr += WRITE_TABLE4_LOG_TO_PHY_MAPm(unit, idx, tbl4_map);
                }
                idx++;
            }
            /* Update hash offset register for this bank */
            if (bank == 0) {
                STAGE_HASH_OFFSETr_BANK0_HASH_OFFSETf_SET(sho[stage], bdx * 4);
            } else if (bank == 1) {
                STAGE_HASH_OFFSETr_BANK1_HASH_OFFSETf_SET(sho[stage], bdx * 4);
            } else if (bank == 2) {
                STAGE_HASH_OFFSETr_BANK2_HASH_OFFSETf_SET(sho[stage], bdx * 4);
            } else if (bank == 3) {
                STAGE_HASH_OFFSETr_BANK3_HASH_OFFSETf_SET(sho[stage], bdx * 4);
            } else if (bank == 4) {
                STAGE_HASH_OFFSETr_BANK4_HASH_OFFSETf_SET(sho[stage], bdx * 4);
            }
        }
    }

    /* Write hash offset registers */
    for (stage = 0; stage < ISM_NUM_STAGES; stage++) {
        ioerr += WRITE_STAGE_HASH_OFFSETr(unit, stage, sho[stage]);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

static int
_firmware_helper(void *ctx, uint32_t offset, uint32_t size, void *data)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    PORT_WC_UCMEM_CTRLr_t ucmem_ctrl;
    PORT_WC_UCMEM_DATAm_t ucmem_data;
    int unit, port, inst, bcast;
    const char *drv_name;
    uint32_t wbuf[4];
    uint32_t *fw_data;
    uint32_t *fw_entry;
    uint32_t fw_size;
    uint32_t speed;
    uint32_t idx, wdx;

    /* Get unit, port and driver name from context */
    bmd_phy_fw_info_get(ctx, &unit, &port, &drv_name);

    /* Check if PHY driver requests optimized MDIO clock */
    if (data == NULL) {
        CMIC_RATE_ADJUSTr_t rate_adjust;
        uint32_t val = 1;

        /* Offset value is MDIO clock freq in kHz (or zero to restore) */
        if (offset) {
            val = offset / 9375;
        }
        ioerr += READ_CMIC_RATE_ADJUSTr(unit, &rate_adjust);
        CMIC_RATE_ADJUSTr_DIVIDENDf_SET(rate_adjust, val);
        ioerr += WRITE_CMIC_RATE_ADJUSTr(unit, rate_adjust);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }

    if (CDK_STRSTR(drv_name, "warpcore") == NULL) {
        return CDK_E_UNAVAIL;
    }

    if (size == 0) {
        return CDK_E_INTERNAL;
    }

    /* Aligned firmware size */
    fw_size = (size + FW_ALIGN_MASK) & ~FW_ALIGN_MASK;

    /* Get XPORT instance within port block */
    inst = bcm56640_a0_xport_inst(unit, port);

    /* Check if broadcast can be used */
    bcast = 0;
    speed = bcm56640_a0_port_speed_max(unit, port);
    if (speed >= 100000) {
        bcast = 1;
    }

    /* Enable parallel bus access and select instance(s) */
    ioerr += READ_PORT_WC_UCMEM_CTRLr(unit, &ucmem_ctrl, port);
    PORT_WC_UCMEM_CTRLr_ACCESS_MODEf_SET(ucmem_ctrl, 1);
    PORT_WC_UCMEM_CTRLr_INST_SELECTf_SET(ucmem_ctrl, inst);
    PORT_WC_UCMEM_CTRLr_WR_BROADCASTf_SET(ucmem_ctrl, bcast);
    ioerr += WRITE_PORT_WC_UCMEM_CTRLr(unit, ucmem_ctrl, port);

    /* DMA buffer needs 32-bit words in little endian order */
    fw_data = (uint32_t *)data;
    for (idx = 0; idx < fw_size; idx += 16) {
        if (idx + 15 < size) {
            fw_entry = &fw_data[idx >> 2];
        } else {
            /* Use staging buffer for modulo bytes */
            CDK_MEMSET(wbuf, 0, sizeof(wbuf));
            CDK_MEMCPY(wbuf, &fw_data[idx >> 2], 16 - (fw_size - size));
            fw_entry = wbuf;
        }
        for (wdx = 0; wdx < 4; wdx++) {
            PORT_WC_UCMEM_DATAm_SET(ucmem_data, wdx^3, fw_entry[wdx]);
        }
        WRITE_PORT_WC_UCMEM_DATAm(unit, idx >> 4, ucmem_data, port);
    }

    /* Disable parallel bus access */
    PORT_WC_UCMEM_CTRLr_ACCESS_MODEf_SET(ucmem_ctrl, 0);
    ioerr += WRITE_PORT_WC_UCMEM_CTRLr(unit, ucmem_ctrl, port);

    return ioerr ? CDK_E_IO : rv;
}

static int
_port_init(int unit, int port)
{
    int ioerr = 0;
    int lport = P2L(unit, port);
    EGR_VLAN_CONTROL_1r_t egr_vlan_ctrl1;
    PORT_TABm_t port_tab;
    EGR_PORTm_t egr_port;
    EGR_ENABLEm_t egr_enable;

    /* Default port VLAN and tag action, enable L2 HW learning */
    PORT_TABm_CLR(port_tab);
    PORT_TABm_PORT_VIDf_SET(port_tab, 1);
    PORT_TABm_FILTER_ENABLEf_SET(port_tab, 1);
    PORT_TABm_OUTER_TPID_ENABLEf_SET(port_tab, 1);
    PORT_TABm_CML_FLAGS_NEWf_SET(port_tab, 8);
    PORT_TABm_CML_FLAGS_MOVEf_SET(port_tab, 8);
    ioerr += WRITE_PORT_TABm(unit, lport, port_tab);

    /* Filter VLAN on egress */
    EGR_PORTm_CLR(egr_port);
    EGR_PORTm_EN_EFILTERf_SET(egr_port, 1);
    ioerr += WRITE_EGR_PORTm(unit, lport, egr_port);

    /* Configure egress VLAN for backward compatibility */
    ioerr += READ_EGR_VLAN_CONTROL_1r(unit, lport, &egr_vlan_ctrl1);
    EGR_VLAN_CONTROL_1r_VT_MISS_UNTAGf_SET(egr_vlan_ctrl1, 0);
    EGR_VLAN_CONTROL_1r_REMARK_OUTER_DOT1Pf_SET(egr_vlan_ctrl1, 1);
    ioerr += WRITE_EGR_VLAN_CONTROL_1r(unit, lport, egr_vlan_ctrl1);

    /* Egress enable */
    ioerr += READ_EGR_ENABLEm(unit, port, &egr_enable);
    EGR_ENABLEm_PRT_ENABLEf_SET(egr_enable, 1);
    ioerr += WRITE_EGR_ENABLEm(unit, port, egr_enable);

    return ioerr;
}

int
bcm56640_a0_xmac_reset_set(int unit, int port, int reset)
{
    int ioerr = 0;
    PORT_MAC_CONTROLr_t port_mac_ctrl;
    int inst;

    inst = bcm56640_a0_xport_inst(unit, port);

    ioerr += READ_PORT_MAC_CONTROLr(unit, &port_mac_ctrl, port);
    if (inst == 2) {
        PORT_MAC_CONTROLr_XMAC2_RESETf_SET(port_mac_ctrl, reset);
    } else if (inst == 1) {
        PORT_MAC_CONTROLr_XMAC1_RESETf_SET(port_mac_ctrl, reset);
    } else {
        PORT_MAC_CONTROLr_XMAC0_RESETf_SET(port_mac_ctrl, reset);
    }
    ioerr += WRITE_PORT_MAC_CONTROLr(unit, port_mac_ctrl, port);

    return ioerr;
}

int
bcm56640_a0_xport_init(int unit, int port)
{
    int ioerr = 0;
    XMAC_TX_CTRLr_t txctrl;
    XMAC_RX_CTRLr_t rxctrl;
    XMAC_RX_MAX_SIZEr_t rxmaxsz;
    XMAC_CTRLr_t mac_ctrl;
    PORT_CNTMAXSIZEr_t cntmaxsz;

    /* Common port initialization */
    ioerr += _port_init(unit, port);

    /* Ensure that MAC (Rx) and loopback mode is disabled */
    XMAC_CTRLr_CLR(mac_ctrl);
    XMAC_CTRLr_SOFT_RESETf_SET(mac_ctrl, 1);
    ioerr += WRITE_XMAC_CTRLr(unit, port, mac_ctrl);

    XMAC_CTRLr_TX_ENf_SET(mac_ctrl, 1);
    if (bcm56640_a0_port_speed_max(unit, port) == 40000) {
        XMAC_CTRLr_XLGMII_ALIGN_ENBf_SET(mac_ctrl, 1);
    }
    ioerr += WRITE_XMAC_CTRLr(unit, port, mac_ctrl);

    /* Configure Tx (Inter-Packet-Gap, recompute CRC mode, IEEE header) */
    XMAC_TX_CTRLr_CLR(txctrl);
    XMAC_TX_CTRLr_TX_PREAMBLE_LENGTHf_SET(txctrl, 8);
    XMAC_TX_CTRLr_PAD_THRESHOLDf_SET(txctrl, 0x40);
    XMAC_TX_CTRLr_AVERAGE_IPGf_SET(txctrl, 0xc);
    XMAC_TX_CTRLr_CRC_MODEf_SET(txctrl, 0x3);
    ioerr += WRITE_XMAC_TX_CTRLr(unit, port, txctrl);

    /* Configure Rx (strip CRC, strict preamble, IEEE header) */
    XMAC_RX_CTRLr_CLR(rxctrl);
    XMAC_RX_CTRLr_STRICT_PREAMBLEf_SET(rxctrl, 1);
    XMAC_RX_CTRLr_RUNT_THRESHOLDf_SET(rxctrl, 0x40);
    ioerr += WRITE_XMAC_RX_CTRLr(unit, port, rxctrl);

    /* Set max Rx frame size */
    XMAC_RX_MAX_SIZEr_CLR(rxmaxsz);
    XMAC_RX_MAX_SIZEr_RX_MAX_SIZEf_SET(rxmaxsz, JUMBO_MAXSZ);
    ioerr += WRITE_XMAC_RX_MAX_SIZEr(unit, port, rxmaxsz);

    /* Set max MIB frame size */
    PORT_CNTMAXSIZEr_SET(cntmaxsz, JUMBO_MAXSZ);
    ioerr += WRITE_PORT_CNTMAXSIZEr(unit, port, cntmaxsz);

    return ioerr;
}

int
bcm56640_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv;
    ING_HW_RESET_CONTROL_1r_t ing_rst_ctl_1;
    ING_HW_RESET_CONTROL_2r_t ing_rst_ctl_2;
    EGR_HW_RESET_CONTROL_0r_t egr_rst_ctl_0;
    EGR_HW_RESET_CONTROL_1r_t egr_rst_ctl_1;
    ISM_HW_RESET_CONTROL_0r_t ism_rst_ctl_0;
    ISM_HW_RESET_CONTROL_1r_t ism_rst_ctl_1;
    AXP_WRX_MEMORY_BULK_RESETr_t axp_wrx_rst;
    AXP_WTX_MEMORY_BULK_RESETr_t axp_wtx_rst;
    AXP_SM_MEMORY_BULK_RESETr_t axp_sm_rst;
    CPU_PBMm_t cpu_pbm;
    CPU_PBM_2m_t cpu_pbm_2;
    PORT_MODE_REGr_t port_mode;
    PORT_ENABLE_REGr_t port_en;
    PORT_MAC_CONTROLr_t port_mac_ctrl;
    PORT_MIB_RESETr_t mib_reset;
    MISCCONFIGr_t misc_cfg;
    ING_EN_EFILTER_BITMAPm_t ing_en_efilter;
    CMIC_RATE_ADJUSTr_t rate_adjust;
    CMIC_RATE_ADJUST_INT_MDIOr_t rate_adjust_int_mdio;
    RDBGC0_SELECTr_t rdbgc0_select;
    VLAN_PROFILE_TABm_t vlan_profile;
    ING_VLAN_TAG_ACTION_PROFILEm_t vlan_action;
    EGR_VLAN_TAG_ACTION_PROFILEm_t egr_action;
    cdk_pbmp_t pbmp;
    uint32_t speed, port_en_mask, lane_en;
    int mac_mode, phy_mode, core_mode, gmii_en;
    int mdio_div;
    int port;
    int idx, inst;

    BMD_CHECK_UNIT(unit);

    /* Reset the IPIPE block */
    ING_HW_RESET_CONTROL_1r_CLR(ing_rst_ctl_1);
    ioerr += WRITE_ING_HW_RESET_CONTROL_1r(unit, ing_rst_ctl_1);
    ING_HW_RESET_CONTROL_2r_CLR(ing_rst_ctl_2);
    ING_HW_RESET_CONTROL_2r_RESET_ALLf_SET(ing_rst_ctl_2, 1);
    ING_HW_RESET_CONTROL_2r_VALIDf_SET(ing_rst_ctl_2, 1);
    ING_HW_RESET_CONTROL_2r_COUNTf_SET(ing_rst_ctl_2, 0x10000);
    ioerr += WRITE_ING_HW_RESET_CONTROL_2r(unit, ing_rst_ctl_2);

    /* Reset the EPIPE block */
    EGR_HW_RESET_CONTROL_0r_CLR(egr_rst_ctl_0);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_0r(unit, egr_rst_ctl_0);
    EGR_HW_RESET_CONTROL_1r_CLR(egr_rst_ctl_1);
    EGR_HW_RESET_CONTROL_1r_RESET_ALLf_SET(egr_rst_ctl_1, 1);
    EGR_HW_RESET_CONTROL_1r_VALIDf_SET(egr_rst_ctl_1, 1);
    EGR_HW_RESET_CONTROL_1r_COUNTf_SET(egr_rst_ctl_1, 0x10000);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_1r(unit, egr_rst_ctl_1);

    /* Reset the ISM block */
    ISM_HW_RESET_CONTROL_0r_CLR(ism_rst_ctl_0);
    ioerr += WRITE_ISM_HW_RESET_CONTROL_0r(unit, ism_rst_ctl_0);
    ISM_HW_RESET_CONTROL_1r_CLR(ism_rst_ctl_1);
    ISM_HW_RESET_CONTROL_1r_RESET_ALLf_SET(ism_rst_ctl_1, 1);
    ISM_HW_RESET_CONTROL_1r_VALIDf_SET(ism_rst_ctl_1, 1);
    ISM_HW_RESET_CONTROL_1r_COUNTf_SET(ism_rst_ctl_1, 0x20000);
    ioerr += WRITE_ISM_HW_RESET_CONTROL_1r(unit, ism_rst_ctl_1);

    /* Clear AXP block memories */
    AXP_WRX_MEMORY_BULK_RESETr_CLR(axp_wrx_rst);
    AXP_WRX_MEMORY_BULK_RESETr_START_RESETf_SET(axp_wrx_rst, 1);
    ioerr += WRITE_AXP_WRX_MEMORY_BULK_RESETr(unit, axp_wrx_rst);
    AXP_WTX_MEMORY_BULK_RESETr_CLR(axp_wtx_rst);
    AXP_WTX_MEMORY_BULK_RESETr_START_RESETf_SET(axp_wtx_rst, 1);
    ioerr += WRITE_AXP_WTX_MEMORY_BULK_RESETr(unit, axp_wtx_rst);
    AXP_SM_MEMORY_BULK_RESETr_CLR(axp_sm_rst);
    AXP_SM_MEMORY_BULK_RESETr_START_RESETf_SET(axp_sm_rst, 1);
    ioerr += WRITE_AXP_SM_MEMORY_BULK_RESETr(unit, axp_sm_rst);

    for (idx = 0; idx < PIPE_RESET_TIMEOUT_MSEC; idx++) {
        ioerr += READ_ING_HW_RESET_CONTROL_2r(unit, &ing_rst_ctl_2);
        if (ING_HW_RESET_CONTROL_2r_DONEf_GET(ing_rst_ctl_2)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (idx >= PIPE_RESET_TIMEOUT_MSEC) {
        CDK_WARN(("bcm56640_a0_bmd_init[%d]: IPIPE reset timeout\n", unit));
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
        CDK_WARN(("bcm56640_a0_bmd_init[%d]: EPIPE reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }

    for (; idx < PIPE_RESET_TIMEOUT_MSEC; idx++) {
        ioerr += READ_ISM_HW_RESET_CONTROL_1r(unit, &ism_rst_ctl_1);
        if (ISM_HW_RESET_CONTROL_1r_DONEf_GET(ism_rst_ctl_1)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (idx >= PIPE_RESET_TIMEOUT_MSEC) {
        CDK_WARN(("bcm56640_a0_bmd_init[%d]: ISM reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }

    for (; idx < PIPE_RESET_TIMEOUT_MSEC; idx++) {
        ioerr += READ_AXP_WRX_MEMORY_BULK_RESETr(unit, &axp_wrx_rst);
        if (AXP_WRX_MEMORY_BULK_RESETr_RESET_DONEf_GET(axp_wrx_rst)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (idx >= PIPE_RESET_TIMEOUT_MSEC) {
        CDK_WARN(("bcm56640_a0_bmd_init[%d]: AXP WRX reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }

    for (; idx < PIPE_RESET_TIMEOUT_MSEC; idx++) {
        ioerr += READ_AXP_WTX_MEMORY_BULK_RESETr(unit, &axp_wtx_rst);
        if (AXP_WTX_MEMORY_BULK_RESETr_RESET_DONEf_GET(axp_wtx_rst)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (idx >= PIPE_RESET_TIMEOUT_MSEC) {
        CDK_WARN(("bcm56640_a0_bmd_init[%d]: AXP WTX reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }

    for (; idx < PIPE_RESET_TIMEOUT_MSEC; idx++) {
        if (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_NO_DPI) {
            /* DPI-SM memories disabled */
            break;
        }
        ioerr += READ_AXP_SM_MEMORY_BULK_RESETr(unit, &axp_sm_rst);
        if (AXP_SM_MEMORY_BULK_RESETr_RESET_DONEf_GET(axp_sm_rst)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (idx >= PIPE_RESET_TIMEOUT_MSEC) {
        CDK_WARN(("bcm56640_a0_bmd_init[%d]: AXP SM reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }

    /* Clear pipe reset registers */
    ING_HW_RESET_CONTROL_2r_CLR(ing_rst_ctl_2);
    ioerr += WRITE_ING_HW_RESET_CONTROL_2r(unit, ing_rst_ctl_2);
    EGR_HW_RESET_CONTROL_1r_CLR(egr_rst_ctl_1);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_1r(unit, egr_rst_ctl_1);
    ISM_HW_RESET_CONTROL_1r_CLR(ism_rst_ctl_1);
    ioerr += WRITE_ISM_HW_RESET_CONTROL_1r(unit, ism_rst_ctl_1);
    AXP_WRX_MEMORY_BULK_RESETr_CLR(axp_wrx_rst);
    ioerr += WRITE_AXP_WRX_MEMORY_BULK_RESETr(unit, axp_wrx_rst);
    AXP_WTX_MEMORY_BULK_RESETr_CLR(axp_wtx_rst);
    ioerr += WRITE_AXP_WTX_MEMORY_BULK_RESETr(unit, axp_wtx_rst);
    AXP_SM_MEMORY_BULK_RESETr_CLR(axp_sm_rst);
    ioerr += WRITE_AXP_SM_MEMORY_BULK_RESETr(unit, axp_sm_rst);

    /* Initialize port mappings */
    ioerr += _port_map_init(unit);

    /* Configure CPU port */
    CPU_PBMm_CLR(cpu_pbm);
    CPU_PBMm_BITMAP_W0f_SET(cpu_pbm, 1);
    ioerr += WRITE_CPU_PBMm(unit, 0, cpu_pbm);
    CPU_PBM_2m_CLR(cpu_pbm_2);
    CPU_PBM_2m_BITMAP_W0f_SET(cpu_pbm_2, 1);
    ioerr += WRITE_CPU_PBM_2m(unit, 0, cpu_pbm_2);

    /* Initialize XLPORTs */
    bcm56640_a0_xport_pbmp_get(unit, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        /* We only need to write once per block */
        if (XPORT_SUBPORT(port) != 0) {
            continue;
        }
        /* Get XPORT instance within port block */
        inst = bcm56640_a0_xport_inst(unit, port);

        /* Select port mode parameters based on port speed */
        speed = bcm56640_a0_port_speed_max(unit, port);
        mac_mode = MAC_MODE_INDEP;
        if (speed >= 100000) {
            mac_mode = MAC_MODE_AGGR;
        }
        phy_mode = PHY_MODE_QUAD;
        core_mode = CORE_MODE_NOTDM;
        gmii_en = 0;
        lane_en = 0;
        if (speed > 20000) {
            phy_mode = PHY_MODE_SINGLE;
            core_mode = CORE_MODE_SINGLE;
            lane_en = 0x1;
        } else if (speed > 10000) {
            phy_mode = PHY_MODE_DUAL;
            core_mode = CORE_MODE_DUAL;
            lane_en = 0x5;
        } else if (speed != 0) {
            core_mode = CORE_MODE_QUAD;
            lane_en = 0xf;
            if (port < 53) {
                gmii_en = 1;
                if (port == 37) {
                    lane_en = 0x1;
                }
            }
        } 
        /* Set port mode */
        ioerr += READ_PORT_MODE_REGr(unit, &port_mode, port);
        if (inst == 2) {
            PORT_MODE_REGr_XPORT2_PHY_PORT_MODEf_SET(port_mode, phy_mode);
            PORT_MODE_REGr_XPORT2_CORE_PORT_MODEf_SET(port_mode, core_mode);
            PORT_MODE_REGr_XPC2_GMII_MII_ENABLEf_SET(port_mode, gmii_en);
        } else if (inst == 1) {
            PORT_MODE_REGr_XPORT1_PHY_PORT_MODEf_SET(port_mode, phy_mode);
            PORT_MODE_REGr_XPORT1_CORE_PORT_MODEf_SET(port_mode, core_mode);
            PORT_MODE_REGr_XPC1_GMII_MII_ENABLEf_SET(port_mode, gmii_en);
        } else {
            PORT_MODE_REGr_XPORT0_PHY_PORT_MODEf_SET(port_mode, phy_mode);
            PORT_MODE_REGr_XPORT0_CORE_PORT_MODEf_SET(port_mode, core_mode);
            PORT_MODE_REGr_XPC0_GMII_MII_ENABLEf_SET(port_mode, gmii_en);
        }
        PORT_MODE_REGr_MAC_MODEf_SET(port_mode, mac_mode);
        /* Keep port in reset while updating port mode */
        bcm56640_a0_xmac_reset_set(unit, port, 1);
        ioerr += WRITE_PORT_MODE_REGr(unit, port_mode, port);
        bcm56640_a0_xmac_reset_set(unit, port, 0);

        /* Set port enable for 4 lanes */
        ioerr += READ_PORT_ENABLE_REGr(unit, &port_en, port);
        port_en_mask = PORT_ENABLE_REGr_GET(port_en);
        port_en_mask &= ~(0xf << (inst << 2));
        port_en_mask |= (lane_en << (inst << 2));
        PORT_ENABLE_REGr_SET(port_en, port_en_mask);
        ioerr += WRITE_PORT_ENABLE_REGr(unit, port_en, port);
    }

    /* Reset MIB counters in all blocks */
    CDK_PBMP_ITER(pbmp, port) {
        PORT_MIB_RESETr_CLR(mib_reset);
        PORT_MIB_RESETr_CLR_CNTf_SET(mib_reset, 0xfff);
        ioerr += WRITE_PORT_MIB_RESETr(unit, mib_reset, port);
        PORT_MIB_RESETr_CLR_CNTf_SET(mib_reset, 0);
        ioerr += WRITE_PORT_MIB_RESETr(unit, mib_reset, port);
    }

    /* Enable Field Processor metering clock */
    ioerr += READ_MISCCONFIGr(unit, &misc_cfg);
    MISCCONFIGr_METERING_CLK_ENf_SET(misc_cfg, 1);
    ioerr += WRITE_MISCCONFIGr(unit, misc_cfg);

    /* Ensure that link bitmap is cleared */
    ioerr += CDK_XGSM_MEM_CLEAR(unit, EPC_LINK_BMAPm);

    /* Enable egress VLAN checks for all ports */
    bcm56640_a0_xport_pbmp_get(unit, &pbmp);
    CDK_PBMP_PORT_ADD(pbmp, CMIC_PORT);
    ING_EN_EFILTER_BITMAPm_CLR(ing_en_efilter);
    ING_EN_EFILTER_BITMAPm_BITMAP_W0f_SET(ing_en_efilter,
                                          CDK_PBMP_WORD_GET(pbmp, 0));
    ING_EN_EFILTER_BITMAPm_BITMAP_W1f_SET(ing_en_efilter,
                                          CDK_PBMP_WORD_GET(pbmp, 1));
    ioerr += WRITE_ING_EN_EFILTER_BITMAPm(unit, 0, ing_en_efilter);

    /*
     * Set MDIO reference clocks based on core clock:
     * mdio_refclk = coreclk * (1/divisor)
     *
     * Actual MDIO clock is reference clock divided by 2:
     * mdio_clk = mdio_refclk/2
     */

    /* mdio_refclk = 450 MHz * (1/6) = 75 MHz */
    mdio_div = 6;

    /* Configure internal MDC (refclk/2 = 37.5 MHz) */
    CMIC_RATE_ADJUST_INT_MDIOr_CLR(rate_adjust_int_mdio);
    CMIC_RATE_ADJUST_INT_MDIOr_DIVISORf_SET(rate_adjust_int_mdio, mdio_div);
    CMIC_RATE_ADJUST_INT_MDIOr_DIVIDENDf_SET(rate_adjust_int_mdio, 1);
    ioerr += WRITE_CMIC_RATE_ADJUST_INT_MDIOr(unit, rate_adjust_int_mdio);

    /* Configure external MDC (1/4 * refclk/2 = 9.375 MHz) */
    CMIC_RATE_ADJUSTr_CLR(rate_adjust);
    CMIC_RATE_ADJUSTr_DIVISORf_SET(rate_adjust, 4 * mdio_div);
    CMIC_RATE_ADJUSTr_DIVIDENDf_SET(rate_adjust, 1);
    ioerr += WRITE_CMIC_RATE_ADJUSTr(unit, rate_adjust);

    /* Configure discard counter */
    RDBGC0_SELECTr_CLR(rdbgc0_select);
    RDBGC0_SELECTr_BITMAPf_SET(rdbgc0_select, 0x0400ad11);
    ioerr += WRITE_RDBGC0_SELECTr(unit, rdbgc0_select);

    /* Initialize MMU */
    rv = _mmu_init(unit);
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    /* Initialize ISM-based hash tables */
    rv = _ism_init(unit);
    if (CDK_FAILURE(rv)) {
        return rv;
    }

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

    /* Probe PHYs */
    bcm56640_a0_xport_pbmp_get(unit, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_probe(unit, port);
        }
        if (CDK_SUCCESS(rv)) {
            speed = bcm56640_a0_port_speed_max(unit, port);
            if (speed > 10000 && speed <= 20000) {
                rv = bmd_phy_mode_set(unit, port, "warpcore",
                                      BMD_PHY_MODE_2LANE, 1);
            }
        }
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_fw_helper_set(unit, port, _firmware_helper);
        }
    }

    if (CDK_SUCCESS(rv)) {
        rv = bmd_phy_staged_init(unit, &pbmp);
    }

    /* Configure XPORTs */
    CDK_PBMP_ITER(pbmp, port) {
        /* Clear MAC hard reset after warpcore is initialized */
        if (XPORT_SUBPORT(port) == 0) {
            PORT_MAC_CONTROLr_CLR(port_mac_ctrl);
            ioerr += WRITE_PORT_MAC_CONTROLr(unit, port_mac_ctrl, port);
        }
        /* Initialize XLPORTs after XMAC is out of reset */
        ioerr += bcm56640_a0_xport_init(unit, port);
    }

#if BMD_CONFIG_INCLUDE_DMA
    /* Common port initialization for CPU port */
    ioerr += _port_init(unit, CMIC_PORT);

    if (CDK_SUCCESS(rv)) {
        rv = bmd_xgsm_dma_init(unit);
    }

    /* Enable all 48 CPU COS queues for Rx DMA channel */
    if (CDK_SUCCESS(rv)) {
        CMIC_CMC_COS_CTRL_RX_0r_t cos_ctrl_0;
        CMIC_CMC_COS_CTRL_RX_1r_t cos_ctrl_1;
        uint32_t cos_bmp;

        CMIC_CMC_COS_CTRL_RX_0r_CLR(cos_ctrl_0);
        for (idx = 0; idx < CMIC_NUM_PKT_DMA_CHAN; idx++) {
            cos_bmp = (idx == XGSM_DMA_RX_CHAN) ? 0xffffffff : 0;
            CMIC_CMC_COS_CTRL_RX_0r_COS_BMPf_SET(cos_ctrl_0, cos_bmp);
            ioerr += WRITE_CMIC_CMC_COS_CTRL_RX_0r(unit, idx, cos_ctrl_0);
        }

        CMIC_CMC_COS_CTRL_RX_1r_CLR(cos_ctrl_1);
        for (idx = 0; idx < CMIC_NUM_PKT_DMA_CHAN; idx++) {
            cos_bmp = (idx == XGSM_DMA_RX_CHAN) ? 0xffff : 0;
            CMIC_CMC_COS_CTRL_RX_1r_COS_BMPf_SET(cos_ctrl_1, cos_bmp);
            ioerr += WRITE_CMIC_CMC_COS_CTRL_RX_1r(unit, idx, cos_ctrl_1);
        }

        if (ioerr) {
            return CDK_E_IO;
        }
    }
#endif

    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56640_A0 */

