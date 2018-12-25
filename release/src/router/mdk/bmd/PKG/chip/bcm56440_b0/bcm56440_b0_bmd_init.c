#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56440_B0 == 1

/*
 * $Id: bcm56440_b0_bmd_init.c,v 1.6 Broadcom SDK $
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
#include <cdk/arch/xgsm_chip.h>
#include <cdk/cdk_debug.h>
#include <cdk/chip/bcm56440_b0_defs.h>
#include <phy/phy.h>
#include <bmd/bmd_phy_ctrl.h>
#include <bmdi/arch/xgsm_dma.h>
#include "bcm56440_b0_bmd.h"
#include "bcm56440_b0_internal.h"

#define PIPE_RESET_TIMEOUT_MSEC         50

STATIC int
_mmu_tdm_init(int unit)
{
    int ioerr = 0;
    int i, tdm_size;
    static int kt_tdm[78] = { 0, 0};
/* 56440/5/8/4/9/56249 TDM sequence */
    const int kt_tdm_0[78] = { 1,9,25,26,27,28,
                        17,2,25,26,27,28,
                        0,10,18,25,26,27,
                        28,3,11,25,26,27,
                        28,35,19,4,25,26,
                        27,28,12,20,25,26,
                        27,28,63,5,13,25,
                        26,27,28,21,6,25,
                        26,27,28,0,14,22,
                        25,26,27,28,7,15,
                        25,26,27,28,35,23,
                        8,25,26,27,28,16,
                        24,25,26,27,28,35
                      };
/* 56441/6 TDM sequence */
    const int kt_tdm_1[48] = { 1,28,63,27,
                        63,28,2,27,
                        63,28,0,27,
                        3,28,63,27,
                        63,28,4,27,
                        35,28,63,27,
                        5,28,63,27,
                        63,28,6,27,
                        35,28,63,27,
                        7,28,63,27,
                        63,28,8,27,
                        35,28,0,27
                     };
/* 56442/7 TDM sequence */
    const int kt_tdm_2[48] = { 1,9,63,35,
                        63,0,2,10,
                        63,63,63,63,
                        3,11,35,63,
                        63,63,4,12,
                        63,0,63,63,
                        5,13,35,63,
                        63,63,6,14,
                        63,63,63,63,
                        7,15,35,63,
                        63,63,8,16,
                        63,63,0,63
                      };

/* 56443 TDM sequence */
    const int kt_tdm_3[40] = { 27,35,26,25,
                        32,28,26,25,
                        33,29,26,25,
                        34,30,26,25,
                        35,31,26,25,
                        27,28,26,25,
                        32,29,26,25,
                        33,30,26,25,
                        34,31,26,25,
                        0,63,26,25
                     };
/* 56241 TDM sequence */
    const int kt_tdm_4[16] = { 27,28,63,35,
                        32,29,0,35,
                        33,30,63,35,
                        34,31,0,63
                      };


    /* Disable IARB TDM before programming... */
    IARB_TDM_CONTROLr_t iarb_tdm_ctrl;
    IARB_TDM_TABLEm_t iarb_tdm;
    LLS_PORT_TDMm_t  lls_tdm;
    LLS_TDM_CAL_CFGr_t cal_cfg;

    tdm_size = 78;
    if(CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX8_MODE ){
        tdm_size = 48;
        CDK_MEMCPY(&kt_tdm[0], &kt_tdm_1[0], (tdm_size * sizeof(int)));
    } else if (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX16_MODE ){
        tdm_size = 48;
        CDK_MEMCPY(&kt_tdm[0], &kt_tdm_2[0], (tdm_size * sizeof(int)));
    } else if (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_EIGHTX25G_MODE){
        tdm_size = 40;
        CDK_MEMCPY(&kt_tdm[0], &kt_tdm_3[0], (tdm_size * sizeof(int)));
    } else if (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX6_MODE){
        tdm_size = 16;
        CDK_MEMCPY(&kt_tdm[0], &kt_tdm_4[0], (tdm_size * sizeof(int)));
    } else {
        CDK_MEMCPY(&kt_tdm[0], &kt_tdm_0[0], (tdm_size * sizeof(int)));
    }

    ioerr +=(READ_IARB_TDM_CONTROLr(unit, &iarb_tdm_ctrl));
    IARB_TDM_CONTROLr_DISABLEf_SET(iarb_tdm_ctrl, 1);
    IARB_TDM_CONTROLr_TDM_WRAP_PTRf_SET(iarb_tdm_ctrl, tdm_size -1);
    ioerr +=(WRITE_IARB_TDM_CONTROLr(unit, iarb_tdm_ctrl));

    for (i = 0; i < tdm_size; i++) {
        IARB_TDM_TABLEm_CLR(iarb_tdm);
        IARB_TDM_TABLEm_PORT_NUMf_SET(iarb_tdm, kt_tdm[i]);
        ioerr +=(WRITE_IARB_TDM_TABLEm(unit, i, iarb_tdm));

        if (0 == (i % 2)) {
            /* Two entries per mem entry */
            LLS_PORT_TDMm_CLR(lls_tdm);
            LLS_PORT_TDMm_PORT_ID_0f_SET(lls_tdm, kt_tdm[i]);
            LLS_PORT_TDMm_PORT_ID_0_ENABLEf_SET(lls_tdm, 1);
        } else {
            LLS_PORT_TDMm_PORT_ID_1f_SET(lls_tdm, kt_tdm[i]);
            LLS_PORT_TDMm_PORT_ID_1_ENABLEf_SET(lls_tdm, 1);
            ioerr +=(WRITE_LLS_PORT_TDMm(unit, (i/2), lls_tdm));
        }
    }
    ioerr +=(READ_IARB_TDM_CONTROLr(unit, &iarb_tdm_ctrl));
    IARB_TDM_CONTROLr_DISABLEf_SET(iarb_tdm_ctrl, 0);
    IARB_TDM_CONTROLr_TDM_WRAP_PTRf_SET(iarb_tdm_ctrl, tdm_size -1);
    ioerr +=(WRITE_IARB_TDM_CONTROLr(unit, iarb_tdm_ctrl));

    
    LLS_TDM_CAL_CFGr_END_Af_SET(cal_cfg, tdm_size - 1);
    LLS_TDM_CAL_CFGr_END_Bf_SET(cal_cfg, tdm_size - 1);
    LLS_TDM_CAL_CFGr_ENABLEf_SET(cal_cfg, 1);
    ioerr +=(WRITE_LLS_TDM_CAL_CFGr(unit, cal_cfg));
    return ioerr;
}

static int
_mmu_init(int unit)
{
    int ioerr = 0;
    int port, i = 0;
    cdk_pbmp_t pbmp, mmu_pbmp;
    /* Init Link List Scheduler */
    LLS_SOFT_RESETr_t soft_reset;
    LLS_INITr_t       lls_init;
    int               nxtaddr = 0;
    TOQ_EXT_MEM_BW_MAP_TABLEr_t toq_ext_mem; 
    TOQ_EXT_MEM_BW_TIMER_CFGr_t   toq_ext_mem_bw_timer;
    DEQ_EFIFO_CFGr_t  deq_efifo;
    TOQ_PORT_BW_CTRLr_t toq_port_bw_ctrl;
    DEQ_EFIFO_CFG_COMPLETEr_t eq_efifo_cfg;
    LLS_CONFIG0r_t    lls_config;
    LLS_MAX_REFRESH_ENABLEr_t lls_max_refresh;
    LLS_MIN_REFRESH_ENABLEr_t  lls_min_refresh;
    LLS_PORT_CONFIGm_t   lls_port_cfg;
    LLS_L0_PARENTm_t     l0_parent;
    LLS_L1_PARENTm_t     l1_parent;
    LLS_L0_CONFIGm_t     l0_config;
    LLS_L1_CONFIGm_t     l1_config;
    LLS_L2_PARENTm_t     l2_parent;
    INPUT_PORT_RX_ENABLE0_64r_t rx_enable;
    THDIEMA_INPUT_PORT_RX_ENABLE0_64r_t iema_rx_enable;
    THDIEXT_INPUT_PORT_RX_ENABLE0_64r_t iext_rx_enable;
    THDIQEN_INPUT_PORT_RX_ENABLE0_64r_t iqen_rx_enable;
    THDIRQE_INPUT_PORT_RX_ENABLE0_64r_t irqe_rx_enable;
    INPUT_PORT_RX_ENABLE1_64r_t rx_enable1;
    THDIEMA_INPUT_PORT_RX_ENABLE1_64r_t iema_rx_enable1;
    THDIEXT_INPUT_PORT_RX_ENABLE1_64r_t iext_rx_enable1;
    THDIQEN_INPUT_PORT_RX_ENABLE1_64r_t iqen_rx_enable1;
    THDIRQE_INPUT_PORT_RX_ENABLE1_64r_t irqe_rx_enable1;
    PORT_MAX_PKT_SIZEr_t  port_max;
    THDIEXT_PORT_MAX_PKT_SIZEr_t iext_port_max; 
    THDIEMA_PORT_MAX_PKT_SIZEr_t iema_port_max;
    THDIRQE_PORT_MAX_PKT_SIZEr_t irqe_port_max;
    THDIQEN_PORT_MAX_PKT_SIZEr_t iqen_port_max;

    PORT_MIN_CELLr_t  port_min;
    THDIEXT_PORT_MIN_CELLr_t iext_port_min; 
    THDIEMA_PORT_MIN_CELLr_t iema_port_min;
    THDIRQE_PORT_MIN_CELLr_t irqe_port_min;
    THDIQEN_PORT_MIN_CELLr_t iqen_port_min;

    PORT_MAX_SHARED_CELLr_t  port_max_shared;
    THDIEXT_PORT_MAX_SHARED_CELLr_t iext_port_max_shared; 
    THDIEMA_PORT_MAX_SHARED_CELLr_t iema_port_max_shared;
    THDIRQE_PORT_MAX_SHARED_CELLr_t irqe_port_max_shared;
    THDIQEN_PORT_MAX_SHARED_CELLr_t iqen_port_max_shared;
    PORT_RESUME_LIMIT_CELLr_t  port_resume_limit;
    THDIEXT_PORT_RESUME_LIMIT_CELLr_t iext_port_resume_limit; 
    THDIEMA_PORT_RESUME_LIMIT_CELLr_t iema_port_resume_limit;
    THDIRQE_PORT_RESUME_LIMIT_CELLr_t irqe_port_resume_limit;
    THDIQEN_PORT_RESUME_LIMIT_CELLr_t iqen_port_resume_limit;
    PORT_PRI_XON_ENABLEr_t  port_pri_xon;
    THDIEXT_PORT_PRI_XON_ENABLEr_t iext_port_pri_xon; 
    THDIEMA_PORT_PRI_XON_ENABLEr_t iema_port_pri_xon;
    THDIRQE_PORT_PRI_XON_ENABLEr_t irqe_port_pri_xon;
    THDIQEN_PORT_PRI_XON_ENABLEr_t iqen_port_pri_xon;
    PORT_SHARED_MAX_PG_ENABLEr_t  port_shared_max_pg;
    THDIEXT_PORT_SHARED_MAX_PG_ENABLEr_t iext_port_shared_max_pg; 
    THDIEMA_PORT_SHARED_MAX_PG_ENABLEr_t iema_port_shared_max_pg;
    THDIRQE_PORT_SHARED_MAX_PG_ENABLEr_t irqe_port_shared_max_pg;
    THDIQEN_PORT_SHARED_MAX_PG_ENABLEr_t iqen_port_shared_max_pg;
    PORT_MIN_PG_ENABLEr_t  port_min_pg;
    THDIEXT_PORT_MIN_PG_ENABLEr_t iext_port_min_pg; 
    THDIEMA_PORT_MIN_PG_ENABLEr_t iema_port_min_pg;
    THDIRQE_PORT_MIN_PG_ENABLEr_t irqe_port_min_pg;
    THDIQEN_PORT_MIN_PG_ENABLEr_t iqen_port_min_pg;
    PG_MIN_CELLr_t  pg_min;
    THDIEXT_PG_MIN_CELLr_t iext_pg_min; 
    THDIEMA_PG_MIN_CELLr_t iema_pg_min;
    THDIRQE_PG_MIN_CELLr_t irqe_pg_min;
    THDIQEN_PG_MIN_CELLr_t iqen_pg_min;
    PG_SHARED_LIMIT_CELLr_t  pg_shared_limit;
    THDIEXT_PG_SHARED_LIMIT_CELLr_t iext_pg_shared_limit; 
    THDIEMA_PG_SHARED_LIMIT_CELLr_t iema_pg_shared_limit;
    THDIRQE_PG_SHARED_LIMIT_CELLr_t irqe_pg_shared_limit;
    THDIQEN_PG_SHARED_LIMIT_CELLr_t iqen_pg_shared_limit;
    PG_HDRM_LIMIT_CELLr_t  pg_hdrm_limit;
    THDIEXT_PG_HDRM_LIMIT_CELLr_t iext_pg_hdrm_limit; 
    THDIEMA_PG_HDRM_LIMIT_CELLr_t iema_pg_hdrm_limit;
    THDIRQE_PG_HDRM_LIMIT_CELLr_t irqe_pg_hdrm_limit;
    THDIQEN_PG_HDRM_LIMIT_CELLr_t iqen_pg_hdrm_limit;
    PG_RESET_OFFSET_CELLr_t  pg_reset_offset;
    THDIEXT_PG_RESET_OFFSET_CELLr_t iext_pg_reset_offset; 
    THDIEMA_PG_RESET_OFFSET_CELLr_t iema_pg_reset_offset;
    THDIRQE_PG_RESET_OFFSET_CELLr_t irqe_pg_reset_offset;
    THDIQEN_PG_RESET_OFFSET_CELLr_t iqen_pg_reset_offset;
    PG_RESET_FLOOR_CELLr_t  pg_reset_floor;
    THDIEXT_PG_RESET_FLOOR_CELLr_t iext_pg_reset_floor; 
    THDIEMA_PG_RESET_FLOOR_CELLr_t iema_pg_reset_floor;
    THDIRQE_PG_RESET_FLOOR_CELLr_t irqe_pg_reset_floor;
    THDIQEN_PG_RESET_FLOOR_CELLr_t iqen_pg_reset_floor;
    THDO_BYPASSr_t bpass0;
    THDI_BYPASSr_t bpass;
    THDIQEN_THDI_BYPASSr_t iqen_bpass;
    THDIRQE_THDI_BYPASSr_t irqe_bpass;
    THDIEXT_THDI_BYPASSr_t iext_bpass;
    THDIEMA_THDI_BYPASSr_t iema_bpass;
    PORT_PRI_GRP0r_t port_pri0;
    PORT_PRI_GRP1r_t port_pri1;
    THDIEXT_PORT_PRI_GRP0r_t iext_port_pri0;
    THDIEXT_PORT_PRI_GRP1r_t iext_port_pri1;
    THDIEMA_PORT_PRI_GRP0r_t iema_port_pri0;
    THDIEMA_PORT_PRI_GRP1r_t iema_port_pri1;
    THDIRQE_PORT_PRI_GRP0r_t irqe_port_pri0;
    THDIRQE_PORT_PRI_GRP1r_t irqe_port_pri1;
    THDIQEN_PORT_PRI_GRP0r_t iqen_port_pri0;
    THDIQEN_PORT_PRI_GRP1r_t iqen_port_pri1;
    MMU_ENQ_HIGIG_25_PRI_GRP0r_t hg_25_pri_gpr0;
    MMU_ENQ_HIGIG_25_PRI_GRP1r_t hg_25_pri_gpr1;
    MMU_ENQ_HIGIG_26_PRI_GRP0r_t hg_26_pri_gpr0;
    MMU_ENQ_HIGIG_26_PRI_GRP1r_t hg_26_pri_gpr1;
    MMU_ENQ_HIGIG_27_PRI_GRP0r_t hg_27_pri_gpr0;
    MMU_ENQ_HIGIG_27_PRI_GRP1r_t hg_27_pri_gpr1;
    MMU_ENQ_HIGIG_28_PRI_GRP0r_t hg_28_pri_gpr0;
    MMU_ENQ_HIGIG_28_PRI_GRP1r_t hg_28_pri_gpr1;
    BUFFER_CELL_LIMIT_SPr_t buf_cell;
    THDIEXT_BUFFER_CELL_LIMIT_SPr_t iext_buf_cell;
    THDIEMA_BUFFER_CELL_LIMIT_SPr_t iema_buf_cell;
    THDIRQE_BUFFER_CELL_LIMIT_SPr_t irqe_buf_cell;
    THDIQEN_BUFFER_CELL_LIMIT_SPr_t iqen_buf_cell;
    BUFFER_CELL_LIMIT_SP_SHAREDr_t sp_shared;
    THDIEXT_BUFFER_CELL_LIMIT_SP_SHAREDr_t iext_sp_shared;
    THDIEMA_BUFFER_CELL_LIMIT_SP_SHAREDr_t iema_sp_shared;
    THDIRQE_BUFFER_CELL_LIMIT_SP_SHAREDr_t irqe_sp_shared;
    THDIQEN_BUFFER_CELL_LIMIT_SP_SHAREDr_t iqen_sp_shared;
    CELL_RESET_LIMIT_OFFSET_SPr_t cell_reset;    
    THDIEXT_CELL_RESET_LIMIT_OFFSET_SPr_t iext_cell_reset;    
    THDIEMA_CELL_RESET_LIMIT_OFFSET_SPr_t iema_cell_reset;    
    THDIRQE_CELL_RESET_LIMIT_OFFSET_SPr_t irqe_cell_reset;    
    THDIQEN_CELL_RESET_LIMIT_OFFSET_SPr_t iqen_cell_reset;    
    GLOBAL_HDRM_LIMITr_t glb_hdrm;
    THDIEXT_GLOBAL_HDRM_LIMITr_t iext_glb_hdrm;
    THDIEMA_GLOBAL_HDRM_LIMITr_t iema_glb_hdrm;
    THDIRQE_GLOBAL_HDRM_LIMITr_t irqe_glb_hdrm;
    THDIQEN_GLOBAL_HDRM_LIMITr_t iqen_glb_hdrm;
    THDO_MISCCONFIGr_t thd0_misc;
    OP_THR_CONFIGr_t   op_thr;
    OP_BUFFER_SHARED_LIMIT_CELLEr_t op_buff_shr_celle;
    OP_BUFFER_SHARED_LIMIT_CELLIr_t op_buff_shr_celli;
    OP_BUFFER_SHARED_LIMIT_QENTRYr_t op_buff_shr_q;
    OP_BUFFER_SHARED_LIMIT_THDORQEQr_t op_buff_shr_thd;
    OP_BUFFER_SHARED_LIMIT_THDOEMAr_t  op_buff_shr_ema;
    OP_BUFFER_SHARED_LIMIT_RESUME_CELLIr_t op_buf_sh_res;
    OP_BUFFER_SHARED_LIMIT_RESUME_CELLEr_t op_buf_sh_res_celle;
    OP_BUFFER_SHARED_LIMIT_RESUME_QENTRYr_t op_sh_res_q;
    OP_BUFFER_SHARED_LIMIT_RESUME_THDORQEQr_t op_sh_res_thd;
    OP_BUFFER_SHARED_LIMIT_RESUME_THDOEMAr_t  op_sh_res_ema;
    OP_QUEUE_CONFIG_THDORQEIr_t op_q_thd_rqei;
    OP_QUEUE_CONFIG_THDORQEEr_t op_q_thd_rqee;
    OP_QUEUE_CONFIG_THDORQEQr_t op_q_thd_rqeq;
    OP_QUEUE_CONFIG_THDOEMAr_t  op_q_thd_ema;
    OP_QUEUE_CONFIG1_THDORQEIr_t op_q_thd_rqei1;
    OP_QUEUE_CONFIG1_THDORQEEr_t op_q_thd_rqee1;
    OP_QUEUE_CONFIG1_THDORQEQr_t op_q_thd_rqeq1;
    OP_QUEUE_CONFIG1_THDOEMAr_t  op_q_thd_ema1;
    OP_QUEUE_RESET_OFFSET_THDORQEIr_t op_q_rthd_rqei;
    OP_QUEUE_RESET_OFFSET_THDORQEEr_t op_q_rthd_rqee;
    OP_QUEUE_RESET_OFFSET_THDORQEQr_t op_q_rthd_rqeq;
    OP_QUEUE_RESET_OFFSET_THDOEMAr_t op_q_rthd_ema;
    MMU_THDO_QCONFIG_CELLm_t   qcfg_cell;  
    MMU_THDO_QOFFSET_CELLm_t  qoff_cell;
    MMU_THDO_QCONFIG_QENTRYm_t   qcfg_qentry;
    MMU_THDO_QOFFSET_QENTRYm_t qoff_qentry;
    MMU_THDO_OPNCONFIG_CELLm_t  opncfg_cell;
    MMU_THDO_OPNCONFIG_QENTRYm_t opncfg_qentry;
    MMU_AGING_LMT_INTm_t   age_int;
    MMU_AGING_LMT_EXTm_t   age_ext;
    WRED_MISCCONFIGr_t wred;
    MISCCONFIGr_t misc;
    WRED_PARITY_ERROR_MASKr_t parity;

    READ_LLS_SOFT_RESETr(unit, &soft_reset);
    LLS_SOFT_RESETr_SOFT_RESETf_SET(soft_reset, 0);
    ioerr  += WRITE_LLS_SOFT_RESETr(unit, soft_reset);

    READ_LLS_INITr(unit, &lls_init);
    LLS_INITr_INITf_SET(lls_init, 1);
    ioerr  += WRITE_LLS_INITr(unit, lls_init);
    BMD_SYS_USLEEP(50000);

    do {
        READ_LLS_INITr(unit, &lls_init);
        if (LLS_INITr_INIT_DONEf_GET(lls_init)) {
            break;
        }
        BMD_SYS_USLEEP(10000);
    } while (TRUE);

    /* Setup TDM for MMU Arb & LLS */
    _mmu_tdm_init(unit);

    for(i = 0; i < 16; i++) {
        READ_TOQ_EXT_MEM_BW_MAP_TABLEr(unit, i, &toq_ext_mem);
        TOQ_EXT_MEM_BW_MAP_TABLEr_GBL_GUARENTEE_BW_LIMITf_SET(toq_ext_mem,1450);
        TOQ_EXT_MEM_BW_MAP_TABLEr_WR_PHASEf_SET(toq_ext_mem, 120);
        TOQ_EXT_MEM_BW_MAP_TABLEr_RD_PHASEf_SET(toq_ext_mem, 120);
        ioerr += WRITE_TOQ_EXT_MEM_BW_MAP_TABLEr(unit, i, toq_ext_mem);
    }
    READ_TOQ_EXT_MEM_BW_TIMER_CFGr(unit, &toq_ext_mem_bw_timer);
    TOQ_EXT_MEM_BW_TIMER_CFGr_MIDPKT_SHAPE_ENABLEf_SET(toq_ext_mem_bw_timer, 0);
    ioerr += WRITE_TOQ_EXT_MEM_BW_TIMER_CFGr(unit, toq_ext_mem_bw_timer);

    /* Ports to configure */
    CDK_PBMP_CLEAR(mmu_pbmp);
    CDK_PBMP_ADD(mmu_pbmp, CMIC_PORT);
    CDK_XGSM_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);
    CDK_XGSM_BLKTYPE_PBMP_GET(unit, BLKTYPE_MXQPORT, &pbmp);
    CDK_PBMP_OR(mmu_pbmp, pbmp);
    CDK_PBMP_ITER(mmu_pbmp, port) {
        /* Configure Egress Fifo */
        READ_DEQ_EFIFO_CFGr(unit, port, &deq_efifo);
        DEQ_EFIFO_CFGr_EGRESS_FIFO_START_ADDRESSf_SET(deq_efifo, nxtaddr);
        DEQ_EFIFO_CFGr_EGRESS_FIFO_XMIT_THRESHOLDf_SET(deq_efifo,1);
        if((CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX8_MODE) ||
           (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX16_MODE) || 
           (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_EIGHTX25G_MODE) || 
           (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX6_MODE)) {
            if( port > 24 && port < 29) {
                DEQ_EFIFO_CFGr_EGRESS_FIFO_DEPTHf_SET(deq_efifo, 9);
                nxtaddr += 9;
            } else {
                DEQ_EFIFO_CFGr_EGRESS_FIFO_DEPTHf_SET(deq_efifo, 3);
                nxtaddr += 3;
            }

        } else {
            if( port > 24 && port < 29) {
                DEQ_EFIFO_CFGr_EGRESS_FIFO_DEPTHf_SET(deq_efifo, 6);
                nxtaddr += 6;
            } else {
                DEQ_EFIFO_CFGr_EGRESS_FIFO_DEPTHf_SET(deq_efifo, 2);
                nxtaddr += 2;
            }
        }
        ioerr += WRITE_DEQ_EFIFO_CFGr(unit, port, deq_efifo);

        /* Port BW Ctrl */
        READ_TOQ_PORT_BW_CTRLr(unit, port, &toq_port_bw_ctrl);
        if ( port == 0 || port == 35) {
            if((CDK_XGSM_FLAGS(unit) & CHIP_FLAG_EIGHTX25G_MODE) || 
               (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX6_MODE)) {
                TOQ_PORT_BW_CTRLr_PORT_BWf_SET(toq_port_bw_ctrl, 125);
            } else {
                TOQ_PORT_BW_CTRLr_PORT_BWf_SET(toq_port_bw_ctrl, 50);
            }
            TOQ_PORT_BW_CTRLr_START_THRESHOLDf_SET(toq_port_bw_ctrl, 127);
        } else if( port > 24 && port < 29) { 
            TOQ_PORT_BW_CTRLr_PORT_BWf_SET(toq_port_bw_ctrl, 500);
            TOQ_PORT_BW_CTRLr_START_THRESHOLDf_SET(toq_port_bw_ctrl, 34);
        } else if ( port > 0 && port < 25) {
            TOQ_PORT_BW_CTRLr_PORT_BWf_SET(toq_port_bw_ctrl, 125);
            TOQ_PORT_BW_CTRLr_START_THRESHOLDf_SET(toq_port_bw_ctrl, 19);
        } else {
            TOQ_PORT_BW_CTRLr_PORT_BWf_SET(toq_port_bw_ctrl, 50);
            TOQ_PORT_BW_CTRLr_START_THRESHOLDf_SET(toq_port_bw_ctrl, 7);
        }
        ioerr += WRITE_TOQ_PORT_BW_CTRLr(unit, port, toq_port_bw_ctrl);
    }
    DEQ_EFIFO_CFG_COMPLETEr_EGRESS_FIFO_CONFIGURATION_COMPLETEf_SET(eq_efifo_cfg, 1);
    ioerr += WRITE_DEQ_EFIFO_CFG_COMPLETEr(unit, eq_efifo_cfg);

    /* Enable LLS */
    LLS_CONFIG0r_CLR(lls_config);
    LLS_CONFIG0r_DEQUEUE_ENABLEf_SET(lls_config, 1);
    LLS_CONFIG0r_ENQUEUE_ENABLEf_SET(lls_config, 1);
    LLS_CONFIG0r_FC_ENABLEf_SET(lls_config, 1);
    LLS_CONFIG0r_MIN_ENABLEf_SET(lls_config, 1);
    LLS_CONFIG0r_PORT_SCHEDULER_ENABLEf_SET(lls_config, 1);
    LLS_CONFIG0r_SHAPER_ENABLEf_SET(lls_config, 1);
    ioerr += WRITE_LLS_CONFIG0r(unit, lls_config);

    /* Enable shaper background refresh */
    LLS_MAX_REFRESH_ENABLEr_CLR(lls_max_refresh);
    LLS_MAX_REFRESH_ENABLEr_L0_MAX_REFRESH_ENABLEf_SET(lls_max_refresh, 1);
    LLS_MAX_REFRESH_ENABLEr_L1_MAX_REFRESH_ENABLEf_SET(lls_max_refresh, 1);
    LLS_MAX_REFRESH_ENABLEr_L2_MAX_REFRESH_ENABLEf_SET(lls_max_refresh, 1);
    LLS_MAX_REFRESH_ENABLEr_PORT_MAX_REFRESH_ENABLEf_SET(lls_max_refresh, 1);
    ioerr += WRITE_LLS_MAX_REFRESH_ENABLEr(unit, lls_max_refresh);

    LLS_MIN_REFRESH_ENABLEr_L0_MIN_REFRESH_ENABLEf_SET(lls_min_refresh, 1);
    LLS_MIN_REFRESH_ENABLEr_L1_MIN_REFRESH_ENABLEf_SET(lls_min_refresh, 1);
    LLS_MIN_REFRESH_ENABLEr_L2_MIN_REFRESH_ENABLEf_SET(lls_min_refresh, 1);
    ioerr += WRITE_LLS_MIN_REFRESH_ENABLEr(unit, lls_min_refresh);

    /* LLS Queue Configuration */
    CDK_PBMP_ITER(mmu_pbmp, port) {
        LLS_PORT_CONFIGm_CLR(lls_port_cfg);
        LLS_PORT_CONFIGm_L0_LOCK_ON_PACKETf_SET(lls_port_cfg, 1);
        LLS_PORT_CONFIGm_L1_LOCK_ON_PACKETf_SET(lls_port_cfg, 1);
        LLS_PORT_CONFIGm_L2_LOCK_ON_PACKETf_SET(lls_port_cfg, 1);
        LLS_PORT_CONFIGm_P_NUM_SPRIf_SET(lls_port_cfg, 1);
        LLS_PORT_CONFIGm_P_START_SPRIf_SET(lls_port_cfg, (port*4));
        ioerr += WRITE_LLS_PORT_CONFIGm(unit, port, lls_port_cfg);

        LLS_L0_PARENTm_CLR(l0_parent);
        LLS_L0_PARENTm_C_PARENTf_SET(l0_parent, port);
        ioerr += WRITE_LLS_L0_PARENTm(unit, (port * 4), l0_parent);

        LLS_L0_CONFIGm_CLR(l0_config);
        LLS_L0_CONFIGm_P_NUM_SPRIf_SET(l0_config, 1);
        LLS_L0_CONFIGm_P_START_SPRIf_SET(l0_config, (port * 16));
        ioerr += WRITE_LLS_L0_CONFIGm(unit, (port * 4), l0_config);

        LLS_L1_PARENTm_CLR(l1_parent);
        LLS_L1_PARENTm_C_PARENTf_SET(l1_parent, (port * 4));
        ioerr += WRITE_LLS_L1_PARENTm(unit, (port * 16), l1_parent);

        LLS_L1_CONFIGm_CLR(l1_config);
        LLS_L1_CONFIGm_P_NUM_SPRIf_SET(l1_config, 8);
        if (port == 0) {
            LLS_L1_CONFIGm_P_START_SPRIf_SET(l1_config, 0);
        } else {
            LLS_L1_CONFIGm_P_START_SPRIf_SET(l1_config, (port*8)+40);
        }
        ioerr += WRITE_LLS_L1_CONFIGm(unit, (port * 16), l1_config);

        LLS_L2_PARENTm_CLR(l2_parent);
        LLS_L2_PARENTm_C_PARENTf_SET(l2_parent, (port*16));
        for(i = 0; i < 8; i++) {
            if (port == 0) {
                ioerr += WRITE_LLS_L2_PARENTm(unit, i, l2_parent);
            } else {
                ioerr += WRITE_LLS_L2_PARENTm(unit, ((port*8)+40+i), l2_parent);
            }
        }
    }

    /* Enable all ports */
    INPUT_PORT_RX_ENABLE0_64r_CLR(rx_enable);
    THDIEMA_INPUT_PORT_RX_ENABLE0_64r_CLR(iema_rx_enable);
    THDIEXT_INPUT_PORT_RX_ENABLE0_64r_CLR(iext_rx_enable);
    THDIQEN_INPUT_PORT_RX_ENABLE0_64r_CLR(iqen_rx_enable);
    THDIRQE_INPUT_PORT_RX_ENABLE0_64r_CLR(irqe_rx_enable);
    INPUT_PORT_RX_ENABLE0_64r_INPUT_PORT_RX_ENABLE_LOf_SET(rx_enable, 0xffffffff);
    INPUT_PORT_RX_ENABLE0_64r_INPUT_PORT_RX_ENABLE_HIf_SET(rx_enable, 0x1f); /* ports 0..36 */
    THDIEMA_INPUT_PORT_RX_ENABLE0_64r_INPUT_PORT_RX_ENABLE_LOf_SET(
                                                    iema_rx_enable, 0xffffffff);
    THDIEMA_INPUT_PORT_RX_ENABLE0_64r_INPUT_PORT_RX_ENABLE_HIf_SET(
                                         iema_rx_enable, 0x1f); /* ports 0..36 */
    THDIEXT_INPUT_PORT_RX_ENABLE0_64r_INPUT_PORT_RX_ENABLE_LOf_SET(
                                              iext_rx_enable, 0xffffffff);
    THDIEXT_INPUT_PORT_RX_ENABLE0_64r_INPUT_PORT_RX_ENABLE_HIf_SET(
                                   iext_rx_enable, 0x1f); /* ports 0..36 */
    THDIQEN_INPUT_PORT_RX_ENABLE0_64r_INPUT_PORT_RX_ENABLE_LOf_SET(
                                             iqen_rx_enable, 0xffffffff);
    THDIQEN_INPUT_PORT_RX_ENABLE0_64r_INPUT_PORT_RX_ENABLE_HIf_SET(
                                        iqen_rx_enable, 0x1f); /* ports 0..36 */
    THDIRQE_INPUT_PORT_RX_ENABLE0_64r_INPUT_PORT_RX_ENABLE_LOf_SET(
                                                irqe_rx_enable, 0xffffffff);
    THDIRQE_INPUT_PORT_RX_ENABLE0_64r_INPUT_PORT_RX_ENABLE_HIf_SET(
                                      irqe_rx_enable, 0x1f); /* ports 0..36 */
    ioerr += WRITE_INPUT_PORT_RX_ENABLE0_64r(unit, rx_enable);
    ioerr += WRITE_THDIEMA_INPUT_PORT_RX_ENABLE0_64r(unit, iema_rx_enable);
    ioerr += WRITE_THDIEXT_INPUT_PORT_RX_ENABLE0_64r(unit, iext_rx_enable);
    ioerr += WRITE_THDIQEN_INPUT_PORT_RX_ENABLE0_64r(unit, iqen_rx_enable);
    ioerr += WRITE_THDIRQE_INPUT_PORT_RX_ENABLE0_64r(unit, irqe_rx_enable);

    INPUT_PORT_RX_ENABLE1_64r_CLR(rx_enable1);
    THDIEMA_INPUT_PORT_RX_ENABLE1_64r_CLR(iema_rx_enable1);
    THDIEXT_INPUT_PORT_RX_ENABLE1_64r_CLR(iext_rx_enable1);
    THDIQEN_INPUT_PORT_RX_ENABLE1_64r_CLR(iqen_rx_enable1);
    THDIRQE_INPUT_PORT_RX_ENABLE1_64r_CLR(irqe_rx_enable1);
    INPUT_PORT_RX_ENABLE1_64r_INPUT_PORT_RX_ENABLE_LOf_SET(rx_enable1, 0xffffffff);
    INPUT_PORT_RX_ENABLE1_64r_INPUT_PORT_RX_ENABLE_HIf_SET(rx_enable1, 0x1f); /* ports 0..36 */
    THDIEMA_INPUT_PORT_RX_ENABLE1_64r_INPUT_PORT_RX_ENABLE_LOf_SET(
                                                    iema_rx_enable1, 0xffffffff);
    THDIEMA_INPUT_PORT_RX_ENABLE1_64r_INPUT_PORT_RX_ENABLE_HIf_SET(
                                         iema_rx_enable1, 0x1f); /* ports 0..36 */
    THDIEXT_INPUT_PORT_RX_ENABLE1_64r_INPUT_PORT_RX_ENABLE_LOf_SET(
                                              iext_rx_enable1, 0xffffffff);
    THDIEXT_INPUT_PORT_RX_ENABLE1_64r_INPUT_PORT_RX_ENABLE_HIf_SET(
                                   iext_rx_enable1, 0x1f); /* ports 0..36 */
    THDIQEN_INPUT_PORT_RX_ENABLE1_64r_INPUT_PORT_RX_ENABLE_LOf_SET(
                                             iqen_rx_enable1, 0xffffffff);
    THDIQEN_INPUT_PORT_RX_ENABLE1_64r_INPUT_PORT_RX_ENABLE_HIf_SET(
                                        iqen_rx_enable1, 0x1f); /* ports 0..36 */
    THDIRQE_INPUT_PORT_RX_ENABLE1_64r_INPUT_PORT_RX_ENABLE_LOf_SET(
                                                irqe_rx_enable1, 0xffffffff);
    THDIRQE_INPUT_PORT_RX_ENABLE1_64r_INPUT_PORT_RX_ENABLE_HIf_SET(
                                      irqe_rx_enable1, 0x1f); /* ports 0..36 */
    ioerr += WRITE_INPUT_PORT_RX_ENABLE1_64r(unit, rx_enable1);
    ioerr += WRITE_THDIEMA_INPUT_PORT_RX_ENABLE1_64r(unit, iema_rx_enable1);
    ioerr += WRITE_THDIEXT_INPUT_PORT_RX_ENABLE1_64r(unit, iext_rx_enable1);
    ioerr += WRITE_THDIQEN_INPUT_PORT_RX_ENABLE1_64r(unit, iqen_rx_enable1);
    ioerr += WRITE_THDIRQE_INPUT_PORT_RX_ENABLE1_64r(unit, irqe_rx_enable1);


    THDIRQE_THDI_BYPASSr_CLR(irqe_bpass);
    THDIEMA_THDI_BYPASSr_CLR(iema_bpass);
    THDIEXT_THDI_BYPASSr_CLR(iext_bpass);
    THDIQEN_THDI_BYPASSr_CLR(iqen_bpass);
    THDI_BYPASSr_CLR(bpass);
    THDO_BYPASSr_CLR(bpass0);
    ioerr += (WRITE_THDI_BYPASSr(unit, bpass));
    ioerr += (WRITE_THDIQEN_THDI_BYPASSr(unit, iqen_bpass));
    ioerr += (WRITE_THDIRQE_THDI_BYPASSr(unit, irqe_bpass));
    ioerr += (WRITE_THDIEXT_THDI_BYPASSr(unit, iext_bpass));
    ioerr += (WRITE_THDIEMA_THDI_BYPASSr(unit, iema_bpass));
    ioerr += (WRITE_THDO_BYPASSr(unit, bpass0));

    if((CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX8_MODE) ||
       (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX16_MODE) || 
       (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_EIGHTX25G_MODE) || 
       (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX6_MODE)) {

        /* WRED Configuration */
        READ_WRED_MISCCONFIGr(unit, &wred);
        WRED_MISCCONFIGr_BASE_UPDATE_INTERVALf_SET(wred, 7);
        ioerr += (WRITE_WRED_MISCCONFIGr(unit, wred));

        READ_WRED_PARITY_ERROR_MASKr(unit, &parity);
        WRED_PARITY_ERROR_MASKr_UPDATE_INTRPT_MASKf_SET(parity, 0);
        ioerr += (WRITE_WRED_PARITY_ERROR_MASKr(unit, parity));

        READ_MISCCONFIGr(unit, &misc);
        MISCCONFIGr_REFRESH_ENf_SET(misc, 1);
        ioerr += (WRITE_MISCCONFIGr(unit, misc));
    } 

    CDK_PBMP_ITER(mmu_pbmp, port) {
 
        PORT_MAX_PKT_SIZEr_PORT_MAX_PKT_SIZEf_SET(port_max, 49);
        THDIEXT_PORT_MAX_PKT_SIZEr_PORT_MAX_PKT_SIZEf_SET(iext_port_max, 49);
        THDIEMA_PORT_MAX_PKT_SIZEr_PORT_MAX_PKT_SIZEf_SET(iema_port_max, 49);
        THDIRQE_PORT_MAX_PKT_SIZEr_PORT_MAX_PKT_SIZEf_SET(irqe_port_max, 49);
        THDIQEN_PORT_MAX_PKT_SIZEr_PORT_MAX_PKT_SIZEf_SET(iqen_port_max, 49);
        ioerr += (WRITE_PORT_MAX_PKT_SIZEr(unit, port, port_max));
        ioerr += (WRITE_THDIEXT_PORT_MAX_PKT_SIZEr(unit, port, iext_port_max));
        ioerr += (WRITE_THDIEMA_PORT_MAX_PKT_SIZEr(unit, port, iema_port_max));
        ioerr += (WRITE_THDIRQE_PORT_MAX_PKT_SIZEr(unit, port, irqe_port_max));
        ioerr += (WRITE_THDIQEN_PORT_MAX_PKT_SIZEr(unit, port, iqen_port_max));

        PORT_MIN_CELLr_CLR(port_min);
        THDIEXT_PORT_MIN_CELLr_CLR(iext_port_min);
        THDIEMA_PORT_MIN_CELLr_CLR(iema_port_min);
        THDIRQE_PORT_MIN_CELLr_CLR(irqe_port_min);
        THDIQEN_PORT_MIN_CELLr_CLR(iqen_port_min);
        ioerr += (WRITE_THDIEXT_PORT_MIN_CELLr(unit, port, iext_port_min));
        ioerr += (WRITE_THDIEMA_PORT_MIN_CELLr(unit, port, iema_port_min));
        ioerr += (WRITE_PORT_MIN_CELLr(unit, port, port_min));
        ioerr += (WRITE_THDIRQE_PORT_MIN_CELLr(unit, port, irqe_port_min));
        ioerr += (WRITE_THDIQEN_PORT_MIN_CELLr(unit, port, iqen_port_min));

   
        PORT_MAX_SHARED_CELLr_PORT_MAXf_SET(port_max_shared, 5226);
        THDIEXT_PORT_MAX_SHARED_CELLr_PORT_MAXf_SET(iext_port_max_shared, 0);
        THDIEMA_PORT_MAX_SHARED_CELLr_PORT_MAXf_SET(iema_port_max_shared, 0);
        THDIRQE_PORT_MAX_SHARED_CELLr_PORT_MAXf_SET(irqe_port_max_shared, 3300);
        THDIQEN_PORT_MAX_SHARED_CELLr_PORT_MAXf_SET(iqen_port_max_shared, 129628);
        ioerr += (WRITE_THDIEXT_PORT_MAX_SHARED_CELLr(unit, port, iext_port_max_shared));
        ioerr += (WRITE_THDIEMA_PORT_MAX_SHARED_CELLr(unit, port, iema_port_max_shared));
        ioerr += (WRITE_PORT_MAX_SHARED_CELLr(unit, port, port_max_shared));
        ioerr += (WRITE_THDIRQE_PORT_MAX_SHARED_CELLr(unit, port, irqe_port_max_shared));
        ioerr += (WRITE_THDIQEN_PORT_MAX_SHARED_CELLr(unit, port, iqen_port_max_shared));


   
        PORT_RESUME_LIMIT_CELLr_CELLSf_SET(port_resume_limit, 5208);
        THDIEXT_PORT_RESUME_LIMIT_CELLr_CELLSf_SET(iext_port_resume_limit, 0);
        THDIEMA_PORT_RESUME_LIMIT_CELLr_CELLSf_SET(iema_port_resume_limit, 0);
        THDIRQE_PORT_RESUME_LIMIT_CELLr_CELLSf_SET(irqe_port_resume_limit, 3298);
        THDIQEN_PORT_RESUME_LIMIT_CELLr_CELLSf_SET(iqen_port_resume_limit, 129574);
        ioerr += (WRITE_THDIEXT_PORT_RESUME_LIMIT_CELLr(unit, port, iext_port_resume_limit));
        ioerr += (WRITE_THDIEMA_PORT_RESUME_LIMIT_CELLr(unit, port, iema_port_resume_limit));
        ioerr += (WRITE_PORT_RESUME_LIMIT_CELLr(unit, port, port_resume_limit));
        ioerr += (WRITE_THDIRQE_PORT_RESUME_LIMIT_CELLr(unit, port, irqe_port_resume_limit));
        ioerr += (WRITE_THDIQEN_PORT_RESUME_LIMIT_CELLr(unit, port, iqen_port_resume_limit));

   
        PORT_PRI_XON_ENABLEr_CLR(port_pri_xon);
        THDIEXT_PORT_PRI_XON_ENABLEr_CLR(iext_port_pri_xon);
        THDIEMA_PORT_PRI_XON_ENABLEr_CLR(iema_port_pri_xon);
        THDIRQE_PORT_PRI_XON_ENABLEr_CLR(irqe_port_pri_xon);
        THDIQEN_PORT_PRI_XON_ENABLEr_CLR(iqen_port_pri_xon);
        ioerr += (WRITE_THDIEXT_PORT_PRI_XON_ENABLEr(unit, port, iext_port_pri_xon));
        ioerr += (WRITE_THDIEMA_PORT_PRI_XON_ENABLEr(unit, port, iema_port_pri_xon));
        ioerr += (WRITE_PORT_PRI_XON_ENABLEr(unit, port, port_pri_xon));
        ioerr += (WRITE_THDIRQE_PORT_PRI_XON_ENABLEr(unit, port, irqe_port_pri_xon));
        ioerr += (WRITE_THDIQEN_PORT_PRI_XON_ENABLEr(unit, port, iqen_port_pri_xon));

   
        PORT_SHARED_MAX_PG_ENABLEr_PG_BMPf_SET(port_shared_max_pg, 0xff);
        THDIEXT_PORT_SHARED_MAX_PG_ENABLEr_PG_BMPf_SET(iext_port_shared_max_pg, 0xff);
        THDIEMA_PORT_SHARED_MAX_PG_ENABLEr_PG_BMPf_SET(iema_port_shared_max_pg, 0xff);
        THDIRQE_PORT_SHARED_MAX_PG_ENABLEr_PG_BMPf_SET(irqe_port_shared_max_pg, 0xff);
        THDIQEN_PORT_SHARED_MAX_PG_ENABLEr_PG_BMPf_SET(iqen_port_shared_max_pg, 0xff);
        ioerr += (WRITE_THDIEXT_PORT_SHARED_MAX_PG_ENABLEr(unit, port, iext_port_shared_max_pg));
        ioerr += (WRITE_THDIEMA_PORT_SHARED_MAX_PG_ENABLEr(unit, port, iema_port_shared_max_pg));
        ioerr += (WRITE_PORT_SHARED_MAX_PG_ENABLEr(unit, port, port_shared_max_pg));
        ioerr += (WRITE_THDIRQE_PORT_SHARED_MAX_PG_ENABLEr(unit, port, irqe_port_shared_max_pg));
        ioerr += (WRITE_THDIQEN_PORT_SHARED_MAX_PG_ENABLEr(unit, port, iqen_port_shared_max_pg));

   
        PORT_MIN_PG_ENABLEr_PG_BMPf_SET(port_min_pg, 0xff);
        THDIEXT_PORT_MIN_PG_ENABLEr_PG_BMPf_SET(iext_port_min_pg, 0xff);
        THDIEMA_PORT_MIN_PG_ENABLEr_PG_BMPf_SET(iema_port_min_pg, 0xff);
        THDIRQE_PORT_MIN_PG_ENABLEr_PG_BMPf_SET(irqe_port_min_pg, 0xff);
        THDIQEN_PORT_MIN_PG_ENABLEr_PG_BMPf_SET(iqen_port_min_pg, 0xff);
        ioerr += (WRITE_THDIEXT_PORT_MIN_PG_ENABLEr(unit, port, iext_port_min_pg));
        ioerr += (WRITE_THDIEMA_PORT_MIN_PG_ENABLEr(unit, port, iema_port_min_pg));
        ioerr += (WRITE_PORT_MIN_PG_ENABLEr(unit, port, port_min_pg));
        ioerr += (WRITE_THDIRQE_PORT_MIN_PG_ENABLEr(unit, port, irqe_port_min_pg));
        ioerr += (WRITE_THDIQEN_PORT_MIN_PG_ENABLEr(unit, port, iqen_port_min_pg));

   
        PG_MIN_CELLr_PG_MINf_SET(pg_min, 0x31);
        THDIEXT_PG_MIN_CELLr_PG_MINf_SET(iext_pg_min, 0);
        THDIEMA_PG_MIN_CELLr_PG_MINf_SET(iema_pg_min, 0);
        THDIRQE_PG_MIN_CELLr_PG_MINf_SET(irqe_pg_min, 0x31);
        THDIQEN_PG_MIN_CELLr_PG_MINf_SET(iqen_pg_min, 0x31);
        ioerr += (WRITE_THDIEXT_PG_MIN_CELLr(unit, port, 0, iext_pg_min));
        ioerr += (WRITE_THDIEMA_PG_MIN_CELLr(unit, port, 0, iema_pg_min));
        ioerr += (WRITE_PG_MIN_CELLr(unit, port, 0, pg_min));
        ioerr += (WRITE_THDIRQE_PG_MIN_CELLr(unit, port, 0, irqe_pg_min));
        ioerr += (WRITE_THDIQEN_PG_MIN_CELLr(unit, port, 0, iqen_pg_min));

   
        PG_SHARED_LIMIT_CELLr_PG_SHARED_DYNAMICf_SET(pg_shared_limit, 1);
        THDIEXT_PG_SHARED_LIMIT_CELLr_PG_SHARED_DYNAMICf_SET(iext_pg_shared_limit, 1);
        THDIEMA_PG_SHARED_LIMIT_CELLr_PG_SHARED_DYNAMICf_SET(iema_pg_shared_limit, 1);
        THDIRQE_PG_SHARED_LIMIT_CELLr_PG_SHARED_DYNAMICf_SET(irqe_pg_shared_limit, 1);
        THDIQEN_PG_SHARED_LIMIT_CELLr_PG_SHARED_DYNAMICf_SET(iqen_pg_shared_limit, 1);
        PG_SHARED_LIMIT_CELLr_PG_SHARED_LIMITf_SET(pg_shared_limit, 7);
        THDIRQE_PG_SHARED_LIMIT_CELLr_PG_SHARED_LIMITf_SET(irqe_pg_shared_limit, 7);
        THDIQEN_PG_SHARED_LIMIT_CELLr_PG_SHARED_LIMITf_SET(iqen_pg_shared_limit, 7);
        ioerr += (WRITE_THDIEXT_PG_SHARED_LIMIT_CELLr(unit, port, 0, iext_pg_shared_limit));
        ioerr += (WRITE_THDIEMA_PG_SHARED_LIMIT_CELLr(unit, port, 0,iema_pg_shared_limit));
        ioerr += (WRITE_PG_SHARED_LIMIT_CELLr(unit, port, 0,pg_shared_limit));
        ioerr += (WRITE_THDIRQE_PG_SHARED_LIMIT_CELLr(unit, port, 0,irqe_pg_shared_limit));
        ioerr += (WRITE_THDIQEN_PG_SHARED_LIMIT_CELLr(unit, port, 0,iqen_pg_shared_limit));

   
        PG_HDRM_LIMIT_CELLr_PG_GEf_SET(pg_hdrm_limit, 1);
        THDIEXT_PG_HDRM_LIMIT_CELLr_PG_GEf_SET(iext_pg_hdrm_limit, 1);
        THDIEMA_PG_HDRM_LIMIT_CELLr_PG_GEf_SET(iema_pg_hdrm_limit, 1);
        THDIRQE_PG_HDRM_LIMIT_CELLr_PG_GEf_SET(irqe_pg_hdrm_limit, 0);
        THDIQEN_PG_HDRM_LIMIT_CELLr_PG_GEf_SET(iqen_pg_hdrm_limit, 0);
        PG_HDRM_LIMIT_CELLr_PG_HDRM_LIMITf_SET(pg_hdrm_limit, 127);
        THDIRQE_PG_HDRM_LIMIT_CELLr_PG_HDRM_LIMITf_SET(irqe_pg_hdrm_limit, 114);
        THDIQEN_PG_HDRM_LIMIT_CELLr_PG_HDRM_LIMITf_SET(iqen_pg_hdrm_limit, 3078);
        ioerr += (WRITE_THDIEXT_PG_HDRM_LIMIT_CELLr(unit, port, 0, iext_pg_hdrm_limit));
        ioerr += (WRITE_THDIEMA_PG_HDRM_LIMIT_CELLr(unit, port, 0, iema_pg_hdrm_limit));
        ioerr += (WRITE_PG_HDRM_LIMIT_CELLr(unit, port, 0, pg_hdrm_limit));
        ioerr += (WRITE_THDIRQE_PG_HDRM_LIMIT_CELLr(unit, port, 0, irqe_pg_hdrm_limit));
        ioerr += (WRITE_THDIQEN_PG_HDRM_LIMIT_CELLr(unit, port, 0, iqen_pg_hdrm_limit));

   
        PG_RESET_OFFSET_CELLr_CLR(pg_reset_offset);
        PG_RESET_OFFSET_CELLr_PG_RESET_OFFSETf_SET(pg_reset_offset, 18);
        THDIEXT_PG_RESET_OFFSET_CELLr_CLR(iext_pg_reset_offset);
        THDIEMA_PG_RESET_OFFSET_CELLr_CLR(iema_pg_reset_offset);
        THDIRQE_PG_RESET_OFFSET_CELLr_CLR(irqe_pg_reset_offset);
        THDIQEN_PG_RESET_OFFSET_CELLr_CLR(iqen_pg_reset_offset);
        THDIRQE_PG_RESET_OFFSET_CELLr_PG_RESET_OFFSETf_SET(irqe_pg_reset_offset, 2);
        THDIQEN_PG_RESET_OFFSET_CELLr_PG_RESET_OFFSETf_SET(iqen_pg_reset_offset, 54);
        ioerr += (WRITE_THDIEXT_PG_RESET_OFFSET_CELLr(unit, port, 0, iext_pg_reset_offset));
        ioerr += (WRITE_THDIEMA_PG_RESET_OFFSET_CELLr(unit, port, 0, iema_pg_reset_offset));
        ioerr += (WRITE_PG_RESET_OFFSET_CELLr(unit, port, 0, pg_reset_offset));
        ioerr += (WRITE_THDIRQE_PG_RESET_OFFSET_CELLr(unit, port, 0, irqe_pg_reset_offset));
        ioerr += (WRITE_THDIQEN_PG_RESET_OFFSET_CELLr(unit, port, 0, iqen_pg_reset_offset));

        PG_RESET_FLOOR_CELLr_CLR(pg_reset_floor);
        THDIEXT_PG_RESET_FLOOR_CELLr_CLR(iext_pg_reset_floor);
        THDIEMA_PG_RESET_FLOOR_CELLr_CLR(iema_pg_reset_floor);
        THDIRQE_PG_RESET_FLOOR_CELLr_CLR(irqe_pg_reset_floor);
        THDIQEN_PG_RESET_FLOOR_CELLr_CLR(iqen_pg_reset_floor);
        ioerr += (WRITE_THDIEXT_PG_RESET_FLOOR_CELLr(unit, port, 0, iext_pg_reset_floor));
        ioerr += (WRITE_THDIEMA_PG_RESET_FLOOR_CELLr(unit, port, 0, iema_pg_reset_floor));
        ioerr += (WRITE_PG_RESET_FLOOR_CELLr(unit, port, 0, pg_reset_floor));
        ioerr += (WRITE_THDIRQE_PG_RESET_FLOOR_CELLr(unit, port, 0, irqe_pg_reset_floor));
        ioerr += (WRITE_THDIQEN_PG_RESET_FLOOR_CELLr(unit, port, 0, iqen_pg_reset_floor));
    }

    /* CPU Port */

    PG_HDRM_LIMIT_CELLr_PG_GEf_SET(pg_hdrm_limit, 1);
    THDIEXT_PG_HDRM_LIMIT_CELLr_CLR(iext_pg_hdrm_limit);
    THDIEMA_PG_HDRM_LIMIT_CELLr_CLR(iema_pg_hdrm_limit);
    THDIRQE_PG_HDRM_LIMIT_CELLr_CLR(irqe_pg_hdrm_limit);
    THDIQEN_PG_HDRM_LIMIT_CELLr_CLR(iqen_pg_hdrm_limit);
    ioerr += (WRITE_THDIEXT_PG_HDRM_LIMIT_CELLr(unit, 0, 0, iext_pg_hdrm_limit));
    ioerr += (WRITE_THDIEMA_PG_HDRM_LIMIT_CELLr(unit, 0, 0, iema_pg_hdrm_limit));
    ioerr += (WRITE_PG_HDRM_LIMIT_CELLr(unit, 0, 0, pg_hdrm_limit));
    ioerr += (WRITE_THDIRQE_PG_HDRM_LIMIT_CELLr(unit, 0, 0, irqe_pg_hdrm_limit));
    ioerr += (WRITE_THDIQEN_PG_HDRM_LIMIT_CELLr(unit, 0, 0, iqen_pg_hdrm_limit));

    /* MXQ Ports */
    CDK_XGSM_BLKTYPE_PBMP_GET(unit, BLKTYPE_MXQPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        /* PRIx_GRP = 0x7 */
        PORT_PRI_GRP0r_SET(port_pri0, 0xffffff);
        PORT_PRI_GRP1r_SET(port_pri1, 0xffffff);
        THDIEXT_PORT_PRI_GRP0r_SET(iext_port_pri0, 0xffffff);
        THDIEXT_PORT_PRI_GRP1r_SET(iext_port_pri1, 0xffffff);
        THDIEMA_PORT_PRI_GRP0r_SET(iema_port_pri0, 0xffffff);
        THDIEMA_PORT_PRI_GRP1r_SET(iema_port_pri1, 0xffffff);
        THDIRQE_PORT_PRI_GRP0r_SET(irqe_port_pri0, 0xffffff);
        THDIRQE_PORT_PRI_GRP1r_SET(irqe_port_pri1, 0xffffff);
        THDIQEN_PORT_PRI_GRP0r_SET(iqen_port_pri0, 0xffffff);
        THDIQEN_PORT_PRI_GRP1r_SET(iqen_port_pri1, 0xffffff);
        ioerr += (WRITE_PORT_PRI_GRP0r(unit, port, port_pri0));
        ioerr += (WRITE_PORT_PRI_GRP1r(unit, port, port_pri1));
        ioerr += (WRITE_THDIEXT_PORT_PRI_GRP0r(unit, port, iext_port_pri0));
        ioerr +=(WRITE_THDIEXT_PORT_PRI_GRP1r(unit, port, iext_port_pri1));
        ioerr +=(WRITE_THDIEMA_PORT_PRI_GRP0r(unit, port, iema_port_pri0));
        ioerr +=(WRITE_THDIEMA_PORT_PRI_GRP1r(unit, port, iema_port_pri1));
        ioerr +=(WRITE_THDIRQE_PORT_PRI_GRP0r(unit, port, irqe_port_pri0));
        ioerr +=(WRITE_THDIRQE_PORT_PRI_GRP1r(unit, port, irqe_port_pri1));
        ioerr +=(WRITE_THDIQEN_PORT_PRI_GRP0r(unit, port, iqen_port_pri0));
        ioerr +=(WRITE_THDIQEN_PORT_PRI_GRP1r(unit, port, iqen_port_pri1));

        PG_SHARED_LIMIT_CELLr_PG_SHARED_DYNAMICf_SET(pg_shared_limit, 1);
        THDIEXT_PG_SHARED_LIMIT_CELLr_PG_SHARED_DYNAMICf_SET(iext_pg_shared_limit, 1);
        THDIEMA_PG_SHARED_LIMIT_CELLr_PG_SHARED_DYNAMICf_SET(iema_pg_shared_limit, 1);
        THDIRQE_PG_SHARED_LIMIT_CELLr_PG_SHARED_DYNAMICf_SET(irqe_pg_shared_limit, 1);
        THDIQEN_PG_SHARED_LIMIT_CELLr_PG_SHARED_DYNAMICf_SET(iqen_pg_shared_limit, 1);
        PG_SHARED_LIMIT_CELLr_PG_SHARED_LIMITf_SET(pg_shared_limit, 7);
        THDIRQE_PG_SHARED_LIMIT_CELLr_PG_SHARED_LIMITf_SET(irqe_pg_shared_limit, 7);
        THDIQEN_PG_SHARED_LIMIT_CELLr_PG_SHARED_LIMITf_SET(iqen_pg_shared_limit, 7);
        ioerr += (WRITE_THDIEXT_PG_SHARED_LIMIT_CELLr(unit, port, 7, iext_pg_shared_limit));
        ioerr += (WRITE_THDIEMA_PG_SHARED_LIMIT_CELLr(unit, port, 7, iema_pg_shared_limit));
        ioerr += (WRITE_PG_SHARED_LIMIT_CELLr(unit, port, 7, pg_shared_limit));
        ioerr += (WRITE_THDIRQE_PG_SHARED_LIMIT_CELLr(unit, port, 7, irqe_pg_shared_limit));
        ioerr += (WRITE_THDIQEN_PG_SHARED_LIMIT_CELLr(unit, port, 7, iqen_pg_shared_limit));

        PG_HDRM_LIMIT_CELLr_PG_GEf_SET(pg_hdrm_limit, 1);
        THDIEXT_PG_HDRM_LIMIT_CELLr_PG_GEf_SET(iext_pg_hdrm_limit, 1);
        THDIEMA_PG_HDRM_LIMIT_CELLr_PG_GEf_SET(iema_pg_hdrm_limit, 1);
        THDIRQE_PG_HDRM_LIMIT_CELLr_PG_GEf_SET(irqe_pg_hdrm_limit, 0);
        THDIQEN_PG_HDRM_LIMIT_CELLr_PG_GEf_SET(iqen_pg_hdrm_limit, 0);
        PG_HDRM_LIMIT_CELLr_PG_HDRM_LIMITf_SET(pg_hdrm_limit, 172);
        THDIRQE_PG_HDRM_LIMIT_CELLr_PG_HDRM_LIMITf_SET(irqe_pg_hdrm_limit, 157);
        THDIQEN_PG_HDRM_LIMIT_CELLr_PG_HDRM_LIMITf_SET(iqen_pg_hdrm_limit, 4239);
        ioerr += (WRITE_THDIEXT_PG_HDRM_LIMIT_CELLr(unit, port, 7, iext_pg_hdrm_limit));
        ioerr += (WRITE_THDIEMA_PG_HDRM_LIMIT_CELLr(unit, port, 7, iema_pg_hdrm_limit));
        ioerr += (WRITE_PG_HDRM_LIMIT_CELLr(unit, port, 7, pg_hdrm_limit));
        ioerr += (WRITE_THDIRQE_PG_HDRM_LIMIT_CELLr(unit, port, 7, irqe_pg_hdrm_limit));
        ioerr += (WRITE_THDIQEN_PG_HDRM_LIMIT_CELLr(unit, port, 7, iqen_pg_hdrm_limit));

        PG_RESET_OFFSET_CELLr_CLR(pg_reset_offset);
        PG_RESET_OFFSET_CELLr_PG_RESET_OFFSETf_SET(pg_reset_offset, 18);
        THDIEXT_PG_RESET_OFFSET_CELLr_CLR(iext_pg_reset_offset);
        THDIEMA_PG_RESET_OFFSET_CELLr_CLR(iema_pg_reset_offset);
        THDIRQE_PG_RESET_OFFSET_CELLr_CLR(irqe_pg_reset_offset);
        THDIQEN_PG_RESET_OFFSET_CELLr_CLR(iqen_pg_reset_offset);
        THDIRQE_PG_RESET_OFFSET_CELLr_PG_RESET_OFFSETf_SET(irqe_pg_reset_offset, 2);
        THDIQEN_PG_RESET_OFFSET_CELLr_PG_RESET_OFFSETf_SET(iqen_pg_reset_offset, 54);
        ioerr += (WRITE_THDIEXT_PG_RESET_OFFSET_CELLr(unit, port, 7, iext_pg_reset_offset));
        ioerr += (WRITE_THDIEMA_PG_RESET_OFFSET_CELLr(unit, port, 7, iema_pg_reset_offset));
        ioerr += (WRITE_PG_RESET_OFFSET_CELLr(unit, port, 7, pg_reset_offset));
        ioerr += (WRITE_THDIRQE_PG_RESET_OFFSET_CELLr(unit, port, 7, irqe_pg_reset_offset));
        ioerr += (WRITE_THDIQEN_PG_RESET_OFFSET_CELLr(unit, port, 7, iqen_pg_reset_offset));

        PG_RESET_FLOOR_CELLr_CLR(pg_reset_floor);
        THDIEXT_PG_RESET_FLOOR_CELLr_CLR(iext_pg_reset_floor);
        THDIEMA_PG_RESET_FLOOR_CELLr_CLR(iema_pg_reset_floor);
        THDIRQE_PG_RESET_FLOOR_CELLr_CLR(irqe_pg_reset_floor);
        THDIQEN_PG_RESET_FLOOR_CELLr_CLR(iqen_pg_reset_floor);
        ioerr += (WRITE_THDIEXT_PG_RESET_FLOOR_CELLr(unit, port, 7, iext_pg_reset_floor));
        ioerr += (WRITE_THDIEMA_PG_RESET_FLOOR_CELLr(unit, port, 7, iema_pg_reset_floor));
        ioerr += (WRITE_PG_RESET_FLOOR_CELLr(unit,port, 7, pg_reset_floor));
        ioerr += (WRITE_THDIRQE_PG_RESET_FLOOR_CELLr(unit, port, 7, irqe_pg_reset_floor));
        ioerr += (WRITE_THDIQEN_PG_RESET_FLOOR_CELLr(unit, port, 7, iqen_pg_reset_floor));

        PG_MIN_CELLr_PG_MINf_SET(pg_min, 0x31);
        THDIEXT_PG_MIN_CELLr_PG_MINf_SET(iext_pg_min, 0);
        THDIEMA_PG_MIN_CELLr_PG_MINf_SET(iema_pg_min, 0);
        THDIRQE_PG_MIN_CELLr_PG_MINf_SET(irqe_pg_min, 0x31);
        THDIQEN_PG_MIN_CELLr_PG_MINf_SET(iqen_pg_min, 0x31);
        ioerr += (WRITE_THDIEXT_PG_MIN_CELLr(unit, port, 7, iext_pg_min));
        ioerr += (WRITE_THDIEMA_PG_MIN_CELLr(unit, port, 7, iema_pg_min));
        ioerr += (WRITE_PG_MIN_CELLr(unit, port, 7, pg_min));
        ioerr += (WRITE_THDIRQE_PG_MIN_CELLr(unit, port, 7, irqe_pg_min));
        ioerr += (WRITE_THDIQEN_PG_MIN_CELLr(unit, port, 7, iqen_pg_min));
    }
    /* PRIx_GRP = 0x7 */

    MMU_ENQ_HIGIG_25_PRI_GRP0r_SET(hg_25_pri_gpr0, 0xffffff);
    MMU_ENQ_HIGIG_25_PRI_GRP1r_SET(hg_25_pri_gpr1, 0xffffff);
    MMU_ENQ_HIGIG_26_PRI_GRP0r_SET(hg_26_pri_gpr0, 0xffffff);
    MMU_ENQ_HIGIG_26_PRI_GRP1r_SET(hg_26_pri_gpr1, 0xffffff);
    MMU_ENQ_HIGIG_27_PRI_GRP0r_SET(hg_27_pri_gpr0, 0xffffff);
    MMU_ENQ_HIGIG_27_PRI_GRP1r_SET(hg_27_pri_gpr1, 0xffffff);
    MMU_ENQ_HIGIG_28_PRI_GRP0r_SET(hg_28_pri_gpr0, 0xffffff);
    MMU_ENQ_HIGIG_28_PRI_GRP1r_SET(hg_28_pri_gpr1, 0xffffff);

    ioerr +=(WRITE_MMU_ENQ_HIGIG_25_PRI_GRP0r(unit, hg_25_pri_gpr0));
    ioerr +=(WRITE_MMU_ENQ_HIGIG_25_PRI_GRP1r(unit, hg_25_pri_gpr1));
    ioerr +=(WRITE_MMU_ENQ_HIGIG_26_PRI_GRP0r(unit, hg_26_pri_gpr0));
    ioerr +=(WRITE_MMU_ENQ_HIGIG_26_PRI_GRP1r(unit, hg_26_pri_gpr1));
    ioerr +=(WRITE_MMU_ENQ_HIGIG_27_PRI_GRP0r(unit, hg_27_pri_gpr0));
    ioerr +=(WRITE_MMU_ENQ_HIGIG_27_PRI_GRP1r(unit, hg_27_pri_gpr1));
    ioerr +=(WRITE_MMU_ENQ_HIGIG_28_PRI_GRP0r(unit, hg_28_pri_gpr0));
    ioerr +=(WRITE_MMU_ENQ_HIGIG_28_PRI_GRP1r(unit, hg_28_pri_gpr1));

    /* Input port shared space */
/*    rval = 0;
    USE_SP_SHAREDr_ENABLEf_SET(rval, 1);
    ioerr +=(WRITE_USE_SP_SHAREDr(unit, rval));
*/
    BUFFER_CELL_LIMIT_SPr_LIMITf_SET(buf_cell, 5226);
    THDIRQE_BUFFER_CELL_LIMIT_SPr_LIMITf_SET(irqe_buf_cell, 3300);
    THDIQEN_BUFFER_CELL_LIMIT_SPr_LIMITf_SET(iqen_buf_cell, 129628);
    ioerr +=(WRITE_THDIEXT_BUFFER_CELL_LIMIT_SPr(unit, 0, iext_buf_cell));
    ioerr +=(WRITE_THDIEMA_BUFFER_CELL_LIMIT_SPr(unit, 0, iema_buf_cell));
    ioerr +=(WRITE_BUFFER_CELL_LIMIT_SPr(unit, 0, buf_cell));
    ioerr +=(WRITE_THDIRQE_BUFFER_CELL_LIMIT_SPr(unit, 0, irqe_buf_cell));
    ioerr +=(WRITE_THDIQEN_BUFFER_CELL_LIMIT_SPr(unit, 0, iqen_buf_cell));


    ioerr +=(WRITE_BUFFER_CELL_LIMIT_SP_SHAREDr(unit, sp_shared));
    ioerr +=(WRITE_THDIEXT_BUFFER_CELL_LIMIT_SP_SHAREDr(unit, iext_sp_shared));
    ioerr +=(WRITE_THDIEMA_BUFFER_CELL_LIMIT_SP_SHAREDr(unit, iema_sp_shared));
    ioerr +=(WRITE_THDIRQE_BUFFER_CELL_LIMIT_SP_SHAREDr(unit, irqe_sp_shared));
    ioerr +=(WRITE_THDIQEN_BUFFER_CELL_LIMIT_SP_SHAREDr(unit, iqen_sp_shared));


    ioerr +=(WRITE_THDIEXT_CELL_RESET_LIMIT_OFFSET_SPr(unit, 0, iext_cell_reset));
    ioerr +=(WRITE_THDIEMA_CELL_RESET_LIMIT_OFFSET_SPr(unit, 0, iema_cell_reset));
    THDIRQE_CELL_RESET_LIMIT_OFFSET_SPr_OFFSETf_SET(irqe_cell_reset, 7);
    ioerr +=(WRITE_THDIRQE_CELL_RESET_LIMIT_OFFSET_SPr(unit, 0, irqe_cell_reset));
    CELL_RESET_LIMIT_OFFSET_SPr_OFFSETf_SET(cell_reset, 63);
    ioerr +=(WRITE_CELL_RESET_LIMIT_OFFSET_SPr(unit, 0, cell_reset));
    THDIQEN_CELL_RESET_LIMIT_OFFSET_SPr_OFFSETf_SET(iqen_cell_reset, 189);
    ioerr +=(WRITE_THDIQEN_CELL_RESET_LIMIT_OFFSET_SPr(unit, 0, iqen_cell_reset));

    /* Input port per-device global headroom */

    ioerr +=(WRITE_THDIEXT_GLOBAL_HDRM_LIMITr(unit, iext_glb_hdrm));
    ioerr +=(WRITE_THDIEMA_GLOBAL_HDRM_LIMITr(unit, iema_glb_hdrm));
    GLOBAL_HDRM_LIMITr_GLOBAL_HDRM_LIMITf_SET(glb_hdrm, 107);
    THDIRQE_GLOBAL_HDRM_LIMITr_GLOBAL_HDRM_LIMITf_SET(irqe_glb_hdrm, 107);
    ioerr +=(WRITE_GLOBAL_HDRM_LIMITr(unit, glb_hdrm));
    ioerr +=(WRITE_THDIRQE_GLOBAL_HDRM_LIMITr(unit, irqe_glb_hdrm));
    THDIQEN_GLOBAL_HDRM_LIMITr_GLOBAL_HDRM_LIMITf_SET(iqen_glb_hdrm, 2889);
    ioerr +=(WRITE_THDIQEN_GLOBAL_HDRM_LIMITr(unit, iqen_glb_hdrm));

    ioerr +=(READ_THDO_MISCCONFIGr(unit, &thd0_misc));
    THDO_MISCCONFIGr_STAT_CLEARf_SET(thd0_misc, 0);
    THDO_MISCCONFIGr_PARITY_CHK_ENf_SET(thd0_misc, 1);
    THDO_MISCCONFIGr_PARITY_GEN_ENf_SET(thd0_misc, 1);
    ioerr +=(WRITE_THDO_MISCCONFIGr(unit, thd0_misc));

    ioerr +=(READ_OP_THR_CONFIGr(unit, &op_thr));
    OP_THR_CONFIGr_EARLY_E2E_SELECTf_SET(op_thr, 0);
    ioerr +=(WRITE_OP_THR_CONFIGr(unit, op_thr));

    ioerr +=(READ_OP_BUFFER_SHARED_LIMIT_CELLIr(unit, &op_buff_shr_celli));
    OP_BUFFER_SHARED_LIMIT_CELLIr_OP_BUFFER_SHARED_LIMIT_CELLIf_SET(op_buff_shr_celli, 10490);
    ioerr +=(WRITE_OP_BUFFER_SHARED_LIMIT_CELLIr(unit, op_buff_shr_celli));

    ioerr +=(READ_OP_BUFFER_SHARED_LIMIT_CELLEr(unit, &op_buff_shr_celle));
    OP_BUFFER_SHARED_LIMIT_CELLEr_OP_BUFFER_SHARED_LIMIT_CELLEf_SET(op_buff_shr_celle, 0);
    ioerr +=(WRITE_OP_BUFFER_SHARED_LIMIT_CELLEr(unit, op_buff_shr_celle));

    ioerr +=(READ_OP_BUFFER_SHARED_LIMIT_QENTRYr(unit, &op_buff_shr_q));
    OP_BUFFER_SHARED_LIMIT_QENTRYr_OP_BUFFER_SHARED_LIMIT_QENTRYf_SET(op_buff_shr_q, 261712);
    ioerr +=(WRITE_OP_BUFFER_SHARED_LIMIT_QENTRYr(unit, op_buff_shr_q));

    ioerr +=(READ_OP_BUFFER_SHARED_LIMIT_THDORQEQr(unit, &op_buff_shr_thd));
    OP_BUFFER_SHARED_LIMIT_THDORQEQr_OP_BUFFER_SHARED_LIMITf_SET(op_buff_shr_thd, 8191);
    ioerr +=(WRITE_OP_BUFFER_SHARED_LIMIT_THDORQEQr(unit, op_buff_shr_thd));

    ioerr +=(READ_OP_BUFFER_SHARED_LIMIT_THDOEMAr(unit, &op_buff_shr_ema));
    OP_BUFFER_SHARED_LIMIT_THDOEMAr_OP_BUFFER_SHARED_LIMITf_SET(op_buff_shr_ema, 0);
    ioerr +=(WRITE_OP_BUFFER_SHARED_LIMIT_THDOEMAr(unit, op_buff_shr_ema));

    ioerr +=(READ_OP_BUFFER_SHARED_LIMIT_RESUME_CELLIr(unit, &op_buf_sh_res));
    OP_BUFFER_SHARED_LIMIT_RESUME_CELLIr_OP_BUFFER_SHARED_LIMIT_RESUME_CELLIf_SET(op_buf_sh_res, 10427);
    ioerr +=(WRITE_OP_BUFFER_SHARED_LIMIT_RESUME_CELLIr(unit, op_buf_sh_res));

    ioerr +=(READ_OP_BUFFER_SHARED_LIMIT_RESUME_CELLEr(unit, &op_buf_sh_res_celle));
    OP_BUFFER_SHARED_LIMIT_RESUME_CELLEr_OP_BUFFER_SHARED_LIMIT_RESUME_CELLEf_SET(op_buf_sh_res_celle, 0);
    ioerr +=(WRITE_OP_BUFFER_SHARED_LIMIT_RESUME_CELLEr(unit, op_buf_sh_res_celle));

    ioerr +=(READ_OP_BUFFER_SHARED_LIMIT_RESUME_QENTRYr(unit, &op_sh_res_q));
    OP_BUFFER_SHARED_LIMIT_RESUME_QENTRYr_OP_BUFFER_SHARED_LIMIT_RESUME_QENTRYf_SET(op_sh_res_q, 261523);
    ioerr +=(WRITE_OP_BUFFER_SHARED_LIMIT_RESUME_QENTRYr(unit, op_sh_res_q));

    ioerr +=(READ_OP_BUFFER_SHARED_LIMIT_RESUME_THDORQEQr(unit, &op_sh_res_thd));
    OP_BUFFER_SHARED_LIMIT_RESUME_THDORQEQr_OP_BUFFER_SHARED_LIMIT_RESUMEf_SET(op_sh_res_thd, 8185);
    ioerr +=(WRITE_OP_BUFFER_SHARED_LIMIT_RESUME_THDORQEQr(unit, op_sh_res_thd));

    ioerr +=(READ_OP_BUFFER_SHARED_LIMIT_RESUME_THDOEMAr(unit, &op_sh_res_ema));
    OP_BUFFER_SHARED_LIMIT_RESUME_THDOEMAr_OP_BUFFER_SHARED_LIMIT_RESUMEf_SET(op_sh_res_ema, 0);
    ioerr +=(WRITE_OP_BUFFER_SHARED_LIMIT_RESUME_THDOEMAr(unit, op_sh_res_ema));


    for(i=0; i< 12; i++) {
        ioerr +=(READ_OP_QUEUE_CONFIG_THDORQEIr(unit, i, &op_q_thd_rqei));
        OP_QUEUE_CONFIG_THDORQEIr_Q_LIMIT_ENABLEf_SET(op_q_thd_rqei, 0);
        OP_QUEUE_CONFIG_THDORQEIr_Q_LIMIT_DYNAMICf_SET(op_q_thd_rqei, 0);
        OP_QUEUE_CONFIG_THDORQEIr_Q_SHARED_LIMITf_SET(op_q_thd_rqei, 7079);
        ioerr +=(WRITE_OP_QUEUE_CONFIG_THDORQEIr(unit, i, op_q_thd_rqei));
    }
    for(i=0; i< 12; i++) {
        ioerr +=(READ_OP_QUEUE_CONFIG_THDORQEEr(unit, i, &op_q_thd_rqee));
        OP_QUEUE_CONFIG_THDORQEEr_Q_LIMIT_ENABLEf_SET(op_q_thd_rqee, 0);
        OP_QUEUE_CONFIG_THDORQEEr_Q_LIMIT_DYNAMICf_SET(op_q_thd_rqee, 0);
        OP_QUEUE_CONFIG_THDORQEEr_Q_SHARED_LIMITf_SET(op_q_thd_rqee, 0);
        ioerr +=(WRITE_OP_QUEUE_CONFIG_THDORQEEr(unit, i, op_q_thd_rqee));
    }
    for(i=0; i< 12; i++) {
        ioerr +=(READ_OP_QUEUE_CONFIG_THDORQEQr(unit, i, &op_q_thd_rqeq));
        OP_QUEUE_CONFIG_THDORQEQr_Q_LIMIT_ENABLEf_SET(op_q_thd_rqeq, 0);
        OP_QUEUE_CONFIG_THDORQEQr_Q_LIMIT_DYNAMICf_SET(op_q_thd_rqeq, 0);
        OP_QUEUE_CONFIG_THDORQEQr_Q_SHARED_LIMITf_SET(op_q_thd_rqeq, 8191);
        ioerr +=(WRITE_OP_QUEUE_CONFIG_THDORQEQr(unit, i, op_q_thd_rqeq));
    }
    for(i=0; i< 8; i++) {
        ioerr +=(READ_OP_QUEUE_CONFIG_THDOEMAr(unit, i, &op_q_thd_ema));
        OP_QUEUE_CONFIG_THDOEMAr_Q_LIMIT_ENABLEf_SET(op_q_thd_ema, 0);
        OP_QUEUE_CONFIG_THDOEMAr_Q_LIMIT_DYNAMICf_SET(op_q_thd_ema, 0);
        OP_QUEUE_CONFIG_THDOEMAr_Q_SHARED_LIMITf_SET(op_q_thd_ema, 0);
        ioerr +=(WRITE_OP_QUEUE_CONFIG_THDOEMAr(unit, i, op_q_thd_ema));
    }

    for(i=0; i< 12; i++) {
        ioerr +=(READ_OP_QUEUE_CONFIG1_THDORQEIr(unit, i, &op_q_thd_rqei1));
        OP_QUEUE_CONFIG1_THDORQEIr_Q_COLOR_ENABLEf_SET(op_q_thd_rqei1, 0);
        OP_QUEUE_CONFIG1_THDORQEIr_Q_COLOR_DYNAMICf_SET(op_q_thd_rqei1, 0);
        OP_QUEUE_CONFIG1_THDORQEIr_Q_MINf_SET(op_q_thd_rqei1, 0);
        ioerr +=(WRITE_OP_QUEUE_CONFIG1_THDORQEIr(unit, i, op_q_thd_rqei1));
    }
    for(i=0; i< 12; i++) {
        ioerr +=(READ_OP_QUEUE_CONFIG1_THDORQEEr(unit, i, &op_q_thd_rqee1));
        OP_QUEUE_CONFIG1_THDORQEEr_Q_COLOR_ENABLEf_SET(op_q_thd_rqee1, 0);
        OP_QUEUE_CONFIG1_THDORQEEr_Q_COLOR_DYNAMICf_SET(op_q_thd_rqee1, 0);
        OP_QUEUE_CONFIG1_THDORQEEr_Q_MINf_SET(op_q_thd_rqee1, 0);
        ioerr +=(WRITE_OP_QUEUE_CONFIG1_THDORQEEr(unit, i, op_q_thd_rqee1));
    }
    for(i=0; i< 12; i++) {
        ioerr +=(READ_OP_QUEUE_CONFIG1_THDORQEQr(unit, i, &op_q_thd_rqeq1));
        OP_QUEUE_CONFIG1_THDORQEQr_Q_COLOR_ENABLEf_SET(op_q_thd_rqeq1, 0);
        OP_QUEUE_CONFIG1_THDORQEQr_Q_COLOR_DYNAMICf_SET(op_q_thd_rqeq1, 0);
        OP_QUEUE_CONFIG1_THDORQEQr_Q_MINf_SET(op_q_thd_rqeq1, 0);
        ioerr +=(WRITE_OP_QUEUE_CONFIG1_THDORQEQr(unit, i, op_q_thd_rqeq1));
    }
    for(i=0; i< 8; i++) {
        ioerr +=(READ_OP_QUEUE_CONFIG1_THDOEMAr(unit, i, &op_q_thd_ema1));
        OP_QUEUE_CONFIG1_THDOEMAr_Q_COLOR_ENABLEf_SET(op_q_thd_ema1, 0);
        OP_QUEUE_CONFIG1_THDOEMAr_Q_COLOR_DYNAMICf_SET(op_q_thd_ema1, 0);
        OP_QUEUE_CONFIG1_THDOEMAr_Q_MINf_SET(op_q_thd_ema1, 0);
        ioerr +=(WRITE_OP_QUEUE_CONFIG1_THDOEMAr(unit, i, op_q_thd_ema1));
    }

    for(i=0; i< 12; i++) {
        ioerr +=(READ_OP_QUEUE_RESET_OFFSET_THDORQEIr(unit, i, &op_q_rthd_rqei));
        OP_QUEUE_RESET_OFFSET_THDORQEIr_Q_RESET_OFFSETf_SET(op_q_rthd_rqei, 2);
        ioerr +=(WRITE_OP_QUEUE_RESET_OFFSET_THDORQEIr(unit, i, op_q_rthd_rqei));
    }
    for(i=0; i< 12; i++) {
        ioerr +=(READ_OP_QUEUE_RESET_OFFSET_THDORQEEr(unit, i, &op_q_rthd_rqee));
        OP_QUEUE_RESET_OFFSET_THDORQEEr_Q_RESET_OFFSETf_SET(op_q_rthd_rqee, 0);
        ioerr +=(WRITE_OP_QUEUE_RESET_OFFSET_THDORQEEr(unit, i, op_q_rthd_rqee));
    }
    for(i=0; i< 12; i++) {
        ioerr +=(READ_OP_QUEUE_RESET_OFFSET_THDORQEQr(unit, i, &op_q_rthd_rqeq));
        OP_QUEUE_RESET_OFFSET_THDORQEQr_Q_RESET_OFFSETf_SET(op_q_rthd_rqeq, 1);
        ioerr +=(WRITE_OP_QUEUE_RESET_OFFSET_THDORQEQr(unit, i, op_q_rthd_rqeq));
    }
    for(i=0; i< 8; i++) {
        ioerr +=(READ_OP_QUEUE_RESET_OFFSET_THDOEMAr(unit, i, &op_q_rthd_ema));
        OP_QUEUE_RESET_OFFSET_THDOEMAr_Q_RESET_OFFSETf_SET(op_q_rthd_ema, 0);
        ioerr +=(WRITE_OP_QUEUE_RESET_OFFSET_THDOEMAr(unit, i, op_q_rthd_ema));
    }
    for(i=0; i < 272; i++) { /* 8 x 28 ports  + 48 CPU */

        ioerr +=(READ_MMU_THDO_QCONFIG_CELLm(unit,i,&qcfg_cell));
        MMU_THDO_QCONFIG_CELLm_Q_SHARED_LIMIT_CELLf_SET(qcfg_cell, 10490);
        MMU_THDO_QCONFIG_CELLm_Q_MIN_CELLf_SET(qcfg_cell, 0);
        MMU_THDO_QCONFIG_CELLm_Q_LIMIT_ENABLE_CELLf_SET(qcfg_cell, 0);
        MMU_THDO_QCONFIG_CELLm_Q_LIMIT_DYNAMIC_CELLf_SET(qcfg_cell, 0);
        MMU_THDO_QCONFIG_CELLm_Q_COLOR_ENABLE_CELLf_SET(qcfg_cell, 0);
        ioerr +=(WRITE_MMU_THDO_QCONFIG_CELLm(unit,i,qcfg_cell));

        ioerr +=(READ_MMU_THDO_QOFFSET_CELLm(unit,i,&qoff_cell));
        MMU_THDO_QOFFSET_CELLm_RESET_OFFSET_CELLf_SET(qoff_cell, 2);
        ioerr +=(WRITE_MMU_THDO_QOFFSET_CELLm(unit,i,qoff_cell));

        ioerr +=(READ_MMU_THDO_QCONFIG_QENTRYm(unit,i,&qcfg_qentry));
        MMU_THDO_QCONFIG_QENTRYm_Q_SHARED_LIMIT_QENTRYf_SET(qcfg_qentry, 261712);
        MMU_THDO_QCONFIG_QENTRYm_Q_MIN_QENTRYf_SET(qcfg_qentry, 0);
        MMU_THDO_QCONFIG_QENTRYm_Q_LIMIT_ENABLE_QENTRYf_SET(qcfg_qentry, 0);
        MMU_THDO_QCONFIG_QENTRYm_Q_LIMIT_DYNAMIC_QENTRYf_SET(qcfg_qentry, 0);
        MMU_THDO_QCONFIG_QENTRYm_Q_COLOR_ENABLE_QENTRYf_SET(qcfg_qentry, 0);
        ioerr +=(WRITE_MMU_THDO_QCONFIG_QENTRYm(unit,i,qcfg_qentry));

        ioerr +=(READ_MMU_THDO_QOFFSET_QENTRYm(unit,i,&qoff_qentry));
        MMU_THDO_QOFFSET_QENTRYm_RESET_OFFSET_QENTRYf_SET(qoff_qentry, 1);
        ioerr +=(WRITE_MMU_THDO_QOFFSET_QENTRYm(unit,i, qoff_qentry));

        ioerr +=(READ_MMU_THDO_OPNCONFIG_CELLm(unit,i,&opncfg_cell));
        MMU_THDO_OPNCONFIG_CELLm_OPN_SHARED_LIMIT_CELLf_SET(opncfg_cell, 10490);
        MMU_THDO_OPNCONFIG_CELLm_OPN_SHARED_RESET_VALUE_CELLf_SET(opncfg_cell, 10472);
        ioerr +=(WRITE_MMU_THDO_OPNCONFIG_CELLm(unit,i,opncfg_cell));

        ioerr +=(READ_MMU_THDO_OPNCONFIG_QENTRYm(unit,i,&opncfg_qentry));
        MMU_THDO_OPNCONFIG_QENTRYm_OPN_SHARED_LIMIT_QENTRYf_SET(opncfg_qentry, 261712);
        MMU_THDO_OPNCONFIG_QENTRYm_OPN_SHARED_RESET_VALUE_QENTRYf_SET(opncfg_qentry, 261710);
        MMU_THDO_OPNCONFIG_QENTRYm_PORT_LIMIT_ENABLE_QENTRYf_SET(opncfg_qentry, 0);
        ioerr +=(WRITE_MMU_THDO_OPNCONFIG_QENTRYm(unit,i, opncfg_qentry));
    }
 
    /* Initialize MMU internal/external aging limit memory */
    MMU_AGING_LMT_INTm_CLR(age_int);
    MMU_AGING_LMT_EXTm_CLR(age_ext);
    for (i=0; i < MMU_AGING_LMT_INTm_MAX; i++) {
        ioerr += (WRITE_MMU_AGING_LMT_INTm(unit, i, age_int));
    }

    for (i=0; i < MMU_AGING_LMT_EXTm_MAX; i++) {
        ioerr += (WRITE_MMU_AGING_LMT_EXTm(unit, i, age_ext));
    }
    return ioerr;
}



static int
_port_init(int unit, int port)
{
    int ioerr = 0;
    EGR_ENABLEm_t egr_enable;
    EGR_PORTm_t egr_port;
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
    ioerr += READ_EGR_PORTm(unit, port, &egr_port);
    EGR_PORTm_EN_EFILTERf_SET(egr_port, 1);
    ioerr += WRITE_EGR_PORTm(unit, port, egr_port);

    /* Configure egress VLAN for backward compatibility */
    ioerr += READ_EGR_VLAN_CONTROL_1r(unit, port, &egr_vlan_ctrl1);
    EGR_VLAN_CONTROL_1r_VT_MISS_UNTAGf_SET(egr_vlan_ctrl1, 0);
    EGR_VLAN_CONTROL_1r_REMARK_OUTER_DOT1Pf_SET(egr_vlan_ctrl1, 1);
    ioerr += WRITE_EGR_VLAN_CONTROL_1r(unit, port, egr_vlan_ctrl1);

    /* Egress enable */
    ioerr += READ_EGR_ENABLEm(unit, port, &egr_enable);
    EGR_ENABLEm_PRT_ENABLEf_SET(egr_enable, 1);
    ioerr += WRITE_EGR_ENABLEm(unit, port, egr_enable);

    return ioerr;
}

static int
_gport_init(int unit, int port)
{
    int ioerr = 0;
    TX_IPG_LENGTHr_t tx_ipg;
    COMMAND_CONFIGr_t command_cfg;
    GPORT_UMAC_CONTROLr_t umac_control;
    int wait_usec = 10000;

    ioerr += _port_init(unit, port);  
    if (port < 25) {
        /* Get UMAC0_RESETf..UMAC7_RESETf */
        READ_GPORT_UMAC_CONTROLr(unit, &umac_control, port);
        GPORT_UMAC_CONTROLr_SET(umac_control, 0xff);
        ioerr += WRITE_GPORT_UMAC_CONTROLr(unit, umac_control, port);
        BMD_SYS_USLEEP(wait_usec); 

        /* Take UMAC0_RESETf..UMAC7_RESETf out of reset */
        GPORT_UMAC_CONTROLr_SET(umac_control, 0x00);
        ioerr += WRITE_GPORT_UMAC_CONTROLr(unit, umac_control, port);
        BMD_SYS_USLEEP(wait_usec); 
        ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
        COMMAND_CONFIGr_SW_RESETf_SET(command_cfg, 1);
        ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);

        /* Ensure that MAC (Rx) and loopback mode is disabled */
        ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
        COMMAND_CONFIGr_LOOP_ENAf_SET(command_cfg, 0);
        COMMAND_CONFIGr_RX_ENAf_SET(command_cfg, 0);
        COMMAND_CONFIGr_TX_ENAf_SET(command_cfg, 0);
        ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);

        ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
        COMMAND_CONFIGr_SW_RESETf_SET(command_cfg, 0);
        ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);

        TX_IPG_LENGTHr_SET(tx_ipg, 12);
        WRITE_TX_IPG_LENGTHr(unit, port, tx_ipg);
    }
    return ioerr;
}

int
bcm56440_b0_xport_init(int unit, int port)
{
    int ioerr = 0;
    int rv;
    XPORT_PORT_ENABLEr_t   xport_enable;
    XPORT_MODE_REGr_t   xport_mode;
    MISCCONFIGr_t misc_config;
    
    /* Common GPORT initialization */
    ioerr += _port_init(unit, port);  

    READ_XPORT_PORT_ENABLEr(unit, &xport_enable, port);
    READ_XPORT_MODE_REGr(unit, &xport_mode, port);
    XPORT_PORT_ENABLEr_PORT0f_SET(xport_enable, 1);
#if 0
    for speeds < 10000
    XPORT_MODE_REGr_PHY_PORT_MODEf_SET(xport_mode, 2);
    XPORT_MODE_REGr_PORT_GMII_MII_ENABLEf_SET(xport_mode, 1); 
#endif
    /* for quad port mode */
    if ((CDK_XGSM_FLAGS(unit) & CHIP_FLAG_EIGHTX25G_MODE) || 
        (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX6_MODE))  {
        if ((port == 27) || (port == 28)) {
            XPORT_MODE_REGr_CORE_PORT_MODEf_SET(xport_mode, 2);
            XPORT_PORT_ENABLEr_PORT1f_SET(xport_enable, 1);
            XPORT_PORT_ENABLEr_PORT2f_SET(xport_enable, 1);
            XPORT_PORT_ENABLEr_PORT3f_SET(xport_enable, 1);
            READ_MISCCONFIGr(unit, &misc_config);
            /* 27, 32 33, 34 */
            if (port == 27) {
                MISCCONFIGr_XPORT2_MULTI_PORTf_SET(misc_config, 1);
            }   
            /*  28, 29,30 and 31 */
            if (port == 28) {
                MISCCONFIGr_XPORT3_MULTI_PORTf_SET(misc_config, 1);
            }
            WRITE_MISCCONFIGr(unit, misc_config);
        }
    }
    ioerr += WRITE_XPORT_MODE_REGr(unit, xport_mode, port);
    ioerr += WRITE_XPORT_PORT_ENABLEr(unit, xport_enable, port);
    rv = bmd_phy_init(unit, port);

    return ioerr ? CDK_E_IO : rv;
}

int
bcm56440_b0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int port;
    cdk_pbmp_t pbmp;
    ING_HW_RESET_CONTROL_1r_t ing_rst_ctl_1;
    ING_HW_RESET_CONTROL_2r_t ing_rst_ctl_2;
    EGR_HW_RESET_CONTROL_0r_t egr_rst_ctl_0;
    EGR_HW_RESET_CONTROL_1r_t egr_rst_ctl_1;
    RDBGC0_SELECTr_t rdbgc0_select;
    TDBGC0_SELECTr_t tdbgc0_select;
    VLAN_PROFILE_TABm_t vlan_profile;
    ING_VLAN_TAG_ACTION_PROFILEm_t vlan_action;
    EGR_VLAN_TAG_ACTION_PROFILEm_t egr_action;
    int idx;
    EGR_VLAN_CONTROL_1r_t  vlan_control;
    EGR_IPMC_CFG2r_t       ipmc_cfg;
    ING_EN_EFILTER_BITMAPm_t efilter_bmap;
    IARB_TDM_CONTROLr_t iarb_tdm_ctrl;
    MISCCONFIGr_t misc;
    GPORT_RSV_MASKr_t gport_rsv_mask;
    GPORT_CONFIGr_t gport_cfg;
    CMIC_TXBUF_CONFIGr_t txbuf_config;
    XPORT_MIB_RESETr_t xport_mib;
    EGR_VLAN_LOGIC_TO_PHYS_MAPr_t logical_to_phy;
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
        CDK_WARN(("bcm56440_b0_bmd_init[%d]: IPIPE reset timeout\n", unit));
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
        CDK_WARN(("bcm56440_b0_bmd_init[%d]: EPIPE reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }

    /* Clear pipe reset registers */
    ioerr += READ_ING_HW_RESET_CONTROL_2r(unit, &ing_rst_ctl_2);
    ING_HW_RESET_CONTROL_2r_RESET_ALLf_SET(ing_rst_ctl_2, 0);
    ING_HW_RESET_CONTROL_2r_CMIC_REQ_ENABLEf_SET(ing_rst_ctl_2, 1);
    ioerr += WRITE_ING_HW_RESET_CONTROL_2r(unit, ing_rst_ctl_2);
    ioerr += READ_EGR_HW_RESET_CONTROL_1r(unit, &egr_rst_ctl_1);
    EGR_HW_RESET_CONTROL_1r_RESET_ALLf_SET(egr_rst_ctl_1, 0);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_1r(unit, egr_rst_ctl_1);

    /* Some registers are implemented in memory, need to clear them in order
     * to have correct parity value */
    EGR_IPMC_CFG2r_CLR(ipmc_cfg);
    EGR_VLAN_CONTROL_1r_CLR(vlan_control);
    CDK_XGSM_BLKTYPE_PBMP_GET(unit, BLKTYPE_MXQPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += WRITE_EGR_VLAN_CONTROL_1r(unit, port, vlan_control);
        ioerr += WRITE_EGR_IPMC_CFG2r(unit, port, ipmc_cfg);
        EGR_VLAN_LOGIC_TO_PHYS_MAPr_PHYSICAL_PORT_NUMf_SET(logical_to_phy, port);
        ioerr += WRITE_EGR_VLAN_LOGIC_TO_PHYS_MAPr(unit, port, logical_to_phy);
    }
    CDK_XGSM_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += WRITE_EGR_VLAN_CONTROL_1r(unit, port, vlan_control);
        ioerr += WRITE_EGR_IPMC_CFG2r(unit, port, ipmc_cfg);
        EGR_VLAN_LOGIC_TO_PHYS_MAPr_PHYSICAL_PORT_NUMf_SET(logical_to_phy, port);
        ioerr += WRITE_EGR_VLAN_LOGIC_TO_PHYS_MAPr(unit, port, logical_to_phy);
    }
    ioerr += WRITE_EGR_VLAN_CONTROL_1r(unit, CMIC_PORT, vlan_control);
    ioerr += WRITE_EGR_IPMC_CFG2r(unit, CMIC_PORT, ipmc_cfg);

    /* Enable arbiter */
    ioerr += READ_IARB_TDM_CONTROLr(unit, &iarb_tdm_ctrl);
    IARB_TDM_CONTROLr_DISABLEf_SET(iarb_tdm_ctrl, 0);
    IARB_TDM_CONTROLr_TDM_WRAP_PTRf_SET(iarb_tdm_ctrl, 32);
    ioerr += WRITE_IARB_TDM_CONTROLr(unit, iarb_tdm_ctrl);

    /* Enable Field Processor metering clock */
    ioerr += READ_MISCCONFIGr(unit, &misc);
    MISCCONFIGr_METERING_CLK_ENf_SET(misc, 1);

    ioerr += WRITE_MISCCONFIGr(unit, misc);

    /* Configure discard counter */
    RDBGC0_SELECTr_CLR(rdbgc0_select);
    RDBGC0_SELECTr_BITMAPf_SET(rdbgc0_select, 0x0400ad11);
    TDBGC0_SELECTr_BITMAPf_SET(tdbgc0_select, 0xffffffff);

    ioerr += WRITE_RDBGC0_SELECTr(unit, rdbgc0_select);
    ioerr += WRITE_TDBGC0_SELECTr(unit, tdbgc0_select);

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
    GPORT_RSV_MASKr_SET(gport_rsv_mask, 0x78);
    WRITE_GPORT_RSV_MASKr(unit, gport_rsv_mask, -1);

    /* Enable GPORTs and clear counters */
    READ_GPORT_CONFIGr(unit, &gport_cfg, -1);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 1);
    WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);
    GPORT_CONFIGr_GPORT_ENf_SET(gport_cfg, 1);
    WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 0);
    WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);

    /* CLEAR XPORT counters */ 
    XPORT_MIB_RESETr_SET(xport_mib, 0xf);
    ioerr += WRITE_XPORT_MIB_RESETr(unit, xport_mib, 25);
    ioerr += WRITE_XPORT_MIB_RESETr(unit, xport_mib, 26);
    ioerr += WRITE_XPORT_MIB_RESETr(unit, xport_mib, 27);
    ioerr += WRITE_XPORT_MIB_RESETr(unit, xport_mib, 28);
    XPORT_MIB_RESETr_SET(xport_mib, 0x0);
    ioerr += WRITE_XPORT_MIB_RESETr(unit, xport_mib, 25);
    ioerr += WRITE_XPORT_MIB_RESETr(unit, xport_mib, 26);
    ioerr += WRITE_XPORT_MIB_RESETr(unit, xport_mib, 27);
    ioerr += WRITE_XPORT_MIB_RESETr(unit, xport_mib, 28);

    READ_ING_EN_EFILTER_BITMAPm(unit, 0, &efilter_bmap);
    ING_EN_EFILTER_BITMAPm_BITMAP_W0f_SET(efilter_bmap, 0); 
    ING_EN_EFILTER_BITMAPm_BITMAP_W1f_SET(efilter_bmap, 0); 
    ioerr += WRITE_ING_EN_EFILTER_BITMAPm(unit, 0, efilter_bmap);

    READ_CMIC_TXBUF_CONFIGr(unit, &txbuf_config);
    CMIC_TXBUF_CONFIGr_FIRST_SERVE_BUFFERS_WITH_EOP_CELLSf_SET(txbuf_config, 0);
    ioerr += WRITE_CMIC_TXBUF_CONFIGr(unit, txbuf_config);

    /* Configure GPORTs */
    CDK_XGSM_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _gport_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }

    /* Configure XQPORTs */
    CDK_XGSM_BLKTYPE_PBMP_GET(unit, BLKTYPE_MXQPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
            ioerr += bcm56440_b0_xport_init(unit, port);
        } else {
            ioerr += _gport_init(unit, port);
        }
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_probe(unit, port);
        }
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_init(unit, port);
        }
    }
#if BMD_CONFIG_INCLUDE_DMA
    /* Common port initialization for CPU port */
    ioerr += _port_init(unit, CMIC_PORT);
    if (CDK_SUCCESS(rv)) {
        rv = bmd_xgsm_dma_init(unit);
    }
#endif
    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56440_B0 */
