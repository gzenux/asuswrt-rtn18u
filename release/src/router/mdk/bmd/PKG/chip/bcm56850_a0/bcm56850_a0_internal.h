/*
 * $Id: bcm56850_a0_internal.h,v 1.3 Broadcom SDK $
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
 * 
 */

#ifndef __BCM56850_A0_INTERNAL_H__
#define __BCM56850_A0_INTERNAL_H__

#define NUM_PHYS_PORTS          130
#define NUM_LOGIC_PORTS         106
#define NUM_MMU_PORTS           108

#define CMIC_LPORT              0
#define CMIC_MPORT              52
#define CMIC_HG_LPORT           106

#define LB_LPORT                105
#define LB_MPORT                116

#define XPORT_MODE_QUAD         0
#define XPORT_MODE_TRI_012      1
#define XPORT_MODE_TRI_023      2
#define XPORT_MODE_DUAL         3
#define XPORT_MODE_SINGLE       4

#define XMAC_MODE_10M           0
#define XMAC_MODE_100M          1
#define XMAC_MODE_1G            2
#define XMAC_MODE_2G5           3
#define XMAC_MODE_10G_PLUS      4

#define PORT_IN_Y_PIPE(_p)      ((_p) >= (NUM_PHYS_PORTS/2))

/* For manipulating port bitmap memory fields */
#define PBM_PORT_WORDS          ((NUM_PHYS_PORTS / 32) + 1)
#define PBM_LPORT_WORDS         ((NUM_LOGIC_PORTS / 32) + 1)
#define PBM_MEMBER(_pbm, _port) \
     ((_pbm)[(_port) >> 5] & LSHIFT32(1, (_port) & 0x1f))
#define PBM_PORT_ADD(_pbm, _port) \
     ((_pbm)[(_port) >> 5] |= LSHIFT32(1, (_port) & 0x1f))
#define PBM_PORT_REMOVE(_pbm, _port) \
     ((_pbm)[(_port) >> 5] &= ~(LSHIFT32(1, (_port) & 0x1f)))

extern uint32_t
bcm56850_a0_port_speed_max(int unit, int port);

extern int
bcm56850_a0_mmu_port_mc_queues(int unit, int port);

extern int
bcm56850_a0_mmu_port_uc_queues(int unit, int port);

extern int
bcm56850_a0_mc_queue_num(int unit, int port, int cosq);

extern int
bcm56850_a0_uc_queue_num(int unit, int port, int cosq);

extern int
bcm56850_a0_warpcore_phy_init(int unit, int port);

extern int
bcm56850_a0_wait_for_tsc_lock(int unit, int port);

extern int
bcm56850_a0_xport_reset(int unit, int port);

extern int
bcm56850_a0_xport_init(int unit, int port);

extern int
bcm56850_a0_xlport_pbmp_get(int unit, cdk_pbmp_t *pbmp);

extern int
bcm56850_a0_p2l(int unit, int port, int inverse);

extern int
bcm56850_a0_p2m(int unit, int port, int inverse);

extern int
bcm56850_a0_port_enable_set(int unit, int port, int enable);

extern int
bcm56850_a0_set_tdm_tbl(
    int speed[130],
    int tdm_bw, 
    int pgw_tdm_tbl_x0[32],
    int ovs_tdm_tbl_x0[32],
    int ovs_spacing_x0[32],
    int pgw_tdm_tbl_x1[32],
    int ovs_tdm_tbl_x1[32],
    int ovs_spacing_x1[32],
    int pgw_tdm_tbl_y0[32],
    int ovs_tdm_tbl_y0[32],
    int ovs_spacing_y0[32],
    int pgw_tdm_tbl_y1[32],
    int ovs_tdm_tbl_y1[32],
    int ovs_spacing_y1[32],
    int mmu_tdm_tbl_x[256],
    int mmu_tdm_ovs_x_1[16],
    int mmu_tdm_ovs_x_2[16],
    int mmu_tdm_ovs_x_3[16],
    int mmu_tdm_ovs_x_4[16],
    int mmu_tdm_tbl_y[256],
    int mmu_tdm_ovs_y_1[16],
    int mmu_tdm_ovs_y_2[16],
    int mmu_tdm_ovs_y_3[16],
    int mmu_tdm_ovs_y_4[16],
    int port_state_map[128],
    int iarb_tdm_tbl_x[512],
    int iarb_tdm_tbl_y[512]);

extern void bcm56850_a0_chk_tdm_tbl(
    int speed[130],
    int core_bw,
    int pgw_tdm_tbl_x0[32],
    int ovs_tdm_tbl_x0[32],
    int ovs_spacing_x0[32],
    int pgw_tdm_tbl_x1[32],
    int ovs_tdm_tbl_x1[32],
    int ovs_spacing_x1[32],
    int pgw_tdm_tbl_y0[32],
    int ovs_tdm_tbl_y0[32],
    int ovs_spacing_y0[32],
    int pgw_tdm_tbl_y1[32],
    int ovs_tdm_tbl_y1[32],
    int ovs_spacing_y1[32],
    int mmu_tdm_tbl_x[256],
    int mmu_tdm_ovs_x_1[16],
    int mmu_tdm_ovs_x_2[16],
    int mmu_tdm_ovs_x_3[16],
    int mmu_tdm_ovs_x_4[16],
    int mmu_tdm_tbl_y[256],
    int mmu_tdm_ovs_y_1[16],
    int mmu_tdm_ovs_y_2[16],
    int mmu_tdm_ovs_y_3[16],
    int mmu_tdm_ovs_y_4[16],
    int port_state_map[128],
    int fail[8]);

extern int
bcm56850_a0_set_iarb_tdm_table(
    int core_bw,
    int is_x_ovs,
    int is_y_ovs,
    int mgm4x1,
    int mgm4x2p5,
    int mgm1x10,
    int *iarb_tdm_wrap_ptr_x,
    int *iarb_tdm_wrap_ptr_y,
    int iarb_tdm_tbl_x[512],
    int iarb_tdm_tbl_y[512]);

#define P2L(_u,_p) bcm56850_a0_p2l(_u,_p,0)
#define L2P(_u,_p) bcm56850_a0_p2l(_u,_p,1)

#define P2M(_u,_p) bcm56850_a0_p2m(_u,_p,0)
#define M2P(_u,_p) bcm56850_a0_p2m(_u,_p,1)

#define XLPORT_BLKIDX(_p) ((_p - 1) >> 2)
#define XLPORT_SUBPORT(_p) ((_p - 1) & 0x3)

#endif /* __BCM56850_A0_INTERNAL_H__ */
