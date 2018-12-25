/*
 * $Id: bcm56640_a0_internal.h,v 1.7 Broadcom SDK $
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

#ifndef __BCM56640_A0_INTERNAL_H__
#define __BCM56640_A0_INTERNAL_H__

#define XMAC_MODE_SPEED_10      0x0
#define XMAC_MODE_SPEED_100     0x1
#define XMAC_MODE_SPEED_1000    0x2
#define XMAC_MODE_SPEED_2500    0x3
#define XMAC_MODE_SPEED_10000   0x4

#define XMAC_MODE_HDR_IEEE      0x0
#define XMAC_MODE_HDR_HIGIG     0x1
#define XMAC_MODE_HDR_HIGIG2    0x2
#define XMAC_MODE_HDR_CLH       0x3
#define XMAC_MODE_HDR_CSH       0x4

#define CORE_MODE_SINGLE        0
#define CORE_MODE_DUAL          1
#define CORE_MODE_QUAD          2
#define CORE_MODE_NOTDM         3

#define PHY_MODE_SINGLE         0
#define PHY_MODE_DUAL           1
#define PHY_MODE_QUAD           2

#define MAC_MODE_INDEP          0
#define MAC_MODE_AGGR           1

#define NUM_PHYS_PORTS          86
#define NUM_LOGIC_PORTS         63
#define NUM_MMU_PORTS           63

#define CMIC_LPORT              0
#define CMIC_MPORT              59

#define MMU_QBASE_UC            0
#define MMU_QBASE_MC            1024
#define MMU_QBASE_MC_HG         1344
#define MMU_QBASE_MC_GE         1520
#define MMU_QBASE_CPU           1536

extern int
bcm56640_a0_tdm_default(int unit, const int **tdm_seq);

extern uint32_t
bcm56640_a0_port_speed_max(int unit, int port);

extern int
bcm56640_a0_mmu_port_mc_queues(int unit, int port);

extern int
bcm56640_a0_mmu_port_uc_queues(int unit, int port);

extern int
bcm56640_a0_mc_queue_num(int unit, int port, int cosq);

extern int
bcm56640_a0_uc_queue_num(int unit, int port, int cosq);

extern int
bcm56640_a0_unicore_phy_init(int unit, int port);

extern int
bcm56640_a0_warpcore_phy_init(int unit, int port);

extern int
bcm56640_a0_xport_inst(int unit, int port);

extern int
bcm56640_a0_xmac_reset_set(int unit, int port, int reset);

extern int
bcm56640_a0_xport_reset(int unit, int port);

extern int
bcm56640_a0_xport_init(int unit, int port);

extern int
bcm56640_a0_xport_pbmp_get(int unit, cdk_pbmp_t *pbmp);

extern int
bcm56640_a0_p2l(int unit, int port, int inverse);

extern int
bcm56640_a0_p2m(int unit, int port, int inverse);

#define P2L(_u,_p) bcm56640_a0_p2l(_u,_p,0)
#define L2P(_u,_p) bcm56640_a0_p2l(_u,_p,1)

#define P2M(_u,_p) bcm56640_a0_p2m(_u,_p,0)
#define M2P(_u,_p) bcm56640_a0_p2m(_u,_p,1)

#define XPORT_BLKIDX(_p) ((_p - 1) >> 2)
#define XPORT_SUBPORT(_p) ((_p - 1) & 0x3)

#endif /* __BCM56640_A0_INTERNAL_H__ */
