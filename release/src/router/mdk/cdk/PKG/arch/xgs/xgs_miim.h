/*
 * $Id: xgs_miim.h,v 1.5 Broadcom SDK $
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
 * MIIM access.
 */

#ifndef __XGS_MIIM_H__
#define __XGS_MIIM_H__

/* 
 * Definitions for 'phy_addr' parameter.
 *
 * Note 1:
 * CDK_XGS_MIIM_BUS_2 overrides CDK_XGS_MIIM_BUS_1.
 *
 * Note 2:
 * If neither CDK_XGS_MIIM_BUS_1 or CDK_XGS_MIIM_BUS_2 is set
 * then external MII bus #0 is used.
 *
 * Note 3:
 * External FE and Gigait PHYs usually reside on external bus #0
 * and use clause 22 access.
 *
 * Note 4:
 * External HiGig/XE PHYs usually reside on external bus #1 (or
 * #2 if supported) and use clause 45 access method.
 *
 * Note 5:
 * Second generation register layout replaces CDK_XGS_MIIM_BUS_1,
 * CDK_XGS_MIIM_BUS_2 and CDK_XGS_MIIM_INTERNAL with a 3-bit
 * bus ID and a new bit for selecting between internal and
 * external MII buses.
 */
#define CDK_XGS_MIIM_BUS_2      0x00000100 /* Select external MII bus #2 */
#define CDK_XGS_MIIM_INTERNAL   0x00000080 /* Select internal SerDes MII bus */
#define CDK_XGS_MIIM_BUS_1      0x00000040 /* Select external MII bus #1 */
#define CDK_XGS_MIIM_CLAUSE45   0x00000020 /* Select clause 45 access method */
#define CDK_XGS_MIIM_PHY_ID     0x0000001f /* PHY address in MII bus */
#define CDK_XGS_MIIM_IBUS(_b)   (((_b) << 6) | 0x200)
#define CDK_XGS_MIIM_EBUS(_b)   ((_b) << 6)

/*
 * Definitions for 'reg' parameter.
 *
 * Note 1:
 * For clause 22 access, the register address is 5 bits.
 *
 * Note 2:
 * For clause 45 access, the register address is 16 bits and
 * the device address is 5 bits.
 *
 * Note 3:
 * For internal SerDes registers, bits [23:8] are used for selecting
 * the block number for registers 0x10-0x1f. The block select value
 * will be written unmodified to register 0x1f.
 */
#define CDK_XGS_MIIM_REG_ADDR   0x0000001f /* Clause 22 register address */
#define CDK_XGS_MIIM_R45_ADDR   0x0000ffff /* Clause 45 register address */
#define CDK_XGS_MIIM_DEV_ADDR   0x001f0000 /* Clause 45 device address */
#define CDK_XGS_MIIM_BLK_ADDR   0x00ffff00 /* SerDes block mapping (reg 0x1f) */

/* Transform register address from software API to datasheet format */
#define CDK_XGS_IBLK_TO_C45(_a) \
    (((_a) & 0xf) | (((_a) >> 8) & 0x7ff0) | (((_a) << 11) & 0x8000));

/* Transform register address from datasheet to software API format */
#define CDK_XGS_C45_TO_IBLK(_a) \
    ((((_a) & 0x7ff0) << 8) | (((_a) & 0x8000) >> 11) | ((_a) & 0xf))

/* MII write access. */
extern int 
cdk_xgs_miim_write(int unit, uint32_t phy_addr, uint32_t reg, uint32_t val); 

/* MII read access. */
extern int
cdk_xgs_miim_read(int unit, uint32_t phy_addr, uint32_t reg, uint32_t *val); 

/* MII write access to internal SerDes PHY registers. */
extern int 
cdk_xgs_miim_iblk_write(int unit, uint32_t phy_addr, uint32_t reg, uint32_t val); 

/* MII read access to internal SerDes PHY registers. */
extern int
cdk_xgs_miim_iblk_read(int unit, uint32_t phy_addr, uint32_t reg, uint32_t *val); 

#endif /* __XGS_MIIM_H__ */
