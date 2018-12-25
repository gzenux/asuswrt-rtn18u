/*
 * $Id: robo_miim.c,v 1.7 Broadcom SDK $
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
 * ROBO MIIM access functions for integrated PHYs.
 */

#include <cdk/cdk_device.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>

#include <cdk/arch/robo_chip.h>
#include <cdk/arch/robo_reg.h>
#include <cdk/arch/robo_miim.h>

/* Convert standard PHY address and register into a ROBO register address */
#define ROBO_REG_ADDR(_pa, _r)    (((_pa) << 8) + (2 * (_r)))
#define EXT_MDIO_REG_ADDR(_pa, _r)   (CDK_DEV_ADDR_EXT_PHY_BUS_MDIO | (((_pa) << 8) + (_r)))

int 
cdk_robo_miim_write(int unit, uint32_t phy_addr, uint32_t reg, uint32_t val)
{
    CDK_ASSERT(CDK_DEV_EXISTS(unit)); 
    
    CDK_DEBUG_MIIM
        (("cdk_robo_miim_write[%d]: phy_addr=0x%08"PRIx32" reg_addr=%08"PRIx32" data: 0x%08"PRIx32"\n",
          unit, phy_addr, reg, val));

    return cdk_robo_reg_write(unit, ROBO_REG_ADDR(phy_addr, reg), &val, 2);
}

int
cdk_robo_miim_read(int unit, uint32_t phy_addr, uint32_t reg, uint32_t *val)
{
    int rv;

    CDK_ASSERT(CDK_DEV_EXISTS(unit)); 
    
    rv = cdk_robo_reg_read(unit, ROBO_REG_ADDR(phy_addr, reg), val, 2);
    
    if (rv >= 0) {
        CDK_DEBUG_MIIM
            (("cdk_robo_miim_read[%d]: phy_addr=0x%08"PRIx32" reg_addr=%08"PRIx32" data: 0x%08"PRIx32"\n",
              unit, phy_addr, reg, *val));
    }
    return rv;
}

int 
cdk_robo_miim_ext_mdio_write(int unit, uint32_t phy_addr, uint32_t reg, uint32_t val)
{
    CDK_ASSERT(CDK_DEV_EXISTS(unit)); 
    
    CDK_DEBUG_MIIM
        (("cdk_robo_miim_write[%d]: phy_addr=0x%08"PRIx32" reg_addr=%08"PRIx32" data: 0x%08"PRIx32"\n",
          unit, phy_addr, reg, val));

    if (phy_addr == 0xffffffff) {
        /* skip attempting access of not supported port */
        return 0;
    } else {
        return cdk_robo_reg_write(unit, EXT_MDIO_REG_ADDR(phy_addr, reg), &val, 2);
    }
}

int
cdk_robo_miim_ext_mdio_read(int unit, uint32_t phy_addr, uint32_t reg, uint32_t *val)
{
    int rv;

    CDK_ASSERT(CDK_DEV_EXISTS(unit)); 

    if (phy_addr == 0xffffffff) {
        /* skip attempting access of not supported port */
        *val = 0xffff;
        rv = 0;
    } else {
        rv = cdk_robo_reg_read(unit, EXT_MDIO_REG_ADDR(phy_addr, reg), val, 2);
    }

    
    if (rv >= 0) {
        CDK_DEBUG_MIIM
            (("cdk_robo_miim_ext_mdio_read[%d]: phy_addr=0x%08"PRIx32" reg_addr=%08"PRIx32" data: 0x%08"PRIx32"\n",
              unit, phy_addr, reg, *val));
    }
    return rv;
}

