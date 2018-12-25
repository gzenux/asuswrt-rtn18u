/*
 * $Id: xgs_miim.c,v 1.4 Broadcom SDK $
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
 * XGS memory access functions.
 */

#include <cdk/cdk_device.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>

#include <cdk/arch/xgs_chip.h>
#include <cdk/arch/xgs_mem.h>
#include <cdk/arch/xgs_schan.h>
#include <cdk/arch/xgs_cmic.h>
#include <cdk/arch/xgs_miim.h>

#define MIIM_PARAM_ID_OFFSET 		16
#define MIIM_PARAM_REG_ADDR_OFFSET	24
#define CMIC_MIIM_ADDRESS_5673r		0x1a4
#define CMIC_MIIM_ADDRESSr		0x4a0

int 
cdk_xgs_miim_write(int unit, uint32_t phy_addr, uint32_t reg, uint32_t val)
{
    int rv = CDK_E_NONE; 
    uint32_t polls;
    uint32_t phy_param, schan_ctrl;

    CDK_ASSERT(CDK_DEV_EXISTS(unit)); 
    
    /* Use clause 45 access if DEVAD specified */
    if (reg & 0x001f0000) {
        phy_addr |= CDK_XGS_MIIM_CLAUSE45;
        reg &= 0x001fffff;
    }

    phy_param = (phy_addr << MIIM_PARAM_ID_OFFSET) | val;

    CDK_DEBUG_MIIM
        (("cdk_xgs_miim_write[%d]: phy_addr=0x%08"PRIx32" reg_addr=%08"PRIx32" data: 0x%08"PRIx32"\n",
          unit, phy_addr, reg, val));

    /* Write parameter register and tell CMIC to start */

    /* Clause 45 support changes Clause 22 access method */
    if (CDK_XGS_FLAGS(unit) & CDK_XGS_CHIP_FLAG_CLAUSE45) {
        if (CDK_XGS_FLAGS(unit) & CDK_XGS_CHIP_FLAG_C45_5673) {
            /* Use non-standard register address */
            CDK_DEV_WRITE32(unit, CMIC_MIIM_ADDRESS_5673r, reg); 
        } else {
            CDK_DEV_WRITE32(unit, CMIC_MIIM_ADDRESSr, reg); 
        }
    } else {
        phy_param |= (reg << MIIM_PARAM_REG_ADDR_OFFSET);
    }

    CDK_DEV_WRITE32(unit, CMIC_MIIM_PARAMr, phy_param); 
    CDK_DEV_WRITE32(unit, CMIC_SCHAN_CTRLr, SC_MIIM_WR_START_SET);

    /* Poll for completion */
    for (polls = 0; polls < CDK_CONFIG_MIIM_MAX_POLLS; polls++) {
        CDK_DEV_READ32(unit, CMIC_SCHAN_CTRLr, &schan_ctrl); 
        if (schan_ctrl & SC_MIIM_OP_DONE_TST) {
            break; 
	}
    }
    
    /* Check for timeout and error conditions */
    if (polls == CDK_CONFIG_MIIM_MAX_POLLS) {
	rv = -1; 
        CDK_DEBUG_MIIM
            (("cdk_xgs_miim_write[%d]: Timeout at phy_addr=0x%08"PRIx32" reg_addr=%08"PRIx32"\n",
              unit, phy_addr, reg));
    }
    
    CDK_DEV_WRITE32(unit, CMIC_SCHAN_CTRLr, SC_MIIM_OP_DONE_CLR); 

    return rv;
}

int
cdk_xgs_miim_read(int unit, uint32_t phy_addr, uint32_t reg, uint32_t *val)
{
    int rv = CDK_E_NONE; 
    uint32_t polls; 
    uint32_t phy_param, schan_ctrl, miim_data;

    CDK_ASSERT(CDK_DEV_EXISTS(unit)); 
    
    /* Use clause 45 access if DEVAD specified */
    if (reg & 0x001f0000) {
        phy_addr |= CDK_XGS_MIIM_CLAUSE45;
        reg &= 0x001fffff;
    }

    phy_param = (phy_addr << MIIM_PARAM_ID_OFFSET);

    /* Write parameter register and tell CMIC to start */

    /* Clause 45 support changes Clause 22 access method */
    if (CDK_XGS_FLAGS(unit) & CDK_XGS_CHIP_FLAG_CLAUSE45) {
        if (CDK_XGS_FLAGS(unit) & CDK_XGS_CHIP_FLAG_C45_5673) {
            /* Use non-standard register address */
            CDK_DEV_WRITE32(unit, CMIC_MIIM_ADDRESS_5673r, reg); 
        } else {
            CDK_DEV_WRITE32(unit, CMIC_MIIM_ADDRESSr, reg); 
        }
    } else {
        phy_param |= (reg << MIIM_PARAM_REG_ADDR_OFFSET);
    }

    CDK_DEV_WRITE32(unit, CMIC_MIIM_PARAMr, phy_param);
    CDK_DEV_WRITE32(unit, CMIC_SCHAN_CTRLr, SC_MIIM_RD_START_SET);

    /* Wait for completion using either the interrupt or polling method */
    for (polls = 0; polls < CDK_CONFIG_MIIM_MAX_POLLS; polls++) {
        CDK_DEV_READ32(unit, CMIC_SCHAN_CTRLr, &schan_ctrl); 
        if (schan_ctrl & SC_MIIM_OP_DONE_TST) {
            break; 
	}
    }
    
    /* Check for timeout and error conditions */
    if (polls == CDK_CONFIG_MIIM_MAX_POLLS) {
	rv = -1; 
        CDK_DEBUG_MIIM
            (("cdk_xgs_miim_read[%d]: Timeout at phy_addr=0x%08"PRIx32" reg_addr=%08"PRIx32"\n",
              unit, phy_addr, reg));
    }

    CDK_DEV_WRITE32(unit, CMIC_SCHAN_CTRLr, SC_MIIM_OP_DONE_CLR); 
    
    if (rv >= 0) {
        CDK_DEV_READ32(unit, CMIC_MIIM_READ_DATAr, &miim_data);
        *val = miim_data;
        CDK_DEBUG_MIIM
            (("cdk_xgs_miim_read[%d]: phy_addr=0x%08"PRIx32" reg_addr=%08"PRIx32" data: 0x%08"PRIx32"\n",
              unit, phy_addr, reg, miim_data));
    }
    return rv;
}
