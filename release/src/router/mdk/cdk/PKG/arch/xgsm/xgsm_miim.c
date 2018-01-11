/*
 * $Id: xgsm_miim.c,v 1.4 Broadcom SDK $
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

#include <cdk/arch/xgsm_chip.h>
#include <cdk/arch/xgsm_mem.h>
#include <cdk/arch/xgsm_schan.h>
#include <cdk/arch/xgsm_cmic.h>
#include <cdk/arch/xgsm_miim.h>

#define MIIM_PARAM_ID_OFFSET 		16
#define MIIM_PARAM_REG_ADDR_OFFSET	24

int 
cdk_xgsm_miim_write(int unit, uint32_t phy_addr, uint32_t reg, uint32_t val)
{
    int rv = CDK_E_NONE; 
    uint32_t polls;
    uint32_t phy_param;
    CMIC_CMC_MIIM_CTRLr_t miim_ctrl;
    CMIC_CMC_MIIM_STATr_t miim_stat;
    CMIC_CMC_MIIM_ADDRESSr_t miim_addr;
    CMIC_CMC_MIIM_PARAMr_t miim_param;

    CDK_ASSERT(CDK_DEV_EXISTS(unit)); 
    
    /*
     * Use clause 45 access if DEVAD specified.
     * Note that DEVAD 32 (0x20) can be used to access special DEVAD 0.
     */
    if (reg & 0x003f0000) {
        phy_addr |= CDK_XGSM_MIIM_CLAUSE45;
        reg &= 0x001fffff;
    }

    CDK_DEBUG_MIIM
        (("cdk_xgsm_miim_write[%d]: phy_addr=0x%08"PRIx32" "
          "reg_addr=%08"PRIx32" data: 0x%08"PRIx32"\n",
          unit, phy_addr, reg, val));

    /* Write address and parameter registers */
    phy_param = (phy_addr << MIIM_PARAM_ID_OFFSET) | val;
    CMIC_CMC_MIIM_PARAMr_SET(miim_param, phy_param);
    WRITE_CMIC_CMC_MIIM_PARAMr(unit, miim_param); 

    CMIC_CMC_MIIM_ADDRESSr_SET(miim_addr, reg);
    WRITE_CMIC_CMC_MIIM_ADDRESSr(unit, miim_addr); 

    /* Tell CMIC to start */
    READ_CMIC_CMC_MIIM_CTRLr(unit, &miim_ctrl);
    CMIC_CMC_MIIM_CTRLr_MIIM_WR_STARTf_SET(miim_ctrl, 1);
    WRITE_CMIC_CMC_MIIM_CTRLr(unit, miim_ctrl);

    /* Poll for completion */
    for (polls = 0; polls < CDK_CONFIG_MIIM_MAX_POLLS; polls++) {
        READ_CMIC_CMC_MIIM_STATr(unit, &miim_stat);
        if (CMIC_CMC_MIIM_STATr_MIIM_OPN_DONEf_GET(miim_stat)) {
            break; 
	}
    }
    
    /* Check for timeout and error conditions */
    if (polls == CDK_CONFIG_MIIM_MAX_POLLS) {
	rv = -1; 
        CDK_DEBUG_MIIM
            (("cdk_xgsm_miim_write[%d]: Timeout at phy_addr=0x%08"PRIx32" "
              "reg_addr=%08"PRIx32"\n",
              unit, phy_addr, reg));
    }
    
    CMIC_CMC_MIIM_CTRLr_MIIM_WR_STARTf_SET(miim_ctrl, 0);
    WRITE_CMIC_CMC_MIIM_CTRLr(unit, miim_ctrl);

    return rv;
}

int
cdk_xgsm_miim_read(int unit, uint32_t phy_addr, uint32_t reg, uint32_t *val)
{
    int rv = CDK_E_NONE; 
    uint32_t polls; 
    uint32_t phy_param;
    CMIC_CMC_MIIM_CTRLr_t miim_ctrl;
    CMIC_CMC_MIIM_STATr_t miim_stat;
    CMIC_CMC_MIIM_ADDRESSr_t miim_addr;
    CMIC_CMC_MIIM_PARAMr_t miim_param;
    CMIC_CMC_MIIM_READ_DATAr_t miim_read_data;

    CDK_ASSERT(CDK_DEV_EXISTS(unit)); 
    
    /*
     * Use clause 45 access if DEVAD specified.
     * Note that DEVAD 32 (0x20) can be used to access special DEVAD 0.
     */
    if (reg & 0x003f0000) {
        phy_addr |= CDK_XGSM_MIIM_CLAUSE45;
        reg &= 0x001fffff;
    }

    phy_param = (phy_addr << MIIM_PARAM_ID_OFFSET);
    CMIC_CMC_MIIM_PARAMr_SET(miim_param, phy_param);
    WRITE_CMIC_CMC_MIIM_PARAMr(unit, miim_param); 

    CMIC_CMC_MIIM_ADDRESSr_SET(miim_addr, reg);
    WRITE_CMIC_CMC_MIIM_ADDRESSr(unit, miim_addr); 

    /* Tell CMIC to start */
    READ_CMIC_CMC_MIIM_CTRLr(unit, &miim_ctrl);
    CMIC_CMC_MIIM_CTRLr_MIIM_RD_STARTf_SET(miim_ctrl, 1);
    WRITE_CMIC_CMC_MIIM_CTRLr(unit, miim_ctrl);

    /* Poll for completion */
    for (polls = 0; polls < CDK_CONFIG_MIIM_MAX_POLLS; polls++) {
        READ_CMIC_CMC_MIIM_STATr(unit, &miim_stat);
        if (CMIC_CMC_MIIM_STATr_MIIM_OPN_DONEf_GET(miim_stat)) {
            break; 
	}
    }
    
    /* Check for timeout and error conditions */
    if (polls == CDK_CONFIG_MIIM_MAX_POLLS) {
	rv = -1; 
        CDK_DEBUG_MIIM
            (("cdk_xgsm_miim_read[%d]: Timeout at phy_addr=0x%08"PRIx32" "
              "reg_addr=%08"PRIx32"\n",
              unit, phy_addr, reg));
    }

    CMIC_CMC_MIIM_CTRLr_MIIM_RD_STARTf_SET(miim_ctrl, 0);
    WRITE_CMIC_CMC_MIIM_CTRLr(unit, miim_ctrl);

    if (rv >= 0) {
        READ_CMIC_CMC_MIIM_READ_DATAr(unit, &miim_read_data);
        *val = CMIC_CMC_MIIM_READ_DATAr_GET(miim_read_data);
        CDK_DEBUG_MIIM
            (("cdk_xgsm_miim_read[%d]: phy_addr=0x%08"PRIx32" "
              "reg_addr=%08"PRIx32" data: 0x%08"PRIx32"\n",
              unit, phy_addr, reg, *val));
    }
    return rv;
}
