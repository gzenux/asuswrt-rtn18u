/*
 * $Id: xgs_chip.c,v 1.5 Broadcom SDK $
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
 * Common XGS chip functions.
 *
 */

#include <cdk/cdk_assert.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_chip.h>

#include <cdk/arch/xgs_cmic.h>

/*
 * Global mode flags for XGS architecture
 */
uint32_t cdk_xgs_chip_flags[CDK_CONFIG_MAX_UNITS];

/*
 * Basic CMIC Initialization
 */
#define CMIC_BIG_ENDIAN_PIO               0x01000001
#define CMIC_BIG_ENDIAN_DMA_PACKET        0x02000002
#define CMIC_BIG_ENDIAN_DMA_OTHER         0x04000004

static int
_cmic_endian_config(int unit)
{
    CMIC_ENDIANESS_SELr_t ces; 
    uint32_t endian_sel = 0;
    int ioerr = 0;

    if (CDK_DEV_FLAGS(unit) & CDK_DEV_BE_PIO) {
        endian_sel |= CMIC_BIG_ENDIAN_PIO; 
    }
    if (CDK_DEV_FLAGS(unit) & CDK_DEV_BE_PACKET) {
        endian_sel |= CMIC_BIG_ENDIAN_DMA_PACKET; 
    }
    if (CDK_DEV_FLAGS(unit) & CDK_DEV_BE_OTHER) {
        endian_sel |= CMIC_BIG_ENDIAN_DMA_OTHER; 
    }

    CMIC_ENDIANESS_SELr_SET(ces, endian_sel);
    ioerr += WRITE_CMIC_ENDIANESS_SELr(unit, ces); 

    return ioerr; 
}

static int
_cmic_burst_config(int unit)
{
    CMIC_CONFIGr_t cc; 
    int ioerr = 0;
    
    /* Read the current CMIC_CONFIG register */
    ioerr += READ_CMIC_CONFIGr(unit, &cc); 

    /* Enable Read and Write Bursting */
    CMIC_CONFIGr_RD_BRST_ENf_SET(cc, 1);
    CMIC_CONFIGr_WR_BRST_ENf_SET(cc, 1);

    /* Write the config */
    ioerr += WRITE_CMIC_CONFIGr(unit, cc); 
    
    return ioerr; 
}

int 
cdk_xgs_cmic_init(int unit)
{
    CMIC_IRQ_MASKr_t irq_mask;
    int ioerr = 0;

    CDK_ASSERT(CDK_DEV_EXISTS(unit)); 

    /*
     * Certain PCIe cores may occasionally return invalid data in the
     * first PCI read following a soft-reset (CPS reset). The following
     * read operation is a dummy read to ensure that any invalid data
     * is flushed from the PCI read pipeline.
     */
    ioerr += READ_CMIC_IRQ_MASKr(unit, &irq_mask); 

    /* Configure endian */
    ioerr += _cmic_endian_config(unit); 
    
    /* Configure Bursting */
    ioerr += _cmic_burst_config(unit); 

    /* Disable Interrupts */
    CMIC_IRQ_MASKr_CLR(irq_mask);
    ioerr += WRITE_CMIC_IRQ_MASKr(unit, irq_mask); 
    
    return ioerr; 
}
