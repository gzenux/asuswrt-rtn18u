/*
 * $Id: xgsm_chip.c,v 1.3 Broadcom SDK $
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

#include <cdk/arch/xgsm_cmic.h>

/*
 * Global mode flags for XGS architecture
 */
uint32_t cdk_xgsm_chip_flags[CDK_CONFIG_MAX_UNITS];

/*
 * Basic CMIC Initialization
 */
#define CMIC_BIG_ENDIAN_PIO             0x01000001

static int
_cmic_endian_config(int unit)
{
    int ioerr = 0;
    CMIC_COMMON_PCIE_PIO_ENDIANESSr_t pio_en; 

    /* Set PCI endian using endian-neutral register value */
    CMIC_COMMON_PCIE_PIO_ENDIANESSr_CLR(pio_en);
    if (CDK_DEV_FLAGS(unit) & CDK_DEV_BE_PIO) {
        CMIC_COMMON_PCIE_PIO_ENDIANESSr_SET(pio_en, CMIC_BIG_ENDIAN_PIO);
    }
    ioerr += WRITE_CMIC_COMMON_PCIE_PIO_ENDIANESSr(unit, pio_en); 

    return ioerr; 
}

int 
cdk_xgsm_cmic_init(int unit)
{
    CMIC_CMC_PCIE_IRQ_MASK0r_t irq_mask0;
    CMIC_CMC_PCIE_IRQ_MASK1r_t irq_mask1;
    int ioerr = 0;

    CDK_ASSERT(CDK_DEV_EXISTS(unit)); 

    /*
     * Certain PCIe cores may occasionally return invalid data in the
     * first PCI read following a soft-reset (CPS reset). The following
     * read operation is a dummy read to ensure that any invalid data
     * is flushed from the PCI read pipeline.
     */
    ioerr += READ_CMIC_CMC_PCIE_IRQ_MASK0r(unit, &irq_mask0); 
    ioerr += READ_CMIC_CMC_PCIE_IRQ_MASK1r(unit, &irq_mask1); 

    /* Configure endian */
    ioerr += _cmic_endian_config(unit); 
    
    /* Disable Interrupts */
    CMIC_CMC_PCIE_IRQ_MASK0r_CLR(irq_mask0);
    ioerr += WRITE_CMIC_CMC_PCIE_IRQ_MASK0r(unit, irq_mask0); 
    CMIC_CMC_PCIE_IRQ_MASK1r_CLR(irq_mask1);
    ioerr += WRITE_CMIC_CMC_PCIE_IRQ_MASK1r(unit, irq_mask1); 
    
    return ioerr; 
}
