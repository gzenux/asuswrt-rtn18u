/*
 * $Id: xgs_schan.c,v 1.6 Broadcom SDK $
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
 * S-Channel (internal command bus) support
 */

#include <cdk/cdk_device.h>
#include <cdk/cdk_debug.h>

#include <cdk/arch/xgs_schan.h>
#include <cdk/arch/xgs_cmic.h>

/*
 * Resets the CMIC S-Channel interface. This is required when we sent
 * a message and did not receive a response after the poll count was
 * exceeded.
 */

static void
_schan_reset(int unit)
{
    CMIC_CONFIGr_t cmic_config; 
    
    CDK_DEBUG_SCHAN(("cdk_xgs_schan_op[%d]: S-channel reset\n", unit));

    READ_CMIC_CONFIGr(unit, &cmic_config); 
    
    /* Toggle S-Channel abort bit in CMIC_CONFIG register */
    CMIC_CONFIGr_SCHAN_ABORTf_SET(cmic_config, 1); 
    WRITE_CMIC_CONFIGr(unit, cmic_config); 

    CDK_CONFIG_MEMORY_BARRIER; 

    CMIC_CONFIGr_SCHAN_ABORTf_SET(cmic_config, 0); 
    WRITE_CMIC_CONFIGr(unit, cmic_config); 

    CDK_CONFIG_MEMORY_BARRIER; 
}

int
cdk_xgs_schan_op(int unit,
                 schan_msg_t *msg,
                 int dwc_write, int dwc_read)
{
    int i, rv = CDK_E_NONE; 
    uint32_t polls = 0; 
    uint32_t schan_ctrl; 
    uint32_t msg_addr;
    uint32_t schan_err;
    CMIC_IRQ_STATr_t irq_stat; 

    /* S-Channel message buffer address */
    msg_addr = (CDK_XGS_FLAGS(unit) & CDK_XGS_CHIP_FLAG_SCHAN_EXT) ? 0x800 : 0;

    /* Write raw S-Channel Data: dwc_write words */
    CDK_DEBUG_SCHAN(("cdk_xgs_schan_op[%d]: S-channel write:", unit));
    for (i = 0; i < dwc_write; i++) {
        CDK_DEV_WRITE32(unit, msg_addr + i*4, msg->dwords[i]);
        CDK_DEBUG_SCHAN((" 0x%08"PRIx32"", msg->dwords[i]));
    }
    CDK_DEBUG_SCHAN(("\n"));

    /* Tell CMIC to start */
    CDK_DEV_WRITE32(unit, CMIC_SCHAN_CTRLr, SC_MSG_START_SET); 

    CDK_CONFIG_MEMORY_BARRIER; 
    
    /* Poll for completion */
    for (polls = 0; polls < CDK_CONFIG_SCHAN_MAX_POLLS; polls++) {
        CDK_DEV_READ32(unit, CMIC_SCHAN_CTRLr, &schan_ctrl); 
        if (schan_ctrl & SC_MSG_DONE_TST) {
            break; 
        }
    }

    /* Check for timeout and error conditions */
    if (polls == CDK_CONFIG_SCHAN_MAX_POLLS) {
        CDK_DEBUG_SCHAN(("cdk_xgs_schan_op[%d]: S-channel timeout\n", unit));
        rv = CDK_E_TIMEOUT; 
    }

    if (schan_ctrl & SC_MSG_NAK_TST) {
        CDK_DEBUG_SCHAN(("cdk_xgs_schan_op[%d]: S-channel NAK\n", unit));
        rv = CDK_E_FAIL; 
    }
            
    READ_CMIC_IRQ_STATr(unit, &irq_stat);
    if (CMIC_IRQ_STATr_SCHAN_ERRf_GET(irq_stat)) {
        CDK_DEV_READ32(unit, CMIC_SCHAN_ERRr, &schan_err);
        CDK_DEBUG_SCHAN(("cdk_xgs_schan_op[%d]: S-channel error 0x%08"PRIx32"\n",
                         unit, schan_err));
        CDK_DEV_WRITE32(unit, CMIC_SCHAN_ERRr, 0);
        rv = CDK_E_FAIL; 
    }

    CDK_DEV_WRITE32(unit, CMIC_SCHAN_CTRLr, SC_MSG_DONE_CLR); 

    CDK_CONFIG_MEMORY_BARRIER; 

    if (CDK_FAILURE(rv)) {
        _schan_reset(unit);
        return rv; 
    }

    /* Read in data from S-Channel buffer space, if any */
    CDK_DEBUG_SCHAN(("cdk_xgs_schan_op[%d]: S-channel read:", unit));
    for (i = 0; i < dwc_read; i++) {
         CDK_DEV_READ32(unit, msg_addr + 4*i, &msg->dwords[i]); 
         CDK_DEBUG_SCHAN((" 0x%08"PRIx32"", msg->dwords[i]));
    }
    CDK_DEBUG_SCHAN(("\n"));

    return CDK_E_NONE; 
}


