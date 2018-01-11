/*
 * $Id: xgsm_schan.c,v 1.3 Broadcom SDK $
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

#include <cdk/arch/xgsm_schan.h>
#include <cdk/arch/xgsm_cmic.h>

/*
 * Resets the CMIC S-Channel interface. This is required when we sent
 * a message and did not receive a response after the poll count was
 * exceeded.
 */

static void
_schan_reset(int unit)
{
    CMIC_CMC_SCHAN_CTRLr_t schan_ctrl;
    
    CDK_DEBUG_SCHAN(("cdk_xgsm_schan_op[%d]: S-channel reset\n", unit));

    READ_CMIC_CMC_SCHAN_CTRLr(unit, &schan_ctrl); 
    
    /* Toggle S-Channel abort bit in CMIC_CMC_SCHAN_CTRL register */
    CMIC_CMC_SCHAN_CTRLr_ABORTf_SET(schan_ctrl, 1); 
    WRITE_CMIC_CMC_SCHAN_CTRLr(unit, schan_ctrl); 

    CDK_CONFIG_MEMORY_BARRIER; 

    CMIC_CMC_SCHAN_CTRLr_ABORTf_SET(schan_ctrl, 0); 
    WRITE_CMIC_CMC_SCHAN_CTRLr(unit, schan_ctrl); 

    CDK_CONFIG_MEMORY_BARRIER; 
}

int
cdk_xgsm_schan_op(int unit,
                 schan_msg_t *msg,
                 int dwc_write, int dwc_read)
{
    int i, rv = CDK_E_NONE; 
    uint32_t polls = 0; 
    CMIC_CMC_SCHAN_CTRLr_t schan_ctrl; 
    uint32_t msg_addr;

    /* S-Channel message buffer address */
    msg_addr = CMIC_CMC_SCHAN_MESSAGEr;

    /* Write raw S-Channel Data: dwc_write words */
    CDK_DEBUG_SCHAN(("cdk_xgsm_schan_op[%d]: S-channel write:", unit));
    for (i = 0; i < dwc_write; i++) {
        CDK_XGSM_CMC_WRITE(unit, msg_addr + i*4, msg->dwords[i]);
        CDK_DEBUG_SCHAN((" 0x%08"PRIx32"", msg->dwords[i]));
    }
    CDK_DEBUG_SCHAN(("\n"));

    /* Tell CMIC to start */
    READ_CMIC_CMC_SCHAN_CTRLr(unit, &schan_ctrl); 
    CMIC_CMC_SCHAN_CTRLr_MSG_STARTf_SET(schan_ctrl, 1); 
    WRITE_CMIC_CMC_SCHAN_CTRLr(unit, schan_ctrl); 

    CDK_CONFIG_MEMORY_BARRIER; 
    
    /* Poll for completion */
    for (polls = 0; polls < CDK_CONFIG_SCHAN_MAX_POLLS; polls++) {
        READ_CMIC_CMC_SCHAN_CTRLr(unit, &schan_ctrl); 
        if (CMIC_CMC_SCHAN_CTRLr_MSG_DONEf_GET(schan_ctrl)) {
            break; 
        }
    }

    /* Check for timeout and error conditions */
    if (polls == CDK_CONFIG_SCHAN_MAX_POLLS) {
        CDK_DEBUG_SCHAN(("cdk_xgsm_schan_op[%d]: S-channel timeout\n", unit));
        rv = CDK_E_TIMEOUT; 
    }

    if (CMIC_CMC_SCHAN_CTRLr_NACKf_GET(schan_ctrl)) {
        CDK_DEBUG_SCHAN(("cdk_xgsm_schan_op[%d]: S-channel NAK\n", unit));
        rv = CDK_E_FAIL; 
    }
            
    if (CMIC_CMC_SCHAN_CTRLr_SER_CHECK_FAILf_GET(schan_ctrl)) {
        CDK_DEBUG_SCHAN(("cdk_xgsm_schan_op[%d]: S-channel SER error\n", unit));
        rv = CDK_E_FAIL; 
    }
            
    if (CMIC_CMC_SCHAN_CTRLr_TIMEOUTf_GET(schan_ctrl)) {
        CDK_DEBUG_SCHAN(("cdk_xgsm_schan_op[%d]: S-channel TO error\n", unit));
        rv = CDK_E_FAIL; 
    }
            
    CMIC_CMC_SCHAN_CTRLr_MSG_DONEf_SET(schan_ctrl, 0);
    WRITE_CMIC_CMC_SCHAN_CTRLr(unit, schan_ctrl); 

    CDK_CONFIG_MEMORY_BARRIER; 

    if (CDK_FAILURE(rv)) {
        _schan_reset(unit);
        return rv; 
    }

    /* Read in data from S-Channel buffer space, if any */
    CDK_DEBUG_SCHAN(("cdk_xgsm_schan_op[%d]: S-channel read:", unit));
    for (i = 0; i < dwc_read; i++) {
         CDK_XGSM_CMC_READ(unit, msg_addr + 4*i, &msg->dwords[i]); 
         CDK_DEBUG_SCHAN((" 0x%08"PRIx32"", msg->dwords[i]));
    }
    CDK_DEBUG_SCHAN(("\n"));

    return CDK_E_NONE; 
}


