/*
 * $Id: cdk_shell_encode_fields_from_tokens.c,v 1.5 Broadcom SDK $
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
 */

#include <cdk/cdk_chip.h>
#include <cdk/cdk_string.h>
#include <cdk/cdk_symbols.h>
#include <cdk/cdk_field.h>
#include <cdk/cdk_shell.h>

/*
 * Function:
 *	cdk_shell_encode_fields_from_tokens
 * Purpose:
 *	Create masks for modifying register/memory
 * Parameters:
 *	symbol - symbol information
 *      csts - array of tokens with field assignments
 *      and_masks - (OUT) data mask to be AND'ed
 *      or_masks - (OUT) data mask to be OR'ed
 *      max - size of masks arrays
 * Returns:
 *      0 if tokens are parsed and encoded successfully
 * Notes:
 *      The output and_masks and or masks should be applied to the
 *      current contents of a register/memory in order to modify the
 *      contents according to the specified field assignments. 
 */
int
cdk_shell_encode_fields_from_tokens(const cdk_symbol_t *symbol, 
                                    const char** fnames, 
                                    const cdk_shell_tokens_t *csts, 
                                    uint32_t *and_masks,
                                    uint32_t *or_masks,
                                    int max)
{
    const cdk_shell_tokens_t *cst = csts;
    uint32_t data; 
    int idx; 

    /* Initialize masks */
    CDK_MEMSET(and_masks, ~0, max * sizeof(*and_masks));
    CDK_MEMSET(or_masks, 0, max * sizeof(*or_masks));

    if (cst->argc == 1 && CDK_STRCMP(cst->argv[0], "all") == 0) {
        /* All 32-bit data words are assigned the same value */
        if (cdk_shell_parse_uint32(cst->argv[1], &data) < 0) {
            return cdk_shell_parse_error("field", cst->str); 
        }
        CDK_MEMSET(and_masks, 0, max * sizeof(*and_masks));
        CDK_MEMSET(or_masks, data, max * sizeof(*or_masks));
    }
    else if (cst->argc > 0 && cdk_shell_parse_is_int(cst->argv[0])) {
        /* All tokens are treated as 32-bit data words */
        for (idx = 0; cst->argc; idx++, cst++) {
            if (cdk_shell_parse_uint32(cst->argv[0], &or_masks[idx]) < 0) {
                return cdk_shell_parse_error("field", cst->str); 
            }
            and_masks[idx] = 0; 
        }
    }
    else {
        /* All tokens are treated as field=value */
        for (idx = 0; cst->argc; idx++, cst++) {
            if (cdk_shell_encode_field(symbol, fnames, cst->argv[0], cst->argv[1],
                                       and_masks, or_masks)) {
                return cdk_shell_parse_error("field", cst->str); 
            }
        }
    }

    return 0; 
}       
