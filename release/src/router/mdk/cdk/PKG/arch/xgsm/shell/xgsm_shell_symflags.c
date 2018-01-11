/*
 * $Id: xgsm_shell_symflags.c,v 1.1 Broadcom SDK $
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
 * XGSM shell symbol flag utilities.
 *
 */

#include <cdk/arch/xgsm_shell.h>

static int
_mask2idx(uint32_t mask)
{
    int idx;

    for (idx = 0; idx < 32; idx++) {
        if (mask & (1 << idx)) {
            return idx;
        }
    }
    return -1;
}

const char *
cdk_xgsm_shell_symflag_type2name(int unit, uint32_t flag)
{
    const char *rc; 
    
    /* Input can be either a CDK_SYMBOL_FLAG* or a blktype bitmap */
    if ((rc = cdk_shell_symflag_type2name(flag)) != NULL) {
        return rc; 
    }
    if ((rc = cdk_xgsm_shell_block_type2name(unit, _mask2idx(flag))) != NULL) {
        return rc; 
    }
    return NULL; 
}

uint32_t
cdk_xgsm_shell_symflag_name2type(int unit, const char *name)
{
    uint32_t rc; 
    int blktype;

    if ((rc = cdk_shell_symflag_name2type(name))) {
        return rc; 
    }
    if ((blktype = cdk_xgsm_shell_block_name2type(unit, name)) >= 0) {
        return 1 << blktype;
    }
    return 0; 
}


int
cdk_xgsm_shell_symflag_cst2flags(int unit, const cdk_shell_tokens_t *cst, 
                                uint32_t *present, uint32_t *absent)
{
    int i; 

    *present = *absent = 0; 
    
    for (i = 0; i < cst->argc; i++) {
        uint32_t flag; 
        char *s = cst->argv[i]; 
        int not_set = 0; 
        
        /* Make sure this flag is 1 or 0 ?*/
        if (s[0] == '!') {
            /* Flag must be zero */
            not_set = 1; 
            s++; 
        }
                
        if (cdk_shell_parse_uint32(s, &flag) < 0) {
            flag = cdk_xgsm_shell_symflag_name2type(unit, s); 
        }

        /*
         * Add the result to the correct flag
         */
        if (not_set) {
            *absent |= flag; 
        } else {
            *present |= flag; 
        }
    }
    return 0;
}    
