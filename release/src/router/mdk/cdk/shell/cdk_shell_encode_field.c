/*
 * $Id: cdk_shell_encode_field.c,v 1.5 Broadcom SDK $
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
 * XGS shell symbol parsing functions.
 *
 */

#include <cdk/cdk_string.h>
#include <cdk/cdk_stdlib.h>
#include <cdk/cdk_chip.h>
#include <cdk/cdk_symbols.h>
#include <cdk/cdk_field.h>
#include <cdk/cdk_shell.h>

int
cdk_shell_encode_field(const cdk_symbol_t *symbol, 
                       const char** fnames, 
                       const char *field, const char *value, 
                       uint32_t *and_masks, uint32_t *or_masks)
{
#if CDK_CONFIG_INCLUDE_FIELD_NAMES == 1
    int v, len, wsize; 
    cdk_field_info_t finfo; 
    char vstr[8 * CDK_MAX_REG_WSIZE + 32];
    uint32_t val[CDK_MAX_REG_WSIZE]; 


    CDK_SYMBOL_FIELDS_ITER_BEGIN(symbol->fields, finfo, fnames) {

        if (CDK_STRCASECMP(finfo.name, field)) {
            continue; 
        }

        if (!cdk_shell_parse_is_int(value)) {
            return -1;
        }

        CDK_STRLCPY(vstr, value, sizeof(vstr));

        CDK_MEMSET(val, 0, sizeof(val));
        if (symbol->flags & CDK_SYMBOL_FLAG_BIG_ENDIAN) {
            wsize = CDK_BYTES2WORDS(CDK_SYMBOL_INDEX_SIZE_GET(symbol->index));
            cdk_field_be_set(and_masks, wsize, finfo.minbit, finfo.maxbit, val);
        } else {
            cdk_field_set(and_masks, finfo.minbit, finfo.maxbit, val);
        }

        /*
         * If the field value starts with 0x the accept values
         * spanning multiple words, e.g. 0x112233445566.
         */
        v = 0;
        if (vstr[0] == '0' && (vstr[1] == 'x' || vstr[1] == 'X')) {
            while ((len = CDK_STRLEN(vstr)) > 10) {
                len -= 8;
                val[v++] = CDK_STRTOUL(&vstr[len], NULL, 16);
                vstr[len] = 0;
            }
        }
        if (cdk_shell_parse_uint32(vstr, &val[v]) < 0) {
            return -1;
        }
        if (symbol->flags & CDK_SYMBOL_FLAG_BIG_ENDIAN) {
            wsize = CDK_BYTES2WORDS(CDK_SYMBOL_INDEX_SIZE_GET(symbol->index));
            cdk_field_be_set(or_masks, wsize, finfo.minbit, finfo.maxbit, val);
        } else {
            cdk_field_set(or_masks, finfo.minbit, finfo.maxbit, val);
        }

        return 0;
    } CDK_SYMBOL_FIELDS_ITER_END(); 

#endif /* CDK_CONFIG_INCLUDE_FIELD_NAMES */

    return -1; 
}
