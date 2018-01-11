/*
 * $Id: cdk_symbol_field_filter.c,v 1.1 Broadcom SDK $
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
 */

#include <cdk/cdk_string.h>
#include <cdk/cdk_stdlib.h>
#include <cdk/cdk_field.h>
#include <cdk/cdk_symbols.h>
#include <cdk/cdk_chip.h>

/*
 * Function:
 *	cdk_symbol_field_filter
 * Purpose:
 *	Callback for Filtering fields based on current data view.
 * Parameters:
 *	symbol - symbol information
 *	fnames - list of all field names for this device
 *	encoding - key for decoding overlay
 *	cookie - context data
 * Returns:
 *      Non-zero if field should be filtered out (not displayed)
 * Notes:
 *      The filter key has the following syntax:
 *
 *        {[<keysrc>]:<keyfield>:<keyval>[|<keyval> ... ]}
 *
 *      Ideally the keysrc is the same data entry which is
 *      being decoded, and in this case it can left out, e.g.:
 *
 *        {:KEY_TYPEf:1}
 *
 *      This example encoding means that if KEY_TYPEf=1, then
 *      this field is valid for this view.
 *
 *      Note that a filed can be for multiple views, e.g.:
 *
 *        {:KEY_TYPEf:1|3}
 *
 *      This example encoding means that this field is valid
 *      if KEY_TYPEf=1 or KEY_TYPEf=3.
 *
 *      The special <keyval>=-1 means that this field is valid
 *      even if there is no context (cookie=NULL).
 *
 *      Note that this filter code does NOT support a <keysrc>
 *      which is different from the current data entry.
 */
int 
cdk_symbol_field_filter(const cdk_symbol_t *symbol, const char **fnames,
                              const char *encoding, void *cookie)
{
#if CDK_CONFIG_INCLUDE_FIELD_NAMES == 1
    uint32_t *data = (uint32_t *)cookie;
    uint32_t val[CDK_MAX_REG_WSIZE];
    cdk_field_info_t finfo; 
    char tstr[128];
    char *keyfield, *keyvals;
    char *ptr;
    int wsize;
    int kval = -1;

    /* Do not filter if no (or unknown) encoding */
    if (encoding == NULL || *encoding != '{') {
        return 0;
    }

    /* Do not filter if encoding cannot be parsed */
    CDK_STRLCPY(tstr, encoding, sizeof(tstr));
    ptr = tstr;
    if ((ptr = CDK_STRCHR(ptr, ':')) == NULL) {
        return 0;
    }
    *ptr++ = 0;
    keyfield = ptr;
    if ((ptr = CDK_STRCHR(ptr, ':')) == NULL) {
        return 0;
    }
    *ptr++ = 0;
    keyvals = ptr;

    /* Only show default view if no context */
    if (data == NULL) {
        return (CDK_STRSTR(keyvals, "-1") == NULL) ? 1 : 0;
    }

    /* Look for <keyfield> in data entry */
    CDK_SYMBOL_FIELDS_ITER_BEGIN(symbol->fields, finfo, fnames) {

        if (finfo.name && CDK_STRCMP(finfo.name, keyfield) == 0) {
            /* Get normalized field value */
            CDK_MEMSET(val, 0, sizeof(val));
            if (symbol->flags & CDK_SYMBOL_FLAG_BIG_ENDIAN) {
                wsize = CDK_BYTES2WORDS(CDK_SYMBOL_INDEX_SIZE_GET(symbol->index));
                cdk_field_be_get(data, wsize, finfo.minbit, finfo.maxbit, val);
            } else {
                cdk_field_get(data, finfo.minbit, finfo.maxbit, val);
            }
            kval = val[0];
            break;
        }

    } CDK_SYMBOL_FIELDS_ITER_END(); 

    /* Check if current key matches any <keyval> in encoding */
    ptr = keyvals;
    while (ptr) {
        if (CDK_ATOI(ptr) == kval) {
            return 0;
        }
        if ((ptr = CDK_STRCHR(ptr, '|')) != NULL) {
            ptr++;
        }
    }
#endif

    /* No match - filter this field */
    return 1; 
}
