/*
 * $Id: cdk_symbol_show_fields.c,v 1.4 Broadcom SDK $
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
#include <cdk/cdk_stdlib.h>
#include <cdk/cdk_string.h>
#include <cdk/cdk_printf.h>
#include <cdk/cdk_symbols.h>
#include <cdk/cdk_field.h>
#include <cdk/cdk_util.h>

#if CDK_CONFIG_INCLUDE_FIELD_INFO == 1

/*
 * Function:
 *	cdk_symbol_show_fields
 * Purpose:
 *	Display all fields of a register/memory
 * Parameters:
 *	symbol - symbol information
 *	fnames - list of all field names
 *	data - symbol data (one or more 32-bit words)
 *	nz - skip fields with value of zero
 *	fcb - filter call-back function
 *	cookie - filter call-back context
 * Returns:
 *      Always 0
 */
int 
cdk_symbol_show_fields(const cdk_symbol_t *symbol,
                       const char **fnames, uint32_t *data, int nz,
                       cdk_symbol_filter_cb_t fcb, void *cookie)
{
    int mval; 
    cdk_field_info_t finfo; 
    char *ptr;
    char vstr[8 * CDK_MAX_REG_WSIZE + 32];
    char fname_str[16];
    const char *fname;
    uint32_t val[CDK_MAX_REG_WSIZE];
    int idx = 0;
    int size;

    CDK_SYMBOL_FIELDS_ITER_BEGIN(symbol->fields, finfo, fnames) {

        /* Create default field name */
        CDK_SPRINTF(fname_str, "field%d", idx++);
        fname = fname_str;

#if CDK_CONFIG_INCLUDE_FIELD_NAMES == 1
        /* Use real field name when available */
        if (finfo.name) {
            if (fcb && fcb(symbol, fnames, finfo.name, cookie) != 0) {
                continue;
            }
            /* Skip encoding part of field name if present */
            if ((fname = CDK_STRCHR(finfo.name, '}')) != NULL) {
                fname++;
            } else {
                fname = finfo.name;
            }
        }
#endif

        /* Create bit range string */
        cdk_util_bit_range(vstr, sizeof(vstr),
                           finfo.minbit, 
                           finfo.maxbit);

        if (data) {
            /* Get normalized field value */
            CDK_MEMSET(val, 0, sizeof(val));
            if (symbol->flags & CDK_SYMBOL_FLAG_BIG_ENDIAN) {
                size = CDK_SYMBOL_INDEX_SIZE_GET(symbol->index);
                cdk_field_be_get(data, CDK_BYTES2WORDS(size),
                                 finfo.minbit, finfo.maxbit, val);
            } else {
                cdk_field_get(data, finfo.minbit, finfo.maxbit, val);
            }

            /* Create field value string */
            mval = COUNTOF(val) - 1;
            while (mval && val[mval] == 0) {
                mval--;
            }

            /* Optionally skip fields with all zeros */
            if (nz && mval == 0 && val[mval] == 0) {
                continue;
            }

            ptr = vstr + CDK_STRLEN(vstr);
            CDK_SPRINTF(ptr, "=0x%"PRIx32"", val[mval]);
            while (mval--) {
                ptr += CDK_STRLEN(ptr);
                CDK_SPRINTF(ptr, "%08"PRIx32"", val[mval]);
            }
        }

        CDK_PRINTF("\t%s%s\n", fname, vstr);

    } CDK_SYMBOL_FIELDS_ITER_END(); 

    return 0; 
}

#endif /* CDK_CONFIG_INCLUDE_FIELD_INFO */
