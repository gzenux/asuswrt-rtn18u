/*
 * $Id: cdk_symbol_fields.c,v 1.2 Broadcom SDK $
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

/*******************************************************************************
 *
 * CDK Symbol Field Routines
 *
 *
 ******************************************************************************/

#include <cdk/cdk_symbols.h>


uint32_t* 
cdk_field_info_decode(uint32_t* fp, cdk_field_info_t* finfo, const char** fnames)
{
    if(!fp) {
        return NULL; 
    }

    if(finfo) {
        /*
         * Single or Double Word Descriptor?
         */
        if(CDK_SYMBOL_FIELD_EXT(*fp)) {
            /* Double Word */
            finfo->fid = CDK_SYMBOL_FIELD_EXT_ID_GET(*fp); 
            finfo->maxbit = CDK_SYMBOL_FIELD_EXT_MAX_GET(*(fp+1)); 
            finfo->minbit = CDK_SYMBOL_FIELD_EXT_MIN_GET(*(fp+1)); 
        }       
        else {
            /* Single Word */
            finfo->fid = CDK_SYMBOL_FIELD_ID_GET(*fp); 
            finfo->maxbit = CDK_SYMBOL_FIELD_MAX_GET(*fp); 
            finfo->minbit = CDK_SYMBOL_FIELD_MIN_GET(*fp); 
        }       

        if(fnames) {
            finfo->name = fnames[finfo->fid]; 
        }
        else {
            finfo->name = NULL; 
        }       
    }

    if(CDK_SYMBOL_FIELD_LAST(*fp)) {
        return NULL; 
    }

    if(CDK_SYMBOL_FIELD_EXT(*fp)) {
        return fp+2; 
    }

    return fp+1; 
}

uint32_t
cdk_field_info_count(uint32_t* fp)
{    
    int count = 0; 
    while(fp) {
        fp = cdk_field_info_decode(fp, NULL, NULL); 
        count++; 
    }   
    return count; 
}
