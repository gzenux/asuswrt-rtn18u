/*
 * $Id: cdk_symbol.c,v 1.16 Broadcom SDK $
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
 * CDK Symbol Routines
 *
 *
 ******************************************************************************/

#include <cdk/cdk_symbols.h>
#include <cdk/cdk_string.h>
#include <cdk/cdk_assert.h>

#if CDK_CONFIG_INCLUDE_CHIP_SYMBOLS == 1

static const void *
__cdk_symbol_find(const char *name, const void *table, int size, int entry_size)
{
    int i; 
    cdk_symbol_t *sym;
    unsigned char *ptr = (unsigned char*)table; 

    CDK_ASSERT(table); 
    
    for (i = 0; (sym = (cdk_symbol_t*)(ptr)) && (i < size); i++) {
	if (CDK_STRCMP(sym->name, name) == 0) {
	    return (void*) sym; 
	}
#if CDK_CONFIG_INCLUDE_ALIAS_NAMES == 1
	if (sym->ufname && CDK_STRCMP(sym->ufname, name) == 0) {
	    return (void*) sym; 
	}
	if (sym->alias && CDK_STRCMP(sym->alias, name) == 0) {
	    return (void*) sym; 
	}
#endif
	ptr += entry_size; 
    }

    return NULL; 
}
	

const cdk_symbol_t *
cdk_symbol_find(const char *name, const cdk_symbol_t *table, int size)
{
    return (cdk_symbol_t*) __cdk_symbol_find(name, table, size, sizeof(cdk_symbol_t)); 
}


int 
cdk_symbols_find(const char *name, const cdk_symbols_t *symbols, cdk_symbol_t *rsym)
{
    const cdk_symbol_t *s = NULL; 

    if (rsym == NULL) return -1; 

    if ((symbols->symbols) && (s = cdk_symbol_find(name, symbols->symbols, symbols->size))) {
	*rsym = *s;
	return 0; 
    }
    return -1;
}

#endif
