/*
 * $Id: shcmd_xgsm_get.c,v 1.1 Broadcom SDK $
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
 * XGSM shell command GET
 *
 */

#include <cdk/arch/xgsm_shell.h>

#include <cdk/arch/shcmd_xgsm_get.h>

#if CDK_CONFIG_SHELL_INCLUDE_GET == 1

#if CDK_CONFIG_INCLUDE_CHIP_SYMBOLS == 1

/*******************************************************************************
 *
 * Private data for symbol iterator.
 * 
 *
 ******************************************************************************/

typedef struct xgsm_iter_s {
    int unit; 
    cdk_shell_id_t *sid;
} xgsm_iter_t; 

/*******************************************************************************
 *
 * Get or Set the data for a symbol -- symbol iterator function
 *
 *
 ******************************************************************************/

static int
_iter_op(const cdk_symbol_t *symbol, void *vptr)
{
    xgsm_iter_t *xgsm_iter = (xgsm_iter_t *)vptr;
    cdk_shell_id_t sid;
    int unit = xgsm_iter->unit;

    CDK_MEMCPY(&sid, xgsm_iter->sid, sizeof(sid)); 

    /* Copy the address in for this symbol */
    CDK_STRCPY(sid.addr.name, symbol->name); 
    sid.addr.name32 = symbol->addr;

    cdk_xgsm_shell_symop(unit, symbol, &sid, NULL, NULL);

    return 0; 
}

#endif /* CDK_CONFIG_INCLUDE_CHIP_SYMBOLS */

int
cdk_shcmd_xgsm_get(int argc, char *argv[])
{       
#if CDK_CONFIG_INCLUDE_CHIP_SYMBOLS == 0
    return CDK_SHELL_CMD_NO_SYM; 
#else
    int i; 
    int unit;
    const cdk_symbols_t *symbols;
    cdk_shell_id_t sid; 
    cdk_symbols_iter_t iter; 
    xgsm_iter_t xgsm_iter; 
    cdk_shell_tokens_t csts[4]; 
    uint32_t sid_flags = 0;

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);
    if(!CDK_DEV_EXISTS(unit)) {
        return CDK_SHELL_CMD_BAD_ARG;
    }
    symbols = CDK_XGSM_SYMBOLS(unit);

    CDK_SHELL_CMD_REQUIRE_SYMBOLS(symbols); 
    CDK_SHELL_CMD_ARGCHECK(1, COUNTOF(csts)); 
    
    /* Parse all of our input arguments for options */
    i = 0; 
    if ((argc == 0) || 
        ((i = cdk_xgsm_shell_parse_args(argc, argv, csts, COUNTOF(csts))) >= 0)) {
        /* Error in argument i */
        return cdk_shell_parse_error("symbol", argv[i]); 
    }

    CDK_MEMSET(&iter, 0, sizeof(iter)); 
    CDK_MEMSET(&xgsm_iter, 0, sizeof(xgsm_iter)); 

    /* Match any symbol by default */
    cdk_shell_parse_id("*", &sid, 0); 

    /* Look through our arguments */
    for (i = 0; i < argc; i++) {
        /* Flags specified? */
        if (CDK_STRCMP("nz", csts[i].argv[0]) == 0) {
            sid_flags |= CDK_SHELL_IDF_NONZERO;
        }
        else if (CDK_STRCMP("raw", csts[i].argv[0]) == 0) {
            sid_flags |= CDK_SHELL_IDF_RAW;
        }
        else if (CDK_STRCMP("flags", csts[i].argv[0]) == 0) {
            cdk_xgsm_shell_symflag_cst2flags(unit, &csts[i],
                                            &iter.pflags, &iter.aflags);
        }
        else {
            /* Crack the identifier */
            if (cdk_shell_parse_id(csts[i].argv[0], &sid, 0) < 0) {
                return cdk_shell_parse_error("identifier", *argv); 
            }
        }
    }   
    sid.flags = sid_flags;

    xgsm_iter.unit = unit; 
    xgsm_iter.sid = &sid; 

    iter.name = sid.addr.name; 
    iter.matching_mode = CDK_SYMBOLS_ITER_MODE_EXACT; 
    iter.symbols = symbols; 
    iter.function = _iter_op; 
    iter.vptr = &xgsm_iter; 

    /* Iterate */
    if (cdk_symbols_iter(&iter) <= 0) {
        CDK_PRINTF("no matching symbols\n"); 
    }

    return 0;
#endif /* CDK_CONFIG_INCLUDE_CHIP_SYMBOLS */
}

#endif /* CDK_CONFIG_SHELL_INCLUDE_GET */
