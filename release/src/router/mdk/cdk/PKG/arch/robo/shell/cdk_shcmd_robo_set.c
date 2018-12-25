/*
 * $Id: cdk_shcmd_robo_set.c,v 1.5 Broadcom SDK $
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
 * ROBO shell command SET
 *
 */

#include <cdk/arch/robo_shell.h>

#include <cdk/arch/shcmd_robo_set.h>

#if CDK_CONFIG_SHELL_INCLUDE_SET == 1

#if CDK_CONFIG_INCLUDE_CHIP_SYMBOLS == 1

/*******************************************************************************
 *
 * Private data for symbol iterator.
 * 
 *
 ******************************************************************************/

typedef struct robo_iter_s {
    int unit; 
    cdk_shell_id_t *sid;
    cdk_shell_tokens_t *csts;    
} robo_iter_t; 

/*******************************************************************************
 *
 * Get or Set the data for a symbol -- symbol iterator function
 *
 *
 ******************************************************************************/

static int
_iter_op(const cdk_symbol_t *symbol, void *vptr)
{
    uint32_t and_masks[32]; 
    uint32_t or_masks[32]; 
    robo_iter_t *robo_iter = (robo_iter_t *)vptr;
    cdk_shell_id_t sid;
    cdk_shell_tokens_t *csts = robo_iter->csts; 
    int unit = robo_iter->unit;

    CDK_MEMCPY(&sid, robo_iter->sid, sizeof(sid)); 

    /* Copy the address in for this symbol */
    CDK_STRCPY(sid.addr.name, symbol->name); 
    sid.addr.name32 = symbol->addr;

    /* These CSTs contain the data and/or field assignments */
    cdk_shell_encode_fields_from_tokens(symbol, CDK_ROBO_SYMBOLS(robo_iter->unit)->field_names, 
                                        csts, 
                                        and_masks, or_masks, 32);

    cdk_robo_shell_symop(unit, symbol, &sid, and_masks, or_masks);

    return 0; 
}

#endif /* CDK_CONFIG_INCLUDE_CHIP_SYMBOLS */

int
cdk_shcmd_robo_set(int argc, char *argv[])
{
#if CDK_CONFIG_INCLUDE_CHIP_SYMBOLS == 0
    return CDK_SHELL_CMD_NO_SYM; 
#else
    int i; 
    int data_start = 0; 
    int unit;
    const cdk_symbols_t *symbols;
    cdk_shell_id_t sid;
    cdk_symbols_iter_t iter; 
    robo_iter_t robo_iter; 
    cdk_shell_tokens_t csts[CDK_CONFIG_SHELL_MAX_ARGS]; 

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);
    if(!CDK_DEV_EXISTS(unit)) {
        return CDK_SHELL_CMD_BAD_ARG;
    }
    symbols = CDK_ROBO_SYMBOLS(unit);

    CDK_SHELL_CMD_REQUIRE_SYMBOLS(symbols); 
    CDK_SHELL_CMD_ARGCHECK(2, CDK_CONFIG_SHELL_MAX_ARGS); 

    CDK_MEMSET(&iter, 0, sizeof(iter)); 
    CDK_MEMSET(&robo_iter, 0, sizeof(robo_iter)); 

    /*
     * The format of this command must be one of the following:
     *
     * set <symbol> [flags=] <[data words] or [field assignments]>
     * set <flags=> <[data words] or [field assignments]>
     */
    
    /* Parse input arguments */
    i = 0; 
    if ((i = cdk_robo_shell_parse_args(argc, argv, csts, CDK_CONFIG_SHELL_MAX_ARGS)) >= 0) {
        /* Error in argument i */
        return cdk_shell_parse_error("", argv[i]); 
    }
           
    /* Is the first argument a symbol or a flags specification? */
    if (CDK_STRCMP("flags", csts[0].argv[0]) == 0) {
        
        /* flags */
        cdk_robo_shell_symflag_cst2flags(&csts[0], &iter.pflags, &iter.aflags); 

        /* No specific symbol specified (!) */
        cdk_shell_parse_id("*", &sid, 0); 

        /* Data starts at cst 1 */
        data_start = 1; 
    }
    else {
        /* arg 0 must be the symbol id */
        if (cdk_shell_parse_id(csts[0].argv[0], &sid, 0) < 0) {
            return cdk_shell_parse_error("symbol", csts[0].argv[0]); 
        }

        if (CDK_STRCMP("flags", csts[1].argv[0]) == 0) {
            /* flags */
            cdk_robo_shell_symflag_cst2flags(&csts[1], &iter.pflags, &iter.aflags); 

            /* Data starts at cst 2 */
            data_start = 2; 
        }
        else {
            /* Data starts at cst 1 */
            data_start = 1; 
        }
    }

    robo_iter.unit = unit; 
    robo_iter.csts = &csts[data_start]; 
    robo_iter.sid = &sid; 

    iter.name = sid.addr.name; 
    iter.symbols = symbols; 
    iter.function = _iter_op; 
    iter.vptr = &robo_iter; 

    /* Iterate */
    if (cdk_symbols_iter(&iter) <= 0) {
        CDK_PRINTF("no matching symbols\n"); 
    }

    return 0;     
#endif /* CDK_CONFIG_INCLUDE_CHIP_SYMBOLS */
}

#endif /* CDK_CONFIG_SHELL_INCLUDE_SET */
