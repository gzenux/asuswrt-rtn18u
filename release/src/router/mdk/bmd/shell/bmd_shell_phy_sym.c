/*
 * $Id: bmd_shell_phy_sym.c,v 1.19 Broadcom SDK $
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
 * Read and write PHY data.
 */

#include "bmd_shell_util.h"

#if BMD_CONFIG_INCLUDE_PHY == 1

#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1

typedef struct phy_iter_s {
    phy_ctrl_t *pc;
    cdk_shell_tokens_t *csts;
    cdk_shell_id_t *sid; 
#define PHY_SHELL_SYM_RAW       0x1     /* Do not decode fields */
#define PHY_SHELL_SYM_LIST      0x2     /* List symbol only */
    uint32_t flags;
} phy_iter_t; 

static int
cdk_shell_phy_parse_args(int argc, char *argv[], cdk_shell_tokens_t *csts, int max)
    
{		
    int idx; 
    cdk_shell_tokens_t *cst = csts;

    CDK_MEMSET(csts, 0, max*sizeof(*csts)); 

    /* For all arguments */
    for (idx = 0; idx < argc && idx < max; idx++, cst++) {
	
	/* Parse each individual argument with '=' into cst */
	if (cdk_shell_tokenize(argv[idx], cst, "=") < 0) {
	    return idx;
	}
	if (cst->argc != 1 && cst->argc != 2) {
            /* Number of tokens must be 1 or 2 */
	    return idx;
	}	

    }
    return -1; 
}

static int
_iter_count(const cdk_symbol_t *symbol, void *vptr)
{
    int *count = (int *)vptr;

    return ++(*count);
}

static int
_iter_op(const cdk_symbol_t *symbol, void *vptr)
{
    uint32_t and_mask;
    uint32_t or_mask; 
    uint32_t data;
    phy_iter_t *phy_iter = (phy_iter_t *)vptr;
    cdk_shell_tokens_t *csts = phy_iter->csts; 
    uint32_t reg_addr, reg_step, serdes_blk;
    const char** fnames = PHY_CTRL_SYMBOLS(phy_iter->pc)->field_names; 

    if (phy_iter->flags & PHY_SHELL_SYM_LIST) {
        CDK_PRINTF("Name:     %s\n", symbol->name); 
        reg_addr = symbol->addr & 0x00ffffff;
        serdes_blk = reg_addr >> 8;
        if (serdes_blk && (serdes_blk & 0xf) == 0) {
            serdes_blk >>= 4;
        }
        switch (PHY_REG_ACCESS_METHOD(symbol->addr)) {
        case PHY_REG_ACC_BRCM_SHADOW:
            if ((reg_addr & 0x1f) == 0x15) {
                CDK_PRINTF("Address:  0x%"PRIx32" (expansion)\n", reg_addr >> 8);
                break;
            } 
            CDK_PRINTF("Address:  0x%"PRIx32"\n", reg_addr & 0x1f); 
            CDK_PRINTF("Shadow:   0x%"PRIx32"\n", reg_addr >> 8); 
            break;
        case PHY_REG_ACC_BRCM_1000X:
            CDK_PRINTF("Address:  0x%"PRIx32" (fiber)\n", reg_addr & 0x1f); 
            break;
        case PHY_REG_ACC_XAUI_IBLK:
            if (symbol->addr & PHY_REG_ACC_XAUI_IBLK_CL22) {
                CDK_PRINTF("Block:    0x%"PRIx32"\n", serdes_blk); 
                CDK_PRINTF("Address:  0x%"PRIx32" (clause 22)\n",
                           reg_addr & 0x1f); 
                break;
            }
            /* fall through */
        case PHY_REG_ACC_XGS_IBLK:
            CDK_PRINTF("Block:    0x%"PRIx32"\n", serdes_blk); 
            CDK_PRINTF("Address:  0x%"PRIx32"\n", reg_addr & 0x1f); 
            break;
        case PHY_REG_ACC_AER_IBLK:
        case PHY_REG_ACC_TSC_IBLK:
            CDK_PRINTF("Address:  0x%"PRIx32"", reg_addr & 0xfffff); 
            data = (reg_addr >> 20) & 0xf;
            if (data == 1) {
                CDK_PRINTF(" (1 copy only)"); 
            } else if (data == 2) {
                CDK_PRINTF(" (2 copies only)"); 
            }
            CDK_PRINTF("\n"); 
            break;
        case PHY_REG_ACC_RAW:
        default:
            CDK_PRINTF("Address:  0x%"PRIx32"\n", symbol->addr); 
            break;
        }
        if (phy_iter->flags & PHY_SHELL_SYM_RAW) {
            CDK_PRINTF("\n"); 
            return 0;
        }
#if CDK_CONFIG_INCLUDE_FIELD_INFO == 1
        if (symbol->fields) {
            CDK_PRINTF("Fields:   %"PRIu32"\n",
                       cdk_field_info_count(symbol->fields));
            cdk_shell_list_fields(symbol, fnames);
        }
#endif
        return 0;
    }
    /* Lane override specified? */
    if (phy_iter->sid->port.start >= 0) {
        PHY_CTRL_LANE(phy_iter->pc) = phy_iter->sid->port.start | PHY_LANE_VALID;
    }
    reg_addr = symbol->addr;
    if (phy_iter->sid->addr.start > 0) {
        switch (PHY_REG_ACCESS_METHOD(symbol->addr)) {
        case PHY_REG_ACC_XGS_IBLK:
            reg_step = PHY_REG_ACC_XGS_IBLK_STEP;
            break;
        case PHY_REG_ACC_XAUI_IBLK:
            reg_step = PHY_REG_ACC_XAUI_IBLK_STEP;
            break;
        case PHY_REG_ACC_AER_IBLK:
            reg_step = PHY_REG_ACC_AER_IBLK_STEP;
            break;
        default:
            reg_step = 1;
            break;
        }
        reg_addr += phy_iter->sid->addr.start * reg_step;
    }
    if (csts->argc) {
        /* These csts contain the data and/or field assignments */
        cdk_shell_encode_fields_from_tokens(symbol, fnames, csts, 
                                            &and_mask, &or_mask, 1);

        /* Read, update and write PHY register */
        if (phy_reg_read(phy_iter->pc, reg_addr, &data) != 0) {
            CDK_PRINTF("Error reading %s\n", symbol->name);
            return -1;
        }
        data &= and_mask;
        data |= or_mask;
        if (phy_reg_write(phy_iter->pc, reg_addr, data) != 0) {
            CDK_PRINTF("Error writing %s\n", symbol->name);
            return -1;
        }
    }
    else {
        /* Decode PHY register */
        if (phy_reg_read(phy_iter->pc, reg_addr, &data) != 0) {
            CDK_PRINTF("Error reading %s\n", symbol->name);
            return 0;
        }
        CDK_PRINTF("%s [0x%08"PRIx32"] = 0x%04"PRIx32"\n", 
                   symbol->name, reg_addr, data);
#if CDK_CONFIG_INCLUDE_FIELD_INFO == 1
        if (phy_iter->flags & PHY_SHELL_SYM_RAW) {
            return 0;
        }
        if (symbol->fields) {
            cdk_shell_show_fields(symbol, fnames, &data); 
        }
#endif
    }

    return 0; 
}

#endif /* PHY_CONFIG_INCLUDE_CHIP_SYMBOLS */

int
bmd_shell_phy_sym(phy_ctrl_t *pc, int argc, char *argv[])
{       
#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 0
    return CDK_SHELL_CMD_NO_SYM; 
#else
    int idx, pdx; 
    const cdk_symbols_t *symbols;
    cdk_symbols_iter_t iter; 
    phy_iter_t phy_iter; 
    cdk_shell_tokens_t csts[CDK_CONFIG_SHELL_MAX_ARGS]; 
    cdk_shell_id_t sid; 
    uint32_t flags;

    if ((symbols = PHY_CTRL_SYMBOLS(pc)) == NULL) {
        CDK_PRINTF("no symbol table\n"); 
        return 0;
    }

    CDK_SHELL_CMD_ARGCHECK(1, COUNTOF(csts)); 
    
    /* Look through our arguments */
    flags = 0;
    for (idx = 0; idx < argc; idx++) {
        if (CDK_STRCMP("raw", argv[idx]) == 0) {
            flags |= PHY_SHELL_SYM_RAW;
        }
        else if (CDK_STRCMP("list", argv[idx]) == 0) {
            flags |= PHY_SHELL_SYM_LIST;
        }
        else {
            idx++;
            break;
        }
    }   

    /* Parse remaining input arguments for field assignments */
    pdx = idx;
    if ((argc == 0) || 
        ((pdx = cdk_shell_phy_parse_args(argc-idx, &argv[idx], csts, COUNTOF(csts))) >= 0)) {
        /* Error in argument i */
        return cdk_shell_parse_error("symbol", argv[pdx]); 
    }

    CDK_MEMSET(&iter, 0, sizeof(iter)); 
    CDK_MEMSET(&phy_iter, 0, sizeof(phy_iter)); 

    /* Crack the identifier */
    if (cdk_shell_parse_id(argv[idx-1], &sid, 0) < 0) {
        return cdk_shell_parse_error("identifier", *argv); 
    }

    iter.name = sid.addr.name; 
    iter.symbols = symbols; 
    iter.matching_mode = CDK_SYMBOLS_ITER_MODE_EXACT; 
    if (CDK_STRCMP(iter.name, "*") != 0) {
        switch (iter.name[0]) {
        case '^':
            iter.matching_mode = CDK_SYMBOLS_ITER_MODE_START; 
            iter.name++;
            break;
        case '*':
            iter.matching_mode = CDK_SYMBOLS_ITER_MODE_STRSTR; 
            iter.name++;
            break;
        case '@':
            iter.matching_mode = CDK_SYMBOLS_ITER_MODE_EXACT; 
            iter.name++;
            break;
        default:
            if (flags & PHY_SHELL_SYM_LIST) {
                iter.matching_mode = CDK_SYMBOLS_ITER_MODE_STRSTR;
            }
            break;
        }
    }
    if (flags & PHY_SHELL_SYM_LIST) {
        int count = 0;
        /*
         * For symbol listings we force raw mode if multiple
         * matches are found.
         */
        iter.function = _iter_count; 
        iter.vptr = &count; 
        if (cdk_symbols_iter(&iter) > 1) {
            flags |= PHY_SHELL_SYM_RAW;
        }
    }

    iter.function = _iter_op; 
    iter.vptr = &phy_iter; 

    phy_iter.pc = pc; 
    phy_iter.csts = csts; 
    phy_iter.sid = &sid; 
    phy_iter.flags = flags; 

    /* Iterate */
    if (cdk_symbols_iter(&iter) <= 0) {
        CDK_PRINTF("no matching symbols\n"); 
    }

    /* Reset lane override */
    PHY_CTRL_LANE(pc) = 0;

    return 0;
#endif /* PHY_CONFIG_INCLUDE_CHIP_SYMBOLS */
}

#endif /* BMD_CONFIG_INCLUDE_PHY */
