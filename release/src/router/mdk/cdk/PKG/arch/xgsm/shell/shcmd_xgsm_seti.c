/*
 * $Id: shcmd_xgsm_seti.c,v 1.1 Broadcom SDK $
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
 * XGSM shell command SETI
 *
 */

#include <cdk/arch/xgsm_shell.h>

#include <cdk/arch/shcmd_xgsm_seti.h>

#if CDK_CONFIG_SHELL_INCLUDE_SETI == 1

static int
_parse_multiword(const char *str, cdk_shell_tokens_t *cst, 
                 uint32_t *words, int max_words)
{
    int idx;

    /* Parse string into word tokens */
    if (cdk_shell_tokenize(str, cst, ":") < 0) {
        return -1;
    }

    /* Check array size */
    if (cst->argc > max_words) {
	return -1;
    }

    /* Convert all tokens to integers */
    for (idx = 0; idx < cst->argc; idx++) {
        /* This argument must be an integer */
        if (cdk_shell_parse_uint32(cst->argv[idx], &words[idx]) < 0) {
            return -1;
	}
    }

    return 0;
}


/*******************************************************************************
 *
 * seti cmic 
 *
 * Set a cmic register
 *
 ******************************************************************************/

static int
_seti_cmic(int argc, char *argv[], void *context)
{
    int unit = *((int *)context);
    uint32_t addr; 
    uint32_t data; 

    if (cdk_shell_parse_uint32(argv[0], &addr) < 0) {
        return cdk_shell_parse_error("address", argv[0]); 
    }
    if (cdk_shell_parse_uint32(argv[1], &data) < 0) {
        return cdk_shell_parse_error("data", argv[1]); 
    }

    addr &= ~3;
    CDK_DEV_WRITE32(unit, addr, data); 

    return 0;     
}

/*******************************************************************************
 *
 * seti reg
 *
 *
 ******************************************************************************/

static int
_seti_reg(int argc, char *argv[], void *context)
{
    int unit = *((int *)context);
    uint32_t and_masks[2];
    uint32_t or_masks[2]; 
    cdk_shell_id_t sid;
    cdk_shell_tokens_t cst;
    int size; 

    /* Register will be cleared */
    and_masks[0] = and_masks[1] = 0;

    /* Crack the identifier */
    if (argc == 0 || cdk_shell_parse_id(*argv, &sid, 1) < 0) {
        return cdk_shell_parse_error("address", *argv); 
    }
    argv++;
    argc--;

    /* 32 or 64 bit multiword value */
    or_masks[0] = or_masks[1] = 0;
    if (argc == 0 ||
        _parse_multiword(*argv, &cst, or_masks, COUNTOF(or_masks)) < 0) {
        return cdk_shell_parse_error("data", *argv);
    }
    argv++; 
    argc--;

    /* Default size is the number of words specified */
    size = cst.argc; 

    /* Optional third argument is the size of the register */
    if (argc > 0 && cdk_shell_parse_int(*argv, &size) < 0) {
        return cdk_shell_parse_error("size", *argv); 
    }

    return cdk_xgsm_shell_regops(unit, NULL, &sid, size, and_masks, or_masks); 
}

static int
_seti_mem(int argc, char *argv[], void *context)
{
    int unit = *((int *)context);
    int size; 
    cdk_shell_tokens_t cst; 
    cdk_shell_id_t sid; 
    uint32_t and_masks[8]; 
    uint32_t or_masks[8]; 

    /* Memory will be cleared */
    CDK_MEMSET(and_masks, 0, sizeof(and_masks));

    /* Crack the identifier */
    if (argc == 0 || cdk_shell_parse_id(*argv, &sid, 1) < 0) {
        return cdk_shell_parse_error("address", *argv); 
    }
    argv++;
    argc--;

    /* Second argument is the data */
    CDK_MEMSET(or_masks, 0, sizeof(or_masks));
    if (argc == 0 ||
        _parse_multiword(*argv, &cst, or_masks, COUNTOF(or_masks)) < 0) {
        return cdk_shell_parse_error("data", *argv); 
    }
    argv++; 
    argc--;

    /* Default size is the number of words specified */
    size = cst.argc; 

    /* 
     * Optional third argument is the the memory size in words
     * Any words NOT specified in the data will be written as 
     * zero (up to the size.)
     */
    if (argc > 0 && (cdk_shell_parse_int(*argv, &size) < 0)) {
        return cdk_shell_parse_error("size", *argv); 
    }

    return cdk_xgsm_shell_memops(unit, NULL, &sid, size, and_masks, or_masks); 
}


/*******************************************************************************
 *
 * seti miim 
 *
 *
 ******************************************************************************/

static int
_seti_miim(int argc, char *argv[], void *context)
{
    int unit = *((int *)context);
    uint32_t data; 
    cdk_shell_id_t sid; 
    int i; 

    /* Crack the phy_id and addresses */
    if (argc == 0 || 
        cdk_shell_parse_id(*argv, &sid, 1) < 0 || sid.addr.start >= 0) {
        return cdk_shell_parse_error("miim addr", *argv); 
    }
    argv++;
    argc--;
    
    if (sid.port.start < 0 && sid.port.end < 0) {
        sid.port.start = 0; 
        sid.port.end = 0x1f; 
    } else if (sid.port.end < 0) {
        sid.port.end = sid.port.start; 
    }

    /* Get the data */
    if (argc == 0 || cdk_shell_parse_uint32(*argv, &data) < 0) {
	return cdk_shell_parse_error("miim data", *argv); 
    }
    argv++; 
    argc--;

    for (i = sid.port.start; i <= sid.port.end; i++) {
        if (cdk_xgsm_miim_write(unit, sid.addr.name32, i, data) < 0) {
	    CDK_PRINTF("%s writing miim(0x%"PRIx32")[0x%x]\n", 
                       CDK_CONFIG_SHELL_ERROR_STR, sid.addr.name32, i); 
	}
    }

    return 0; 
}


static cdk_shell_vect_t _seti_vects[] = 
{
    { "cmic",   _seti_cmic,     }, 
    { "reg",    _seti_reg,      }, 
    { "mem",    _seti_mem,      },     
    { "miim",   _seti_miim,     },
    { 0, 0 }, 
}; 
      
int
cdk_shcmd_xgsm_seti(int argc, char* argv[])
{
    int unit;

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);
    if(!CDK_DEV_EXISTS(unit)) {
        return CDK_SHELL_CMD_BAD_ARG;
    }
    if (cdk_shell_parse_vect(argc, argv, &unit, _seti_vects, NULL) < 0) {
        cdk_shell_parse_error("type", *argv); 
    }
    return 0; 
}

#endif /*  CDK_CONFIG_SHELL_INCLUDE_SETI */
