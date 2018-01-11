/*
 * $Id: shcmd_xgsm_unit.c,v 1.3 Broadcom SDK $
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
 * XGSM shell command UNIT
 *
 */

#include <cdk/arch/xgsm_shell.h>

#include <cdk/arch/shcmd_xgsm_unit.h>

#if CDK_CONFIG_SHELL_INCLUDE_UNIT == 1

/*
 * Print out the current switch unit information
 */
int
cdk_shcmd_xgsm_unit(int argc, char *argv[])
{
    int unit;
    int u, b; 
    char tmp[CDK_PBMP_WORD_MAX * 16]; 

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);
    if(!CDK_DEV_EXISTS(unit)) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    if (argc) {
        /* Either a unit number or 'all', '*', or unit number */
        if (CDK_STRCMP(argv[0], "all") == 0 || *argv[0] == '*') {
            /* Specify all units */
            unit = -1; 
        }
    }

    for (u = 0; u < CDK_CONFIG_MAX_UNITS; u++) {
        if (CDK_DEV_EXISTS(u) && (unit == -1 || unit == u)) {
            CDK_PRINTF("unit %d:\n", u); 
            if ((CDK_DEV_FLAGS(u) & CDK_DEV_ARCH_XGSM) == 0) {
                CDK_PRINTF("  Not XGSM architecture\n"); 
                continue;
            }
            CDK_PRINTF("  Device: %s [%04x:%04x:%02x]\n",
                       CDK_DEV(u)->name, CDK_DEV(u)->id.vendor_id,
                       CDK_DEV(u)->id.device_id, CDK_DEV(u)->id.revision); 
            CDK_PRINTF("  Base Address: %p\n", (void*)CDK_DEV_BASE_ADDR(u)); 
            cdk_shell_port_bitmap(tmp, sizeof(tmp),
                                  &CDK_DEV(u)->valid_pbmps,
                                  &CDK_XGSM_INFO(u)->valid_pbmps);
            CDK_PRINTF("  Valid Ports:         %s\n", tmp); 
            CDK_PRINTF("  Flags: 0x%"PRIx32"\n", CDK_XGSM_INFO(u)->flags); 
            if (unit == -1) {
                continue;
            }
            CDK_PRINTF("  Block  Name          Ports\n"); 
            for (b = 0; b < CDK_XGSM_INFO(u)->nblocks; b++) {  
                const cdk_xgsm_block_t *blkp = CDK_XGSM_INFO(u)->blocks+b; 
                if (cdk_xgsm_shell_block_name(u, blkp->blknum, tmp)) {
                    CDK_PRINTF("  %-2d     %-12s  ", blkp->blknum, tmp); 
                    cdk_shell_port_bitmap(tmp, sizeof(tmp),
                                          &blkp->pbmps,
                                          &CDK_XGSM_INFO(u)->valid_pbmps);
                    CDK_PRINTF("%s\n", tmp);
                }
            }
        }
    }
    return 0; 
}

#endif /* CDK_CONFIG_SHELL_INCLUDE_UNIT */
