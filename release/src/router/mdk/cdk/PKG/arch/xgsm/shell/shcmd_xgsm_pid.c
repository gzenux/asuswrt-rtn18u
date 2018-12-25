/*
 * $Id: shcmd_xgsm_pid.c,v 1.1 Broadcom SDK $
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
 * XGSM shell command PID
 *
 * This command prints out how an input identifier is parsed. 
 * Used mainly for debugging. 
 * 
 * If you aren't getting the right information based on the input identifier, 
 * you can use this command to see if it got parsed incorrectly. 
 *
 */

#include <cdk/arch/xgsm_shell.h>

#include <cdk/arch/shcmd_xgsm_pid.h>

#if CDK_CONFIG_SHELL_INCLUDE_PID == 1

int
cdk_shcmd_xgsm_pid(int argc, char* argv[])
{
    cdk_shell_id_t sid; 
    int unit;

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);
    if(!CDK_DEV_EXISTS(unit)) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    if(argc == 0) {
        return cdk_shell_parse_error("identifier", *argv); 
    }
    
    if(cdk_shell_parse_id(argv[0], &sid, 0) < 0) {
        return cdk_shell_parse_error("identifier", *argv); 
    }

    if(sid.addr.valid) {
        CDK_PRINTF("Address: '%s' : 0x%"PRIx32" : %d : %d\n", 
                   sid.addr.name, sid.addr.name32, 
                   sid.addr.start, sid.addr.end); 
    }
    else {
        CDK_PRINTF("Address: (invalid)\n"); 
    }

    if(sid.block.valid) {
        CDK_PRINTF("Block:   '%s' : 0x%"PRIx32" : %d : %d\n", 
                   sid.block.name, sid.block.name32, 
                   sid.block.start, sid.block.end); 
    }
    else {
        CDK_PRINTF("Block:   (invalid)\n"); 
    }

    if(sid.port.valid) {
        CDK_PRINTF("Port:    '%s' : 0x%"PRIx32" : %d : %d\n", 
                   sid.port.name, sid.port.name32, 
                   sid.port.start, sid.port.end); 
    }
    else {
        CDK_PRINTF("Port:    (invalid)\n"); 
    }
    
    return 0; 
}

#endif
