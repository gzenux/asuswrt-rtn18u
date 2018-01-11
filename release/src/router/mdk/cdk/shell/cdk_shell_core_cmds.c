/*
 * $Id: cdk_shell_core_cmds.c,v 1.8 Broadcom SDK $
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
 * CDK core commands
 *
 * This file also serves as a template for installing additional
 * shell commands.
 *
 * Note that the command structures are linked directly into the
 * command table, and will they will be modified by the shell, 
 * hence they cannot be declared as type const.
 */

#include <cdk/cdk_shell.h>

#include <cdk/shell/shcmd_quit.h>
#include <cdk/shell/shcmd_help.h>
#include <cdk/shell/shcmd_cdk.h>
#include <cdk/shell/shcmd_debug.h>

static cdk_shell_command_t shcmd_quit = {
    "quit",
    cdk_shcmd_quit,
    CDK_SHCMD_QUIT_DESC,
};

static cdk_shell_command_t shcmd_exit = {
    "exit",
    cdk_shcmd_quit,
    CDK_SHCMD_QUIT_DESC,
};

static cdk_shell_command_t shcmd_help = {
    "help",
    cdk_shcmd_help,
    CDK_SHCMD_HELP_DESC,
    CDK_SHCMD_HELP_SYNOP,
#if CDK_CONFIG_SHELL_INCLUDE_HELP == 1
    { CDK_SHCMD_HELP_HELP }
#endif
};

#if CDK_CONFIG_SHELL_INCLUDE_CDK == 1
static cdk_shell_command_t shcmd_cdk = {
    "cdk",
    cdk_shcmd_cdk,
    CDK_SHCMD_CDK_DESC,
    CDK_SHCMD_CDK_SYNOP,
#if CDK_CONFIG_SHELL_INCLUDE_HELP == 1
    { CDK_SHCMD_CDK_HELP }
#endif
};
#endif /* CDK_CONFIG_SHELL_INCLUDE_CDK */

#if CDK_CONFIG_SHELL_INCLUDE_DEBUG == 1
static cdk_shell_command_t shcmd_debug = {
    "debug",
    cdk_shcmd_debug,
    CDK_SHCMD_DEBUG_DESC,
    CDK_SHCMD_DEBUG_SYNOP,
#if CDK_CONFIG_SHELL_INCLUDE_HELP == 1
    { CDK_SHCMD_DEBUG_HELP }
#endif
};
#endif /* CDK_CONFIG_SHELL_INCLUDE_DEBUG */

void
cdk_shell_add_core_cmds(void)
{
    cdk_shell_add_command(&shcmd_help, 0);
    cdk_shell_add_command(&shcmd_quit, 0);
    cdk_shell_add_command(&shcmd_exit, 0);
#if CDK_CONFIG_SHELL_INCLUDE_CDK == 1
    cdk_shell_add_command(&shcmd_cdk, 0);
#endif /* CDK_CONFIG_SHELL_INCLUDE_CDK */
#if CDK_CONFIG_SHELL_INCLUDE_DEBUG == 1
    cdk_shell_add_command(&shcmd_debug, 0);
#endif /* CDK_CONFIG_SHELL_INCLUDE_DEBUG */
}
