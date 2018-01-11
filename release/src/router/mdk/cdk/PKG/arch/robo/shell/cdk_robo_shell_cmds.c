/*
 * $Id: cdk_robo_shell_cmds.c,v 1.4 Broadcom SDK $
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
 * ROBO core commands
 *
 */

#include <cdk/cdk_shell.h>
#include <cdk/cdk_device.h>

#include <cdk/arch/shcmd_robo_get.h>
#include <cdk/arch/shcmd_robo_set.h>
#include <cdk/arch/shcmd_robo_geti.h>
#include <cdk/arch/shcmd_robo_seti.h>
#include <cdk/arch/shcmd_robo_list.h>
#include <cdk/arch/shcmd_robo_unit.h>
#include <cdk/arch/robo_cmds.h>

#if CDK_CONFIG_SHELL_INCLUDE_GET == 1
static cdk_shell_command_t shcmd_get = {
    "get",
    cdk_shcmd_robo_get,
    CDK_SHCMD_ROBO_GET_DESC,
    CDK_SHCMD_ROBO_GET_SYNOP,
#if CDK_CONFIG_SHELL_INCLUDE_HELP == 1
    { CDK_SHCMD_ROBO_GET_HELP }
#endif
};
#endif /* CDK_CONFIG_SHELL_INCLUDE_GET */

#if CDK_CONFIG_SHELL_INCLUDE_SET == 1
static cdk_shell_command_t shcmd_set = {
    "set",
    cdk_shcmd_robo_set,
    CDK_SHCMD_ROBO_SET_DESC,
    CDK_SHCMD_ROBO_SET_SYNOP,
#if CDK_CONFIG_SHELL_INCLUDE_HELP == 1
    { CDK_SHCMD_ROBO_SET_HELP }
#endif
};
#endif /* CDK_CONFIG_SHELL_INCLUDE_SET */

#if CDK_CONFIG_SHELL_INCLUDE_GETI == 1
static cdk_shell_command_t shcmd_geti = {
    "geti",
    cdk_shcmd_robo_geti,
    CDK_SHCMD_ROBO_GETI_DESC,
    CDK_SHCMD_ROBO_GETI_SYNOP,
#if CDK_CONFIG_SHELL_INCLUDE_HELP == 1
    { CDK_SHCMD_ROBO_GETI_HELP }
#endif
};
#endif /* CDK_CONFIG_SHELL_INCLUDE_GETI */

#if CDK_CONFIG_SHELL_INCLUDE_SETI == 1
static cdk_shell_command_t shcmd_seti = {
    "seti",
    cdk_shcmd_robo_seti,
    CDK_SHCMD_ROBO_SETI_DESC,
    CDK_SHCMD_ROBO_SETI_SYNOP,
#if CDK_CONFIG_SHELL_INCLUDE_HELP == 1
    { CDK_SHCMD_ROBO_SETI_HELP }
#endif
};
#endif /* CDK_CONFIG_SHELL_INCLUDE_SETI */

#if CDK_CONFIG_SHELL_INCLUDE_LIST == 1
static cdk_shell_command_t shcmd_list = {
    "list",
    cdk_shcmd_robo_list,
    CDK_SHCMD_ROBO_LIST_DESC,
    CDK_SHCMD_ROBO_LIST_SYNOP,
#if CDK_CONFIG_SHELL_INCLUDE_HELP == 1
    { CDK_SHCMD_ROBO_LIST_HELP }
#endif
};
#endif /* CDK_CONFIG_SHELL_INCLUDE_LIST */

#if CDK_CONFIG_SHELL_INCLUDE_UNIT == 1
static cdk_shell_command_t shcmd_unit = {
    "unit",
    cdk_shcmd_robo_unit,
    CDK_SHCMD_ROBO_UNIT_DESC,
    CDK_SHCMD_ROBO_UNIT_SYNOP,
#if CDK_CONFIG_SHELL_INCLUDE_HELP == 1
    { CDK_SHCMD_ROBO_UNIT_HELP }
#endif
};
#endif /* CDK_CONFIG_SHELL_INCLUDE_UNIT */

void
cdk_shell_add_robo_core_cmds(void)
{
#if CDK_CONFIG_SHELL_INCLUDE_GET == 1
    cdk_shell_add_command(&shcmd_get, CDK_DEV_ARCH_ROBO);
#endif
#if CDK_CONFIG_SHELL_INCLUDE_SET == 1
    cdk_shell_add_command(&shcmd_set, CDK_DEV_ARCH_ROBO);
#endif
#if CDK_CONFIG_SHELL_INCLUDE_GETI == 1
    cdk_shell_add_command(&shcmd_geti, CDK_DEV_ARCH_ROBO);
#endif
#if CDK_CONFIG_SHELL_INCLUDE_SETI == 1
    cdk_shell_add_command(&shcmd_seti, CDK_DEV_ARCH_ROBO);
#endif
#if CDK_CONFIG_SHELL_INCLUDE_LIST == 1
    cdk_shell_add_command(&shcmd_list, CDK_DEV_ARCH_ROBO);
#endif
#if CDK_CONFIG_SHELL_INCLUDE_UNIT == 1
    cdk_shell_add_command(&shcmd_unit, CDK_DEV_ARCH_ROBO);
#endif
}
