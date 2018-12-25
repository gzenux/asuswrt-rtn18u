/*
 * $Id
 * $Copyright: Copyright 2009 Broadcom Corporation.
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
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$1,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 *
 * Chip packet vlan command
 */

#include <cdk/cdk_shell.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_string.h>
#include <cdk/cdk_stdlib.h>
#include <cdk/cdk_printf.h>
#include <cdk/cdk_debug.h>

#include <bmd/bmd.h>
#include <bmd/shell/shcmd_switch.h>

#include "bmd_shell_util.h"

int 
bmd_shcmd_switch(int argc, char *argv[])
{
    int unit;
    int rv;
    int value, length;
    char *action;

    if (argc < 1) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);

    action = argv[0];

    if (CDK_STRCMP(action, "vlan") == 0) {
        if (argc == 2) {
            if (CDK_STRCMP(argv[1], "enable") == 0)
                value = 1;
			else if (CDK_STRCMP(argv[1], "disable") == 0)
				value = 0;
			else
				return CDK_SHELL_CMD_BAD_ARG;
			rv = bmd_switch_control_set(unit, bmdSwitch8021QControl, value);
        } else if (argc == 1) {
			rv = bmd_switch_control_get(unit, bmdSwitch8021QControl, &value); 
			if (rv == CDK_E_NONE) {
                if (value)
				    CDK_PRINTF("802.1Q VLAN is enabled \n");
				else
				    CDK_PRINTF("802.1Q VLAN is disabled \n");
			}
        } else {
			return CDK_SHELL_CMD_BAD_ARG;
        }
	}else if (CDK_STRCMP(action, "padding") == 0) {
        if (argc >= 2) {
            if (CDK_STRCMP(argv[1], "enable") == 0) {
                value = 1;
                if (argv[2])
					length = CDK_STRTOUL(argv[2], NULL, 0);
				else
					return CDK_SHELL_CMD_BAD_ARG;
            } else if (CDK_STRCMP(argv[1], "disable") == 0) {
				value = 0;
			} else {
				return CDK_SHELL_CMD_BAD_ARG;
			}
			rv = bmd_packet_padding_set(unit, value, length);
        } else if (argc == 1) {
			rv = bmd_packet_padding_get(unit, &value, &length); 
			if (rv == CDK_E_NONE) {
                if (value)
				    CDK_PRINTF("Padding is enabled to pad size of %d \n", length);
				else
				    CDK_PRINTF("Padding is disabled \n");
			}
        } else {
			return CDK_SHELL_CMD_BAD_ARG;
        }

    }else {
		return CDK_SHELL_CMD_BAD_ARG;
   	}

    return cdk_shell_error(rv);

}
