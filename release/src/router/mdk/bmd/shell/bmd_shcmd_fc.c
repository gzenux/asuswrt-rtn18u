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
#include <bmd/shell/shcmd_fc.h>

#include "bmd_shell_util.h"

int 
bmd_shcmd_fc(int argc, char *argv[])
{
    int unit;
    int rv;
    int queue;
    int value;
    int set = 0;
    char *action;
	bmd_switch_control_t type;

    if (argc == 0) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);

    action = argv[0];

    if (CDK_STRCMP(action, "threshold") == 0) {
		if ((argv[1] == NULL) || (argv[2] == NULL))
            return CDK_SHELL_CMD_BAD_ARG;		
		action = argv[1];

		queue = CDK_STRTOUL(argv[2], NULL, 0);

        if (argv[3]) {
			set = 1;
            value = CDK_STRTOUL(argv[3], NULL, 0);
       	}
		if (CDK_STRCMP(action, "txqhyst") == 0) {
            type = bmdSwitchTxQHiHysteresisThreshold;
		} else if (CDK_STRCMP(action, "txqdrop") == 0) {
            type = bmdSwitchTxQHiDropThreshold;
		} else if (CDK_STRCMP(action, "txqpause") == 0) {
            type = bmdSwitchTxQHiPauseThreshold;
		} else if (CDK_STRCMP(action, "txqlowdrop") == 0) {
            type = bmdSwitchTxQLowDropThreshold;
		} else if (CDK_STRCMP(action, "tothyst") == 0) {
            type = bmdSwitchTotalHysteresisThreshold;
		} else if (CDK_STRCMP(action, "totpause") == 0) {
            type = bmdSwitchTotalPauseThreshold;
		} else if (CDK_STRCMP(action, "txqdrop") == 0) {
            type = bmdSwitchTotalDropThreshold;
        } else {
            return CDK_SHELL_CMD_BAD_ARG;		
        }
		if (set) {
			rv = bmd_switch_control_priority_set(unit, queue, type, value);
		} else {
			rv = bmd_switch_control_priority_get(unit, queue, type, &value);
			if (rv == CDK_E_NONE) {
				CDK_PRINTF("Threshold value is 0x%x \n", value);
			}
		}
    } else {
        if (argv[1]) {
			set = 1;
            if (CDK_STRCMP(argv[1], "enable") == 0)
                value = 1;
			else if (CDK_STRCMP(argv[1], "disable") == 0)
				value = 0;
			else
				return CDK_SHELL_CMD_BAD_ARG;
       	}
        if (CDK_STRCMP(action, "txqdrop") == 0) {
            type = bmdSwitchTXQDropControl;
        } else if (CDK_STRCMP(action, "txqpause") == 0) {
            type = bmdSwitchTXQPauseControl;
        } else if (CDK_STRCMP(action, "totdrop") == 0) {
            type = bmdSwitchTotalDropControl;
        } else if (CDK_STRCMP(action, "totpause") == 0) {
            type = bmdSwitchTotalPauseControl;
       	} else {
			return CDK_SHELL_CMD_BAD_ARG;
       	}	
		if (set) {
			rv = bmd_switch_control_set(unit, type, value);
		} else {
			rv = bmd_switch_control_get(unit, type, &value);
			if (rv == CDK_E_NONE) {
				if (value)
					CDK_PRINTF("Enabled \n");
				else
					CDK_PRINTF("Disabled \n");
			}
		}
    }

    return cdk_shell_error(rv);
}
