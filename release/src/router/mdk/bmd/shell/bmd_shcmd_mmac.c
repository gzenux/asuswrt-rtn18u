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


#include <bmd/shell/shcmd_mmac.h>

#include "bmd_shell_util.h"

int 
bmd_shcmd_mmac(int argc, char *argv[])
{
    int unit;
    int rv;
    int entry_num;
    int vlan;
    cdk_pbmp_t pbmp;
    int port, portmap;
    int priority, used, valid;
    bmd_mac_addr_t mac_addr;

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);

    if (argc < 2) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    entry_num = CDK_STRTOUL(argv[1], NULL, 0);

    if (CDK_STRCMP(argv[0], "add") == 0) {
		if (argc != 6) {
			return CDK_SHELL_CMD_BAD_ARG;
		}
		vlan = CDK_STRTOUL(argv[2], NULL, 0);
		if (bmd_shell_parse_mac_addr(argv[3], &mac_addr) < 0) {
			return CDK_SHELL_CMD_BAD_ARG;
		}
		port = bmd_shell_parse_port_str(unit, argv[4], &pbmp);
		if (port < 0) {
			return CDK_SHELL_CMD_BAD_ARG;
		}
        portmap = CDK_PBMP_WORD_GET(pbmp, 0);
		priority = CDK_STRTOUL(argv[5], NULL, 0);
		rv = bmd_mcast_mac_addr_set(unit, entry_num, vlan, &mac_addr, portmap, priority, 1);
    } else if (CDK_STRCMP(argv[0], "del") == 0) {
		if (argc != 2) {
			return CDK_SHELL_CMD_BAD_ARG;
		}
		rv = bmd_mcast_mac_addr_set(unit, entry_num, vlan, &mac_addr, portmap, priority, 0);
	} else if (CDK_STRCMP(argv[0], "show") == 0) {
		if (argc != 2) {
			return CDK_SHELL_CMD_BAD_ARG;
		}
		rv = bmd_mcast_mac_addr_get(unit, entry_num, &vlan, &mac_addr, &portmap, &priority, &used, &valid);
		if (rv == CDK_E_NONE) {
			CDK_PRINTF("VLAN = 0x%x; MAC = %02x:%02x:%02x:%02x:%02x:%02x \n", vlan, mac_addr.b[0],
				        mac_addr.b[1],mac_addr.b[2],mac_addr.b[3],mac_addr.b[4],mac_addr.b[5]);
			CDK_PRINTF("portmap = 0x%x, priority = 0x%x; used = %d; valid = %d \n", portmap, 
				        priority, used, valid);
		}
    } else {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    return cdk_shell_error(rv);
}
