/*
 * $Id: bmd_shcmd_port_info.c,v 1.3 Broadcom SDK $
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
 */

#include <cdk/cdk_shell.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_string.h>
#include <cdk/cdk_stdlib.h>
#include <cdk/cdk_printf.h>
#include <cdk/cdk_ctype.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>

#include <bmd/bmd.h>
#include <bmd/bmd_device.h>
#include <bmd/bmd_phy_ctrl.h>
#include <bmd/shell/shcmd_port_info.h>

#include "bmd_shell_util.h"

static int
_show_phy_info(int unit, int port)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    phy_bus_t **bus;

    /* Check that we have PHY bus list */
    bus = BMD_PORT_PHY_BUS(unit, port);
    if (bus == NULL) {
        return CDK_E_NONE;
    }

    /* Loop over PHY buses for this port */
    while (*bus != NULL) {
        CDK_PRINTF("%s(0x%04"PRIx32") ",
                   (*bus)->drv_name, (*bus)->phy_addr(port));
        bus++;
    }
#endif

    return CDK_E_NONE;
}

static int
_show_port_info(int unit, int port)
{
    uint32_t speed;
    uint32_t properties = BMD_PORT_PROPERTIES(unit, port);

    if (properties & BMD_PORT_FE) {
        CDK_PRINTF("FE");
    } else if (properties & BMD_PORT_GE) {
        CDK_PRINTF("GE");
    } else if (properties & BMD_PORT_XE) {
        CDK_PRINTF("XE");
    } else if (properties & BMD_PORT_HG) {
        CDK_PRINTF("HG");
    } else {
        CDK_PRINTF("--");
    }
    if (properties & BMD_PORT_FLEX) {
        CDK_PRINTF("(f)");
    }
    CDK_PRINTF(" phys=%d", port);
    if (BMD_PORT_P2L(unit)) {
        CDK_PRINTF(" logic=%d", (BMD_PORT_P2L(unit))(unit, port, 0));
    }
    if (BMD_PORT_P2M(unit)) {
        CDK_PRINTF(" mmu=%d", (BMD_PORT_P2M(unit))(unit, port, 0));
    }
    if (BMD_PORT_SPEED_MAX(unit)) {
        speed = (BMD_PORT_SPEED_MAX(unit))(unit, port);
        if (speed > 0) {
            CDK_PRINTF(" speed=");
            if (speed < 1000) {
                CDK_PRINTF("%"PRIu32"M", speed);
            } else if (speed % 1000) {
                CDK_PRINTF("%"PRIu32".%"PRIu32"G",
                           speed / 1000, (speed % 1000) / 100);
            } else {
                CDK_PRINTF("%"PRIu32"G", speed / 1000);
            }
        }
    }

    return CDK_E_NONE;
}

int 
bmd_shcmd_port_info(int argc, char *argv[])
{
    int unit;
    cdk_pbmp_t pbmp;
    int lport, port = -1;
    int ax;
    int phybus = 0;
    int rv = CDK_E_NONE;

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);

    for (ax = 0; ax < argc; ax++) {
        if (CDK_STRCMP(argv[ax], "phybus") == 0) {
            phybus = 1;
        } else if (port < 0) {
            port = bmd_shell_parse_port_str(unit, argv[ax], &pbmp);
        } else {
            return CDK_SHELL_CMD_BAD_ARG;
        }
    }

    if (port < 0) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    CDK_LPORT_ITER(unit, pbmp, lport, port) {
        CDK_PRINTF("Port %d: ", CDK_PORT_MAP_P2L(unit, port));
        if (phybus) {
            rv = _show_phy_info(unit, port);
        } else {
            rv = _show_port_info(unit, port);
        }
        CDK_PRINTF("\n");
        if (CDK_FAILURE(rv)) {
            break;
        }
    }

    return cdk_shell_error(rv);
}
