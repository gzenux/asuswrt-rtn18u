/*
 * $Id: bmd_shcmd_port_mode.c,v 1.26 Broadcom SDK $
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
 * Create VLAN command
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
#include <bmd/shell/shcmd_port_mode.h>

#include "bmd_shell_util.h"

static char *_pm_str[] = {
    BMD_PORT_MODE_STRINGS
};

/* Print abitrary string in lowercase */
static void
_lc_print(char *str)
{
    while (*str) {
        CDK_PRINTF("%c", CDK_TOLOWER(*str));
        str++;
    }
}

/* Return alternate port mode string */
static char *
_pm_alt(const char *str, char *alt_str)
{
    char *ptr;
    if (CDK_STRCMP(str, "2500fd") == 0) {
        CDK_STRCPY(alt_str, "2.5g");
    } else {
        CDK_STRCPY(alt_str, str);
        if ((ptr = CDK_STRSTR(alt_str, "000fd")) != NULL) {
            CDK_STRCPY(ptr, "g");
        } else {
            return NULL;
        }
    }
    return alt_str;
}

static int
_show_port_mode(int unit, int port)
{
    bmd_port_mode_t pm, port_mode;
    uint32_t flags;
    int rv;
    char *mode_str = "-";
    char port_str[16];

    rv = bmd_port_mode_get(unit, port, &port_mode, &flags);

    if (CDK_SUCCESS(rv)) {
        if (port_mode != bmdPortModeAuto) {
            for (pm = 0; pm < COUNTOF(_pm_str); pm++) {
                if (port_mode == pm) {
                    mode_str = _pm_str[pm];
                    break;
                }
            }
        }
        cdk_shell_lport(port_str, sizeof(port_str), unit, port);
        CDK_PRINTF("Port %s: ", port_str);
        _lc_print(mode_str);
        if (flags & BMD_PORT_MODE_F_AUTONEG) {
            CDK_PRINTF(", auto-neg");
        } else {
            CDK_PRINTF(", forced");
        }
        if (flags & BMD_PORT_MODE_F_MAC_LOOPBACK) {
            CDK_PRINTF(", MAC loopback");
        }
        if (flags & BMD_PORT_MODE_F_PHY_LOOPBACK) {
            CDK_PRINTF(", PHY loopback");
        }
        if (flags & BMD_PORT_MODE_F_REMOTE_LOOPBACK) {
            CDK_PRINTF(", remote loopback");
        }
        if (flags & BMD_PORT_MODE_F_LINK_UP) {
            CDK_PRINTF(", link up");
        } else {
            CDK_PRINTF(", link down");
        }
        if (flags & BMD_PORT_MODE_F_HIGIG) {
            CDK_PRINTF(", higig");
        }
        if (flags & BMD_PORT_MODE_F_HIGIG2) {
            CDK_PRINTF(", higig2");
        }
        if (flags & BMD_PORT_MODE_F_HGLITE) {
            CDK_PRINTF(", hglite");
        }
        if (flags & BMD_PORT_MODE_F_EEE) {
            CDK_PRINTF(", eee");
        }
        if (flags & BMD_PORT_MODE_F_AUTOGREEEN) {
            CDK_PRINTF(", autogreeen");
        }
        CDK_PRINTF("\n");
    }
    return rv;
}

int 
bmd_shcmd_port_mode(int argc, char *argv[])
{
    int unit;
    cdk_pbmp_t pbmp;
    int lport, port = -1;
    int update = 0;
    int ax;
    char *ptr;
    bmd_port_mode_t pm, port_mode = bmdPortModeCount;
    uint32_t flags = 0;
    int rv = CDK_E_NONE;
    char alt_str[32];

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);

    if (argc == 0) {
        CDK_PRINTF("Valid port modes:\n");
        for (pm = 0; pm < COUNTOF(_pm_str); pm++) {
            _lc_print(_pm_str[pm]);
            CDK_PRINTF("\n");
        }
        for (pm = 0; pm < COUNTOF(_pm_str); pm++) {
            if ((ptr = _pm_alt(_pm_str[pm], alt_str)) != NULL) {
                CDK_PRINTF("%s\n", ptr);
            }
        }
        return CDK_SHELL_CMD_OK;
    }

    for (ax = 0; ax < argc; ax++) {
        if ((ptr = cdk_shell_opt_val(argc, argv, "loopback", &ax)) != NULL ||
            (ptr = cdk_shell_opt_val(argc, argv, "lb", &ax)) != NULL) {
            if (CDK_STRCMP(ptr, "mac") == 0) {
                flags |= BMD_PORT_MODE_F_MAC_LOOPBACK;
            } else if (CDK_STRCMP(ptr, "phy") == 0) {
                flags |= BMD_PORT_MODE_F_PHY_LOOPBACK;
            } else if (CDK_STRCMP(ptr, "remote") == 0) {
                flags |= BMD_PORT_MODE_F_REMOTE_LOOPBACK;
            } else {
                return CDK_SHELL_CMD_BAD_ARG;
            }
        } else if (CDK_STRCMP(argv[ax], "higig") == 0) {
            flags |= BMD_PORT_MODE_F_HIGIG;
        } else if (CDK_STRCMP(argv[ax], "higig2") == 0) {
            flags |= BMD_PORT_MODE_F_HIGIG2;
        } else if (CDK_STRCMP(argv[ax], "hglite") == 0) {
            flags |= BMD_PORT_MODE_F_HGLITE;
        } else if (CDK_STRCMP(argv[ax], "eee") == 0) {
            flags |= BMD_PORT_MODE_F_EEE;
        } else if (CDK_STRCMP(argv[ax], "autogreeen") == 0) {
            flags |= BMD_PORT_MODE_F_AUTOGREEEN;
        } else if (CDK_STRCMP(argv[ax], "update") == 0) {
            update = 1;
        } else if (port < 0) {
            port = bmd_shell_parse_port_str(unit, argv[ax], &pbmp);
        } else if (port_mode == bmdPortModeCount) {
            for (pm = 0; pm < COUNTOF(_pm_str); pm++) {
                if (CDK_STRCASECMP(argv[ax], _pm_str[pm]) == 0) {
                    port_mode = pm;
                    break;
                }
                if ((ptr = _pm_alt(_pm_str[pm], alt_str)) != NULL) {
                    if (CDK_STRCMP(argv[ax], ptr) == 0) {
                        port_mode = pm;
                        break;
                    }
                }
            }
            if (port_mode == bmdPortModeCount) {
                return CDK_SHELL_CMD_BAD_ARG;
            }
        } else {
            return CDK_SHELL_CMD_BAD_ARG;
        }
    }

    if (port < 0) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    if (CDK_SUCCESS(rv)) {
        if (update) {
            CDK_LPORT_ITER(unit, pbmp, lport, port) {
                rv = bmd_port_mode_update(unit, port);
                if (CDK_FAILURE(rv)) {
                    break;
                }
            }
        }
    }

    if (CDK_SUCCESS(rv)) {
        if (port_mode == bmdPortModeCount) {
            /* No mode specified, perform get */
            CDK_LPORT_ITER(unit, pbmp, lport, port) {
                rv = _show_port_mode(unit, port);
                if (CDK_FAILURE(rv)) {
                    break;
                }
            }
        } else {
            CDK_LPORT_ITER(unit, pbmp, lport, port) {
                rv = bmd_port_mode_set(unit, port, port_mode, flags);
                if (CDK_FAILURE(rv)) {
                    break;
                }
            }
        }
    }

    return cdk_shell_error(rv);
}
