/*
 * $Id: bmd_shcmd_stat.c,v 1.10 Broadcom SDK $
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
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>

#include <bmd/bmd.h>
#include <bmd/shell/shcmd_stat.h>

#include "bmd_shell_util.h"

static struct {
    bmd_stat_t  stat;
    char        *name;
} _stat_ctrs[] = {
    { bmdStatTxPackets,         "Tx packets" },
    { bmdStatTxBytes,           "Tx bytes"   },
    { bmdStatTxErrors,          "Tx errors"  },
    { bmdStatRxPackets,         "Rx packets" },
    { bmdStatRxBytes,           "Rx bytes"   },
    { bmdStatRxErrors,          "Rx errors"  },
    { bmdStatRxDrops,           "Rx drops"   }
};

static int
_clear_stat(int unit, int port)
{
    int rv = CDK_E_NONE;
    int idx;

    for (idx = 0; idx < COUNTOF(_stat_ctrs); idx++) {
        rv = bmd_stat_clear(unit, port, _stat_ctrs[idx].stat);
        if (CDK_FAILURE(rv)) {
            break;
        }
    }
    return rv;
}

static int
_show_stat(int unit, int port)
{
    bmd_counter_t counter;
    int rv = CDK_E_NONE;
    int idx;

    CDK_PRINTF("Port %d statistics:\n", CDK_PORT_MAP_P2L(unit, port));
    for (idx = 0; idx < COUNTOF(_stat_ctrs); idx++) {
        rv = bmd_stat_get(unit, port, _stat_ctrs[idx].stat, &counter);
        if (CDK_FAILURE(rv)) {
            break;
        }
        CDK_PRINTF("%-16s %10"PRIu32"\n", _stat_ctrs[idx].name, counter.v[0]);
    }
    return rv;
}

int 
bmd_shcmd_stat(int argc, char *argv[])
{
    int unit;
    cdk_pbmp_t pbmp;
    int lport, port = -1;
    int clear = 0;
    int ax;
    int rv = CDK_E_NONE;

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);

    for (ax = 0; ax < argc; ax++) {
        if (CDK_STRCMP(argv[ax], "clear") == 0) {
            clear = 1;
        } else if (port < 0) {
            port = bmd_shell_parse_port_str(unit, argv[ax], &pbmp);
        } else {
            return CDK_SHELL_CMD_BAD_ARG;
        }
    }

    if (port < 0) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    if (clear) {
        CDK_LPORT_ITER(unit, pbmp, lport, port) {
            rv = _clear_stat(unit, port);
            if (CDK_FAILURE(rv)) {
                break;
            }
        }
    } else {
        CDK_LPORT_ITER(unit, pbmp, lport, port) {
            rv = _show_stat(unit, port);
            if (CDK_FAILURE(rv)) {
                break;
            }
        }
    }

    return cdk_shell_error(rv);
}
