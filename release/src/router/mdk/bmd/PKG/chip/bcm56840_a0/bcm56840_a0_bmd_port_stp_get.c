#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56840_A0 == 1

/*
 * $Id: bcm56840_a0_bmd_port_stp_get.c,v 1.1 Broadcom SDK $
 * 
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
 */

#include <bmd/bmd.h>

#include <bmdi/arch/xgs_stp_xlate.h>

#include <cdk/chip/bcm56840_a0_defs.h>
#include <cdk/cdk_assert.h>

#include "bcm56840_a0_bmd.h"
#include "bcm56840_a0_internal.h"

int
bcm56840_a0_bmd_port_stp_get(int unit, int port, bmd_stp_state_t *state)
{
    int ioerr = 0;
    int lport;
    int hw_state;
    STG_TABm_t stg_tab;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    lport = P2L(unit, port);

    ioerr += READ_STG_TABm(unit, 1, &stg_tab);

    switch (lport) {
    case 1: hw_state = STG_TABm_SP_TREE_PORT1f_GET(stg_tab); break;
    case 2: hw_state = STG_TABm_SP_TREE_PORT2f_GET(stg_tab); break;
    case 3: hw_state = STG_TABm_SP_TREE_PORT3f_GET(stg_tab); break;
    case 4: hw_state = STG_TABm_SP_TREE_PORT4f_GET(stg_tab); break;
    case 5: hw_state = STG_TABm_SP_TREE_PORT5f_GET(stg_tab); break;
    case 6: hw_state = STG_TABm_SP_TREE_PORT6f_GET(stg_tab); break;
    case 7: hw_state = STG_TABm_SP_TREE_PORT7f_GET(stg_tab); break;
    case 8: hw_state = STG_TABm_SP_TREE_PORT8f_GET(stg_tab); break;
    case 9: hw_state = STG_TABm_SP_TREE_PORT9f_GET(stg_tab); break;
    case 10: hw_state = STG_TABm_SP_TREE_PORT10f_GET(stg_tab); break;
    case 11: hw_state = STG_TABm_SP_TREE_PORT11f_GET(stg_tab); break;
    case 12: hw_state = STG_TABm_SP_TREE_PORT12f_GET(stg_tab); break;
    case 13: hw_state = STG_TABm_SP_TREE_PORT13f_GET(stg_tab); break;
    case 14: hw_state = STG_TABm_SP_TREE_PORT14f_GET(stg_tab); break;
    case 15: hw_state = STG_TABm_SP_TREE_PORT15f_GET(stg_tab); break;
    case 16: hw_state = STG_TABm_SP_TREE_PORT16f_GET(stg_tab); break;
    case 17: hw_state = STG_TABm_SP_TREE_PORT17f_GET(stg_tab); break;
    case 18: hw_state = STG_TABm_SP_TREE_PORT18f_GET(stg_tab); break;
    case 19: hw_state = STG_TABm_SP_TREE_PORT19f_GET(stg_tab); break;
    case 20: hw_state = STG_TABm_SP_TREE_PORT20f_GET(stg_tab); break;
    case 21: hw_state = STG_TABm_SP_TREE_PORT21f_GET(stg_tab); break;
    case 22: hw_state = STG_TABm_SP_TREE_PORT22f_GET(stg_tab); break;
    case 23: hw_state = STG_TABm_SP_TREE_PORT23f_GET(stg_tab); break;
    case 24: hw_state = STG_TABm_SP_TREE_PORT24f_GET(stg_tab); break;
    case 25: hw_state = STG_TABm_SP_TREE_PORT25f_GET(stg_tab); break;
    case 26: hw_state = STG_TABm_SP_TREE_PORT26f_GET(stg_tab); break;
    case 27: hw_state = STG_TABm_SP_TREE_PORT27f_GET(stg_tab); break;
    case 28: hw_state = STG_TABm_SP_TREE_PORT28f_GET(stg_tab); break;
    case 29: hw_state = STG_TABm_SP_TREE_PORT29f_GET(stg_tab); break;
    case 30: hw_state = STG_TABm_SP_TREE_PORT30f_GET(stg_tab); break;
    case 31: hw_state = STG_TABm_SP_TREE_PORT31f_GET(stg_tab); break;
    case 32: hw_state = STG_TABm_SP_TREE_PORT32f_GET(stg_tab); break;
    case 33: hw_state = STG_TABm_SP_TREE_PORT33f_GET(stg_tab); break;
    case 34: hw_state = STG_TABm_SP_TREE_PORT34f_GET(stg_tab); break;
    case 35: hw_state = STG_TABm_SP_TREE_PORT35f_GET(stg_tab); break;
    case 36: hw_state = STG_TABm_SP_TREE_PORT36f_GET(stg_tab); break;
    case 37: hw_state = STG_TABm_SP_TREE_PORT37f_GET(stg_tab); break;
    case 38: hw_state = STG_TABm_SP_TREE_PORT38f_GET(stg_tab); break;
    case 39: hw_state = STG_TABm_SP_TREE_PORT39f_GET(stg_tab); break;
    case 40: hw_state = STG_TABm_SP_TREE_PORT40f_GET(stg_tab); break;
    case 41: hw_state = STG_TABm_SP_TREE_PORT41f_GET(stg_tab); break;
    case 42: hw_state = STG_TABm_SP_TREE_PORT42f_GET(stg_tab); break;
    case 43: hw_state = STG_TABm_SP_TREE_PORT43f_GET(stg_tab); break;
    case 44: hw_state = STG_TABm_SP_TREE_PORT44f_GET(stg_tab); break;
    case 45: hw_state = STG_TABm_SP_TREE_PORT45f_GET(stg_tab); break;
    case 46: hw_state = STG_TABm_SP_TREE_PORT46f_GET(stg_tab); break;
    case 47: hw_state = STG_TABm_SP_TREE_PORT47f_GET(stg_tab); break;
    case 48: hw_state = STG_TABm_SP_TREE_PORT48f_GET(stg_tab); break;
    case 49: hw_state = STG_TABm_SP_TREE_PORT49f_GET(stg_tab); break;
    case 50: hw_state = STG_TABm_SP_TREE_PORT50f_GET(stg_tab); break;
    case 51: hw_state = STG_TABm_SP_TREE_PORT51f_GET(stg_tab); break;
    case 52: hw_state = STG_TABm_SP_TREE_PORT52f_GET(stg_tab); break;
    case 53: hw_state = STG_TABm_SP_TREE_PORT53f_GET(stg_tab); break;
    case 54: hw_state = STG_TABm_SP_TREE_PORT54f_GET(stg_tab); break;
    case 55: hw_state = STG_TABm_SP_TREE_PORT55f_GET(stg_tab); break;
    case 56: hw_state = STG_TABm_SP_TREE_PORT56f_GET(stg_tab); break;
    case 57: hw_state = STG_TABm_SP_TREE_PORT57f_GET(stg_tab); break;
    case 58: hw_state = STG_TABm_SP_TREE_PORT58f_GET(stg_tab); break;
    case 59: hw_state = STG_TABm_SP_TREE_PORT59f_GET(stg_tab); break;
    case 60: hw_state = STG_TABm_SP_TREE_PORT60f_GET(stg_tab); break;
    case 61: hw_state = STG_TABm_SP_TREE_PORT61f_GET(stg_tab); break;
    case 62: hw_state = STG_TABm_SP_TREE_PORT62f_GET(stg_tab); break;
    case 63: hw_state = STG_TABm_SP_TREE_PORT63f_GET(stg_tab); break;
    case 64: hw_state = STG_TABm_SP_TREE_PORT64f_GET(stg_tab); break;
    case 65: hw_state = STG_TABm_SP_TREE_PORT65f_GET(stg_tab); break;
    default:
        return ioerr ? CDK_E_IO : CDK_E_PORT;
    }

    if (CDK_FAILURE(bmd_xgs_stp_state_from_hw(hw_state, state))) {
        /* should never fail */
        CDK_ASSERT(0);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56840_A0 */
