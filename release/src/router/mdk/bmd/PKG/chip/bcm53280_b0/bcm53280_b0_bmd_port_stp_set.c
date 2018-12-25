#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53280_B0 == 1

/*
 * $Id: bcm53280_b0_bmd_port_stp_set.c,v 1.2 Broadcom SDK $
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

#include <bmdi/arch/robo_stp_xlate.h>

#include <cdk/chip/bcm53280_b0_defs.h>
#include <cdk/arch/robo_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm53280_b0_bmd.h"

int
bcm53280_b0_bmd_port_stp_set(int unit, int port, bmd_stp_state_t state)
{
    int ioerr = 0;
    int hw_state;
    MSPT_TABm_t stg_tab;
    
    BMD_CHECK_UNIT(unit);

    /* TB use 2 bits (4 states) differ from Robo other chips */
    switch (state) {
    case bmdSpanningTreeDisabled:
        hw_state = 0;
        break;
    case bmdSpanningTreeBlocking:
        hw_state = 1;
        break;
    case bmdSpanningTreeListening:
        hw_state = 1;
        break;
    case bmdSpanningTreeLearning:
        hw_state = 2;
        break;
    case bmdSpanningTreeForwarding:
        hw_state = 3;
        break;
    default:
        return CDK_E_PARAM;
        
    }

    ioerr += READ_MSPT_TABm(unit, 1, &stg_tab);

    switch (port) {
    case 0: MSPT_TABm_MSP_TREE_PORT0f_SET(stg_tab, hw_state); break;
    case 1: MSPT_TABm_MSP_TREE_PORT1f_SET(stg_tab, hw_state); break;
    case 2: MSPT_TABm_MSP_TREE_PORT2f_SET(stg_tab, hw_state); break;
    case 3: MSPT_TABm_MSP_TREE_PORT3f_SET(stg_tab, hw_state); break;
    case 4: MSPT_TABm_MSP_TREE_PORT4f_SET(stg_tab, hw_state); break;
    case 5: MSPT_TABm_MSP_TREE_PORT5f_SET(stg_tab, hw_state); break;
    case 6: MSPT_TABm_MSP_TREE_PORT6f_SET(stg_tab, hw_state); break;
    case 7: MSPT_TABm_MSP_TREE_PORT7f_SET(stg_tab, hw_state); break;
    case 8: MSPT_TABm_MSP_TREE_PORT8f_SET(stg_tab, hw_state); break;
    case 9: MSPT_TABm_MSP_TREE_PORT9f_SET(stg_tab, hw_state); break;
    case 10: MSPT_TABm_MSP_TREE_PORT10f_SET(stg_tab, hw_state); break;
    case 11: MSPT_TABm_MSP_TREE_PORT11f_SET(stg_tab, hw_state); break;
    case 12: MSPT_TABm_MSP_TREE_PORT12f_SET(stg_tab, hw_state); break;
    case 13: MSPT_TABm_MSP_TREE_PORT13f_SET(stg_tab, hw_state); break;
    case 14: MSPT_TABm_MSP_TREE_PORT14f_SET(stg_tab, hw_state); break;
    case 15: MSPT_TABm_MSP_TREE_PORT15f_SET(stg_tab, hw_state); break;
    case 16: MSPT_TABm_MSP_TREE_PORT16f_SET(stg_tab, hw_state); break;
    case 17: MSPT_TABm_MSP_TREE_PORT17f_SET(stg_tab, hw_state); break;
    case 18: MSPT_TABm_MSP_TREE_PORT18f_SET(stg_tab, hw_state); break;
    case 19: MSPT_TABm_MSP_TREE_PORT19f_SET(stg_tab, hw_state); break;
    case 20: MSPT_TABm_MSP_TREE_PORT20f_SET(stg_tab, hw_state); break;
    case 21: MSPT_TABm_MSP_TREE_PORT21f_SET(stg_tab, hw_state); break;
    case 22: MSPT_TABm_MSP_TREE_PORT22f_SET(stg_tab, hw_state); break;
    case 23: MSPT_TABm_MSP_TREE_PORT23f_SET(stg_tab, hw_state); break;
    case 24: MSPT_TABm_MSP_TREE_PORT24f_SET(stg_tab, hw_state); break;
    case 25: MSPT_TABm_MSP_TREE_PORT25f_SET(stg_tab, hw_state); break;
    case 26: MSPT_TABm_MSP_TREE_PORT26f_SET(stg_tab, hw_state); break;
    case 27: MSPT_TABm_MSP_TREE_PORT27f_SET(stg_tab, hw_state); break;
    case 28: MSPT_TABm_MSP_TREE_PORT28f_SET(stg_tab, hw_state); break;
    default:
        return ioerr ? CDK_E_IO : CDK_E_PORT;
    }

    ioerr += WRITE_MSPT_TABm(unit, 1, stg_tab);
    return ioerr ? CDK_E_IO : CDK_E_NONE;
}
#endif /* CDK_CONFIG_INCLUDE_BCM53280_B0 */
