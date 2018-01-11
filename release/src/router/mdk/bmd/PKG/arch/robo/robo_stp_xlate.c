/*
 * $Id: robo_stp_xlate.c,v 1.4 Broadcom SDK $
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

#ifdef CDK_CONFIG_ARCH_ROBO_INSTALLED

#include <bmdi/arch/robo_stp_xlate.h>

#include <cdk/cdk_error.h>

int 
bmd_robo_stp_state_to_hw(bmd_stp_state_t bmd_state, int *hw_state)
{
    switch (bmd_state) {
    case bmdSpanningTreeDisabled:
        *hw_state = 1;
        break;
    case bmdSpanningTreeBlocking:
        *hw_state = 2;
        break;
    case bmdSpanningTreeListening:
        *hw_state = 3;
        break;
    case bmdSpanningTreeLearning:
        *hw_state = 4;
        break;
    case bmdSpanningTreeForwarding:
        *hw_state = 5;
        break;
    default:
        return CDK_E_PARAM;
    }
    return CDK_E_NONE;
}

int 
bmd_robo_stp_state_from_hw(int hw_state, bmd_stp_state_t *bmd_state)
{
    switch (hw_state) {
    case 0:
    case 1:
        *bmd_state = bmdSpanningTreeDisabled;
        break;
    case 2:
        *bmd_state = bmdSpanningTreeBlocking;
        break;
    case 3:
        *bmd_state = bmdSpanningTreeListening;
        break;
    case 4:
        *bmd_state = bmdSpanningTreeLearning;
        break;
    case 5:
        *bmd_state = bmdSpanningTreeForwarding;
        break;
    default:
        return CDK_E_PARAM;
    }
    return CDK_E_NONE;
}

#endif /* CDK_CONFIG_ARCH_ROBO_INSTALLED */
