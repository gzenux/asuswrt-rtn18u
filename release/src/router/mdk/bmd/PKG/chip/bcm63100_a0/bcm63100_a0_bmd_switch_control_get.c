#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM63100_A0 == 1
/*
 * $Id: bcm63100_a0_bmd_switch_control_get.c,v 1.2 Broadcom SDK $
 * 
 * $Copyright: Copyright 2010 Broadcom Corporation.
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
#include <cdk/chip/bcm63100_a0_defs.h>

int 
bcm63100_a0_bmd_switch_control_get(
    int unit, 
    bmd_switch_control_t type, 
    int *value)
{
    int ioerr = 0;
    VLAN_CTRL0r_t vlan_ctrl;
    FC_PAUSE_DROP_CTRLr_t fc_ctrl;

    BMD_CHECK_UNIT(unit);

    switch (type) {
        case bmdSwitchTXQPauseControl:
            ioerr += READ_FC_PAUSE_DROP_CTRLr(unit, &fc_ctrl);
            *value = FC_PAUSE_DROP_CTRLr_EN_TX_PAUSEf_GET(fc_ctrl);
            break;

        case bmdSwitchTXQDropControl:
            ioerr += READ_FC_PAUSE_DROP_CTRLr(unit, &fc_ctrl);
            *value = FC_PAUSE_DROP_CTRLr_EN_TX_DROPf_GET(fc_ctrl);
            break;

        case bmdSwitchTotalPauseControl:
            ioerr += READ_FC_PAUSE_DROP_CTRLr(unit, &fc_ctrl);
            *value = FC_PAUSE_DROP_CTRLr_EN_TOTAL_PAUSEf_GET(fc_ctrl);
            break;

        case bmdSwitchTotalDropControl:
            ioerr += READ_FC_PAUSE_DROP_CTRLr(unit, &fc_ctrl);
            *value = FC_PAUSE_DROP_CTRLr_EN_TOTAL_DROPf_GET(fc_ctrl);
            break;

        case bmdSwitch8021QControl:
            ioerr += READ_VLAN_CTRL0r(unit, &vlan_ctrl);
            *value = VLAN_CTRL0r_VLAN_ENf_GET(vlan_ctrl);
            break;

        default:
            return CDK_E_PARAM;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}
#endif /* CDK_CONFIG_INCLUDE_BCM63100_A0 */

