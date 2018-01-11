/*
 * $Id: $
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
#include <cdk/chip/bcm6300_a0_defs.h>

int 
bcm6300_a0_bmd_switch_control_priority_get(
    int unit, 
    int priority, 
    bmd_switch_control_t type, 
    int *value)
{
    int ioerr = 0;
    FC_TXQ_TH_RSRV_Qr_t txq_hyst;
    FC_TXQ_TH_PAUSE_Qr_t txq_pause;
    FC_TXQ_TH_DROP_Qr_t txq_drop;
    FC_TOTAL_TH_HYST_Qr_t total_hyst;
    FC_TOTAL_TH_PAUSE_Qr_t total_pause;
    FC_TOTAL_TH_DROP_Qr_t total_drop;

    BMD_CHECK_UNIT(unit);
    if ((priority < 0) || (priority >= NUM_EGRESS_QUEUES))
        return CDK_E_PARAM;

    switch (type) {
        case bmdSwitchTxQHiHysteresisThreshold:
            ioerr += READ_FC_TXQ_TH_RSRV_Qr(unit, priority, &txq_hyst);
            *value = FC_TXQ_TH_RSRV_Qr_TXQ_HYST_THRSf_GET(txq_hyst);
            break;

        case bmdSwitchTxQHiPauseThreshold:
            ioerr += READ_FC_TXQ_TH_PAUSE_Qr(unit, priority, &txq_pause);
            *value = FC_TXQ_TH_PAUSE_Qr_TXQ_PAUSE_THRSf_GET(txq_pause);
            break;

        case bmdSwitchTxQHiDropThreshold:
            ioerr += READ_FC_TXQ_TH_DROP_Qr(unit, priority, &txq_drop);
            *value = FC_TXQ_TH_DROP_Qr_TXQ_DROP_THRSf_GET(txq_drop);
            break;

        case bmdSwitchTotalHysteresisThreshold:
            ioerr += READ_FC_TOTAL_TH_HYST_Qr(unit, priority, &total_hyst);
            *value = FC_TOTAL_TH_HYST_Qr_TXQ_TOTAL_HYST_THRSf_GET(total_hyst);
            break;

        case bmdSwitchTotalPauseThreshold:
            ioerr += READ_FC_TOTAL_TH_PAUSE_Qr(unit, priority, &total_pause);
            *value = FC_TOTAL_TH_PAUSE_Qr_TXQ_TOTAL_PAUSE_THRSf_GET(total_pause);
            break;

        case bmdSwitchTotalDropThreshold:
            ioerr += READ_FC_TOTAL_TH_DROP_Qr(unit, priority, &total_drop);
            *value = FC_TOTAL_TH_DROP_Qr_TXQ_TOTAL_DROP_THRSf_GET(total_drop);
            break;

        default:
            return CDK_E_PARAM;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

