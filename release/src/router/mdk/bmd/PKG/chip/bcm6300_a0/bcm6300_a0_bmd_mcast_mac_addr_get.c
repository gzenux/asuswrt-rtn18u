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
#include "bcm6300_a0_bmd.h"
#include <cdk/cdk_device.h>
#include <cdk/cdk_error.h>
#include <cdk/chip/bcm6300_a0_defs.h>

/* TBD: move to robo_mac_util.c */
void field_to_mac_val(uint32_t *fval, uint8_t *mac) {
    mac[0] = (fval[1] >> 8) & 0xFF;
    mac[1] = fval[1] & 0xFF;
    mac[2] = (fval[0] >> 24) & 0xFF;
    mac[3] = (fval[0] >> 16) & 0xFF;
    mac[4] = (fval[0] >> 8) & 0xFF;
    mac[5] = fval[0] & 0xFF;
}

int 
bcm6300_a0_bmd_mcast_mac_addr_get(
    int unit, 
    int entry_id, 
    int *vlan, 
    bmd_mac_addr_t *mac_addr, 
    int *fwd_portmap, 
    int *priority, 
    int *used_bit, 
    int *valid_bit)
{
    int ioerr = 0;
    MARLA_MACVID_ENTRY0r_t mac_vid_entry;
    MARLA_DATA_ENTRY0r_t data_entry;
    uint32_t fval[2];

    if (entry_id < 0 || entry_id > 15) {
        return CDK_E_PARAM;
    }

    ioerr += READ_MARLA_MACVID_ENTRY0r(unit, entry_id, &mac_vid_entry);
    ioerr += READ_MARLA_DATA_ENTRY0r(unit, entry_id, &data_entry);

    *fwd_portmap = MARLA_DATA_ENTRY0r_FWD_PRT_MAPf_GET(data_entry) | 
                   (MARLA_DATA_ENTRY0r_FWD_PRT_MAP8f_GET(data_entry) << CPIC_PORT);
    *priority = MARLA_DATA_ENTRY0r_PRIORITYf_GET(data_entry);
    *used_bit = MARLA_DATA_ENTRY0r_USEDf_GET(data_entry);
    *valid_bit = MARLA_DATA_ENTRY0r_VALIDf_GET(data_entry);

    *vlan = MARLA_MACVID_ENTRY0r_VID_Rf_GET(mac_vid_entry);
    MARLA_MACVID_ENTRY0r_ARL_MACADDRf_GET(mac_vid_entry, fval);
    field_to_mac_val(fval, mac_addr->b);

    return ioerr ? CDK_E_IO : CDK_E_NONE;  
}

