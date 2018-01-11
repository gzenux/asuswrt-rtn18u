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
#include <bmdi/arch/robo_mac_util.h>

int 
bcm6300_a0_bmd_mcast_mac_addr_set(
    int unit, 
    int entry_id, 
    int vlan, 
    bmd_mac_addr_t *mac_addr, 
    int fwd_portmap, 
    int priority,
    int valid)
{
    int ioerr = 0;
    MARLA_MACVID_ENTRY0r_t mac_vid_entry;
    MARLA_DATA_ENTRY0r_t data_entry;
    uint32_t fval[2];

    if (entry_id < 0 || entry_id > 15) {
        return CDK_E_PARAM;
    }

    MARLA_MACVID_ENTRY0r_CLR(mac_vid_entry);
    MARLA_DATA_ENTRY0r_CLR(data_entry);

    MARLA_DATA_ENTRY0r_FWD_PRT_MAPf_SET(data_entry, fwd_portmap & 0xFF);
    MARLA_DATA_ENTRY0r_FWD_PRT_MAP8f_SET(data_entry, (fwd_portmap >> CPIC_PORT)&0x1);
    MARLA_DATA_ENTRY0r_PRIORITYf_SET(data_entry, priority);    
    MARLA_DATA_ENTRY0r_VALIDf_SET(data_entry, valid?1:0);
    MARLA_DATA_ENTRY0r_STATICf_SET(data_entry, 1);

    MARLA_MACVID_ENTRY0r_VID_Rf_SET(mac_vid_entry, vlan);
    robo_mac_to_field_val(mac_addr->b, fval);
    MARLA_MACVID_ENTRY0r_ARL_MACADDRf_SET(mac_vid_entry, fval);

    ioerr += WRITE_MARLA_MACVID_ENTRY0r(unit, entry_id, mac_vid_entry);
    ioerr += WRITE_MARLA_DATA_ENTRY0r(unit, entry_id, data_entry);

    return ioerr ? CDK_E_IO : CDK_E_NONE;  
}

