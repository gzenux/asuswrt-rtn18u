#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56524_B0 == 1

/*
 * $Id: bcm56524_b0_bmd_vlan_port_remove.c,v 1.2 Broadcom SDK $
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

#include <cdk/chip/bcm56524_b0_defs.h>

#include "bcm56524_b0_bmd.h"

int
bcm56524_b0_bmd_vlan_port_remove(int unit, int vlan, int port)
{
    int ioerr = 0;
    VLAN_TABm_t vlan_tab;
    EGR_VLANm_t egr_vlan;
    uint32_t pbmp, mask;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_VLAN(unit, vlan);
    BMD_CHECK_PORT(unit, port);

    ioerr += READ_VLAN_TABm(unit, vlan, &vlan_tab);
    if (VLAN_TABm_VALIDf_GET(vlan_tab) == 0) {
        return ioerr ? CDK_E_IO : CDK_E_NOT_FOUND;
    }
    ioerr += READ_EGR_VLANm(unit, vlan, &egr_vlan);
    if (port >= 32) {
        mask = 1 << (port - 32);
        pbmp = VLAN_TABm_PORT_BITMAP_HIf_GET(vlan_tab);
        if ((pbmp & mask) == 0) {
            return ioerr ? CDK_E_IO : CDK_E_NOT_FOUND;
        }
        VLAN_TABm_PORT_BITMAP_HIf_SET(vlan_tab, pbmp & ~mask);
        pbmp = EGR_VLANm_PORT_BITMAP_HIf_GET(egr_vlan);
        EGR_VLANm_PORT_BITMAP_HIf_SET(egr_vlan, pbmp & ~mask);
        pbmp = EGR_VLANm_UT_BITMAP_HIf_GET(egr_vlan);
        EGR_VLANm_UT_BITMAP_HIf_SET(egr_vlan, pbmp & ~mask);
    } else {
        mask = 1 << port;
        pbmp = VLAN_TABm_PORT_BITMAP_LOf_GET(vlan_tab);
        if ((pbmp & mask) == 0) {
            return ioerr ? CDK_E_IO : CDK_E_NOT_FOUND;
        }
        VLAN_TABm_PORT_BITMAP_LOf_SET(vlan_tab, pbmp & ~mask);
        pbmp = EGR_VLANm_PORT_BITMAP_LOf_GET(egr_vlan);
        EGR_VLANm_PORT_BITMAP_LOf_SET(egr_vlan, pbmp & ~mask);
        pbmp = EGR_VLANm_UT_BITMAP_LOf_GET(egr_vlan);
        EGR_VLANm_UT_BITMAP_LOf_SET(egr_vlan, pbmp & ~mask);
    }
    ioerr += WRITE_VLAN_TABm(unit, vlan, vlan_tab);
    ioerr += WRITE_EGR_VLANm(unit, vlan, egr_vlan);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56524_B0 */
