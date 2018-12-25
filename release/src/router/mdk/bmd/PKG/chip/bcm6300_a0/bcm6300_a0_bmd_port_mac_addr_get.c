#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM6300_A0 == 1

/*
 * $Id: bcm6300_a0_bmd_port_mac_addr_add.c,v 1.5 Broadcom SDK $
 * 
 * $Copyright: Copyright 2009 Broadcom Corporation.
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
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$1,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 *
 * The table index is a hash based on MAC address and VLAN ID.
 *
 */

#include <bmd/bmd.h>

#include <bmdi/arch/robo_mac_util.h>

#include <cdk/chip/bcm6300_a0_defs.h>

#include <cdk/arch/robo_mem_regs.h>

#include <cdk/cdk_debug.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_error.h>

#include "bcm6300_a0_internal.h"
#include "bcm6300_a0_bmd.h"

#define MAX_POLL 10000
#define MAX_ENTRIES 4096

int
bcm6300_a0_arl_get(int unit, int port, int num_req_entries, bmd_arl_entry_t *arl_entries, int *num_entries)
{
    int ioerr = 0;
    int rv = 0, cnt = 0, cnt1 = 0, found = 0;
    ARLA_SRCH_CTLr_t srch_ctrl;
    ARLA_SRCH_RSLTr_t srch_rslt;
    ARLA_SRCH_RSLT_MACVIDr_t macvid;

    /* Complete any previous search */
    while (cnt++ < MAX_ENTRIES) {
        READ_ARLA_SRCH_CTLr(unit, &srch_ctrl);
        if (ARLA_SRCH_CTLr_ARLA_SRCH_STDNf_GET(srch_ctrl)) {
            READ_ARLA_SRCH_RSLTr(unit, &srch_rslt);
        } else {
            break;
        }
        BMD_SYS_USLEEP(1);
    }

    /*Start a new search */
    ARLA_SRCH_CTLr_CLR(srch_ctrl);
    ARLA_SRCH_CTLr_ARLA_SRCH_STDNf_SET(srch_ctrl, 1);
    WRITE_ARLA_SRCH_CTLr(unit, srch_ctrl);

    /* Read Entries */
    cnt = 0;
    while (cnt++ < MAX_POLL) {
        READ_ARLA_SRCH_CTLr(unit, &srch_ctrl);
        if ((found >= num_req_entries) || (!ARLA_SRCH_CTLr_ARLA_SRCH_STDNf_GET(srch_ctrl))) {
            goto finish_srch_and_return;
        }

        cnt1 = 0;
        while (cnt1++ < MAX_POLL) {
            if (ARLA_SRCH_CTLr_ARLA_SRCH_VLIDf_GET(srch_ctrl)) {
                READ_ARLA_SRCH_RSLT_MACVIDr(unit, &macvid);
                READ_ARLA_SRCH_RSLTr(unit, &srch_rslt);
                if (ARLA_SRCH_RSLTr_PORTID_Rf_GET(srch_rslt) == port) {
                    arl_entries[found].b[0] = macvid.arla_srch_rslt_macvid[0] & 0xFF;
                    arl_entries[found].b[1] = (macvid.arla_srch_rslt_macvid[0] >> 8) & 0xFF;
                    arl_entries[found].b[2] = (macvid.arla_srch_rslt_macvid[0] >> 16) & 0xFF;
                    arl_entries[found].b[3] = (macvid.arla_srch_rslt_macvid[0] >> 24) & 0xFF;
                    arl_entries[found].b[4] = macvid.arla_srch_rslt_macvid[1] & 0xFF;
                    arl_entries[found].b[5] = (macvid.arla_srch_rslt_macvid[1] >> 8) & 0xFF;
                    arl_entries[found].vlan = BCM6300_A0_ARLA_SRCH_RSLT_MACVIDr_ARLA_SRCH_RSLT_VIDf_GET(macvid);
                    found++;
                }
            } else {
                BMD_SYS_USLEEP(1);
            }
            READ_ARLA_SRCH_CTLr(unit, &srch_ctrl);
            if (!ARLA_SRCH_CTLr_ARLA_SRCH_STDNf_GET(srch_ctrl)) {
                goto finish_srch_and_return;
            }
        }
        BMD_SYS_USLEEP(1);
    }

finish_srch_and_return:
    /* Finish the search so next search can start at beginning */
    cnt = 0;
    while (cnt++ < MAX_ENTRIES) {
        READ_ARLA_SRCH_CTLr(unit, &srch_ctrl);
        if (ARLA_SRCH_CTLr_ARLA_SRCH_STDNf_GET(srch_ctrl)) {
            READ_ARLA_SRCH_RSLTr(unit, &srch_rslt);
        } else {
            break;
        }
        BMD_SYS_USLEEP(1);
    }

    *num_entries = found;

    return ioerr ? CDK_E_IO : rv;
}

int
bcm6300_a0_bmd_port_mac_addr_get(int unit, int port, int num_req_entries, bmd_arl_entry_t *arl_entries, int *num_entries)
{
    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    return bcm6300_a0_arl_get(unit, port, num_req_entries, arl_entries, num_entries);
}

#endif /* CDK_CONFIG_INCLUDE_BCM6300_A0 */
