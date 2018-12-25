#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM6300_A0 == 1

/*
 * $Id: bcm6300_a0_bmd_port_mac_addr_clr.c,v 1.5 Broadcom SDK $
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

#define MAX_POLL 100

int
bcm6300_a0_arl_clear(int unit, int port, bmd_arl_entry_type_t type)
{
    int ioerr = 0;
    int rv = 0, cnt;
    FAST_AGING_PORTr_t fast_age_port;
    FAST_AGE_CTLr_t ctrl;

    FAST_AGING_PORTr_SET(fast_age_port, port);
    WRITE_FAST_AGING_PORTr(unit, fast_age_port);

    FAST_AGE_CTLr_CLR(ctrl);
    FAST_AGE_CTLr_EN_AGE_PORTf_SET(ctrl, 1);
    if (type == bmdArlEntryAll) {
        FAST_AGE_CTLr_EN_AGE_DYNAMICf_SET(ctrl, 1);
        FAST_AGE_CTLr_EN_FAST_AGE_STATICf_SET(ctrl, 1);
    } else if (type == bmdArlEntryStatic) {
        FAST_AGE_CTLr_EN_FAST_AGE_STATICf_SET(ctrl, 1);
    } else {
        FAST_AGE_CTLr_EN_AGE_DYNAMICf_SET(ctrl, 1);
    }
    FAST_AGE_CTLr_FAST_AGE_START_DONEf_SET(ctrl, 1);
    WRITE_FAST_AGE_CTLr(unit, ctrl);

    cnt = 0;
    while (cnt++ < MAX_POLL) {
        READ_FAST_AGE_CTLr(unit, &ctrl);
        if (FAST_AGE_CTLr_FAST_AGE_START_DONEf_GET(ctrl))
            break;
        BMD_SYS_USLEEP(10);
    }

    if (cnt >= MAX_POLL)
        printf("Timeout waiting for FastAge StartDone to clear \n");

    return ioerr ? CDK_E_IO : rv;
}

int
bcm6300_a0_bmd_port_mac_addr_clear(int unit, int port, bmd_arl_entry_type_t type)
{
    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    return bcm6300_a0_arl_clear(unit, port, type);
}

#endif /* CDK_CONFIG_INCLUDE_BCM6300_A0 */
