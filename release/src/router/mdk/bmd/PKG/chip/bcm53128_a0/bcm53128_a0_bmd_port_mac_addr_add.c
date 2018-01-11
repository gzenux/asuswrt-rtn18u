#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53128_A0 == 1

/*
 * $Id: bcm53128_a0_bmd_port_mac_addr_add.c,v 1.2 Broadcom SDK $
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
 *
 * The ARL table has 4 bins per index.
 * The table index is a hash based on MAC address and VLAN ID.
 *
 * When writing the ARL table we look for an available
 * bin using the following priorities:
 *
 *   1. Key match
 *   2. Empty bin
 *   3. Bin with dynamic entry
 */

#include <bmd/bmd.h>

#include <bmdi/arch/robo_mac_util.h>

#include <cdk/chip/bcm53128_a0_defs.h>

#include <cdk/arch/robo_mem_regs.h>

#include <cdk/cdk_debug.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_error.h>

#include "bcm53128_a0_internal.h"
#include "bcm53128_a0_bmd.h"

#define NUM_BINS 4
#define MAX_POLL 20

static int
_arl_op(int unit, int opcode)
{
    int ioerr = 0;
    int cnt;
    ARLA_RWCTLr_t arla_rwctl;

    ARLA_RWCTLr_CLR(arla_rwctl);
    ARLA_RWCTLr_ARL_RWf_SET(arla_rwctl, opcode);
    ARLA_RWCTLr_ARL_STRTDNf_SET(arla_rwctl, 1);
    ioerr += WRITE_ARLA_RWCTLr(unit, arla_rwctl);

    cnt = 0;
    while (cnt++ < MAX_POLL) {
        ioerr += READ_ARLA_RWCTLr(unit, &arla_rwctl);
        if (ioerr == 0 && 
            ARLA_RWCTLr_ARL_STRTDNf_GET(arla_rwctl) == 0) {
            return CDK_E_NONE;
        }
    }

    return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
}

int
bcm53128_a0_arl_write(int unit, int port, int vlan, const bmd_mac_addr_t *mac_addr)
{
    int ioerr = 0;
    int rv;
    ARLA_MACr_t arla_mac;
    ARLA_VIDr_t arla_vid;
    ARLA_MACVID_ENTRY0r_t arla_macvid, macvid_chk;
    ARLA_FWD_ENTRY0r_t arla_fwd, fwd_chk;
    uint32_t macvid_base = ARLA_MACVID_ENTRY0r;
    uint32_t macvid_inc = ARLA_MACVID_ENTRY1r - ARLA_MACVID_ENTRY0r;
    int macvid_size = ARLA_MACVID_ENTRY0r_SIZE;
    uint32_t fwd_base = ARLA_FWD_ENTRY0r;
    uint32_t fwd_inc = ARLA_FWD_ENTRY1r - ARLA_FWD_ENTRY0r;
    int fwd_size = ARLA_FWD_ENTRY0r_SIZE;
    uint32_t reg;
    uint32_t fval[2];
    int idx, bin_no, dyn_bin;

    /* Convert MAC address to standard field value */
    robo_mac_to_field_val(mac_addr->b, fval);

    /* Create ARL entry */
    ARLA_MACVID_ENTRY0r_CLR(arla_macvid);
    ARLA_MACVID_ENTRY0r_ARL_MACADDRf_SET(arla_macvid, fval);
    ARLA_MACVID_ENTRY0r_VIDf_SET(arla_macvid, vlan);
    ARLA_FWD_ENTRY0r_CLR(arla_fwd);
    /* If port is negative, then clear the entry */
    if (port >= 0) {
        ARLA_FWD_ENTRY0r_PORTIDf_SET(arla_fwd, port);
        ARLA_FWD_ENTRY0r_ARL_STATICf_SET(arla_fwd, 1);
        ARLA_FWD_ENTRY0r_ARL_VALIDf_SET(arla_fwd, 1);
    }

    /* Set up MAC and VLAN for hash index calculation */
    ARLA_MACr_CLR(arla_mac);
    ARLA_MACr_MAC_ADDR_INDXf_SET(arla_mac, fval);
    ioerr += WRITE_ARLA_MACr(unit, arla_mac);

    ARLA_VIDr_CLR(arla_vid);
    ARLA_VIDr_ARLA_VIDTAB_INDXf_SET(arla_vid, vlan);
    ioerr += WRITE_ARLA_VIDr(unit, arla_vid);

    /* Read ARL entry */
    rv = _arl_op(unit, ROBO_MEM_OP_READ);

    /* Find matching/available bin */
    bin_no = -1;
    dyn_bin = -1;
    for (idx = 0; idx < NUM_BINS; idx++) {
        reg = fwd_base + (idx * fwd_inc);
        ioerr += cdk_robo_reg_read(unit, reg, &fwd_chk, fwd_size);
        if (ARLA_FWD_ENTRY0r_ARL_VALIDf_GET(fwd_chk)) {
            if (ARLA_FWD_ENTRY0r_ARL_STATICf_GET(fwd_chk) == 0) {
                /* Track valid dynamic bins */
                CDK_VVERB(("bcm53128_a0_arl_write: dynamic bin %d\n", idx));
                dyn_bin = idx;
            }
            reg = macvid_base + (idx * macvid_inc);
            ioerr += cdk_robo_reg_read(unit, reg, &macvid_chk, macvid_size);
            if (CDK_MEMCMP(&macvid_chk, &arla_macvid, sizeof(&macvid_chk)) == 0) {
                /* Found a matching key */
                CDK_VVERB(("bcm53128_a0_arl_write: matching bin %d\n", idx));
                bin_no = idx;
                break;
            }
        } else if (bin_no < 0) {
            /* First empty bin */
            CDK_VVERB(("bcm53128_a0_arl_write: empty bin %d\n", idx));
            bin_no = idx;
        }
    }

    if (bin_no < 0) {
        if (dyn_bin < 0) {
            return CDK_E_FULL;
        }
        /* Overwrite dynamic ARL entry */
        bin_no = dyn_bin;
    }

    /* Check for errors */
    if (ioerr) {
        return CDK_E_IO;
    }

    if (CDK_SUCCESS(rv)) {
        /* Write new ARL entry to selected bin */
        reg = macvid_base + (bin_no * macvid_inc);
        ioerr += cdk_robo_reg_write(unit, reg, &arla_macvid, macvid_size);
        reg = fwd_base + (bin_no * fwd_inc);
        ioerr += cdk_robo_reg_write(unit, reg, &arla_fwd, fwd_size);
        /* Write ARL entry */
        rv = _arl_op(unit, ROBO_MEM_OP_WRITE);
    }
    return ioerr ? CDK_E_IO : rv;
}

int
bcm53128_a0_bmd_port_mac_addr_add(int unit, int port, int vlan, const bmd_mac_addr_t *mac_addr)
{
    BMD_CHECK_UNIT(unit);
    BMD_CHECK_VLAN(unit, vlan);
    BMD_CHECK_PORT(unit, port);

    return bcm53128_a0_arl_write(unit, port, vlan, mac_addr);
}

#endif /* CDK_CONFIG_INCLUDE_BCM53128_A0 */
