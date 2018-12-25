#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53280_A0 == 1

/*
 * $Id: bcm53280_a0_bmd_port_mac_addr_add.c,v 1.6 Broadcom SDK $
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

#include <cdk/chip/bcm53280_a0_defs.h>

#include <cdk/arch/robo_mem_regs.h>

#include <cdk/cdk_debug.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_error.h>

#include "bcm53280_a0_internal.h"
#include "bcm53280_a0_bmd.h"

#define NUM_BINS 4
#define MAX_POLL 20
#define MEM_OP_IDX_READ    0x03
#define MEM_OP_IDX_WRITE   0x04
#define VA_BIT       3

static int
_arl_op(int unit, int opcode)
{
    int ioerr = 0;
    int cnt;
    MEM_CTRLr_t mem_ctrl;

    ioerr += READ_MEM_CTRLr(unit, &mem_ctrl);
    MEM_CTRLr_OP_CMDf_SET(mem_ctrl, opcode);
    MEM_CTRLr_MEM_STDNf_SET(mem_ctrl, 1);
    ioerr += WRITE_MEM_CTRLr(unit, mem_ctrl);

    cnt = 0;
    while (cnt++ < MAX_POLL) {
        ioerr += READ_MEM_CTRLr(unit, &mem_ctrl);
        if (ioerr == 0 && 
            MEM_CTRLr_MEM_STDNf_GET(mem_ctrl) == 0) {
            return CDK_E_NONE;
        }
    }

    return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
}

int
bcm53280_a0_arl_write(int unit, int port, int vlan, const bmd_mac_addr_t *mac_addr)
{
    int ioerr = 0;
    int rv;
    
    MEM_INDEXr_t mem_index;
    MEM_KEY_0r_t mem_key_0;
    MEM_KEY_1r_t mem_key_1;
    uint32_t fval[2], fval0[2], fval1[2];
    uint32_t fwd_base = MEM_DATA_0r;
    uint32_t fwd_inc = MEM_DATA_2r - MEM_DATA_0r;
    int fwd_size = MEM_DATA_0r_SIZE;
    int fwd_size1 = MEM_DATA_1r_SIZE;
    uint32_t reg;
    int idx, bin_no;
    /* Convert MAC address to standard field value */
    robo_mac_to_field_val(mac_addr->b, fval);
    
    /* Select ARL table */
    ioerr += READ_MEM_INDEXr(unit, &mem_index);
    MEM_INDEXr_INDEXf_SET(mem_index, 0x01);
    ioerr += WRITE_MEM_INDEXr(unit, mem_index);
    /* set searching keys */
    MEM_KEY_0r_CLR(mem_key_0);
    MEM_KEY_0r_SET(mem_key_0, 0, fval[0]);
    MEM_KEY_0r_SET(mem_key_0, 1, fval[1]);
    ioerr += WRITE_MEM_KEY_0r(unit, mem_key_0);
    MEM_KEY_1r_CLR(mem_key_1);
    MEM_KEY_1r_SET(mem_key_1, 0, vlan);
    ioerr += WRITE_MEM_KEY_1r(unit, mem_key_1);
    rv = _arl_op(unit, MEM_OP_IDX_READ);

    /* Create ARL entry */
    fval0[0] = fval0[1] = 0;
    fval1[0] = fval1[1] = 0;
    fval0[0] = ((fval[0] >> 12) & 0x000fffff) | (1L << 20);
    fval0[1] = ((fval[1] >> 12) & 0x0000000f) | 
                      (LSHIFT32(vlan, 16) & 0x0fff0000);
    if (port >= 0) {
        fval0[1] = fval0[1] | ((port << 4) & 0x000001f0) |
                              (1L << 28);
        fval1[0] = 3;
    }

    /* Find matching/available bin */
    bin_no = -1;
    fval[0] = fval[1] = 0;

    /* Find matching/available bin */
    bin_no = -1;
    for (idx = 0; idx < NUM_BINS; idx++) {
        reg = fwd_base + (idx * fwd_inc);
        ioerr += cdk_robo_reg_read(unit, reg + fwd_size, fval, fwd_size1);
        if ((fval[0] & 3) != VA_BIT) {
            bin_no = idx;
            break;
        }
    }

    if (bin_no < 0) {
        /* Overwrite dynamic ARL entry */
        bin_no = 0;
    }
    if (CDK_SUCCESS(rv)) {
        /* Write new ARL entry to selected bin */
        reg = fwd_base + (bin_no * fwd_inc);
        ioerr += cdk_robo_reg_write(unit, reg, fval0, fwd_size);
        ioerr += cdk_robo_reg_write(unit, reg + fwd_size, fval1, fwd_size1);
        /* Write ARL entry */
        rv = _arl_op(unit, MEM_OP_IDX_WRITE);
    }

    return ioerr ? CDK_E_IO : rv;
}

int
bcm53280_a0_bmd_port_mac_addr_add(int unit, int port, int vlan, const bmd_mac_addr_t *mac_addr)
{
    BMD_CHECK_UNIT(unit);
    BMD_CHECK_VLAN(unit, vlan);
    BMD_CHECK_PORT(unit, port);

    return bcm53280_a0_arl_write(unit, port, vlan, mac_addr);
}

#endif /* CDK_CONFIG_INCLUDE_BCM53280_A0 */
