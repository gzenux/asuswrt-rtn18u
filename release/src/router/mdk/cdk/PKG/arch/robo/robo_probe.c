/*
 * $Id: robo_probe.c,v 1.2 Broadcom SDK $
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
 *
 * Architecture specific probe function that extracts chip ID
 * information from the Robo PHY ID registers and optionally
 * retrieves model information from chip-specific register
 *
 * The reg_read functions has same prototype as the read
 * function in the cdk_dev_vectors_t type.
 *
 * The id.model_info for Robo devices is defined like this:
 *
 *  31  28 27         20 19  16 15          8 7           0
 * +------+-------------+------+-------------+-------------+
 * | rlen |   roffset   | mlen |    page     |   moffset   |
 * +------+-------------+------+-------------+-------------+
 *
 * rlen:        Size of revision register (in bytes)
 * roffset:     Revision register offset
 * mlen:        Size of model ID register (in bytes)
 * page:        Page containing model ID and revision registers
 * moffset:     Model ID register offset
 *
 */

#include <cdk/cdk_device.h>
#include <cdk/arch/robo_chip.h>

int
cdk_robo_probe(void *dvc, cdk_dev_id_t *id,
               int (*reg_read)(void *, uint32_t, uint8_t *, uint32_t))
{
    cdk_dev_probe_info_t pi;
    uint8_t buf[16];

    /* Re-read PHY ID registers */
    reg_read(dvc, 0x1004, buf, 2);
    id->vendor_id = buf[0] | (buf[1] << 8);
    reg_read(dvc, 0x1006, buf, 2);
    id->device_id = buf[0] | (buf[1] << 8);

    /* Revision is lower 4 bits of device ID (usually - see below) */
    id->revision = id->device_id & 0xf;
    id->device_id &= 0xfff0;

    /* Look for additional probing info */
    cdk_dev_probe_info_get(id, &pi);
    if (pi.model_info) {
        /* Read model ID */
        uint32_t addr = pi.model_info & 0xffff;
        uint32_t len = (pi.model_info >> 16) & 0xf;
        buf[0] = buf[1] = 0;
        reg_read(dvc, addr, buf, len);
        id->model = buf[0] | (buf[1] << 8);
        /* Optionally read revision from alternative location */
        len = (pi.model_info >> 28) & 0xf;
        if (len > 0) {
            addr &= 0xff00;
            addr |= (pi.model_info >> 20) & 0xff;
            reg_read(dvc, addr, buf, len);
            id->revision = buf[0];
        }
    }

    return 0;
}
