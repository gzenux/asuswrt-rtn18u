/*
 * $Id: robo_reg.c,v 1.6 Broadcom SDK $
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
 * ROBO register access functions.
 */

#include <cdk/cdk_device.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>

#include <cdk/arch/robo_chip.h>
#include <cdk/arch/robo_reg.h>

/*******************************************************************************
 *
 * Common register routines
 *
 *
 ******************************************************************************/

int
cdk_robo_reg_read(int unit, uint32_t addr, void *entry_data, int size)
{
    int rv;
    int wsize = CDK_BYTES2WORDS(size);
    uint32_t *wdata = (uint32_t *)entry_data;

    /* CDK internals are word-based, so fill clear fill bytes if any */
    if (size & 3) {
        wdata[wsize - 1] = 0;
    }

    /* Read data from device */
    rv = cdk_dev_read(unit, addr, (uint8_t *)entry_data, size);
    if (CDK_FAILURE(rv)) {
        CDK_ERR(("cdk_robo_reg_read[%d]: error reading addr=%08"PRIx32"\n",
                 unit, addr));
        return rv;
    }

    /* Debug output */
    CDK_DEBUG_REG(("cdk_robo_reg_read[%d]: addr=0x%08"PRIx32" data: 0x",
                   unit, addr));
    while (size) {
        size--;
        CDK_DEBUG_REG(("%02x", (int)((uint8_t *)entry_data)[size]));
    }
    CDK_DEBUG_REG(("\n"));

    /* Byte-swap each word if necessary */
    if (CDK_DEV_FLAGS(unit) & CDK_DEV_BE_HOST) {
        while (wsize) {
            wsize--;
            wdata[wsize] = cdk_util_swap32(wdata[wsize]);
        }
    }
    return rv;
}

int
cdk_robo_reg_write(int unit, uint32_t addr, void *entry_data, int size)
{
    int rv;
    int wsize = CDK_BYTES2WORDS(size);
    uint8_t *bdata = (uint8_t *)entry_data;
    uint32_t *wdata = (uint32_t *)entry_data;
    uint32_t swap_data[2];

    /* Byte-swap each word if necessary */
    if (CDK_DEV_FLAGS(unit) & CDK_DEV_BE_HOST) {
        if (wsize > COUNTOF(swap_data)) {
            return CDK_E_PARAM;
        }
        while (wsize) {
            wsize--;
            swap_data[wsize] = cdk_util_swap32(wdata[wsize]);
        }
        bdata = (uint8_t *)swap_data;
    }

    /* Write data to device */
    rv = cdk_dev_write(unit, addr, bdata, size);

    if (CDK_FAILURE(rv)) {
        CDK_ERR(("cdk_robo_reg_write[%d]: error writing addr=%08"PRIx32"\n",
                 unit, addr));
        return rv;
    }

    /* Debug output */
    CDK_DEBUG_REG(("cdk_robo_reg_write[%d]: addr=0x%08"PRIx32" data: 0x",
                   unit, addr));
    while (size) {
        size--;
        CDK_DEBUG_REG(("%02x", (int)bdata[size]));
    }
    CDK_DEBUG_REG(("\n"));

    return rv;
}
