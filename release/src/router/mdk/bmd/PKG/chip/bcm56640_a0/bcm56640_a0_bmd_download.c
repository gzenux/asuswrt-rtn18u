#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56640_A0 == 1

/*
 * $Id: bcm56640_a0_bmd_download.c,v 1.1 Broadcom SDK $
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

#include <bmdi/arch/xgsm_led.h>

#include <cdk/chip/bcm56640_a0_defs.h>

#include "bcm56640_a0_bmd.h"

int
bcm56640_a0_bmd_download(int unit, bmd_download_t type, uint8_t *data, int size)
{
    int rv = CDK_E_UNAVAIL;
    int ioerr = 0;
    int offset, idx;
    CMIC_LEDUP0_PORT_ORDER_REMAPr_t remap0;
    CMIC_LEDUP1_PORT_ORDER_REMAPr_t remap1;
    CMIC_LEDUP0_CTRLr_t led_ctrl0;
    CMIC_LEDUP1_CTRLr_t led_ctrl1;
    CMIC_LEDUP0_SCANCHAIN_ASSEMBLY_ST_ADDRr_t scan_addr0;
    CMIC_LEDUP1_SCANCHAIN_ASSEMBLY_ST_ADDRr_t scan_addr1;
    CMIC_LEDUP1_PROGRAM_RAMr_t led_prog1;
    CMIC_LEDUP1_DATA_RAMr_t led_data1;
    uint32_t rval;

    BMD_CHECK_UNIT(unit);

    switch (type) {
    case bmdDownloadPortLedController:
        /* Stop and configure LED processor #1 */
        ioerr += READ_CMIC_LEDUP1_CTRLr(unit, &led_ctrl1);
        CMIC_LEDUP1_CTRLr_LEDUP_ENf_SET(led_ctrl1, 0);
        CMIC_LEDUP1_CTRLr_LEDUP_SCAN_START_DELAYf_SET(led_ctrl1, 15);
        ioerr += WRITE_CMIC_LEDUP1_CTRLr(unit, led_ctrl1);
        CMIC_LEDUP1_SCANCHAIN_ASSEMBLY_ST_ADDRr_SET(scan_addr1, 0x4a);
        ioerr += WRITE_CMIC_LEDUP1_SCANCHAIN_ASSEMBLY_ST_ADDRr(unit, scan_addr1);
        /* Initialize the LEDUP1 port mapping to match LEDUP0's default */
        for (idx = 0; idx < 9; idx++) {
            ioerr += READ_CMIC_LEDUP0_PORT_ORDER_REMAPr(unit, idx, &remap0);
            rval = CMIC_LEDUP0_PORT_ORDER_REMAPr_GET(remap0);
            CMIC_LEDUP1_PORT_ORDER_REMAPr_SET(remap1, rval);
            ioerr += WRITE_CMIC_LEDUP1_PORT_ORDER_REMAPr(unit, idx, remap1);
        }
        /* Load program */
        for (offset = 0; offset < CMIC_LED_PROGRAM_RAM_SIZE; offset++) {
            CMIC_LEDUP1_PROGRAM_RAMr_SET(led_prog1, 0);
            if (offset < size) {
                CMIC_LEDUP1_PROGRAM_RAMr_SET(led_prog1, data[offset]);
            }
            ioerr += WRITE_CMIC_LEDUP1_PROGRAM_RAMr(unit, offset, led_prog1);
        }
        /* The LED data area should be clear whenever program starts */
        CMIC_LEDUP1_DATA_RAMr_SET(led_data1, 0);
        for (offset = 0x80; offset < CMIC_LED_DATA_RAM_SIZE; offset++) {
            ioerr += WRITE_CMIC_LEDUP1_DATA_RAMr(unit, offset, led_data1);
        }
        /* Start new LED program */
        CMIC_LEDUP1_CTRLr_LEDUP_ENf_SET(led_ctrl1, 1);
        ioerr += WRITE_CMIC_LEDUP1_CTRLr(unit, led_ctrl1);

        /* Stop and configure LED processor #0 */
        ioerr += READ_CMIC_LEDUP0_CTRLr(unit, &led_ctrl0);
        CMIC_LEDUP0_CTRLr_LEDUP_ENf_SET(led_ctrl0, 0);
        CMIC_LEDUP0_CTRLr_LEDUP_SCAN_START_DELAYf_SET(led_ctrl0, 11);
        ioerr += WRITE_CMIC_LEDUP0_CTRLr(unit, led_ctrl0);
        CMIC_LEDUP0_SCANCHAIN_ASSEMBLY_ST_ADDRr_SET(scan_addr0, 0x4a);
        ioerr += WRITE_CMIC_LEDUP0_SCANCHAIN_ASSEMBLY_ST_ADDRr(unit, scan_addr0);
        if (ioerr) {
            return CDK_E_IO;
        }
        /* Load and start program on LED processor #0 */
        rv = xgsm_led_prog(unit, data, size);
        break;
    default:
        break;
    }

    return rv; 
}
#endif /* CDK_CONFIG_INCLUDE_BCM56640_A0 */
