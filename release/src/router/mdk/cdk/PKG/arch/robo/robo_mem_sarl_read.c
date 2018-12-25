/*
 * $Id: robo_mem_sarl_read.c,v 1.4 Broadcom SDK $
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
 * ROBO ARL access through debug memory interface.
 */

#include <cdk/cdk_device.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>
#include <cdk/cdk_field.h>

#include <cdk/arch/robo_mem_regs.h>
#include <cdk/arch/robo_mem.h>

#define MAX_POLL 0x10000

int
cdk_robo_mem_sarl_read(int unit, uint32_t addr, uint32_t idx, void *vptr, int size)
{
    int ioerr = 0;
    uint32_t wsize = CDK_BYTES2WORDS(size);
    uint32_t *wdata = (uint32_t *)vptr;
    uint32_t data_reg, srch_idx;
    ROBO_ARLA_SRCH_CTLr_t srch_ctl;
    ROBO_ARLA_SRCH_ADRr_t srch_adr;
    uint32_t cnt, found;
    uint32_t data[6];

    data_reg = addr & 0xffff;

    /* Start search operation */
    ROBO_ARLA_SRCH_CTLr_CLR(srch_ctl);
    ROBO_ARLA_SRCH_CTLr_ARLA_SRCH_STDNf_SET(srch_ctl, 1);
    ioerr += ROBO_WRITE_ARLA_SRCH_CTLr(unit, srch_ctl);

    cnt = 0;
    found = 0;
    while (!found  && ++cnt < MAX_POLL) {
        ioerr += ROBO_READ_ARLA_SRCH_CTLr(unit, &srch_ctl);
        if (ROBO_ARLA_SRCH_CTLr_ARLA_SRCH_STDNf_GET(srch_ctl) == 0) {
            break;
        } else if (ROBO_ARLA_SRCH_CTLr_ARLA_SRCH_VLIDf_GET(srch_ctl)) {
            ioerr += ROBO_READ_ARLA_SRCH_ADRr(unit, &srch_adr);
            srch_idx = ROBO_ARLA_SRCH_ADRr_SRCH_ADRf_GET(srch_adr);
            if (srch_idx == idx) {
                found = 1;
                /* Read secondary data register(s) */
                ioerr += cdk_robo_reg_read(unit, data_reg + 8, &data[2], 2);
            }
            /* Read data register (continue search) */
            ioerr += cdk_robo_reg_read(unit, data_reg, data, 8);
        }
    }

    /* Check for errors */
    if (ioerr || cnt >= MAX_POLL) {
        CDK_ERR(("cdk_robo_mem_sarl_read[%d]: error reading addr=%08"PRIx32"\n",
                 unit, addr));
        return CDK_E_FAIL;
    }

    if (!found) {
        CDK_MEMSET(data, 0 , sizeof(data));
    }

    /* Copy data to output buffer */
    switch ((addr >> 16) & 0xff) {
    case ROBO_ARLA_SRCH_BCM53242:
        wdata[0] = (data[0] >> 12) | (data[1] << 20);
        wdata[1] = (data[1] >> 12) & 0x3ff;
        wdata[1] |= (data[1] & 0xf0000000);
        wdata[1] |= ((data[2] & 0xfff) << 16);
        break;
    default:
        CDK_MEMSET(wdata, 0 , size);
        CDK_ERR(("cdk_robo_mem_sarl_read[%d]: no decoder for addr=%08"PRIx32"\n",
                 unit, addr));
        return CDK_E_FAIL;
    }

    /* Debug output */
    CDK_DEBUG_MEM(("cdk_robo_mem_sarl_read[%d]: addr=0x%08"PRIx32" idx=%"PRIu32" data:",
                   unit, addr, idx));

    for (cnt = 0; cnt < wsize; cnt++) {
        CDK_DEBUG_MEM((" 0x%08"PRIx32, wdata[cnt]));
    }
    CDK_DEBUG_MEM(("\n"));

    return CDK_E_NONE;
}
