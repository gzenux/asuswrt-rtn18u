/*
 * $Id: robo_mem_arl_read.c,v 1.7 Broadcom SDK $
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

#define MAX_POLL 20

int
cdk_robo_mem_arl_read(int unit, uint32_t addr, uint32_t idx, void *vptr, int size)
{
    int ioerr = 0;
    int wsize = CDK_BYTES2WORDS(size);
    uint32_t *wdata = (uint32_t *)vptr;
    uint32_t data_reg;
    ROBO_MEM_CTRLr_t mem_ctrl;
    ROBO_MEM_ADDRr_t mem_addr;
    int memidx, cnt, msd;
    uint32_t data[4];

    if (idx & 1) {
        data_reg = (addr & 0xff00) | ((addr >> 16) & 0xff);
    } else {
        data_reg = (addr & 0xffff);
    }

    /* Set up access type */
    ROBO_MEM_CTRLr_CLR(mem_ctrl);
    ROBO_MEM_CTRLr_MEM_TYPEf_SET(mem_ctrl, ROBO_MEM_TYPE_ARL);
    ioerr += ROBO_WRITE_MEM_CTRLr(unit, mem_ctrl);

    /* Two ARL entries per debug memory entry */
    memidx = idx >> 1;

    /* Initialize read operation */
    ROBO_MEM_ADDRr_CLR(mem_addr);
    ROBO_MEM_ADDRr_MEM_RWf_SET(mem_addr, ROBO_MEM_OP_READ);
    ROBO_MEM_ADDRr_MEM_ADRf_SET(mem_addr, memidx);
    ROBO_MEM_ADDRr_MEM_STDNf_SET(mem_addr, 1);
    ioerr += ROBO_WRITE_MEM_ADDRr(unit, mem_addr);

    cnt = 0;
    while (cnt < MAX_POLL) {
        ioerr += ROBO_READ_MEM_ADDRr(unit, &mem_addr);
        if (ioerr == 0 && ROBO_MEM_ADDRr_MEM_STDNf_GET(mem_addr) == 0) {
            /* Read data register(s) */
            ioerr += cdk_robo_reg_read(unit, data_reg, data, 8);
            if (addr & ROBO_MEM_ARL_F_KEY_REV) {
                data[0] = ROBO_MEM_ARL_KEY_REV_0(data[0]);
                data[1] = ROBO_MEM_ARL_KEY_REV_1(data[1]);
            }
            if (size > 8) {
                msd = (addr & ROBO_MEM_ARL_F_MSD_16) ? 2 : 8;
                ioerr += cdk_robo_reg_read(unit, data_reg + 8, &data[2], msd);
            }
            break;
        }
    }

    /* Check for errors */
    if (ioerr || cnt >= MAX_POLL) {
        CDK_ERR(("cdk_robo_mem_arl_read[%d]: error reading addr=%08"PRIx32"\n",
                 unit, addr));
        return CDK_E_FAIL;
    }

    /* Debug output */
    CDK_DEBUG_MEM(("cdk_robo_mem_arl_read[%d]: addr=0x%08"PRIx32" idx=%"PRIu32" data:",
                   unit, addr, idx));

    /* Copy data to output buffer */
    for (cnt = 0; cnt < wsize; cnt++) {
        wdata[cnt] = data[cnt];
        CDK_DEBUG_MEM((" 0x%08"PRIx32, wdata[cnt]));
    }
    CDK_DEBUG_MEM(("\n"));

    return CDK_E_NONE;
}
