/*
 * $Id: robo_mem_gen_write.c,v 1.3 Broadcom SDK $
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
cdk_robo_mem_gen_write(int unit, uint32_t addr, uint32_t idx, void *vptr, int size)
{
    int ioerr = 0;
    int wsize = CDK_BYTES2WORDS(size);
    uint32_t *wdata = (uint32_t *)vptr;
    uint32_t mem_type;
    ROBO_MEM_INDEXr_t mem_index;
    ROBO_MEM_ADDR_0r_t mem_addr_0;
    ROBO_MEM_CTRLr_t mem_ctrl;
    uint32_t data_reg;
    uint32_t index_reg, addr_reg, ctrl_reg, data_0_reg;
    int cnt;
    int bin, bin_no;
    uint32_t data[4];

    if (size > (int)sizeof(data)) {
        return CDK_E_FAIL;
    }

    index_reg = addr & 0xffff;
    mem_type = (addr >> 16) & 0xff;
    
    addr_reg = index_reg + 0x10;
    ctrl_reg = index_reg + 0x08;
    data_0_reg = addr_reg + 0x10;

    /* Set entry (idx)*/
    bin_no = (addr >> 24) & 0xf;
    if (bin_no == 0) {
        bin = idx;
    } else {
        /* arl index size = 16K */
        bin = idx >> 2;
    }
    /* Copy data into local buffer */
    CDK_MEMSET(data, 0, sizeof(data));
    for (cnt = 0; cnt < wsize; cnt++) {
        data[cnt] = wdata[cnt];
    }

    /* Set memory index */
    ROBO_MEM_INDEXr_INDEXf_SET(mem_index, mem_type);
    ioerr += cdk_robo_reg_write(unit, index_reg, &mem_index, 1);

    /* Set MEM_ADDR_0 to read, Addr = 0x10 */
    ioerr += cdk_robo_reg_read(unit, addr_reg, &mem_addr_0, 2);
    ROBO_MEM_ADDR_0r_MEM_ADDR_OFFSETf_SET(mem_addr_0, bin);
    ioerr += cdk_robo_reg_write(unit,addr_reg, &mem_addr_0, 2);

    /* Write data registers */
    if (bin_no == 0) {
        data_reg = data_0_reg;
    } else {
        data_reg = data_0_reg + ((idx & 0x11) * 0x10);
    }

    ioerr += cdk_robo_reg_write(unit, data_reg, data, 8);
    if (size > 8) {
        ioerr += cdk_robo_reg_write(unit, data_reg + 0x08, &data[2], 8);
    }

    /* Set MEM_CTRL, OP_CMD=0x02 MEM_STDN=1 */
    ioerr += cdk_robo_reg_read(unit, ctrl_reg, &mem_ctrl, 1);
    ROBO_MEM_CTRLr_OP_CMDf_SET(mem_ctrl, 0x02);
    ROBO_MEM_CTRLr_MEM_STDNf_SET(mem_ctrl, 1);
    ioerr += cdk_robo_reg_write(unit, ctrl_reg, &mem_ctrl, 1);

    cnt = 0;
    while (cnt < MAX_POLL) {
        ioerr += cdk_robo_reg_read(unit, ctrl_reg, &mem_ctrl, 1);
        if (ioerr == 0 && ROBO_MEM_CTRLr_MEM_STDNf_GET(mem_ctrl) == 0) {
            break;
        }
    }

    /* Check for errors */
    if (ioerr || cnt >= MAX_POLL) {
        CDK_ERR(("cdk_robo_mem_gen_write[%d]: error writing addr=%08"PRIx32"\n",
                 unit, addr));
        return CDK_E_FAIL;
    }

    /* Debug output */
    CDK_DEBUG_MEM(("cdk_robo_mem_gen_write[%d]: addr=0x%08"PRIx32" idx=%"PRIu32" data:",
                   unit, addr, idx));

    for (cnt = 0; cnt < wsize; cnt++) {
        CDK_DEBUG_MEM((" 0x%08"PRIx32, wdata[cnt]));
    }
    CDK_DEBUG_MEM(("\n"));

    return CDK_E_NONE;
}
