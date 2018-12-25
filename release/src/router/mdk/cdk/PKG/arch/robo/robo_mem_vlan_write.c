/*
 * $Id: robo_mem_vlan_write.c,v 1.4 Broadcom SDK $
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
 * ROBO VLAN access through 32-bit interface.
 */

#include <cdk/cdk_device.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>
#include <cdk/cdk_field.h>

#include <cdk/arch/robo_mem_regs.h>
#include <cdk/arch/robo_mem.h>

#define MAX_POLL 20

int
cdk_robo_mem_vlan_write(int unit, uint32_t addr, uint32_t idx, void *vptr, int size)
{
    int ioerr = 0;
    int wsize = CDK_BYTES2WORDS(size);
    int bsize = CDK_WORDS2BYTES(wsize);
    uint32_t *wdata = (uint32_t *)vptr;
    uint32_t rwctrl_reg, addr_reg, entry_reg;
    ROBO_ARLA_VTBL_ADDRr_t vtbl_addr;
    ROBO_ARLA_VTBL_RWCTRLr_t vtbl_rwctrl;
    ROBO_ARLA_VTBL_ENTRYr_t vtbl_entry;
    int cnt;

    /* Initialize access register addresses */
/*CONFIG_MDK_BCA_BEGIN*/
  /* The offsets are aligned in case of integrated switch. 
        TBD: change the if to check for switch device_id rather than actual address */
    if ((addr & 0xfff) == 0x560) {    
        rwctrl_reg = addr & 0xffff;
        addr_reg = rwctrl_reg + 2;
        entry_reg = rwctrl_reg + 4;
    } else {
        rwctrl_reg = addr & 0xffff;
        addr_reg = rwctrl_reg + 1;
        entry_reg = rwctrl_reg + 3;
    }
/*CONFIG_MDK_BCA_END*/

    /* Set VLAN memory index */
    ROBO_ARLA_VTBL_ADDRr_CLR(vtbl_addr);
    ROBO_ARLA_VTBL_ADDRr_VTBL_ADDR_INDEXf_SET(vtbl_addr, idx);
    ioerr += cdk_robo_reg_write(unit, addr_reg, &vtbl_addr, 2);

    /* Write 32-bit VLAN entry */
    for (cnt = 0; cnt < wsize; cnt++) {
        ROBO_ARLA_VTBL_ENTRYr_SET(vtbl_entry, cnt, wdata[cnt]);
    }
    ioerr += cdk_robo_reg_write(unit, entry_reg, &vtbl_entry, bsize);

    /* Initialize write operation */
    ROBO_ARLA_VTBL_RWCTRLr_CLR(vtbl_rwctrl);
    ROBO_ARLA_VTBL_RWCTRLr_ARLA_VTBL_RW_CLRf_SET(vtbl_rwctrl, ROBO_MEM_OP_WRITE);
    ROBO_ARLA_VTBL_RWCTRLr_ARLA_VTBL_STDNf_SET(vtbl_rwctrl, 1);
    ioerr += cdk_robo_reg_write(unit, rwctrl_reg, &vtbl_rwctrl, 1);

    cnt = 0;
    while (cnt < MAX_POLL) {
        ioerr += cdk_robo_reg_read(unit, rwctrl_reg, &vtbl_rwctrl, 1);
        if (ioerr == 0 && 
            ROBO_ARLA_VTBL_RWCTRLr_ARLA_VTBL_STDNf_GET(vtbl_rwctrl) == 0) {
            break;
        }
    }

    /* Check for errors */
    if (ioerr || cnt >= MAX_POLL) {
        CDK_ERR(("cdk_robo_mem_vlan_read[%d]: error reading addr=%08"PRIx32"\n",
                 unit, addr));
        return CDK_E_FAIL;
    }

    /* Debug output */
    CDK_DEBUG_MEM(("cdk_robo_mem_vlan_read[%d]: addr=0x%08"PRIx32" idx=%"PRIu32" data:",
                   unit, addr, idx));

    for (cnt = 0; cnt < wsize; cnt++) {
        CDK_DEBUG_MEM((" 0x%08"PRIx32, wdata[cnt]));
    }
    CDK_DEBUG_MEM(("\n"));

    return CDK_E_NONE;
}
