/*
 * $Id: robo_mem.c,v 1.6 Broadcom SDK $
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
 * ROBO memory access functions.
 */

#include <cdk/cdk_device.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>
#include <cdk/cdk_field.h>

#include <cdk/arch/robo_mem_regs.h>
#include <cdk/arch/robo_mem.h>

int
cdk_robo_mem_read(int unit, uint32_t addr, uint32_t idx, void *vptr, int size)
{
    switch (ROBO_MEM_ACCESS_METHOD(addr)) {
    case ROBO_MEM_ACC_ARL:
        return cdk_robo_mem_arl_read(unit, addr, idx, vptr, size);
    case ROBO_MEM_ACC_VLAN:
        return cdk_robo_mem_vlan_read(unit, addr, idx, vptr, size);
    case ROBO_MEM_ACC_GARL:
        return cdk_robo_mem_garl_read(unit, addr, idx, vptr, size);
    case ROBO_MEM_ACC_SARL:
        return cdk_robo_mem_sarl_read(unit, addr, idx, vptr, size);
    case ROBO_MEM_ACC_GEN:
        return cdk_robo_mem_gen_read(unit, addr, idx, vptr, size);
    default:
        CDK_ERR(("cdk_robo_mem_read[%d]: unknown access method\n", unit));
        break;
    }

    /* Unsupported access method */
    return CDK_E_FAIL;
}

int
cdk_robo_mem_write(int unit, uint32_t addr, uint32_t idx, void *vptr, int size)
{
    switch (ROBO_MEM_ACCESS_METHOD(addr)) {
    case ROBO_MEM_ACC_ARL:
        return cdk_robo_mem_arl_write(unit, addr, idx, vptr, size);
    case ROBO_MEM_ACC_VLAN:
        return cdk_robo_mem_vlan_write(unit, addr, idx, vptr, size);
    case ROBO_MEM_ACC_GARL:
        return cdk_robo_mem_garl_write(unit, addr, idx, vptr, size);
    case ROBO_MEM_ACC_SARL:
        return cdk_robo_mem_sarl_write(unit, addr, idx, vptr, size);
    case ROBO_MEM_ACC_GEN:
        return cdk_robo_mem_gen_write(unit, addr, idx, vptr, size);
    default:
        CDK_ERR(("cdk_robo_mem_write[%d]: unknown access method\n", unit));
        break;
    }

    /* Unsupported access method */
    return CDK_E_FAIL;
}
