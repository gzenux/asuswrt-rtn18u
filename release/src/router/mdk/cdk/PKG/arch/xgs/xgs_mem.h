/*
 * $Id: xgs_mem.h,v 1.7 Broadcom SDK $
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
 * XGS memory access functions.
 */

#ifndef __CDK_MEM_H__
#define __CDK_MEM_H__

#include <cdk/arch/xgs_chip.h>

/*******************************************************************************
 *
 * Access memories
 *
 *
 ******************************************************************************/

extern int
cdk_xgs_mem_read(int unit, uint32_t addr, uint32_t idx, void *entry_data, int size); 

extern int
cdk_xgs_mem_write(int unit, uint32_t addr, uint32_t idx, void *entry_data, int size); 

extern int
cdk_xgs_mem_clear(int unit, uint32_t addr, uint32_t si, uint32_t ei, int size); 

#define CDK_XGS_MEM_CLEAR(_u, _m) \
    cdk_xgs_mem_clear(_u, _m, _m##_MIN, _m##_MAX, (_m##_SIZE + 3) >> 2)


/*******************************************************************************
 *
 * Access block-based memories
 *
 *
 ******************************************************************************/

extern int
cdk_xgs_mem_block_read(int unit, int block, uint32_t addr, 
                       int idx, void *entry_data, int size); 

extern int
cdk_xgs_mem_block_write(int unit, int block, uint32_t addr, 
                        int idx, void *entry_data, int size); 

extern int
cdk_xgs_mem_block_clear(int unit, int block, uint32_t addr, 
                        uint32_t si, uint32_t ei, int size); 

extern int
cdk_xgs_mem_blocks_read(int unit, uint32_t blktypes, int port,
                        uint32_t addr, int idx, void *entry_data, int size);

extern int
cdk_xgs_mem_blocks_write(int unit, uint32_t blktypes, int port,
                         uint32_t addr, int idx, void *entry_data, int size);

/*******************************************************************************
 *
 * Active memory sizes may depend on configuration
 *
 *
 ******************************************************************************/

extern uint32_t
cdk_xgs_mem_maxidx(int unit, uint32_t addr, uint32_t maxidx);


/*******************************************************************************
 *
 * Non-indexed access to memories
 *
 *
 ******************************************************************************/

extern int
cdk_xgs_mem_op(int unit, cdk_xgs_mem_op_info_t *mem_op_info);

#endif /* __CDK_MEM_H__ */
