/*
 * $Id: xgsm_mem_op.c,v 1.1 Broadcom SDK $
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
 */

#include <cdk/cdk_device.h>
#include <cdk/cdk_debug.h>

#include <cdk/arch/xgsm_schan.h>
#include <cdk/arch/xgsm_chip.h>
#include <cdk/arch/xgsm_mem.h>

#include <cdk/arch/xgsm_schan.h>

#if 0
#include <cdk/chip/bcm56624_b0_defs.h>
#endif

int
cdk_xgsm_mem_op(int unit, cdk_xgsm_mem_op_info_t *moi)
{
#if 0
    int rv;
    schan_msg_t schan_msg;
    int dstblk;
    int rsp_type;

    if (CDK_XGSM_INFO(unit)->mem_op) {
        return CDK_XGSM_INFO(unit)->mem_op(unit, moi);
    }

    if (moi == NULL) {
        return CDK_E_PARAM;
    }

    dstblk = (moi->addr >> CDK_XGSM_BLOCK_BP) & 0xf;

    if (moi->mem_op == CDK_XGSM_MEM_OP_INSERT) {
        SCHAN_MSG_CLEAR(&schan_msg);
        SCMH_OPCODE_SET(schan_msg.gencmd.header, TABLE_INSERT_CMD_MSG);
        SCMH_SRCBLK_SET(schan_msg.gencmd.header, CDK_XGSM_CMIC_BLOCK(unit)); 
        SCMH_DSTBLK_SET(schan_msg.gencmd.header, dstblk); 
        SCMH_DATALEN_SET(schan_msg.gencmd.header, moi->size * 4); 
        CDK_MEMCPY(schan_msg.gencmd.data, moi->data, moi->size * 4);
        schan_msg.gencmd.address = moi->addr;
        return cdk_xgsm_schan_op(unit, &schan_msg, moi->size + 2, 1);
    }
    if (moi->mem_op == CDK_XGSM_MEM_OP_DELETE) {
        SCHAN_MSG_CLEAR(&schan_msg);
        SCMH_OPCODE_SET(schan_msg.gencmd.header, TABLE_DELETE_CMD_MSG);
        SCMH_SRCBLK_SET(schan_msg.gencmd.header, CDK_XGSM_CMIC_BLOCK(unit)); 
        SCMH_DSTBLK_SET(schan_msg.gencmd.header, dstblk); 
        SCMH_DATALEN_SET(schan_msg.gencmd.header, moi->size * 4); 
        CDK_MEMCPY(schan_msg.gencmd.data, moi->data, moi->size * 4);
        schan_msg.gencmd.address = moi->addr;
        return cdk_xgsm_schan_op(unit, &schan_msg, moi->size + 2, 1);
    }
    if (moi->mem_op == CDK_XGSM_MEM_OP_LOOKUP) {
        SCHAN_MSG_CLEAR(&schan_msg);
        SCMH_OPCODE_SET(schan_msg.gencmd.header, TABLE_LOOKUP_CMD_MSG);
        SCMH_SRCBLK_SET(schan_msg.gencmd.header, CDK_XGSM_CMIC_BLOCK(unit)); 
        SCMH_DSTBLK_SET(schan_msg.gencmd.header, dstblk); 
        SCMH_DATALEN_SET(schan_msg.gencmd.header, moi->size * 4); 
        CDK_MEMCPY(schan_msg.gencmd.data, moi->key, moi->size * 4);
        schan_msg.gencmd.address = moi->addr;
        rv = cdk_xgsm_schan_op(unit, &schan_msg, moi->size + 2, moi->size + 2);
        if (CDK_SUCCESS(rv)) {
            rsp_type = SCGR_TYPE_GET(schan_msg.genresp.response);
            if (rsp_type == SCGR_TYPE_NOT_FOUND) {
                return CDK_E_NOT_FOUND;
            }
            moi->idx_min = SCGR_INDEX_GET(schan_msg.genresp.response);
            if (moi->data != NULL) {
                CDK_MEMCPY(moi->data, schan_msg.genresp.data, moi->size * 4);
            }
        }
        return rv;
    }
    if (moi->mem_op == CDK_XGSM_MEM_OP_PUSH) {
        SCHAN_MSG_CLEAR(&schan_msg);
        SCMH_OPCODE_SET(schan_msg.pushcmd.header, FIFO_PUSH_CMD_MSG);
        SCMH_SRCBLK_SET(schan_msg.pushcmd.header, CDK_XGSM_CMIC_BLOCK(unit)); 
        SCMH_DSTBLK_SET(schan_msg.pushcmd.header, dstblk); 
        SCMH_DATALEN_SET(schan_msg.pushcmd.header, moi->size * 4); 
        schan_msg.pushcmd.address = moi->addr;
        CDK_MEMCPY(schan_msg.pushcmd.data, moi->data, moi->size * 4);
        rv = cdk_xgsm_schan_op(unit, &schan_msg, moi->size + 2, 1);
        if (CDK_SUCCESS(rv) && SCMH_CPU_GET(schan_msg.pushresp.header)) {
            rv = CDK_E_FULL;
        }
        return rv;
    }
    if (moi->mem_op == CDK_XGSM_MEM_OP_POP) {
        SCHAN_MSG_CLEAR(&schan_msg);
        SCMH_OPCODE_SET(schan_msg.popcmd.header, FIFO_POP_CMD_MSG);
        SCMH_SRCBLK_SET(schan_msg.popcmd.header, CDK_XGSM_CMIC_BLOCK(unit)); 
        SCMH_DSTBLK_SET(schan_msg.popcmd.header, dstblk); 
        SCMH_DATALEN_SET(schan_msg.popcmd.header, 0); 
        schan_msg.popcmd.address = moi->addr;
        rv = cdk_xgsm_schan_op(unit, &schan_msg, 2, moi->size + 1);
        if (CDK_SUCCESS(rv)) {
            if (SCMH_CPU_GET(schan_msg.popresp.header)) {
                rv = CDK_E_NOT_FOUND;
            } else {
                CDK_MEMCPY(moi->data, schan_msg.popresp.data, moi->size * 4);
            }
        }
        return rv;
    }
#endif
    return CDK_E_UNAVAIL;
}
