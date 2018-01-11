/*
 * $Id: xgsm_mem.c,v 1.3 Broadcom SDK $
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

#include <cdk/cdk_device.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>
#include <cdk/cdk_simhook.h>

#include <cdk/arch/xgsm_chip.h>
#include <cdk/arch/xgsm_mem.h>
#include <cdk/arch/xgsm_schan.h>

/*******************************************************************************
 *
 * Access memories
 *
 *
 ******************************************************************************/

int
cdk_xgsm_mem_read(int unit, uint32_t adext, uint32_t addr, uint32_t idx,
                  void* vptr, int size)
{
    schan_msg_t schan_msg;
    int i; 
    int rv; 
    int acctype, dstblk, datalen;
    uint32_t* entry_data = (uint32_t*)vptr; 
    int entry_dw = size; 

    CDK_ASSERT(CDK_DEV_EXISTS(unit)); 
    
    /* Simulator hooks */
    if (cdk_simhook_read) {
        CDK_DEBUG_MEM(("cdk_xgsm_mem_read[%d]: "
                       "addr=0x%03"PRIx32"%08"PRIx32" idx=%"PRIx32"\n",
                       unit, adext, addr, idx));
        return cdk_simhook_read(unit, 2, addr + idx, vptr,
                                CDK_WORDS2BYTES(size)); 
    }

    /* Configure S-Channel parameters */
    acctype = CDK_XGSM_ADEXT2ACCTYPE(adext);
    dstblk = CDK_XGSM_ADEXT2BLOCK(adext);
    datalen = entry_dw * sizeof(uint32_t);

    /*
     * Setup S-Channel command packet
     *
     * NOTE: the datalen field matters only for the Write Memory and
     * Write Register commands, where it is used only by the CMIC to
     * determine how much data to send, and is in units of bytes.
     */

    SCHAN_MSG_CLEAR(&schan_msg);
    SCMH_OPCODE_SET(schan_msg.readcmd.header, READ_MEMORY_CMD_MSG);
    SCMH_ACCTYPE_SET(schan_msg.readcmd.header, acctype);
    SCMH_DSTBLK_SET(schan_msg.readcmd.header, dstblk);
    SCMH_DATALEN_SET(schan_msg.readcmd.header, datalen);
    schan_msg.readcmd.address = addr + idx; 

    /* Issue SCHAN op */
    rv = cdk_xgsm_schan_op(unit, &schan_msg, 2, 1 + entry_dw);
    if (CDK_FAILURE(rv)) {
        CDK_ERR(("cdk_xgsm_mem_read[%d]: S-channel error "
                 "addr=0x%03"PRIx32"%08"PRIx32"\n",
                 unit, adext, addr));
	return rv; 
    }
    
    /* Check for errors */
    if (SCMH_OPCODE_GET(schan_msg.readresp.header) != READ_MEMORY_ACK_MSG) {
        CDK_ERR(("cdk_xgsm_mem_read[%d]: Invalid S-channel ACK: %"PRIu32""
                 " (expected %d) addr=0x%08"PRIx32"\n", unit,
                 SCMH_OPCODE_GET(schan_msg.readresp.header),
                 READ_MEMORY_ACK_MSG, addr));
	return CDK_E_FAIL; 
    }

    /* Copy the data out */
    CDK_DEBUG_MEM(("cdk_xgsm_mem_read[%d]: "
                   "addr=0x%03"PRIx32"%08"PRIx32" idx=%"PRIx32" data:",
                   unit, adext, addr, idx));
    for (i = 0; i < entry_dw; i++) {
	entry_data[i] = schan_msg.readresp.data[i]; 
        CDK_DEBUG_MEM((" 0x%08"PRIx32"", entry_data[i]));
    }    
    CDK_DEBUG_MEM(("\n"));

    return CDK_E_NONE; 
}   

int
cdk_xgsm_mem_write(int unit, uint32_t adext, uint32_t addr, uint32_t idx,
                   void* vptr, int size)
{
    int rv; 
    int acctype, dstblk, datalen;
    schan_msg_t schan_msg;
    int i;
    uint32_t* entry_data = (uint32_t*)vptr; 
    int entry_dw = size;

    CDK_ASSERT(CDK_DEV_EXISTS(unit)); 
    
    /* Simulator hooks */
    if (cdk_simhook_write) {
        CDK_DEBUG_MEM(("cdk_xgsm_mem_write[%d]: "
                       "addr=0x%03"PRIx32"%08"PRIx32" idx=%"PRIx32"\n",
                       unit, adext, addr, idx));
        return cdk_simhook_write(unit, 2, addr + idx, vptr,
                                 CDK_WORDS2BYTES(size)); 
    }

    /* Configure S-Channel parameters */
    acctype = CDK_XGSM_ADEXT2ACCTYPE(adext);
    dstblk = CDK_XGSM_ADEXT2BLOCK(adext);
    datalen = entry_dw * sizeof(uint32_t);

    /*
     * Setup S-Channel command packet
     *
     * NOTE: the datalen field matters only for the Write Memory and
     * Write Register commands, where it is used only by the CMIC to
     * determine how much data to send, and is in units of bytes.
     */

    SCHAN_MSG_CLEAR(&schan_msg);
    SCMH_OPCODE_SET(schan_msg.writecmd.header, WRITE_MEMORY_CMD_MSG);
    SCMH_ACCTYPE_SET(schan_msg.writecmd.header, acctype);
    SCMH_DSTBLK_SET(schan_msg.writecmd.header, dstblk);
    SCMH_DATALEN_SET(schan_msg.writecmd.header, datalen);
    
    CDK_DEBUG_MEM(("cdk_xgsm_mem_write[%d]: "
                   "addr=0x%03"PRIx32"%08"PRIx32" idx=%"PRIx32" data:",
                   unit, adext, addr, idx));
    for (i = 0; i < entry_dw; i++) {
	schan_msg.writecmd.data[i] = entry_data[i]; 
        CDK_DEBUG_MEM((" 0x%08"PRIx32"", entry_data[i]));
    }
    CDK_DEBUG_MEM(("\n"));

    schan_msg.writecmd.address = addr + idx; 

    /* 
     * Write header + address + entry_dw data DWORDs
     * Note: The hardware does not send WRITE_MEMORY_ACK_MSG. 
     */
    rv = cdk_xgsm_schan_op(unit, &schan_msg, 2 + entry_dw, 0); 
    if (CDK_FAILURE(rv)) {
        CDK_ERR(("cdk_xgsm_mem_write[%d]: S-channel error "
                 "addr=0x%03"PRIx32"%08"PRIx32"\n",
                 unit, adext, addr));
    }
    return rv;
}
