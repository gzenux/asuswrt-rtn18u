/*
 * $Id: bmd_dma.c,v 1.4 Broadcom SDK $
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
#include <bmd/bmd_dma.h>

#include <cdk/cdk_device.h>
#include <cdk/cdk_error.h>
#include <cdk/cdk_assert.h>

/*
 * Function:
 *	bmd_dma_alloc_coherent
 * Purpose:
 *      Allocate coherent DMA memory
 * Parameters:
 *      unit - Unit number
 *      size - Size of DMA buffer
 *      baddr - (OUT) Physical bus address of DMA buffer
 * Returns:
 *      Logical DMA buffer address or NULL if error.
 * Notes:
 *      This function is used for allocating coherent DMA
 *      memory, which is typically used for storing DMA
 *      descriptors.
 *      On memory architectures that do not provide cache
 *      coherency, this function should return non-cached
 *      memory.
 */
void *
bmd_dma_alloc_coherent(int unit, size_t size, dma_addr_t *baddr)
{
    void *laddr = NULL;

#if BMD_CONFIG_INCLUDE_DMA
    /* Allocate coherent DMA memory */
    laddr = BMD_SYS_DMA_ALLOC_COHERENT(CDK_DEV_DVC(unit), size, baddr); 
#endif
    return laddr; 
}

/*
 * Function:
 *	bmd_dma_free_coherent
 * Purpose:
 *      Free coherent DMA memory
 * Parameters:
 *      unit - Unit number
 *      size - Size of DMA buffer
 *      laddr - Logical DMA buffer address
 *      baddr - (OUT) Physical bus address of DMA buffer
 * Returns:
 *      Nothing.
 * Notes:
 *      This function is used for freeing DMA memory
 *      allocated with bmd_dma_alloc_coherent.
 */
void
bmd_dma_free_coherent(int unit, size_t size, void *laddr, dma_addr_t baddr)
{
#if BMD_CONFIG_INCLUDE_DMA
    /* Free coherent DMA memory */
    BMD_SYS_DMA_FREE_COHERENT(CDK_DEV_DVC(unit), size, laddr, baddr); 
#endif
}

#if BMD_CONFIG_INCLUDE_DMA_CACHE_CONTROL

/* 
 * Function:
 *      bmd_dma_cache_flush
 * Purpose:
 *      Flush block of DMA memory
 * Parameters:
 *      addr - Address of memory block to flush
 *      len - Size of block
 * Returns:
 *      Nothing
 */
void
bmd_dma_cache_flush(void *addr, size_t len)
{
    BMD_SYS_DMA_CACHE_FLUSH(addr, len);
}

/* 
 * Function:
 *      bmd_dma_cache_inval
 * Purpose:
 *      Invalidate block of DMA memory
 * Parameters:
 *      addr - Address of memory block to invalidate
 *      len - Size of block
 * Returns:
 *      Nothing
 */
void
bmd_dma_cache_inval(void *addr, size_t len)
{
    BMD_SYS_DMA_CACHE_INVAL(addr, len);
}

#endif

