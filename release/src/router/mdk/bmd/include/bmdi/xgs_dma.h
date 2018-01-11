/*
 * $Id: xgs_dma.h,v 1.3 Broadcom SDK $
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
 * XGS DMA definitions.
 */

#ifndef __XGS_DMA_H__
#define __XGS_DMA_H__

#include <bmd/bmd.h>

/*
 * Default channel configuration
 */
#define XGS_DMA_TX_CHAN         0
#define XGS_DMA_RX_CHAN         1

/* Initialize DMA */
extern int bmd_xgs_dma_init(int unit); 

/* DMA TX */
extern int bmd_xgs_dma_tx_start(int unit, dma_addr_t dcb); 
extern int bmd_xgs_dma_tx_poll(int unit, int num_polls); 
extern int bmd_xgs_dma_tx_abort(int unit, int num_polls); 

/* DMA RX */
extern int bmd_xgs_dma_rx_start(int unit, dma_addr_t dcb); 
extern int bmd_xgs_dma_rx_poll(int unit, int num_polls); 
extern int bmd_xgs_dma_rx_abort(int unit, int num_polls); 


/*
 * Per-channel dma
 * Should not be called directly under normal circumstances
 */

#define XGS_DMA_CHAN_DIR_TX     1
#define XGS_DMA_CHAN_DIR_RX     0

extern int bmd_xgs_dma_chan_init(int unit, int chan, int dir); 
extern int bmd_xgs_dma_chan_start(int unit, int chan,  dma_addr_t dcb); 
extern int bmd_xgs_dma_chan_poll(int unit, int chan, int num_polls); 
extern int bmd_xgs_dma_chan_abort(int unit, int chan, int num_polls); 

#endif /* __XGS_DMA_H__ */
