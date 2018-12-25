/*
 * $Id: xgs_dma.h,v 1.5 Broadcom SDK $
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

#include <cdk/cdk_higig_defs.h>

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

/*
 * Utility functions for parsing Rx DMA descriptors
 */

#if BMD_CONFIG_INCLUDE_HIGIG == 1

extern int bmd_xgs_parse_higig(int unit, bmd_pkt_t *pkt, uint32_t *mh);
extern int bmd_xgs_parse_higig2(int unit, bmd_pkt_t *pkt, uint32_t *mh);

#else

#define bmd_xgs_parse_higig(_u, _pkt, _mh)
#define bmd_xgs_parse_higig2(_u, _pkt, _mh)

#endif

/*
 * Utility functions for debugging Rx DMA descriptors
 */

#if CDK_CONFIG_INCLUDE_DEBUG == 1

extern int bmd_xgs_dump_rx_dcb(int unit, uint32_t *dcb,
                               int dcb_size, int mh_size);
extern int bmd_xgs_dump_tx_dcbs(int unit, uint32_t *dcbs, int dcb_cnt,
                                int dcb_size, int mh_size);

#else

#define bmd_xgs_dump_rx_dcb(_u, _dcb, _dcb_size, _mh_size)
#define bmd_xgs_dump_tx_dcbs(_u, _dcbs, _dcb_cnt, _dcb_size, _mh_size)

#endif


/* Assume 1:1 mapping between HiGig opcode and BMD packet type */
#define BMD_PKT_TYPE_FROM_HIGIG(_x)     (_x)

#endif /* __XGS_DMA_H__ */
