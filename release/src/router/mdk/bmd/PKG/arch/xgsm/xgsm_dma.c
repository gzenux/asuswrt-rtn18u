/*
 * $Id: xgsm_dma.c,v 1.6 Broadcom SDK $
 *
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

#ifdef CDK_CONFIG_ARCH_XGSM_INSTALLED

#include <bmdi/arch/xgsm_dma.h>

#include <cdk/cdk_error.h>
#include <cdk/arch/xgsm_cmic.h>

#define CMIC_NUM_PKT_DMA_CHAN           4

/*
 * Per-channel operations. 
 * These are the basis for the TX/RX functions
 */

static int
_clear_chan(int unit, int chan)
{
    int ioerr = 0;
    CMIC_CMC_DMA_CTRLr_t cdc;
    CMIC_CMC_DMA_STAT_CLRr_t cdsc;

    /* Clear descriptor complete */
    CMIC_CMC_DMA_STAT_CLRr_CLR(cdsc); 
    CMIC_CMC_DMA_STAT_CLRr_DESCRD_CMPLT_CLRf_SET(cdsc, (1 << chan)); 
    ioerr += WRITE_CMIC_CMC_DMA_STAT_CLRr(unit, cdsc); 

    CDK_CONFIG_MEMORY_BARRIER; 

    /* Disable DMA */
    ioerr += READ_CMIC_CMC_DMA_CTRLr(unit, chan, &cdc); 
    CMIC_CMC_DMA_CTRLr_DMA_ENf_SET(cdc, 0);
    ioerr += WRITE_CMIC_CMC_DMA_CTRLr(unit, chan, cdc); 

    CDK_CONFIG_MEMORY_BARRIER; 

    return CDK_E_NONE; 
}

int 
bmd_xgsm_dma_chan_init(int unit, int chan, int dir)
{
    int ioerr = 0;
    CMIC_CMC_DMA_CTRLr_t cdc;

    ioerr += READ_CMIC_CMC_DMA_CTRLr(unit, chan, &cdc); 
    CMIC_CMC_DMA_CTRLr_DIRECTIONf_SET(cdc, dir);
    ioerr += WRITE_CMIC_CMC_DMA_CTRLr(unit, chan, cdc); 

    return ioerr ? CDK_E_IO : CDK_E_NONE; 
}

int 
bmd_xgsm_dma_chan_start(int unit, int chan, dma_addr_t dcb)
{
    int ioerr = 0;
    CMIC_CMC_DMA_CTRLr_t cdc;

    /* Write the DCB address to the DESC address for this channel */
    CDK_DEV_WRITE32(unit, CMIC_CMC_DMA_DESCr + 4*chan, dcb);
    
    CDK_CONFIG_MEMORY_BARRIER; 

    /* Kick it off */
    ioerr += READ_CMIC_CMC_DMA_CTRLr(unit, chan, &cdc); 
    CMIC_CMC_DMA_CTRLr_DMA_ENf_SET(cdc, 1);
    ioerr += WRITE_CMIC_CMC_DMA_CTRLr(unit, chan, cdc); 

    CDK_CONFIG_MEMORY_BARRIER; 

    return ioerr ? CDK_E_IO : CDK_E_NONE; 
}

int
bmd_xgsm_dma_chan_poll(int unit, int chan, int polls)
{
    int ioerr = 0;
    CMIC_CMC_DMA_STATr_t dma_stat;
    uint32_t done;
    int px; 
    
    for (px = 0; px < polls; px++) {
        ioerr += READ_CMIC_CMC_DMA_STATr(unit, &dma_stat);
        if (chan == XGSM_DMA_TX_CHAN) {
            done = CMIC_CMC_DMA_STATr_CHAIN_DONEf_GET(dma_stat);
        } else {
            done = CMIC_CMC_DMA_STATr_DESC_DONEf_GET(dma_stat);
        }
        if (done & (1 << chan)) {
            /* DMA complete. Clear the channel */
            _clear_chan(unit, chan); 

            return ioerr ? CDK_E_IO : px; 
        }
    }
    return CDK_E_TIMEOUT; 
}

int
bmd_xgsm_dma_chan_abort(int unit, int chan, int polls)
{
    int ioerr = 0;
    CMIC_CMC_DMA_CTRLr_t cdc;
    CMIC_CMC_DMA_STATr_t dma_stat;
    uint32_t active;
    int px;

    /* Abort the channel */
    ioerr += READ_CMIC_CMC_DMA_CTRLr(unit, chan, &cdc); 
    CMIC_CMC_DMA_CTRLr_ABORT_DMAf_SET(cdc, 1);
    ioerr += WRITE_CMIC_CMC_DMA_CTRLr(unit, chan, cdc); 

    CDK_CONFIG_MEMORY_BARRIER; 

    /* Poll for abort completion */
    for (px = 0; px < polls; px++) {
        ioerr += READ_CMIC_CMC_DMA_STATr(unit, &dma_stat);
        active = CMIC_CMC_DMA_STATr_DMA_ACTIVEf_GET(dma_stat);
        if (!(active & (1 << chan))) {
            /* Clear abort */
            ioerr += READ_CMIC_CMC_DMA_CTRLr(unit, chan, &cdc); 
            CMIC_CMC_DMA_CTRLr_ABORT_DMAf_SET(cdc, 0);
            ioerr += WRITE_CMIC_CMC_DMA_CTRLr(unit, chan, cdc); 

            /* DMA complete. Clear the channel */
            _clear_chan(unit, chan); 

            return ioerr ? CDK_E_IO : px; 
        }
    }
    return CDK_E_TIMEOUT; 
}

int 
bmd_xgsm_dma_init(int unit)
{
    int ioerr = 0;
    CMIC_CMC_DMA_CTRLr_t dma_ctrl;
    CMIC_RXBUF_EP_RLS_CREDr_t rel_credit;
    CMIC_CMC_COS_CTRL_RX_0r_t cos_ctrl0;
    CMIC_CMC_COS_CTRL_RX_1r_t cos_ctrl1;
    int chan;

    /* Set Packet DMA endian */
    for (chan = 0; chan < CMIC_NUM_PKT_DMA_CHAN; chan++) {
        ioerr += READ_CMIC_CMC_DMA_CTRLr(unit, chan, &dma_ctrl);
        if (CDK_DEV_FLAGS(unit) & CDK_DEV_BE_PACKET) {
            CMIC_CMC_DMA_CTRLr_PKTDMA_ENDIANESSf_SET(dma_ctrl, 1);
        }
        if (CDK_DEV_FLAGS(unit) & CDK_DEV_BE_OTHER) {
            CMIC_CMC_DMA_CTRLr_DESC_ENDIANESSf_SET(dma_ctrl, 1);
        }
        ioerr += WRITE_CMIC_CMC_DMA_CTRLr(unit, chan, dma_ctrl);
    }

    /* Release all credits to EPIPE */
    CMIC_RXBUF_EP_RLS_CREDr_RELEASE_ALL_CREDITSf_SET(rel_credit, 1);
    ioerr += WRITE_CMIC_RXBUF_EP_RLS_CREDr(unit, rel_credit);

    /* Enable 48 CPU COS queues */
    CMIC_CMC_COS_CTRL_RX_0r_SET(cos_ctrl0, 0xffffffff);
    WRITE_CMIC_CMC_COS_CTRL_RX_0r(unit, XGSM_DMA_RX_CHAN, cos_ctrl0);
    CMIC_CMC_COS_CTRL_RX_1r_SET(cos_ctrl1, 0xffff);
    WRITE_CMIC_CMC_COS_CTRL_RX_1r(unit, XGSM_DMA_RX_CHAN, cos_ctrl1);

    /* Initialize TX and RX channels */
    bmd_xgsm_dma_chan_init(unit, XGSM_DMA_TX_CHAN, XGSM_DMA_CHAN_DIR_TX); 
    bmd_xgsm_dma_chan_init(unit, XGSM_DMA_RX_CHAN, XGSM_DMA_CHAN_DIR_RX); 

    return ioerr ? CDK_E_IO : CDK_E_NONE; 
}


int 
bmd_xgsm_dma_tx_start(int unit, dma_addr_t dcb)
{       
    return bmd_xgsm_dma_chan_start(unit, XGSM_DMA_TX_CHAN, dcb); 
}

int
bmd_xgsm_dma_tx_poll(int unit, int num_polls)
{
    return bmd_xgsm_dma_chan_poll(unit, XGSM_DMA_TX_CHAN, num_polls); 
}

int
bmd_xgsm_dma_tx_abort(int unit, int num_polls)
{
    return bmd_xgsm_dma_chan_abort(unit, XGSM_DMA_TX_CHAN, num_polls); 
}

int 
bmd_xgsm_dma_rx_start(int unit, dma_addr_t dcb)
{       
    return bmd_xgsm_dma_chan_start(unit, XGSM_DMA_RX_CHAN, dcb); 
}

int
bmd_xgsm_dma_rx_poll(int unit, int num_polls)
{
    return bmd_xgsm_dma_chan_poll(unit, XGSM_DMA_RX_CHAN, num_polls); 
}

int
bmd_xgsm_dma_rx_abort(int unit, int num_polls)
{
    return bmd_xgsm_dma_chan_abort(unit, XGSM_DMA_RX_CHAN, num_polls); 
}

#endif /* CDK_CONFIG_ARCH_XGSM_INSTALLED */
