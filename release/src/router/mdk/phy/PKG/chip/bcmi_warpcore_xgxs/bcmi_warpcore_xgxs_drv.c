/*
 * $Id: bcmi_warpcore_xgxs_drv.c,v 1.64 Broadcom SDK $
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
 * PHY driver for internal Warpcore 40G XGXS PHY.
 *
 */

#include <phy/phy.h>
#include <phy/phy_drvlist.h>
#include <phy/phy_brcm_serdes_id.h>

#include <phy/chip/bcmi_warpcore_xgxs_defs.h>
#include <phy/chip/bcmi_warpcore_xgxs_firmware_set.h>

#define BCM_SERDES_PHY_ID0              0x143
#define BCM_SERDES_PHY_ID1              0xbff0

#define PHY_ID1_REV_MASK                0x000f

#define SERDES_ID0_XGXS_WARPCORE        0x09

/* Actual speeds */
#define FV_adr_10M                      0x0
#define FV_adr_100M                     0x1
#define FV_adr_1G                       0x2
#define FV_adr_2p5G                     0x3
#define FV_adr_5G_X4                    0x4
#define FV_adr_6G_X4                    0x5
#define FV_adr_10G_HiG                  0x6
#define FV_adr_10G_CX4                  0x7
#define FV_adr_12G_HiG                  0x8
#define FV_adr_12p5G_X4                 0x9
#define FV_adr_13G_X4                   0xa
#define FV_adr_15G_X4                   0xb
#define FV_adr_16G_X4                   0xc
#define FV_adr_1G_KX                    0xd
#define FV_adr_10G_KX4                  0xe
#define FV_adr_10G_KR                   0xf
#define FV_adr_5G                       0x10
#define FV_adr_6p4G                     0x11
#define FV_adr_20G_X4                   0x12
#define FV_adr_21G_X4                   0x13
#define FV_adr_25G_X4                   0x14
#define FV_adr_10G_HiG_DXGXS            0x15
#define FV_adr_10G_DXGXS                0x16
#define FV_adr_10p5G_HiG_DXGXS          0x17
#define FV_adr_10p5G_DXGXS              0x18
#define FV_adr_12p773G_HiG_DXGXS        0x19
#define FV_adr_12p773G_DXGXS            0x1a
#define FV_adr_10G_XFI                  0x1b
#define FV_adr_40G                      0x1c
#define FV_adr_20G_HiG_DXGXS            0x1d
#define FV_adr_20G_DXGXS                0x1e
#define FV_adr_10G_SFI                  0x1f
#define FV_adr_31p5G                    0x20
#define FV_adr_32p7G                    0x21
#define FV_adr_20G_SCR                  0x22
#define FV_adr_10G_HiG_DXGXS_SCR        0x23
#define FV_adr_10G_DXGXS_SCR            0x24
#define FV_adr_12G_R2                   0x25
#define FV_adr_10G_X2                   0x26
#define FV_adr_40G_KR4                  0x27
#define FV_adr_40G_CR4                  0x28
#define FV_adr_100G_CR10                0x29
/* Not in current datasheet - may change name */
#define FV_adr_15p75GHiG_DXGXS          0x2c

/* Forced speeds */
#define FV_fdr_2500BRCM_X1              0x10
#define FV_fdr_5000BRCM_X4              0x11
#define FV_fdr_6000BRCM_X4              0x12
#define FV_fdr_10GHiGig_X4              0x13
#define FV_fdr_10GBASE_CX4              0x14
#define FV_fdr_12GHiGig_X4              0x15
#define FV_fdr_12p5GHiGig_X4            0x16
#define FV_fdr_13GHiGig_X4              0x17
#define FV_fdr_15GHiGig_X4              0x18
#define FV_fdr_16GHiGig_X4              0x19
#define FV_fdr_5000BRCM_X1              0x1a
#define FV_fdr_6363BRCM_X1              0x1b
#define FV_fdr_20GHiGig_X4              0x1c
#define FV_fdr_21GHiGig_X4              0x1d
#define FV_fdr_25p45GHiGig_X4           0x1e
#define FV_fdr_10G_HiG_DXGXS            0x1f
#define FV_fdr_10G_DXGXS                0x20
#define FV_fdr_10p5G_HiG_DXGXS          0x21
#define FV_fdr_10p5G_DXGXS              0x22
#define FV_fdr_12p773G_HiG_DXGXS        0x23
#define FV_fdr_12p773G_DXGXS            0x24
#define FV_fdr_10G_XFI                  0x25
#define FV_fdr_40G_X4                   0x26
#define FV_fdr_20G_HiG_DXGXS            0x27
#define FV_fdr_20G_DXGXS                0x28
#define FV_fdr_10G_SFI                  0x29
#define FV_fdr_31p5G                    0x2a
#define FV_fdr_32p7G                    0x2b /* not supported */
#define FV_fdr_20G_SCR                  0x2c
#define FV_fdr_10G_HiG_DXGXS_SCR        0x2d
#define FV_fdr_10G_DXGXS_SCR            0x2e
#define FV_fdr_12G_R2                   0x2f
#define FV_fdr_10G_X2                   0x30
#define FV_fdr_40G_KR4                  0x31
#define FV_fdr_40G_CR4                  0x32
#define FV_fdr_100G_CR10                0x33 /* not supported */
#define FV_fdr_5G_HiG_DXGXS             0x34 /* not supported */
#define FV_fdr_5G_DXGXS                 0x35 /* not supported */
#define FV_fdr_15p75G_HiG_DXGXS         0x36

/* PLL mode AFE */
#define FV_div32                        0x0
#define FV_div36                        0x1
#define FV_div40                        0x2
#define FV_div42                        0x3
#define FV_div48                        0x4
#define FV_div50                        0x5
#define FV_div52                        0x6
#define FV_div54                        0x7
#define FV_div60                        0x8
#define FV_div64                        0x9
#define FV_div66                        0xa
#define FV_div68                        0xb
#define FV_div80                        0xc
#define FV_div120                       0xd
#define FV_div200                       0xe
#define FV_div240                       0xf

/* Core modes */
#define FV_XGXS                         0x0
#define FV_XGXS_nCC                     0x1
#define FV_IndLane_OS8                  0x4
#define FV_IndLane_OS5                  0x5
#define FV_Indlanes                     0x6
#define FV_PCI                          0x7
#define FV_XGXS_nLQ                     0x8
#define FV_XGXS_nLQ_nCC                 0x9
#define FV_PBypass                      0xa
#define FV_PBypass_nDSK                 0xb
#define FV_ComboCoreMode                0xc
#define FV_Clocks_off                   0xf

/* Lane from PHY control instance */
#define LANE_NUM_MASK                   0x3

#define PLL_LOCK_MSEC                   200

/* PHY core revisions used for errata workarounds */
#define REV_A0                          0x00
#define REV_A1                          0x01
#define REV_A2                          0x02
#define REV_B0                          0x10

#define IS_1LANE_PORT(_pc) \
    ((PHY_CTRL_FLAGS(_pc) & (PHY_F_SERDES_MODE | PHY_F_2LANE_MODE)) == PHY_F_SERDES_MODE)
#define IS_2LANE_PORT(_pc) \
    (PHY_CTRL_FLAGS(_pc) & PHY_F_2LANE_MODE)
#define IS_4LANE_PORT(_pc) \
    ((PHY_CTRL_FLAGS(_pc) & PHY_F_SERDES_MODE) == 0)

/*
 * Private driver data
 *
 * We use a single 32-bit word which is used like this:
 *
 * 31               16 15               8 7             0
 * +------------------+------------------+---------------+
 * |     Reserved     | Active interface | Lane polarity |
 * +------------------+------------------+---------------+
 */
#if PHY_CONFIG_PRIVATE_DATA_WORDS > 0

#define PRIV_DATA(_pc) ((_pc)->priv[0])

#define LANE_POLARITY_GET(_pc) (PRIV_DATA(_pc) & 0xff)
#define LANE_POLARITY_SET(_pc,_val) \
do { \
    PRIV_DATA(_pc) &= ~0xff; \
    PRIV_DATA(_pc) |= (_val) & 0xff; \
} while (0)

#define ACTIVE_INTERFACE_GET(_pc) ((PRIV_DATA(_pc) >> 8) & 0xff)
#define ACTIVE_INTERFACE_SET(_pc,_val) \
do { \
    PRIV_DATA(_pc) &= ~0xff00; \
    PRIV_DATA(_pc) |= LSHIFT32(_val, 8) & 0xff00; \
} while (0)

#else

#define LANE_POLARITY_GET(_pc) (0)
#define LANE_POLARITY_SET(_pc,_val)
#define ACTIVE_INTERFACE_GET(_pc) (0)
#define ACTIVE_INTERFACE_SET(_pc,_val)

#endif /* PHY_CONFIG_PRIVATE_DATA_WORDS */

/* Low level debugging (off by default) */
#ifdef PHY_DEBUG_ENABLE
#define _PHY_DBG(_pc, _stuff) \
    PHY_VERB(_pc, _stuff)
#else
#define _PHY_DBG(_pc, _stuff)
#endif

/***********************************************************************
 *
 * HELPER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      _warpcore_id_rev
 * Purpose:
 *      Retrieve PHY core revision number
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      Revision number (REV_A0, etc.)
 */
static int
_warpcore_id_rev(phy_ctrl_t *pc)
{
    int ioerr = 0;
    SERDESID0r_t serdesid0;
    int rev;

    ioerr += READ_SERDESID0r(pc, &serdesid0);

    rev = SERDESID0r_REV_LETTERf_GET(serdesid0) << 4;
    rev |= SERDESID0r_REV_NUMBERf_GET(serdesid0);

    return ioerr ? -1 : rev;
}

/*
 * Function:
 *      _warpcore_serdes_lane
 * Purpose:
 *      Retrieve XGXS lane number for this PHY instance.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      Lane number or -1 if lane is unknown
 */
static int
_warpcore_serdes_lane(phy_ctrl_t *pc)
{
    uint32_t inst = PHY_CTRL_INST(pc);

    if (inst & PHY_INST_VALID) {
        return inst & LANE_NUM_MASK;
    }
    return -1;
}

/*
 * Function:
 *      _warpcore_primary_lane
 * Purpose:
 *      Ensure that each warpcore is initialized only once.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      TRUE/FALSE
 */
static int
_warpcore_primary_lane(phy_ctrl_t *pc)
{
    return ((PHY_CTRL_INST(pc) & LANE_NUM_MASK) == 0) ? TRUE : FALSE;
}

/*
 * Function:
 *      _warpcore_pll_lock_wait
 * Purpose:
 *      Wait for PLL lock after sequencer (re)start.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_warpcore_pll_lock_wait(phy_ctrl_t *pc)
{
    int ioerr = 0;
    XGXSSTATUSr_t xgxs_stat;
    int cnt;
    int lock = 0;
    
    for (cnt = 0; ioerr == 0 && cnt < PLL_LOCK_MSEC; cnt++) {
        ioerr += READ_XGXSSTATUSr(pc, &xgxs_stat); 
        if (ioerr) {
            return CDK_E_IO;
        }
        lock = XGXSSTATUSr_TXPLL_LOCKf_GET(xgxs_stat);
        if (lock) {
            break;
        }
        PHY_SYS_USLEEP(1000);
    }
    if (lock == 0) {
        PHY_WARN(pc, ("TXPLL did not lock\n"));
        return CDK_E_TIMEOUT;
    }
    return CDK_E_NONE;
}

/*
 * Function:
 *      _warpcore_rx_div_clk_set
 * Purpose:
 *      Select analog Rx div/16 and div/33 clocks for digital lanes.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_warpcore_rx_div_clk_set(phy_ctrl_t *pc)
{
    int ioerr = 0;
    RXLNSWAP1r_t rxlnswap1;
    TESTMODEMUXr_t testmodemux;
    CL72_MISC4_CONTROLr_t cl72_misc4;
    int rev;
    int digilane;
    int div_mode;

    /* Get PHY revision */
    rev = _warpcore_id_rev(pc);

    if (rev == REV_A0 || rev == REV_A1) {
        /* Use override in single-lane mode */
        ioerr += READ_TESTMODEMUXr(pc, &testmodemux);
        TESTMODEMUXr_TO_DIG_MUX_OVR_ENf_SET(testmodemux, 0);
        if (IS_1LANE_PORT(pc)) {
            TESTMODEMUXr_TO_DIG_MUX_OVR_ENf_SET(testmodemux, 1);
            /* Select analog Rx div/16 clock based on lane remapping */
            ioerr += READ_RXLNSWAP1r(pc, &rxlnswap1);
            digilane = RXLNSWAP1r_RX0_LNSWAP_SELf_GET(rxlnswap1);
            TESTMODEMUXr_TO_DIG_MUX_OVR0f_SET(testmodemux, digilane);
            digilane = RXLNSWAP1r_RX1_LNSWAP_SELf_GET(rxlnswap1);
            TESTMODEMUXr_TO_DIG_MUX_OVR1f_SET(testmodemux, digilane);
            digilane = RXLNSWAP1r_RX2_LNSWAP_SELf_GET(rxlnswap1);
            TESTMODEMUXr_TO_DIG_MUX_OVR2f_SET(testmodemux, digilane);
            digilane = RXLNSWAP1r_RX3_LNSWAP_SELf_GET(rxlnswap1);
            TESTMODEMUXr_TO_DIG_MUX_OVR3f_SET(testmodemux, digilane);
        }
        ioerr += WRITE_TESTMODEMUXr(pc, testmodemux);
    } else {
        /* Set Rx div clocks based on core mode */
        div_mode = 1;
        if (IS_2LANE_PORT(pc)) {
            div_mode = 2;
        } else if (IS_1LANE_PORT(pc)) {
            div_mode = 3;
        }
        ioerr += READ_CL72_MISC4_CONTROLr(pc, &cl72_misc4);
        CL72_MISC4_CONTROLr_RX_WCLK16_MODE_SELf_SET(cl72_misc4, div_mode);
        CL72_MISC4_CONTROLr_RX_WCLK33_MODE_SELf_SET(cl72_misc4, div_mode);
        ioerr += WRITE_CL72_MISC4_CONTROLr(pc, cl72_misc4);

        ioerr += READ_TESTMODEMUXr(pc, &testmodemux);
        TESTMODEMUXr_TO_DIG_MUX_OVR_ENf_SET(testmodemux, 0);
        ioerr += WRITE_TESTMODEMUXr(pc, testmodemux);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      _warpcore_serdes_stop
 * Purpose:
 *      Put PHY in or out of reset depending on conditions.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_warpcore_serdes_stop(phy_ctrl_t *pc)
{
    int ioerr = 0;
    LANECTRL3r_t lane_ctrl3;
    uint32_t pwrdn_tx, pwrdn_rx, lane_mask;
    uint32_t f_any = PHY_F_PHY_DISABLE | PHY_F_PORT_DRAIN;
    uint32_t f_copper = PHY_F_MAC_DISABLE | PHY_F_SPEED_CHG | PHY_F_DUPLEX_CHG;
    int stop, lane;

    ioerr += READ_LANECTRL3r(pc, &lane_ctrl3);
    pwrdn_tx = LANECTRL3r_PWRDN_TXf_GET(lane_ctrl3);

    stop = 0;
    lane_mask = 0xf;
    if ((PHY_CTRL_FLAGS(pc) & f_any) ||
        ((PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) == 0 &&
         (PHY_CTRL_FLAGS(pc) & f_copper))) {
        lane = _warpcore_serdes_lane(pc);
        /* No power-down if lane is unknown */
        if (lane >= 0) {
            stop = 1;
            lane_mask = LSHIFT32(1, lane);
        }
    }
    /* Disable Tx only as disabling Rx may affect 10G rx_ck */
    pwrdn_rx = 0;
    pwrdn_tx &= ~lane_mask;
    if (stop) {
        pwrdn_tx |= lane_mask;
    }
    LANECTRL3r_PWRDN_RXf_SET(lane_ctrl3, pwrdn_rx);
    LANECTRL3r_PWRDN_TXf_SET(lane_ctrl3, pwrdn_tx);
    ioerr += WRITE_LANECTRL3r(pc, lane_ctrl3);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      _warpcore_linkup_event
 * Purpose:
 *      PHY link-up event handler
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_warpcore_linkup_event(phy_ctrl_t *pc)
{
    int ioerr = 0;
    TXBERTCTRLr_t txbert_ctrl;    
    int rev;

    if (!IS_1LANE_PORT(pc)) {
        /* Get revision for errata workarounds */
        rev = _warpcore_id_rev(pc);
        /*
         * Erratum 15
         * Tx FIFO auto-reset workaround for multi-lane mode.
         * Issue FIFO pointer reset to recenter FIFO pointers.
         * Applies to rev A0/A1.
         */
        if (rev == REV_A0 || rev == REV_A1) {
            ioerr +=  READ_TXBERTCTRLr(pc, &txbert_ctrl);
            TXBERTCTRLr_FIFO_RSTf_SET(txbert_ctrl, 1);
            ioerr +=  WRITE_TXBERTCTRLr(pc, txbert_ctrl);
            TXBERTCTRLr_FIFO_RSTf_SET(txbert_ctrl, 0);
            ioerr +=  WRITE_TXBERTCTRLr(pc, txbert_ctrl);
        }
    }
    _PHY_DBG(pc, ("link up event\n"));
    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      _warpcore_fw_get
 * Purpose:
 *      Get firmware for this warpcore revision
 * Parameters:
 *      pc - PHY control structure
 *      size - (OUT) firmware size (in bytes)
 * Returns:
 *      Pointer to firmware data
 */
static void *
_warpcore_fw_get(phy_ctrl_t *pc, uint32_t *size)
{
    int rev;
    uint8_t *fw_data;
    uint32_t fw_size;

    /* Get revision for errata workarounds */
    rev = _warpcore_id_rev(pc);

    /* Firmware for rev B0 and newer */
    fw_data = wc40_ucode_b0_bin;
    fw_size = wc40_ucode_b0_bin_len;
    if (rev == REV_A0 || rev == REV_A1) { 
        /* Special firmware for rev A0/A1 */
        fw_data = wc40_ucode_bin;
        fw_size = wc40_ucode_bin_len;
    }
    *size = fw_size;
    return fw_data;
}

/*
 * Function:
 *      _warpcore_init_stage_0
 * Purpose:
 *      Initialization required before firmware download.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_warpcore_init_stage_0(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv;
    XGXSCONTROLr_t xgxs_ctrl;
    CL72_DEBUG_4r_t cl72_dbg4;
    UD_FIELDr_t ud_fld;
    XGXSX2CONTROL2r_t x2_ctrl;
    RXB_ANARXCONTROLPCIr_t rx_ctrl;
    MISC1r_t misc1;
    CONTROL1000X2r_t ctrl2;
    PARDET10GCONTROLr_t pd10_ctrl;
    int rev;
    void *fw_data;
    uint32_t fw_size;

    _PHY_DBG(pc, ("init_stage_0\n"));

    /* Initialize resources shared by all 4 lanes */
    if (!_warpcore_primary_lane(pc)) {
        return CDK_E_NONE;
    }

    /* Get revision for errata workarounds */
    rev = _warpcore_id_rev(pc);

    /* Stop the PLL sequencer */
    ioerr += READ_XGXSCONTROLr(pc, &xgxs_ctrl);
    XGXSCONTROLr_START_SEQUENCERf_SET(xgxs_ctrl, 0);
    ioerr += WRITE_XGXSCONTROLr(pc, xgxs_ctrl);

    /* Initialize Tx FIR */
    ioerr += READ_CL72_DEBUG_4r(pc, &cl72_dbg4);
    CL72_DEBUG_4r_TAP_V2_VALf_SET(cl72_dbg4, 9);
    ioerr += WRITE_CL72_DEBUG_4r(pc, cl72_dbg4);

    /* Advertise 5 next pages in MP1024 */
    ioerr += READ_UD_FIELDr(pc, &ud_fld);
    UD_FIELDr_NP3_COUNTf_SET(ud_fld, 2);
    ioerr += WRITE_UD_FIELDr(pc, ud_fld);

    if (!IS_4LANE_PORT(pc)) {
        /* Configure VCO frequency */
        ioerr += READ_MISC1r(pc, &misc1);
        MISC1r_FORCE_PLL_MODE_AFE_SELf_SET(misc1, 1);
        if (IS_2LANE_PORT(pc)) {
            /* Clear to force update when speed is set */
            MISC1r_FORCE_PLL_MODE_AFEf_SET(misc1, FV_div48);
        } else if (XGXSCONTROLr_MODE_10Gf_GET(xgxs_ctrl) == FV_IndLane_OS5) {
            MISC1r_FORCE_PLL_MODE_AFEf_SET(misc1, FV_div40);
        } else {
            MISC1r_FORCE_PLL_MODE_AFEf_SET(misc1, FV_div66);
        }
        /* All lane broadcast */
        ioerr += WRITEALL_MISC1r(pc, misc1);
    }

    if (IS_1LANE_PORT(pc)) {
        /*
         * Erratum 2
         * Keep clause 48 sync acquisition state machine in reset.
         * Applies to rev A0/A1/B0.
         */
        if (rev == REV_A0 || rev == REV_A1) {
            ioerr += READ_RXB_ANARXCONTROLPCIr(pc, &rx_ctrl);
            RXB_ANARXCONTROLPCIr_LINK_EN_FORCE_SMf_SET(rx_ctrl, 1);
            RXB_ANARXCONTROLPCIr_LINK_EN_Rf_SET(rx_ctrl, 0);
            ioerr += WRITE_RXB_ANARXCONTROLPCIr(pc, rx_ctrl);
        }
        if (rev == REV_B0) {
            ioerr += READ_RXB_ANARXCONTROLPCIr(pc, &rx_ctrl);
            RXB_ANARXCONTROLPCIr_SYNC_STATUS_FORCE_R_SMf_SET(rx_ctrl, 1);
            RXB_ANARXCONTROLPCIr_SYNC_STATUS_FORCE_Rf_SET(rx_ctrl, 0);
            ioerr += WRITE_RXB_ANARXCONTROLPCIr(pc, rx_ctrl);
        }
        /*
         * Erratum 3
         * Set mdio override control to send out 312.5MHz clock on txck_out[0].
         * this allow lane1-lane3 to support 10G speed while lane 0 runs at 1G.
         * Applies to rev A1/B0. No workaround for A0.
         */
        if (rev == REV_A1 || rev == REV_B0) {
            ioerr += READ_XGXSX2CONTROL2r(pc, &x2_ctrl);
            XGXSX2CONTROL2r_TXCKOUT33_OVERRIDEf_SET(x2_ctrl, 1);
            ioerr += WRITE_XGXSX2CONTROL2r(pc, x2_ctrl);
        }
    }

    /* Disable 1000X parallel detect */
    ioerr += READ_CONTROL1000X2r(pc, &ctrl2);
    CONTROL1000X2r_ENABLE_PARALLEL_DETECTIONf_SET(ctrl2, 0);
    ioerr += WRITE_CONTROL1000X2r(pc, ctrl2);

    /* Disable 10G parallel detect */
    PARDET10GCONTROLr_CLR(pd10_ctrl);
    ioerr += WRITE_PARDET10GCONTROLr(pc, pd10_ctrl);

    /* Configure the txck/rxck  */
    ioerr += READ_XGXSX2CONTROL2r(pc, &x2_ctrl);
    XGXSX2CONTROL2r_MAC_INF_RXCK_OVERRIDEf_SET(x2_ctrl, 1);
    if (IS_4LANE_PORT(pc)) {
        XGXSX2CONTROL2r_MAC_INF_TXCK_SELf_SET(x2_ctrl, 0xf);
    } else if (IS_2LANE_PORT(pc)) {
        XGXSX2CONTROL2r_MAC_INF_TXCK_SELf_SET(x2_ctrl, 0x9);
    }
    ioerr += WRITEALL_XGXSX2CONTROL2r(pc, x2_ctrl);

    /* Select the analog Rx div/16 clock for digital lanes */
    ioerr += _warpcore_rx_div_clk_set(pc);

    /* Load firmware and start uController */
    fw_data = _warpcore_fw_get(pc, &fw_size);
    rv = bcmi_warpcore_xgxs_firmware_set(pc, 0, fw_size, fw_data);
    if (CDK_FAILURE(rv)) {
        PHY_WARN(pc, ("firmware download error\n"));
    }

    /* Prepare to start seqencer */
    ioerr += READ_XGXSCONTROLr(pc, &xgxs_ctrl);

    if (!IS_1LANE_PORT(pc)) {
        /*
         * Erratum 15
         * Tx FIFO auto-reset workaround for multi-lane mode.
         * Turn off Auto FIFO Reset.
         * Applies to rev A0/A1.
         */
        if (rev == REV_A0 || rev == REV_A1) {
            XGXSCONTROLr_AFRST_ENf_SET(xgxs_ctrl, 0);
        }
    }

    /* Start the PLL sequencer */
    XGXSCONTROLr_START_SEQUENCERf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_XGXSCONTROLr(pc, xgxs_ctrl);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      _warpcore_init_stage_1
 * Purpose:
 *      Check firmware CRC (if enabled).
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_warpcore_init_stage_1(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;

    _PHY_DBG(pc, ("init_stage_1\n"));

    /* Check firmware CRC */
    if (_warpcore_primary_lane(pc)) {
        rv = bcmi_warpcore_xgxs_firmware_check(pc);
    }

    return rv;
}

/*
 * Function:
 *      _warpcore_init_stage_2
 * Purpose:
 *      Initialization required after firmware download.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_warpcore_init_stage_2(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    MISC1r_t misc1;
    MISC2r_t misc2;
    MISC3r_t misc3;
    MISC4r_t misc4;
    RX66_SCW0r_t scw0;
    RX66_SCW1r_t scw1;
    RX66_SCW2r_t scw2;
    RX66_SCW3r_t scw3;
    RX66_SCW0_MASKr_t scw0_mask;
    RX66_SCW1_MASKr_t scw1_mask;
    RX66_SCW2_MASKr_t scw2_mask;
    RX66_SCW3_MASKr_t scw3_mask;
    CONTROL1000X1r_t ctrl1;
    CONTROL1000X3r_t ctrl3;
    UNICOREMODE10Gr_t unicore_mode;
    RX66_CONTROLr_t rx66_ctrl;
    CL73_BAMCTRL3r_t cl73_bamctrl3;
    CL73CONTROL8r_t cl73_ctrl8;
    LOCALCONTROL0r_t local_ctrl0;
    MISC6r_t misc6;
    COMBO_MIICNTLr_t mii_ctrl;
    TENGBASE_KR_PMD_CONTROL_150r_t pmd_10g;
    CL72_MISC1_CONTROLr_t cl72_misc1;
    int rev;
    int speed_val;

    _PHY_DBG(pc, ("init_stage_2\n"));

    /* Get revision for errata workarounds */
    rev = _warpcore_id_rev(pc);

    /* Check lock from firmware download */
    (void)_warpcore_pll_lock_wait(pc);

    /* Configure Rx clock compensation */
    if (IS_1LANE_PORT(pc)) {
        ioerr += READ_RX66_CONTROLr(pc, &rx66_ctrl);
        RX66_CONTROLr_CC_ENf_SET(rx66_ctrl, 1);
        RX66_CONTROLr_CC_DATA_SELf_SET(rx66_ctrl, 1);
        ioerr += WRITE_RX66_CONTROLr(pc, rx66_ctrl);
    } else {
        UNICOREMODE10Gr_CLR(unicore_mode);
        UNICOREMODE10Gr_UNICOREMODE10GCX4f_SET(unicore_mode, FV_XGXS_nCC);
        UNICOREMODE10Gr_UNICOREMODE10GHIGf_SET(unicore_mode, FV_XGXS_nLQ_nCC);
        if (rev == REV_A0 || rev == REV_A1) { 
            UNICOREMODE10Gr_UNICOREMODE10GCX4f_SET(unicore_mode, FV_XGXS);
            UNICOREMODE10Gr_UNICOREMODE10GHIGf_SET(unicore_mode, FV_XGXS_nLQ);
        }
        if (IS_4LANE_PORT(pc) && !(rev == REV_A0 || rev == REV_A1)) {
            UNICOREMODE10Gr_RESERVED0f_SET(unicore_mode, 0x80);
        }
        ioerr += WRITE_UNICOREMODE10Gr(pc, unicore_mode);
    }

    /* Configure clause 73 BAM auto-negotiation */
    CL73_BAMCTRL3r_CLR(cl73_bamctrl3);
    CL73_BAMCTRL3r_UD_CODE_FIELDf_SET(cl73_bamctrl3, 1);
    ioerr += WRITE_CL73_BAMCTRL3r(pc, cl73_bamctrl3);

    /* Auto selection of PCS speed status report */
    ioerr += READ_MISC4r(pc, &misc4);
    MISC4r_AUTO_PCS_TYPE_SEL_ENf_SET(misc4, 1);
    ioerr += WRITE_MISC4r(pc, misc4);

    /* Disable forced speed control thru PMA/PMD IEEE registers */
    ioerr += READ_MISC2r(pc, &misc2);
    MISC2r_PMA_PMD_FORCED_SPEED_ENC_ENf_SET(misc2, 0);
    ioerr += WRITE_MISC2r(pc, misc2);

    /* Configure 64/66 */
    RX66_SCW0r_SET(scw0, 0xe070);
    RX66_SCW1r_SET(scw1, 0xc0d0);
    RX66_SCW2r_SET(scw2, 0xa0b0);
    RX66_SCW3r_SET(scw3, 0x8090);
    RX66_SCW0_MASKr_SET(scw0_mask, 0xf0f0);
    RX66_SCW1_MASKr_SET(scw1_mask, 0xf0f0);
    RX66_SCW2_MASKr_SET(scw2_mask, 0xf0f0);
    RX66_SCW3_MASKr_SET(scw3_mask, 0xf0f0);
    ioerr += WRITE_RX66_SCW0r(pc, scw0);
    ioerr += WRITE_RX66_SCW1r(pc, scw1);
    ioerr += WRITE_RX66_SCW2r(pc, scw2);
    ioerr += WRITE_RX66_SCW3r(pc, scw3);
    ioerr += WRITE_RX66_SCW0_MASKr(pc, scw0_mask);
    ioerr += WRITE_RX66_SCW1_MASKr(pc, scw1_mask);
    ioerr += WRITE_RX66_SCW2_MASKr(pc, scw2_mask);
    ioerr += WRITE_RX66_SCW3_MASKr(pc, scw3_mask);

    /* Disable PLL powerdown and SGMII/fiber auto-detect */
    ioerr += READ_CONTROL1000X1r(pc, &ctrl1);
    CONTROL1000X1r_DISABLE_PLL_PWRDWNf_SET(ctrl1, 1);
    CONTROL1000X1r_AUTODET_ENf_SET(ctrl1, 0);
    ioerr += WRITE_CONTROL1000X1r(pc, ctrl1);

    /* Set FIFO elasticity to 13.5k and disable Tx CRS generation */
    ioerr += READ_CONTROL1000X3r(pc, &ctrl3);
    CONTROL1000X3r_FIFO_ELASICITY_TXf_SET(ctrl3, 2);
    CONTROL1000X3r_DISABLE_TX_CRSf_SET(ctrl3, 1);
    ioerr += WRITE_CONTROL1000X3r(pc, ctrl3);

    /*
     * Erratum 1
     * Keep InBand MDIO block in reset to prevent soft reset after link
     * acquisition in 31.5G MLD mode.
     * Applies to rev A0/A1.
     */
    if (rev == REV_A0 || rev == REV_A1) {
        ioerr += READ_LOCALCONTROL0r(pc, &local_ctrl0);
        LOCALCONTROL0r_RX_INBANDMDIO_RSTf_SET(local_ctrl0, 1);
        ioerr += WRITE_LOCALCONTROL0r(pc, local_ctrl0);
    }

    /*
     * Erratum 6
     * Increase deskew buffer depth to prevent link failures at speeds
     * that use BRCM 64/66 endec.
     * Applies to rev A0/A1.
     */
    if (rev == REV_A0 || rev == REV_A1) {
        ioerr += READ_CL73CONTROL8r(pc, &cl73_ctrl8);
        CL73CONTROL8r_CL73_AN_SWITCH_CNTHf_SET(cl73_ctrl8, 7);
        ioerr += WRITE_CL73CONTROL8r(pc, cl73_ctrl8);
    }

    /* Configure 31.5G speed */
    if (IS_4LANE_PORT(pc)) {
        /* Enable BRCM 64/66 endec for 31.5G */
        ioerr += READ_MISC6r(pc, &misc6);
        MISC6r_USE_BRCM6466_31500_CYAf_SET(misc6, 1);
        ioerr += WRITE_MISC6r(pc, misc6);
    }

    /* Disable auto-negotiation in 2-lane mode */
    if (IS_2LANE_PORT(pc)) {
        ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
        COMBO_MIICNTLr_AUTONEG_ENABLEf_SET(mii_ctrl, 0);
        ioerr += WRITE_COMBO_MIICNTLr(pc, mii_ctrl);
    }

    /* Clear forced speed setting */
    ioerr += READ_MISC1r(pc, &misc1);
    MISC1r_FORCE_SPEEDf_SET(misc1, 0);
    ioerr += WRITE_MISC1r(pc, misc1);

    ioerr += READ_MISC3r(pc, &misc3);
    MISC3r_FORCE_SPEED_B5f_SET(misc3, 0);
    ioerr += WRITE_MISC3r(pc, misc3);

    /* Configure custom DXGXS speed */
    if (IS_2LANE_PORT(pc) && PHY_CTRL_FLAGS(pc) & PHY_F_CUSTOM_MODE) {

        /* Custom speed */
        speed_val = FV_fdr_12G_R2;

        /* Set bits [4:0] of forced speed */
        ioerr += READ_MISC1r(pc, &misc1);
        MISC1r_FORCE_SPEEDf_SET(misc1, (speed_val & 0x1f));
        ioerr += WRITE_MISC1r(pc, misc1);

        /* Set bit [5] of forced speed */
        ioerr += READ_MISC3r(pc, &misc3);
        MISC3r_FORCE_SPEED_B5f_SET(misc3, (speed_val >> 5));
        ioerr += WRITE_MISC3r(pc, misc3);
    }

    /* Disable clause 72 if no auto-neg */
    if (IS_2LANE_PORT(pc)) {
        ioerr += READ_TENGBASE_KR_PMD_CONTROL_150r(pc, &pmd_10g);
        TENGBASE_KR_PMD_CONTROL_150r_TRAINING_ENABLEf_SET(pmd_10g, 0);
        ioerr += WRITE_TENGBASE_KR_PMD_CONTROL_150r(pc, pmd_10g);

        ioerr += READ_CL72_MISC1_CONTROLr(pc, &cl72_misc1);
        CL72_MISC1_CONTROLr_LINK_CONTROL_FORCEf_SET(cl72_misc1, 1);
        ioerr += WRITE_CL72_MISC1_CONTROLr(pc, cl72_misc1);
    }

    /* Default mode is fiber */
    PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      _warpcore_init_stage
 * Purpose:
 *      Execute specified init stage.
 * Parameters:
 *      pc - PHY control structure
 *      stage - init stage
 * Returns:
 *      CDK_E_xxx
 */
static int
_warpcore_init_stage(phy_ctrl_t *pc, int stage)
{
    switch (stage) {
    case 0:
        return _warpcore_init_stage_0(pc);
    case 1:
        return _warpcore_init_stage_1(pc);
    case 2:
        return _warpcore_init_stage_2(pc);
    default:
        break;
    }
    return CDK_E_UNAVAIL;
}

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
extern cdk_symbols_t bcmi_warpcore_xgxs_symbols;
#endif

/*
 * Function:
 *      bcmi_warpcore_xgxs_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_warpcore_xgxs_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    SERDESID0r_t serdesid0;
    XGXSCONTROLr_t xgxs_ctrl;
    MMDSELECTr_t mmdselect;
    uint32_t model;
    int mode10g;
    int ioerr = 0;

    ioerr += phy_brcm_serdes_id(pc, &phyid0, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCM_SERDES_PHY_ID0 && phyid1 == BCM_SERDES_PHY_ID1) {
        /* Common PHY ID found - read specific SerDes ID */
        ioerr += READ_SERDESID0r(pc, &serdesid0);
        model = SERDESID0r_MODEL_NUMBERf_GET(serdesid0);
        if (model == SERDES_ID0_XGXS_WARPCORE) {
#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
            PHY_CTRL_SYMBOLS(pc) = &bcmi_warpcore_xgxs_symbols;
#endif
            /* Use clause 45 access if possible (force lane 0) */
            ioerr += READLN_MMDSELECTr(pc, 0, &mmdselect);
            if (MMDSELECTr_MULTIMMDS_ENf_GET(mmdselect) == 1) {
                PHY_CTRL_FLAGS(pc) |= PHY_F_CLAUSE45;
            }

            /* All lanes are accessed from the same PHY address */
            PHY_CTRL_FLAGS(pc) |= PHY_F_ADDR_SHARE;

            /* Check for independent lane mode (force lane 0) */
            ioerr += READ_XGXSCONTROLr(pc, &xgxs_ctrl);
            mode10g = XGXSCONTROLr_MODE_10Gf_GET(xgxs_ctrl);
            if (mode10g != FV_ComboCoreMode) {
                PHY_CTRL_FLAGS(pc) |= PHY_F_SERDES_MODE;
            }

            return ioerr ? CDK_E_IO : CDK_E_NONE;
        }
    }
    return CDK_E_NOT_FOUND;
}


/*
 * Function:
 *      bcmi_warpcore_xgxs_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_warpcore_xgxs_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    CONTROL1000X1r_t ctrl1;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToPassthru:
        if (PHY_CTRL_FLAGS(pc) & PHY_F_SERDES_MODE) {
            PHY_CTRL_FLAGS(pc) &= ~PHY_F_FIBER_MODE;
            PHY_CTRL_FLAGS(pc) |= PHY_F_PASSTHRU;
            /* Put the Serdes in passthru mode */
            ioerr += READ_CONTROL1000X1r(pc, &ctrl1);
            CONTROL1000X1r_FIBER_MODE_1000Xf_SET(ctrl1, 0);
            ioerr += WRITE_CONTROL1000X1r(pc, ctrl1);
        }
        break;
    case PhyEvent_ChangeToFiber:
        if (PHY_CTRL_FLAGS(pc) & PHY_F_SERDES_MODE) {
            PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;
            PHY_CTRL_FLAGS(pc) &= ~PHY_F_PASSTHRU;
            /* Put the Serdes in fiber mode */
            ioerr += READ_CONTROL1000X1r(pc, &ctrl1);
            CONTROL1000X1r_FIBER_MODE_1000Xf_SET(ctrl1, 1);
            ioerr += WRITE_CONTROL1000X1r(pc, ctrl1);
        }
        break;
    case PhyEvent_MacDisable:
        PHY_CTRL_FLAGS(pc) |= PHY_F_MAC_DISABLE;
        break;
    case PhyEvent_MacEnable:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_MAC_DISABLE;
        break;
    case PhyEvent_PortDrainStart:
        PHY_CTRL_FLAGS(pc) |= PHY_F_PORT_DRAIN;
        break;
    case PhyEvent_PortDrainStop:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_PORT_DRAIN;
        break;
    default:
        break;
    }

    /* Update power-down state */
    rv = _warpcore_serdes_stop(pc);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      bcmi_warpcore_xgxs_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_warpcore_xgxs_reset(phy_ctrl_t *pc)
{
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_warpcore_xgxs_init
 * Purpose:     
 *      Initialize PHY driver.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_NONE
 */
static int
bcmi_warpcore_xgxs_init(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    int stage;

    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_FLAGS(pc) & PHY_F_STAGED_INIT) {
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_STAGED_INIT;
    }

    for (stage = 0; CDK_SUCCESS(rv); stage++) {
        rv = _warpcore_init_stage(pc, stage);
    }

    if (rv == CDK_E_UNAVAIL) {
        /* Successfully completed all stages */
        rv = CDK_E_NONE;
    }

    return rv;
}

/*
 * Function:    
 *      bcmi_warpcore_xgxs_link_get
 * Purpose:     
 *      Determine the current link up/down status.
 * Parameters:
 *      pc - PHY control structure
 *      link - (OUT) non-zero indicates link established.
 *      autoneg_done - (OUT) if true, auto-negotiation is complete
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_warpcore_xgxs_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    PCS_IEEESTATUS1r_t pcs_stat;
    COMBO_MIISTATr_t mii_stat;

    PHY_CTRL_CHECK(pc);

    *link = FALSE;

    /* Check PCS link status */
    ioerr += READ_PCS_IEEESTATUS1r(pc, &pcs_stat);
    if (PCS_IEEESTATUS1r_RX_LINKSTATUSf_GET(pcs_stat)) {
        *link = TRUE;
    }

    ioerr += READ_COMBO_MIISTATr(pc, &mii_stat);
    if (autoneg_done) {
        *autoneg_done = COMBO_MIISTATr_AUTONEG_COMPLETEf_GET(mii_stat);
    }

    /* Finally check combo status for 1G link  */
    if (*link == FALSE) {
        if (COMBO_MIISTATr_LINK_STATUSf_GET(mii_stat)) {
            *link = TRUE;
        }
    }

    /* Check if a link down->up transition */
    if (*link == TRUE) {
        if (!(PHY_CTRL_FLAGS(pc) & PHY_F_LINK_UP)) {
            ioerr += _warpcore_linkup_event(pc);
        }
        PHY_CTRL_FLAGS(pc) |= PHY_F_LINK_UP;
    } else {
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_LINK_UP;
    }

    if (*link == 0) {
        ACTIVE_INTERFACE_SET(pc, 0);
    }
    
    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_warpcore_xgxs_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_warpcore_xgxs_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    STATUS1000X1r_t stat1;
    FX100_CONTROL1r_t fx100_ctrl1;
    COMBO_MIICNTLr_t mii_ctrl;

    PHY_CTRL_CHECK(pc);

    if (IS_1LANE_PORT(pc)) {
        /* Check for fiber mode (SGMII disabled) */
        ioerr += READ_STATUS1000X1r(pc, &stat1);
        if (STATUS1000X1r_SGMII_MODEf_GET(stat1) == 0) {
            /* Configure 100FX mode */
            ioerr += READ_FX100_CONTROL1r(pc, &fx100_ctrl1);
            FX100_CONTROL1r_FULL_DUPLEXf_SET(fx100_ctrl1, duplex ? 1 : 0);
            ioerr += WRITE_FX100_CONTROL1r(pc, fx100_ctrl1);
            /* 1000X should always be full duplex */
            duplex = TRUE;
        }
    } else if (duplex == 0) {
        return CDK_E_PARAM;
    }

    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    COMBO_MIICNTLr_FULL_DUPLEXf_SET(mii_ctrl, duplex ? 1 : 0);
    ioerr += WRITE_COMBO_MIICNTLr(pc, mii_ctrl);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_warpcore_xgxs_duplex_get
 * Purpose:     
 *      Get the current operating duplex mode. If autoneg is enabled, 
 *      then operating mode is returned, otherwise forced mode is returned.
 * Parameters:
 *      pc - PHY control structure
 *      duplex - (OUT) non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_warpcore_xgxs_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_warpcore_xgxs_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 * Notes:
 *      The actual speed is controlled elsewhere, so we accept any value.
 */
static int
bcmi_warpcore_xgxs_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    UNICOREMODE10Gr_t unicore_mode;
    FIRMWARE_MODEr_t firmware_mode;
    XGXSCONTROLr_t xgxs_ctrl;
    FX100_CONTROL1r_t fx100_ctrl1;
    FX100_CONTROL2r_t fx100_ctrl2;
    FX100_CONTROL3r_t fx100_ctrl3;
    MISC1r_t misc1;
    MISC3r_t misc3;
    MISC6r_t misc6;
    STATUS1000X1r_t stat1;
    COMBO_MIICNTLr_t mii_ctrl;
    CL82_TX_CONTROL_1r_t tx_control1;
    PCS_TPCONTROLr_t pcs_tpcontrol;
    TXBERTCTRLr_t txbertctrl;
    LANECTRL2r_t lanectrl2;
    uint32_t gloop1g;
    uint32_t speed_val, speed_mii_lsb, speed_mii_msb;
    uint32_t fw_mode;
    uint32_t cur_speed;
    int ind_40bitif;
    int autoneg;
    int lane_num;
    int pll_mode, cur_pll_mode;
    int mode10ghig;
    int rev, e20fix;

    PHY_CTRL_CHECK(pc);

    lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;

    /* Do not set speed if auto-negotiation is enabled */
    rv = PHY_AUTONEG_GET(pc, &autoneg);
    if (CDK_FAILURE(rv)) {
        return rv;
    }
    if (autoneg) {
        return CDK_E_NONE;
    }

    /* In custom mode speed is fixed and should be set in init */
    if (IS_2LANE_PORT(pc) && (PHY_CTRL_FLAGS(pc) & PHY_F_CUSTOM_MODE)) {
        return CDK_E_NONE;
    }

    /* Assume default firmware mode */
    if (IS_4LANE_PORT(pc)) {
        fw_mode = 0;
    } else {
        ioerr += READ_FIRMWARE_MODEr(pc, &firmware_mode);
        fw_mode = FIRMWARE_MODEr_GET(firmware_mode);
        fw_mode &= ~LSHIFT32(0xf, 4 * lane_num);
    }

    speed_val = 0;
    speed_mii_lsb = 0;
    speed_mii_msb = 0;
    pll_mode = FV_div66;
    mode10ghig = FV_XGXS_nLQ_nCC;
    ind_40bitif = 0;
    e20fix = 0;

    if (IS_4LANE_PORT(pc)) {
        switch (speed) {
        case 0:
            return CDK_E_NONE;
        case 10:
            if (PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) {
                return CDK_E_PARAM;
            }
            break;
        case 100:
            speed_mii_lsb = 1;
            break;
        case 1000:
            speed_mii_msb = 1;
            break;
        case 2500:
            break;
        case 10000:
            speed_val = FV_fdr_10GBASE_CX4;
            break;
        case 12000:
            speed_val = FV_fdr_12GHiGig_X4;
            break;
        case 13000:
            speed_val = FV_fdr_13GHiGig_X4;
            break;
        case 16000:
            speed_val = FV_fdr_16GHiGig_X4;
            break;
        case 20000:
            speed_val = FV_fdr_20GHiGig_X4;
            mode10ghig = FV_XGXS_nLQ_nCC;
            break;
        case 21000:
            speed_val = FV_fdr_21GHiGig_X4;
            break;
        case 25000:
            speed_val = FV_fdr_25p45GHiGig_X4;
            break;
        case 30000:
            speed_val = FV_fdr_31p5G;
            break;
        case 40000:
            if (PHY_CTRL_LINE_INTF(pc) == PHY_IF_KR) {
                speed_val = FV_fdr_40G_KR4;
                /* SFP_DAC mode (3) on all lanes */
                fw_mode = 0x3333;
            } else if (PHY_CTRL_LINE_INTF(pc) == PHY_IF_CR) {
                speed_val = FV_fdr_40G_CR4;
            } else {
                /* Default is XLAUI */
                speed_val = FV_fdr_40G_X4;
            }
            /* Get revision for errata workarounds */
            rev = _warpcore_id_rev(pc);
            /*
             * Erratum 20
             * Keep clause 82 PCS in reset while PLL is tuning.
             * Applies to rev A0/A1.
             */ 
            if (rev == REV_A0 || rev == REV_A1) {
                e20fix = 1;
            }
            break;
        default:
            return CDK_E_PARAM;
        }
    } else {
        /* Speeds above 10G require DXGXS mode */
        if (speed > 10000 && IS_1LANE_PORT(pc)) {
            return CDK_E_PARAM;
        }

        switch (speed) {
        case 0:
            return CDK_E_NONE;
        case 10:
            if (PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) {
                return CDK_E_PARAM;
            }
            break;
        case 100:
            speed_mii_lsb = 1;
            break;
        case 1000:
            speed_mii_msb = 1;
            break;
        case 2500:
            speed_val = FV_fdr_2500BRCM_X1;
            break;
        case 10000:
            if (IS_2LANE_PORT(pc)) {
                pll_mode = FV_div40;
                if (PHY_CTRL_FLAGS(pc) & PHY_F_CUSTOM_MODE) {
                    speed_val = FV_fdr_10G_X2;
                } else if (PHY_CTRL_LINE_INTF(pc) == PHY_IF_HIGIG) {
                    speed_val = FV_fdr_10G_HiG_DXGXS;
                    pll_mode = FV_div42;
                } else {
                    speed_val = FV_fdr_10G_DXGXS;
                }
            } else { 
                if (PHY_CTRL_LINE_INTF(pc) == PHY_IF_SFI) {
                    speed_val = FV_fdr_10G_SFI;
                    /* SFP_DAC mode */
                    fw_mode |= LSHIFT32(2, 4 * lane_num);
                } else {
                    speed_val = FV_fdr_10G_XFI;
                }
                ind_40bitif = 1;
            }
            break;
        case 12000:
        case 13000:
            if (PHY_CTRL_FLAGS(pc) & PHY_F_CUSTOM_MODE) {
                speed_val = FV_fdr_12G_R2;
            } else {
                speed_val = FV_fdr_12p773G_DXGXS;
            }
            pll_mode = FV_div42;
            break;
        case 15000:
            speed_val = FV_fdr_15p75G_HiG_DXGXS;
            pll_mode = FV_div52;
            break;
        case 20000:
            if (PHY_CTRL_LINE_INTF(pc) == PHY_IF_HIGIG) {
                speed_val = FV_fdr_20G_HiG_DXGXS;
            } else {
                speed_val = FV_fdr_20G_DXGXS;
            }
            ind_40bitif = 1;
            break;
        default:
            return CDK_E_PARAM;
        }
    }

    /* Do not set speed if unchanged */
    rv = PHY_SPEED_GET(pc, &cur_speed);
    if (CDK_FAILURE(rv)) {
        return rv;
    }
    if (speed == cur_speed &&
        PHY_CTRL_LINE_INTF(pc) == ACTIVE_INTERFACE_GET(pc)) {
        return CDK_E_NONE;
    }

    if (IS_4LANE_PORT(pc)) {
        /*
         * Erratum 20
         * Keep clause 82 PCS in reset while PLL is tuning.
         * Applies to rev A0/A1.
         */ 
        if (e20fix) {
            /* Disable PCS */
            ioerr += READ_CL82_TX_CONTROL_1r(pc, &tx_control1);
            CL82_TX_CONTROL_1r_CL82_EN_VALf_SET(tx_control1, 0);
            CL82_TX_CONTROL_1r_CL82_EN_OVERRIDEf_SET(tx_control1, 1);
            ioerr += WRITE_CL82_TX_CONTROL_1r(pc, tx_control1);
        }

        /* Update Rx clock compensation */
        ioerr += READ_UNICOREMODE10Gr(pc, &unicore_mode);
        UNICOREMODE10Gr_UNICOREMODE10GHIGf_SET(unicore_mode, mode10ghig);
        ioerr += WRITE_UNICOREMODE10Gr(pc, unicore_mode);

        /* Stop the PLL sequencer */
        ioerr += READ_XGXSCONTROLr(pc, &xgxs_ctrl);
        XGXSCONTROLr_START_SEQUENCERf_SET(xgxs_ctrl, 0);
        ioerr += WRITE_XGXSCONTROLr(pc, xgxs_ctrl);
    } else {
        /* Hold Tx/Rx ASIC reset */
        ioerr += READ_MISC6r(pc, &misc6);
        MISC6r_RESET_RX_ASICf_SET(misc6, 1);
        MISC6r_RESET_TX_ASICf_SET(misc6, 1);
        ioerr += WRITE_MISC6r(pc, misc6);
    }

    /* Update firmware mode for all lanes */
    FIRMWARE_MODEr_SET(firmware_mode, fw_mode);
    ioerr += WRITE_FIRMWARE_MODEr(pc, firmware_mode);

    /* Disable 100FX and 100FX auto-detect */
    ioerr += READ_FX100_CONTROL1r(pc, &fx100_ctrl1);
    FX100_CONTROL1r_ENABLEf_SET(fx100_ctrl1, 0);
    FX100_CONTROL1r_AUTO_DETECT_FX_MODEf_SET(fx100_ctrl1, 0);
    ioerr += WRITE_FX100_CONTROL1r(pc, fx100_ctrl1);

    /* Disable 100FX idle detect */
    ioerr += READ_FX100_CONTROL3r(pc, &fx100_ctrl3);
    FX100_CONTROL3r_CORRELATOR_DISABLEf_SET(fx100_ctrl3, 1);
    ioerr += WRITE_FX100_CONTROL3r(pc, fx100_ctrl3);
 
    /* Set bits [4:0] of speed_val */
    ioerr += READ_MISC1r(pc, &misc1);
    MISC1r_FORCE_SPEEDf_SET(misc1, speed_val & 0x1f);
    ioerr += WRITE_MISC1r(pc, misc1);

    /* Set bit [5] of speed_val and 40-bit interface mode */
    ioerr += READ_MISC3r(pc, &misc3);
    MISC3r_FORCE_SPEED_B5f_SET(misc3, (speed_val & 0x20) ? 1 : 0);
    MISC3r_IND_40BITIFf_SET(misc3, ind_40bitif);
    ioerr += WRITE_MISC3r(pc, misc3);

    /* Update VCO frequency */
    if (IS_2LANE_PORT(pc)) {
        cur_pll_mode = MISC1r_FORCE_PLL_MODE_AFEf_GET(misc1);
        if (pll_mode != cur_pll_mode) {
            /* Turn off loopback while changing VCO */
            ioerr += READ_LANECTRL2r(pc, &lanectrl2);
            gloop1g = LANECTRL2r_GLOOP1Gf_GET(lanectrl2);
            if (gloop1g) {
                LANECTRL2r_GLOOP1Gf_SET(lanectrl2, 0);
                ioerr += WRITE_LANECTRL2r(pc, lanectrl2);
            }

            /* Update VCO */
            MISC1r_FORCE_PLL_MODE_AFEf_SET(misc1, pll_mode);
            ioerr += WRITEALL_MISC1r(pc, misc1);

            /* Restart the PLL sequencer after VCO change */
            ioerr += READ_XGXSCONTROLr(pc, &xgxs_ctrl);
            XGXSCONTROLr_START_SEQUENCERf_SET(xgxs_ctrl, 0);
            ioerr += WRITE_XGXSCONTROLr(pc, xgxs_ctrl);
            XGXSCONTROLr_START_SEQUENCERf_SET(xgxs_ctrl, 1);
            ioerr += WRITE_XGXSCONTROLr(pc, xgxs_ctrl);

            (void) _warpcore_pll_lock_wait(pc); 

            /* Restore loopback */
            if (gloop1g) {
                LANECTRL2r_GLOOP1Gf_SET(lanectrl2, gloop1g);
                ioerr += WRITE_LANECTRL2r(pc, lanectrl2);
            }
        }
    }

    if (speed <= 1000) {
        /* Check for 100FX mode */
        ioerr += READ_STATUS1000X1r(pc, &stat1);
        if (STATUS1000X1r_SGMII_MODEf_GET(stat1) == 0 && speed == 100) {
            /* Enable 100FX mode */
            ioerr += READ_FX100_CONTROL1r(pc, &fx100_ctrl1);
            FX100_CONTROL1r_ENABLEf_SET(fx100_ctrl1, 1);
            FX100_CONTROL1r_FAR_END_FAULT_ENf_SET(fx100_ctrl1, 1);
            ioerr += WRITE_FX100_CONTROL1r(pc, fx100_ctrl1);

            /* Enable 100FX extended packet size */
            ioerr += READ_FX100_CONTROL2r(pc, &fx100_ctrl2);
            FX100_CONTROL2r_EXTEND_PKT_SIZEf_SET(fx100_ctrl2, 1);
            ioerr += WRITE_FX100_CONTROL2r(pc, fx100_ctrl2);
        } else {
            /* Set IEEE speed if not 100FX */
            ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
            COMBO_MIICNTLr_MANUAL_SPEED0f_SET(mii_ctrl, speed_mii_lsb);
            COMBO_MIICNTLr_MANUAL_SPEED1f_SET(mii_ctrl, speed_mii_msb);
            ioerr += WRITE_COMBO_MIICNTLr(pc, mii_ctrl);
        }
    }

    if (IS_4LANE_PORT(pc)) {
        /* Start the PLL sequencer */
        ioerr += READ_XGXSCONTROLr(pc, &xgxs_ctrl);
        XGXSCONTROLr_START_SEQUENCERf_SET(xgxs_ctrl, 1);
        ioerr += WRITE_XGXSCONTROLr(pc, xgxs_ctrl);

        (void) _warpcore_pll_lock_wait(pc); 

        /*
         * Erratum 20
         * Keep clause 82 PCS in reset while PLL is tuning.
         * Applies to rev A0/A1.
         */ 
        if (e20fix) {
            /* Enable test mode */
            ioerr += READ_PCS_TPCONTROLr(pc, &pcs_tpcontrol);
            PCS_TPCONTROLr_PRBS31TX_ENf_SET(pcs_tpcontrol, 1);
            PCS_TPCONTROLr_TP_SELf_SET(pcs_tpcontrol, 0);
            ioerr += WRITE_PCS_TPCONTROLr(pc, pcs_tpcontrol);

            PHY_SYS_USLEEP(100);

            /* Enable PCS */
            ioerr += READ_CL82_TX_CONTROL_1r(pc, &tx_control1);
            CL82_TX_CONTROL_1r_CL82_EN_VALf_SET(tx_control1, 0);
            CL82_TX_CONTROL_1r_CL82_EN_OVERRIDEf_SET(tx_control1, 0);
            ioerr += WRITE_CL82_TX_CONTROL_1r(pc, tx_control1);

            /* Reset MAC interface FIFO */
            ioerr += READ_TXBERTCTRLr(pc, &txbertctrl);
            TXBERTCTRLr_FIFO_RSTf_SET(txbertctrl, 1);
            ioerr += WRITE_TXBERTCTRLr(pc, txbertctrl);
            TXBERTCTRLr_FIFO_RSTf_SET(txbertctrl, 0);
            ioerr += WRITE_TXBERTCTRLr(pc, txbertctrl);

            PHY_SYS_USLEEP(100);

            /* Disable test mode */
            ioerr += READ_PCS_TPCONTROLr(pc, &pcs_tpcontrol);
            PCS_TPCONTROLr_PRBS31TX_ENf_SET(pcs_tpcontrol, 0);
            ioerr += WRITE_PCS_TPCONTROLr(pc, pcs_tpcontrol);
        }
    } else {
        /* Release Tx/Rx ASIC reset */
        ioerr += READ_MISC6r(pc, &misc6);
        MISC6r_RESET_RX_ASICf_SET(misc6, 0);
        MISC6r_RESET_TX_ASICf_SET(misc6, 0);
        ioerr += WRITE_MISC6r(pc, misc6);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_warpcore_xgxs_speed_get
 * Purpose:     
 *      Get the current operating speed.
 * Parameters:
 *      pc - PHY control structure
 *      speed - (OUT) current link speed
 * Returns:     
 *      CDK_E_xxx
 * Notes:
 *      The actual speed is controlled elsewhere, so always return 10000
 *      for sanity purposes.
 */

static int
bcmi_warpcore_xgxs_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int ioerr = 0;
    XGXSSTATUS4r_t xgxs_stat4;
    GP2_2r_t gp2_2;
    GP2_3r_t gp2_3;
    uint32_t speed_mode;
    int lane_num;

    PHY_CTRL_CHECK(pc);

    *speed = 0;

    if (IS_4LANE_PORT(pc)) {
        ioerr += READ_XGXSSTATUS4r(pc, &xgxs_stat4);
        speed_mode = XGXSSTATUS4r_ACTUAL_SPEED_LN0f_GET(xgxs_stat4);
    } else {
        lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;
        if (lane_num < 2) {
            ioerr += READ_GP2_2r(pc, &gp2_2);
            if (lane_num == 0) {
                speed_mode = GP2_2r_ACTUAL_SPEED_LN0f_GET(gp2_2);
            } else {
                speed_mode = GP2_2r_ACTUAL_SPEED_LN1f_GET(gp2_2);
            }
        } else {
            ioerr += READ_GP2_3r(pc, &gp2_3);
            if (lane_num == 2) {
                speed_mode = GP2_3r_ACTUAL_SPEED_LN2f_GET(gp2_3);
            } else {
                speed_mode = GP2_3r_ACTUAL_SPEED_LN3f_GET(gp2_3);
            }
        }
    }

    switch (speed_mode) {
        case FV_adr_10M:
            *speed = 10;
            break;
        case FV_adr_100M:
            *speed = 100;
            break;        
        case FV_adr_1G:
            *speed = 1000;
            break;
        case FV_adr_2p5G:
            *speed = 2500;
            break;
        case FV_adr_5G_X4:
            *speed = 5000;
            break;
        case FV_adr_6G_X4:
            *speed = 6000;
            break;
        case FV_adr_10G_HiG:
            *speed = 10000;
            ACTIVE_INTERFACE_SET(pc, PHY_IF_HIGIG);
            break;
        case FV_adr_10G_CX4:
            *speed = 10000;
            ACTIVE_INTERFACE_SET(pc, 0);
            break;
        case FV_adr_12G_HiG:
            *speed = 12000;
            ACTIVE_INTERFACE_SET(pc, PHY_IF_HIGIG);
            break;
        case FV_adr_12p5G_X4:
            *speed = 12500;
            break;
        case FV_adr_13G_X4:
            *speed = 13000;
            break;
        case FV_adr_15G_X4:
            *speed = 15000;
            break;
        case FV_adr_16G_X4:
            *speed = 16000;
            break;
        case FV_adr_1G_KX:
            *speed = 1000;
            break;
        case FV_adr_10G_KX4:
            *speed = 10000;
            break;
        case FV_adr_10G_KR:
            *speed = 10000;
            ACTIVE_INTERFACE_SET(pc, PHY_IF_KR);
            break;
        case FV_adr_5G:
            *speed = 5000;
            break;
        case FV_adr_6p4G:
            *speed = 6000;
            break;
        case FV_adr_20G_X4:
            *speed = 20000;
            break;
        case FV_adr_21G_X4:
            *speed = 21000;
            break;
        case FV_adr_25G_X4:
            *speed = 25000;
            break;
        case FV_adr_10G_HiG_DXGXS:
        case FV_adr_10p5G_HiG_DXGXS:
            *speed = 10000;
            ACTIVE_INTERFACE_SET(pc, PHY_IF_HIGIG);
            break;
        case FV_adr_10G_DXGXS:
        case FV_adr_10p5G_DXGXS:
            *speed = 10000;
            break;
        case FV_adr_12p773G_HiG_DXGXS:
            *speed = 12000;
            ACTIVE_INTERFACE_SET(pc, PHY_IF_HIGIG);
            break;
        case FV_adr_12p773G_DXGXS:
            *speed = 12000;
            break;
        case FV_adr_10G_XFI:
            *speed = 10000;
            ACTIVE_INTERFACE_SET(pc, PHY_IF_XFI);
            break;
        case FV_adr_40G:
            *speed = 40000;
            ACTIVE_INTERFACE_SET(pc, 0);
            break;
        case FV_adr_20G_HiG_DXGXS:
            *speed = 20000;
            ACTIVE_INTERFACE_SET(pc, PHY_IF_HIGIG);
            break;
        case FV_adr_20G_DXGXS:
            *speed = 20000;
            break;
        case FV_adr_10G_SFI:
            *speed = 10000;
            ACTIVE_INTERFACE_SET(pc, PHY_IF_SFI);
            break;
        case FV_adr_31p5G:
            *speed = 31000;
            break;
        case FV_adr_32p7G:
            *speed = 32000;
            break;
        case FV_adr_20G_SCR:
            *speed = 20000;
            break;
        case FV_adr_10G_HiG_DXGXS_SCR:
            *speed = 10000;
            ACTIVE_INTERFACE_SET(pc, PHY_IF_HIGIG);
            break;
        case FV_adr_10G_DXGXS_SCR:
            *speed = 10000;
            break;
        case FV_adr_12G_R2:
            *speed = 12000;
            break;
        case FV_adr_10G_X2:
            *speed = 10000;
            break;
        case FV_adr_40G_KR4:
            *speed = 40000;
            ACTIVE_INTERFACE_SET(pc, PHY_IF_KR);
            break;
        case FV_adr_40G_CR4:
            *speed = 40000;
            ACTIVE_INTERFACE_SET(pc, PHY_IF_CR);
            break;
        case FV_adr_15p75GHiG_DXGXS:
            *speed = 15000;
            ACTIVE_INTERFACE_SET(pc, PHY_IF_HIGIG);
            break;
        default:
            break;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_warpcore_xgxs_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */

static int
bcmi_warpcore_xgxs_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int ioerr = 0;
    int lane_num;
    int cl73_an;
    MISC1r_t misc1;
    MISC3r_t misc3;
    UNICOREMODE10Gr_t unicore_mode;
    TENGBASE_KR_PMD_CONTROL_150r_t pmd_10g;
    CL72_MISC1_CONTROLr_t cl72_misc1;
    XGXSCONTROLr_t xgxs_ctrl;
    CONTROL1000X1r_t ctrl1;
    CONTROL1000X2r_t ctrl2;
    PARDET10GCONTROLr_t pd10_ctrl;
    MP5_NEXTPAGECTRLr_t mp5_np_ctrl;
    COMBO_MIICNTLr_t mii_ctrl;
    CL73_BAMCTRL1r_t bam_ctrl;
    AN_IEEECONTROL1r_t an_ctrl;

    PHY_CTRL_CHECK(pc);

    lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;

    /* 2-lane mode uses fixed speed - autoneg turned off in init */
    if (IS_2LANE_PORT(pc)) {
        return CDK_E_NONE;
    }

    /* In passthru mode we always disable autoneg */
    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU)) {
        autoneg = 0;
    }

    if (autoneg) {
        /* Disable forced speed if autoneg is enabled */
        ioerr += READ_MISC1r(pc, &misc1);
        MISC1r_FORCE_SPEEDf_SET(misc1, 0);
        ioerr += WRITE_MISC1r(pc, misc1);
        ioerr += READ_MISC3r(pc, &misc3);
        MISC3r_FORCE_SPEED_B5f_SET(misc3, 0);
        ioerr += WRITE_MISC3r(pc, misc3);

        /* Default Rx clock compensation */
        ioerr += READ_UNICOREMODE10Gr(pc, &unicore_mode);
        UNICOREMODE10Gr_UNICOREMODE10GHIGf_SET(unicore_mode, FV_XGXS_nLQ_nCC);
        ioerr += WRITE_UNICOREMODE10Gr(pc, unicore_mode);

        /* Used as field value, so cannot be any non-zero value */
        autoneg = 1;
    }

    cl73_an = autoneg;
    if (PHY_CTRL_LINE_INTF(pc) == PHY_IF_HIGIG) {
        cl73_an = 0;
    }

    /* Enable clause 72 training if auto-neg */
    ioerr += READ_TENGBASE_KR_PMD_CONTROL_150r(pc, &pmd_10g);
    TENGBASE_KR_PMD_CONTROL_150r_TRAINING_ENABLEf_SET(pmd_10g, autoneg);
    ioerr += WRITE_TENGBASE_KR_PMD_CONTROL_150r(pc, pmd_10g);

    /* Disable clause 72 forced link control if auto-neg */
    ioerr += READ_CL72_MISC1_CONTROLr(pc, &cl72_misc1);
    CL72_MISC1_CONTROLr_LINK_CONTROL_FORCEf_SET(cl72_misc1, autoneg ? 0 : 1);
    ioerr += WRITE_CL72_MISC1_CONTROLr(pc, cl72_misc1);

    if (IS_4LANE_PORT(pc)) {
        /* Stop the PLL sequencer */
        ioerr += READ_XGXSCONTROLr(pc, &xgxs_ctrl);
        XGXSCONTROLr_START_SEQUENCERf_SET(xgxs_ctrl, 0);
        ioerr += WRITE_XGXSCONTROLr(pc, xgxs_ctrl);

        /* Configure 10G parallel detect */
        ioerr += READ_PARDET10GCONTROLr(pc, &pd10_ctrl);
        PARDET10GCONTROLr_PARDET10G_ENf_SET(pd10_ctrl, autoneg);
        ioerr += WRITE_PARDET10GCONTROLr(pc, pd10_ctrl);

    } else {
        /* Set fiber auto detect */
        ioerr += READ_CONTROL1000X1r(pc, &ctrl1);
        CONTROL1000X1r_AUTODET_ENf_SET(ctrl1, autoneg);
        ioerr += WRITE_CONTROL1000X1r(pc, ctrl1);
    }

    /* Configure 1000X parallel detect */
    ioerr += READ_CONTROL1000X2r(pc, &ctrl2);
    CONTROL1000X2r_ENABLE_PARALLEL_DETECTIONf_SET(ctrl2, autoneg);
    ioerr += WRITE_CONTROL1000X2r(pc, ctrl2);

    /* Set BAM/TETON enable */
    ioerr += READ_MP5_NEXTPAGECTRLr(pc, &mp5_np_ctrl);
    MP5_NEXTPAGECTRLr_BAM_MODEf_SET(mp5_np_ctrl, autoneg);
    MP5_NEXTPAGECTRLr_TETON_MODEf_SET(mp5_np_ctrl, autoneg);
    MP5_NEXTPAGECTRLr_TETON_MODE_UP3_ENf_SET(mp5_np_ctrl, autoneg);
    ioerr += WRITE_MP5_NEXTPAGECTRLr(pc, mp5_np_ctrl);

    /* Configure IEEE auto-neg */
    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    COMBO_MIICNTLr_AUTONEG_ENABLEf_SET(mii_ctrl, autoneg);
    ioerr += WRITE_COMBO_MIICNTLr(pc, mii_ctrl);

    /* Configure Broadcom auto-neg */
    ioerr += READ_CL73_BAMCTRL1r(pc, &bam_ctrl);
    CL73_BAMCTRL1r_CL73_BAMENf_SET(bam_ctrl, cl73_an);
    ioerr += WRITE_CL73_BAMCTRL1r(pc, bam_ctrl);

    /* Only modify auto-neg on primary lane */
    ioerr += READ_AN_IEEECONTROL1r(pc, &an_ctrl);
    AN_IEEECONTROL1r_AN_ENABLEf_SET(an_ctrl, cl73_an);
    ioerr += WRITELN_AN_IEEECONTROL1r(pc, lane_num, an_ctrl);

    if (IS_4LANE_PORT(pc)) {
        /* Start the PLL sequencer */
        ioerr += READ_XGXSCONTROLr(pc, &xgxs_ctrl);
        XGXSCONTROLr_START_SEQUENCERf_SET(xgxs_ctrl, 1);
        ioerr += WRITE_XGXSCONTROLr(pc, xgxs_ctrl);

        (void)_warpcore_pll_lock_wait(pc);
    }

    /* Restart autoneg if enabled */
    if (autoneg) {
        COMBO_MIICNTLr_RESTART_AUTONEGf_SET(mii_ctrl, 1);
        ioerr += WRITE_COMBO_MIICNTLr(pc, mii_ctrl);

        /* Only modify auto-neg on primary lane */
        ioerr += READ_AN_IEEECONTROL1r(pc, &an_ctrl);
        AN_IEEECONTROL1r_RESTARTANf_SET(an_ctrl, cl73_an);
        ioerr += WRITELN_AN_IEEECONTROL1r(pc, lane_num, an_ctrl);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_warpcore_xgxs_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_warpcore_xgxs_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    int ioerr = 0;
    COMBO_MIICNTLr_t mii_ctrl;

    PHY_CTRL_CHECK(pc);

    /* 2-lane mode uses fixed speed - autoneg turned off in init */
    if (IS_2LANE_PORT(pc)) {
        *autoneg = 0;
        return CDK_E_NONE;
    }

    /* Read IEEE autoneg */
    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    *autoneg = COMBO_MIICNTLr_AUTONEG_ENABLEf_GET(mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE; 
}

/*
 * Function:    
 *      bcmi_warpcore_xgxs_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_warpcore_xgxs_loopback_set(phy_ctrl_t *pc, int enable)
{
    int ioerr = 0;
    int rv;
    LANETESTr_t lane_test;
    ANARXCONTROLPCIr_t rx_ctrl;
    ANATXACONTROL0r_t tx_ctrl;
    XGXSCONTROLr_t xgxs_ctrl;
    LANECTRL2r_t lanectrl2;
    uint32_t rx_flip = 0;
    uint32_t tx_flip = 0;
    uint32_t lane_mask;
    uint32_t gloop1g;
    int cur_lb;
    int lane_num, lane_end;
    int idx;
    int rev;

    PHY_CTRL_CHECK(pc);

    if (enable) {
        /* Used as field value, so cannot be any non-zero value */
        enable = 1;
    }

    rv = PHY_LOOPBACK_GET(pc, &cur_lb);
    if (CDK_FAILURE(rv)) {
        return rv;
    }
    if (cur_lb == enable) {
        return CDK_E_NONE;
    }

    lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;

    lane_end = lane_num;
    if (IS_2LANE_PORT(pc)) {
        lane_end += 1;
    } else if (IS_4LANE_PORT(pc)) {
        lane_end += 3;
    }

    if (IS_4LANE_PORT(pc)) {
        /* Get revision for errata workarounds */
        rev = _warpcore_id_rev(pc);
        /*
         * Erratum 12
         * Ensure that PLL clock works correctly in loopback mode. 
         * Applies to rev A0/A1/B0.
         */
        if (rev == REV_A0 || rev == REV_A1 || rev == REV_B0) {
            ioerr += READ_LANETESTr(pc, &lane_test);
            LANETESTr_PWRDN_SAFE_DISf_SET(lane_test, enable);
            ioerr += WRITE_LANETESTr(pc, lane_test);
        }
    }

    if (enable) {
        /* Enable 1G MDIO controls in loopback mode */
        ioerr += READ_XGXSCONTROLr(pc, &xgxs_ctrl);
        XGXSCONTROLr_MDIO_CONT_ENf_SET(xgxs_ctrl, 1);
        ioerr += WRITE_XGXSCONTROLr(pc, xgxs_ctrl);

        if (LANE_POLARITY_GET(pc) == 0) {
            /* Save the polarity setting and clear hardware */
            for (idx = lane_num; idx <= lane_end; idx++) {
                ioerr += READ_ANARXCONTROLPCIr(pc, idx, &rx_ctrl);
                if (ANARXCONTROLPCIr_RX_POLARITY_Rf_GET(rx_ctrl)) {
                    rx_flip |= LSHIFT32(1, idx);
                    ANARXCONTROLPCIr_RX_POLARITY_Rf_SET(rx_ctrl, 0);
                    ANARXCONTROLPCIr_RX_POLARITY_FORCE_SMf_SET(rx_ctrl, 0);
                    ioerr += WRITE_ANARXCONTROLPCIr(pc, idx, rx_ctrl);
                }
                ioerr += READ_ANATXACONTROL0r(pc, idx, &tx_ctrl);
                if (ANATXACONTROL0r_TXPOL_FLIPf_GET(tx_ctrl)) {
                    tx_flip |= LSHIFT32(1, idx);
                    ANATXACONTROL0r_TXPOL_FLIPf_SET(tx_ctrl, 0);
                    ioerr += WRITE_ANATXACONTROL0r(pc, idx, tx_ctrl);
                }
            }
            LANE_POLARITY_SET(pc, LSHIFT32(tx_flip, 4) | rx_flip);
        }
    } else {
        if (LANE_POLARITY_GET(pc) != 0) {
            /* Restore the polarity setting to hardware */
            rx_flip = LANE_POLARITY_GET(pc) & 0xf;
            tx_flip = ((LANE_POLARITY_GET(pc)) >> 4) & 0xf;
            for (idx = lane_num; idx <= lane_end; idx++) {
                ioerr += READ_ANARXCONTROLPCIr(pc, idx, &rx_ctrl);
                if (rx_flip & LSHIFT32(1, idx)) {
                    ANARXCONTROLPCIr_RX_POLARITY_Rf_SET(rx_ctrl, 1);
                    ANARXCONTROLPCIr_RX_POLARITY_FORCE_SMf_SET(rx_ctrl, 1);
                    ioerr += WRITE_ANARXCONTROLPCIr(pc, idx, rx_ctrl);
                }
                ioerr += READ_ANATXACONTROL0r(pc, idx, &tx_ctrl);
                if (tx_flip & LSHIFT32(1, idx)) {
                    ANATXACONTROL0r_TXPOL_FLIPf_SET(tx_ctrl, 1);
                    ioerr += WRITE_ANATXACONTROL0r(pc, idx, tx_ctrl);
                }
            }
            LANE_POLARITY_SET(pc, 0);
        }
    }

    lane_mask = 0;
    for (idx = lane_num; idx <= lane_end; idx++) {
        lane_mask |= (1 << idx);
    }

    /* Set loopback XGXS core */
    ioerr += READ_LANECTRL2r(pc, &lanectrl2);
    gloop1g = LANECTRL2r_GLOOP1Gf_GET(lanectrl2);
    gloop1g &= ~lane_mask;
    if (enable) {
        gloop1g |= lane_mask;
    }
    LANECTRL2r_GLOOP1Gf_SET(lanectrl2, gloop1g);
    ioerr += WRITE_LANECTRL2r(pc, lanectrl2);

    /* Disable 1G MDIO controls if no lanes are in loopback mode */
    if (gloop1g == 0) {
        ioerr += READ_XGXSCONTROLr(pc, &xgxs_ctrl);
        XGXSCONTROLr_MDIO_CONT_ENf_SET(xgxs_ctrl, 0);
        ioerr += WRITE_XGXSCONTROLr(pc, xgxs_ctrl);
    }

    if (enable && IS_4LANE_PORT(pc)) {
        /* Stop the PLL sequencer */
        ioerr += READ_XGXSCONTROLr(pc, &xgxs_ctrl);
        XGXSCONTROLr_START_SEQUENCERf_SET(xgxs_ctrl, 0);
        ioerr += WRITE_XGXSCONTROLr(pc, xgxs_ctrl);

        /* Start the PLL sequencer */
        XGXSCONTROLr_START_SEQUENCERf_SET(xgxs_ctrl, 1);
        ioerr += WRITE_XGXSCONTROLr(pc, xgxs_ctrl);

        (void)_warpcore_pll_lock_wait(pc);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_warpcore_xgxs_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_warpcore_xgxs_loopback_get(phy_ctrl_t *pc, int *enable)
{
    int ioerr = 0;
    LANECTRL2r_t lanectrl2;
    int lane_num;

    PHY_CTRL_CHECK(pc);

    lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;

    /* Get loopback mode */
    ioerr += READ_LANECTRL2r(pc, &lanectrl2);
    *enable = (LANECTRL2r_GLOOP1Gf_GET(lanectrl2) & (1 << lane_num)) ? 1 : 0;

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_warpcore_xgxs_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_warpcore_xgxs_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    if (IS_4LANE_PORT(pc)) {
        *abil = (PHY_ABIL_40GB | PHY_ABIL_30GB | PHY_ABIL_25GB |
                 PHY_ABIL_21GB | PHY_ABIL_16GB | PHY_ABIL_13GB |
                 PHY_ABIL_10GB | PHY_ABIL_1000MB_FD |
                 PHY_ABIL_PAUSE | PHY_ABIL_LOOPBACK | 
                 PHY_ABIL_XAUI | PHY_ABIL_XGMII);
    } else if (PHY_CTRL_FLAGS(pc) & PHY_F_CUSTOM_MODE) {
        *abil = PHY_ABIL_10GB | PHY_ABIL_13GB | PHY_ABIL_LOOPBACK |
            PHY_ABIL_XAUI | PHY_ABIL_XGMII;
    } else {
        *abil = (PHY_ABIL_2500MB | PHY_ABIL_1000MB | PHY_ABIL_SERDES |
                 PHY_ABIL_PAUSE | PHY_ABIL_LOOPBACK |
                 PHY_ABIL_GMII);
    }
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_warpcore_xgxs_config_set
 * Purpose:
 *      Modify PHY configuration value.
 * Parameters:
 *      pc - PHY control structure
 *      cfg - Configuration parameter
 *      val - Configuration value
 *      cd - Additional configuration data (if any)
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_warpcore_xgxs_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
    case PhyConfig_PortInterface:
        return CDK_E_NONE;
#if PHY_CONFIG_INCLUDE_XAUI_TX_LANE_MAP_SET
    case PhyConfig_XauiTxLaneRemap: {
        int ioerr = 0;
        TXLNSWAP1r_t txlnswap1;

        ioerr += READ_TXLNSWAP1r(pc, &txlnswap1);
        TXLNSWAP1r_TX0_LNSWAP_SELf_SET(txlnswap1, val & 0x3);
        TXLNSWAP1r_TX1_LNSWAP_SELf_SET(txlnswap1, (val >> 4) & 0x3);
        TXLNSWAP1r_TX2_LNSWAP_SELf_SET(txlnswap1, (val >> 8) & 0x3);
        TXLNSWAP1r_TX3_LNSWAP_SELf_SET(txlnswap1, (val >> 12) & 0x3);
        ioerr += WRITE_TXLNSWAP1r(pc, txlnswap1);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_RX_LANE_MAP_SET
    case PhyConfig_XauiRxLaneRemap: {
        int ioerr = 0;
        RXLNSWAP1r_t rxlnswap1;

        ioerr += READ_RXLNSWAP1r(pc, &rxlnswap1);
        RXLNSWAP1r_RX0_LNSWAP_SELf_SET(rxlnswap1, val & 0x3);
        RXLNSWAP1r_RX1_LNSWAP_SELf_SET(rxlnswap1, (val >> 4) & 0x3);
        RXLNSWAP1r_RX2_LNSWAP_SELf_SET(rxlnswap1, (val >> 8) & 0x3);
        RXLNSWAP1r_RX3_LNSWAP_SELf_SET(rxlnswap1, (val >> 12) & 0x3);
        ioerr += WRITE_RXLNSWAP1r(pc, rxlnswap1);

        /* Select analog Rx div/16 clock for digital lanes after remap */
        ioerr += _warpcore_rx_div_clk_set(pc);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_TX_POLARITY_SET
    case PhyConfig_XauiTxPolInvert: {
        int ioerr = 0;
        ANATXACONTROL0r_t tx_ctrl;
        int lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;
        int lane_end;
        int idx, fval;

        lane_end = lane_num;
        if (IS_2LANE_PORT(pc)) {
            lane_end += 1;
        } else if (IS_4LANE_PORT(pc)) {
            lane_end += 3;
        }
        for (idx = lane_num; idx <= lane_end; idx++) {
            fval = (val >> ((idx - lane_num) * 4));
            ioerr += READ_ANATXACONTROL0r(pc, idx, &tx_ctrl);
            ANATXACONTROL0r_TXPOL_FLIPf_SET(tx_ctrl, fval);
            ioerr += WRITE_ANATXACONTROL0r(pc, idx, tx_ctrl);
        }
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_RX_POLARITY_SET
    case PhyConfig_XauiRxPolInvert: {
        int ioerr = 0;
        ANARXCONTROLPCIr_t rx_ctrl;
        int lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;
        int lane_end;
        int idx, fval;

        lane_end = lane_num;
        if (IS_2LANE_PORT(pc)) {
            lane_end += 1;
        } else if (IS_4LANE_PORT(pc)) {
            lane_end += 3;
        }
        for (idx = lane_num; idx <= lane_end; idx++) {
            fval = (val >> ((idx - lane_num) * 4));
            ioerr += READ_ANARXCONTROLPCIr(pc, idx, &rx_ctrl);
            ANARXCONTROLPCIr_RX_POLARITY_Rf_SET(rx_ctrl, fval);
            ANARXCONTROLPCIr_RX_POLARITY_FORCE_SMf_SET(rx_ctrl, fval);
            ioerr += WRITE_ANARXCONTROLPCIr(pc, idx, rx_ctrl);
        }
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
    case PhyConfig_TxPreemp: {
        int ioerr = 0;
        CL72_TX_FIR_TAPr_t tx_fir_tap;

        CL72_TX_FIR_TAPr_SET(tx_fir_tap, val);
        ioerr += WRITE_CL72_TX_FIR_TAPr(pc, tx_fir_tap);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxIDrv: {
        int ioerr = 0;
        TXB_TX_DRIVERr_t tx_drv;

        ioerr += READ_TXB_TX_DRIVERr(pc, &tx_drv);
        TXB_TX_DRIVERr_IDRIVERf_SET(tx_drv, val);
        ioerr += WRITE_TXB_TX_DRIVERr(pc, tx_drv);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxPreIDrv: {
        int ioerr = 0;
        TXB_TX_DRIVERr_t tx_drv;

        ioerr += READ_TXB_TX_DRIVERr(pc, &tx_drv);
        TXB_TX_DRIVERr_IPREDRIVERf_SET(tx_drv, val);
        ioerr += WRITE_TXB_TX_DRIVERr(pc, tx_drv);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_InitStage: {
        if (PHY_CTRL_FLAGS(pc) & PHY_F_STAGED_INIT) {
            return _warpcore_init_stage(pc, val);
        }
        break;
    }
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcmi_warpcore_xgxs_config_get
 * Purpose:
 *      Get PHY configuration value.
 * Parameters:
 *      pc - PHY control structure
 *      cfg - Configuration parameter
 *      val - (OUT) Configuration value
 *      cd - (OUT) Additional configuration data (if any)
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_warpcore_xgxs_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = 1;
        return CDK_E_NONE;
    case PhyConfig_Clause45Devs:
        *val = 0;
        if (PHY_CTRL_FLAGS(pc) & PHY_F_CLAUSE45) {
            *val = 0x8b;
        }
        return CDK_E_NONE;
    case PhyConfig_TxPreemp: {
        int ioerr = 0;
        CL72_TX_FIR_TAPr_t tx_fir_tap;

        ioerr += READ_CL72_TX_FIR_TAPr(pc, &tx_fir_tap);
        *val = CL72_TX_FIR_TAPr_GET(tx_fir_tap);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxIDrv: {
        int ioerr = 0;
        TXB_TX_DRIVERr_t tx_drv;

        ioerr += READ_TXB_TX_DRIVERr(pc, &tx_drv);
        *val = TXB_TX_DRIVERr_IDRIVERf_GET(tx_drv);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxPreIDrv: {
        int ioerr = 0;
        TXB_TX_DRIVERr_t tx_drv;

        ioerr += READ_TXB_TX_DRIVERr(pc, &tx_drv);
        *val = TXB_TX_DRIVERr_IPREDRIVERf_GET(tx_drv);
        ioerr += WRITE_TXB_TX_DRIVERr(pc, tx_drv);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcmi_warpcore_xgxs_status_get
 * Purpose:
 *      Get PHY status value.
 * Parameters:
 *      pc - PHY control structure
 *      stat - status parameter
 *      val - (OUT) status value
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_warpcore_xgxs_status_get(phy_ctrl_t *pc, phy_status_t stat, uint32_t *val)
{
    PHY_CTRL_CHECK(pc);

    switch (stat) {
    case PhyStatus_LineInterface:
        *val = ACTIVE_INTERFACE_GET(pc);
        if (*val == 0) {
            *val = PHY_CTRL_LINE_INTF(pc);
        }
        if (*val == 0) {
            *val = PHY_IF_XGMII;
        }
        return CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/* Public PHY Driver Structure */
phy_driver_t bcmi_warpcore_xgxs_drv = {
    "bcmi_warpcore_xgxs", 
    "Internal Warpcore 40G XGXS PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_warpcore_xgxs_probe,           /* pd_probe */
    bcmi_warpcore_xgxs_notify,          /* pd_notify */
    bcmi_warpcore_xgxs_reset,           /* pd_reset */
    bcmi_warpcore_xgxs_init,            /* pd_init */
    bcmi_warpcore_xgxs_link_get,        /* pd_link_get */
    bcmi_warpcore_xgxs_duplex_set,      /* pd_duplex_set */
    bcmi_warpcore_xgxs_duplex_get,      /* pd_duplex_get */
    bcmi_warpcore_xgxs_speed_set,       /* pd_speed_set */
    bcmi_warpcore_xgxs_speed_get,       /* pd_speed_get */
    bcmi_warpcore_xgxs_autoneg_set,     /* pd_autoneg_set */
    bcmi_warpcore_xgxs_autoneg_get,     /* pd_autoneg_get */
    bcmi_warpcore_xgxs_loopback_set,    /* pd_loopback_set */
    bcmi_warpcore_xgxs_loopback_get,    /* pd_loopback_get */
    bcmi_warpcore_xgxs_ability_get,     /* pd_ability_get */
    bcmi_warpcore_xgxs_config_set,      /* pd_config_set */
    bcmi_warpcore_xgxs_config_get,      /* pd_config_get */
    bcmi_warpcore_xgxs_status_get,      /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
