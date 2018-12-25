/*
 * $Id: bcmi_combo65_serdes_drv.c,v 1.9 Broadcom SDK $
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
 * PHY driver for internal Combo 2.5G/1.25G SerDes.
 *
 */

#include <phy/phy.h>
#include <phy/phy_xgs_iblk.h>
#include <phy/phy_brcm_serdes_id.h>

#define PHY_RESET_POLL_MAX              10

#define BCM_SERDES_PHY_ID0              0x143
#define BCM_SERDES_PHY_ID1              0xbff0

#define PHY_ID1_REV_MASK                0x000f

#define SERDES_ID0_SERDES_CL73          0x00

#define _PHY_REG_READ(_pc, _r, _v)      phy_xgs_iblk_read(_pc, _r, _v)
#define _PHY_REG_WRITE(_pc, _r, _v)     phy_xgs_iblk_write(_pc, _r, _v)

/* Standard MII Registers */
#define CS_MII_CTRL_REG                 0xffe010
#define CS_MII_STAT_REG                 0xffe011
#define CS_MII_PHY_ID0_REG              0xffe012
#define CS_MII_PHY_ID1_REG              0xffe013
#define CS_MII_ANA_REG                  0xffe014
#define CS_MII_ANP_REG                  0xffe015
#define CS_MII_AN_EXP_REG               0xffe016

/* SerDes Digital Block */
/* 1000X Control 1 Register */ 
#define DIGITAL_CTRL1                            0x830010
#define CTRL1_FIBER_MODE                         (1 << 0)
#define CTRL1_TBI_INTERFACE                      (1 << 1)
#define CTRL1_SIGNAL_DETECT_EN                   (1 << 2)
#define CTRL1_INVERT_SIGNAL_DETECT               (1 << 3)
#define CTRL1_AUTODET_EN                         (1 << 4)
#define CTRL1_SGMII_MASTER_MODE                  (1 << 5)
#define CTRL1_DISABLE_PLL_PWRDWN                 (1 << 6)
#define CTRL1_CRC_CHECKER_DISABLE                (1 << 7)
#define CTRL1_COMMA_DET_EN                       (1 << 8)
#define CTRL1_ZERO_COMMA_DETECTOR_PHASE          (1 << 9)
#define CTRL1_REMOTE_LOOPBACK                    (1 << 10)
#define CTRL1_SEL_RX_PKTS_FOR_CNTR               (1 << 11)
#define CTRL1_SERDES_TX_AMPLITUDE_OVERRIDE       (1 << 12)
#define CTRL1_MASTER_MDIO_PHY_SEL                (1 << 13)
#define CTRL1_DISABLE_SIGNAL_DETECT_FILTER       (1 << 14)

/* 1000X Control 2 Register */
#define DIGITAL_CTRL2                            0x830011
#define CTRL2_ENABLE_PARALLEL_DETECT             (1 << 0)
#define CTRL2_DISABLE_FALSE_LINK                 (1 << 1)
#define CTRL2_FILTER_FORCE_LINK                  (1 << 2)
#define CTRL2_ENABLE_AUTONEG_ERR_TIMER           (1 << 3)
#define CTRL2_DISABLE_REMOTE_ERR_TIMER           (1 << 4)
#define CTRL2_FORCE_XMIT_DATA_ON_TXSIDE          (1 << 5)
#define CTRL2_AUTONEG_FAST_TIMERS                (1 << 6)
#define CTRL2_DISABLE_CARRIER_EXTEND             (1 << 7)
#define CTRL2_DISABLE_TRRRR_GENERATION           (1 << 8)
#define CTRL2_BYPASS_PCS_RX                      (1 << 9)
#define CTRL2_BYPASS_PCS_TX                      (1 << 10)
#define CTRL2_TEST_CNTR                          (1 << 11)
#define CTRL2_TRANSMIT_PACKET_SEQ_TEST           (1 << 12)
#define CTRL2_TRANSMIT_IDLEJAM_SEQ_TEST          (1 << 13)
#define CTRL2_CLEAR_BER_COUNT                    (1 << 14)
#define CTRL2_DISABLE_EXTEND_FDX_ONLY            (1 << 15)

/* 1000X Control 3 Register */
#define DIGITAL_CTRL3                            0x830012
#define CTRL3_TX_FIFO_RST                        (1 << 0)
#define CTRL3_FIFO_ELASTICITY_TX_RX              (3 << 1)
#define CTRL3_EARLY_PREAMBLE_TX                  (1 << 3)
#define CTRL3_EARLY_PREAMBLE_RX                  (1 << 4)
#define CTRL3_FREQ_LOCK_EASTICITY_RX             (1 << 5)
#define CTRL3_FREQ_LOCK_ELASTICITY_TX            (1 << 6)
#define CTRL3_BYPASS_TXFIFO100                   (1 << 7)
#define CTRL3_FORCE_FIFO_ON                      (1 << 8)
#define CTRL3_BLOCK_TXEN_MODE                    (1 << 9)
#define CTRL3_JAM_FALSE_CARRIER_MODE             (1 << 10)
#define CTRL3_EXT_PHY_CRS_MODE                   (1 << 11)
#define CTRL3_INVERT_EXT_PHY_CRS                 (1 << 12)
#define CTRL3_DISABLE_TX_CRS                     (1 << 13)
#define CTRL3_RXFIFO_GMII_RESET                  (1 << 14)
#define CTRL3_DISABLE_PACKET_MISALIGN            (1 << 15)

/* 1000X Control 4 Register */
#define DIGITAL_CTRL4                            0x830013
#define CTRL4_MISC_RX_STAT_SEL                   (7 << 0)
#define CTRL4_NP_COUNT_CLRNRD                    (1 << 3)
#define CTRL4_NP_COUNT_CLRNBP                    (1 << 4)
#define CTRL4_LP_NEXT_PAGE_SEL                   (1 << 5)
#define CTRL4_LINK_FORCE                         (1 << 7) 
#define CTRL4_LATCH_LINKDOWN_ENABLE              (1 << 8)
#define CTRL4_CLEAR_LINKDOWN                     (1 << 9)
#define CTRL4_ZERO_RXDGMII                       (1 << 10)
#define CTRL4_TX_CONFIG_REG_SEL                  (1 << 11)
#define CTRL4_ENABLE_LAST_RESOLUTION_ERR         (1 << 12)
#define CTRL4_DISABLE_RESOLUTION_ERR_RESTART     (1 << 13)

/* 1000X STATUS 1 Register */
#define DIGITAL_STAT1                            0x830014
#define STAT1_SGMII_MODE                         (1 << 0)
#define STAT1_LINK_STATUS                        (1 << 1)
#define STAT1_DUPLEX_STATUS                      (1 << 2)
#define STAT1_SPEED_STATUS                       (3 << 3)
#define STAT1_SPEED_10MB                         (0 << 3)
#define STAT1_SPEED_100MB                        (1 << 3)
#define STAT1_SPEED_1000MB                       (2 << 3)
#define STAT1_SPEED_2P5GB                        (3 << 3)
#define STAT1_PAUSE_RESOLUTION_RXSIDE            (1 << 5)
#define STAT1_PAUSE_RESOLUTION_TXSIDE            (1 << 6)
#define STAT1_LINK_CHANGED                       (1 << 7)
#define STAT1_EARLY_END_EXTENSION_DETECTED       (1 << 8)
#define STAT1_CARRIER_EXTEND_ERR_DETECTED        (1 << 9)
#define STAT1_RX_ERR_DETECTED                    (1 << 10)
#define STAT1_TX_ERR_DETECTED                    (1 << 11)
#define STAT1_CRC_ERR_DETECTED                   (1 << 12)
#define STAT1_FALSE_CARRIER_DETECTED             (1 << 13)
#define STAT1_RXFIFO_ERR_DETECTED                (1 << 14)
#define STAT1_TXFIFO_ERR_DETECTED                (1 << 15)

/* 1000X STATUS 2 Register */
#define DIGITAL_STAT2                            0x830015
#define STAT2_AN_ENABLE_STATE                    (1 << 0)
#define STAT2_AN_ERROR_STATE                     (1 << 1)
#define STAT2_ABILITY_DETECT_STATE               (1 << 2)
#define STAT2_ACKNOWLEDGE_DETECT_STATE           (1 << 3)
#define STAT2_COMPLETE_ACKNOWLEDGE_STATE         (1 << 4)
#define STAT2_IDLE_DETECT_STATE                  (1 << 5)
#define STAT2_LINK_DOWN_LOSS_SYNC                (1 << 6)
#define STAT2_RUDI_INVALID                       (1 << 7)
#define STAT2_RUDI_L                             (1 << 8)
#define STAT2_RUDI_C                             (1 << 9)
#define STAT2_SYNC_STATUS_OK                     (1 << 10)
#define STAT2_SYNC_STATUS_FAIL                   (1 << 11)
#define STAT2_SGMII_SELECTOR_MISMATCH            (1 << 12)
#define STAT2_AUTONEG_RESOLUTION_ERR             (1 << 13)
#define STAT2_CONSISTENCY_MISTMATCH              (1 << 14)
#define STAT2_SGMII_MODE_CHANGE                  (1 << 15)

/* 1000X STATUS 3 Register */
#define DIGITAL_STAT3                            0x830016
#define STAT3_SD_FILTER_CHG	                 (1 << 7)
#define STAT3_SD_MUX                             (1 << 8)
#define STAT3_SD_FILTER                          (1 << 9)
#define STAT3_LATCH_LINKDOWN                     (1 << 10)
#define STAT3_REMOTE_PHY_AUTOSEL                 (1 << 11)
#define STAT3_PD_PARK_AN                         (1 << 12)

/* CRC Error/RX Packet Counter Register */
#define DIGITAL_PKT_COUNTER                      0x830017
#define COUNTER_CRC_ERR                          (0xFF << 0)
#define COUNTER_RX_PKT                           (0xFF << 0)
#define COUNTER_BIT_ERR_RATE                     (0xFF << 8)

/* MISC 1 Register */
#define DIGITAL_MISC1                            0x830018
#define MISC1_FORCE_SPEED                        (0xF << 0)
#define MISC1_FORCE_SPEED_2P5GB                  (0 << 0)
#define MISC1_FORCE_SPEED_5GB                    (1 << 0)
#define MISC1_FORCE_SPEED_6GB                    (2 << 0)
#define MISC1_FORCE_SPEED_10GB                   (3 << 0)
#define MISC1_FORCE_SPEED_10GB_CX4               (4 << 0)
#define MISC1_FORCE_SPEED_12GB                   (5 << 0)
#define MISC1_FORCE_SPEED_12P5GB                 (6 << 0)
#define MISC1_FORCE_SPEED_13GB                   (7 << 0)
#define MISC1_FORCE_SPEED_15GB                   (8 << 0)
#define MISC1_FORCE_SPEED_16GB                   (9 << 0)
#define MISC1_FORCE_SPEED_SEL                    (1 << 4)
#define MISC1_FORCE_LN_MODE                      (1 << 5)
#define MISC1_TX_UNDERRUN_1000_DIS               (1 << 6)
#define MISC1_FORCE_TICK0_SW                     (1 << 7)
#define MISC1_FORCE_PLL_MODE_AFE                 (7 << 8)
#define MISC1_FORCE_PLL_MODE_AFE_SEL             (1 << 12)
#define MISC1_REFCLK_SEL                         (7 << 13)

/*
 * Useful constants for XGXS PHY chips
 */

/****************/
/* XGXS Block 0 */
/****************/
/* XGXS Control Register */
#define XGXS_BLK0_CTRL                           0x800010
#define XGXS_CTRL_TXCKO_DIV                      (1 << 0)
#define XGXS_CTRL_AFRST_EN                       (1 << 1)
#define XGXS_CTRL_EDEN                           (1 << 2)
#define XGXS_CTRL_CDET_EN                        (1 << 3)
#define XGXS_CTRL_MDIO_CONT_EN                   (1 << 4)
#define XGXS_CTRL_HSTL                           (1 << 5)
#define XGXS_CTRL_RLOOP                          (1 << 6)
#define XGXS_CTRL_PLL_BYPASS                     (1 << 7)
#define XGXS_CTRL_MODE_10G                       (0xF << 8)
#define XGXS_CTRL_RESET_ANLG                     (1 << 12)
#define XGXS_CTRL_START_SEQUENCER                (1 << 13)
#define XGXS_CTRL_PCMP_EN                        (1 << 14)
#define XGXS_CTRL_PGEN_EN                        (1 << 15)

#define XGXS_BLK0_STAT                           0x800011
 
/*****************/
/* TX All Block */
/*****************/
/* TX Driver Register */
#define TX_ALL_DRIVER                            0x80A017
#define TX_DRIVER_ICBUF1T                        (1 << 0)
#define TX_DRIVER_IFULLSPD                       (7 << 1)
#define TX_DRIVER_IPREDRIVER                     (0xF << 4)
#define TX_DRIVER_IDRIVER                        (0xF << 8)
#define TX_DRIVER_PREEMPHASIS                    (0xF << 12)

/*****************/
/* Over 1G Block */
/*****************/
/* UP 1 Register */
#define OVER_1G_UP1                              0x832019
#define UP1_ADV_2P5GB                            (1 << 0)
#define UP1_ADV_5GB                              (1 << 1)
#define UP1_ADV_6GB                              (1 << 2)
#define UP1_ADV_10GB                             (1 << 3)
#define UP1_ADV_10GB_CX4                         (1 << 4)
#define UP1_ADV_12GB                             (1 << 5)
#define UP1_ADV_12P5GB                           (1 << 6)
#define UP1_ADV_13GB                             (1 << 7)
#define UP1_ADV_15GB                             (1 << 8)
#define UP1_ADV_16GB                             (1 << 9)

/* LP_UP1 Register */
#define OVER_1G_LP_UP1                              0x83201C
#define LP_UP1_ADV_2P5GB                            (1 << 0)
#define LP_UP1_ADV_5GB                              (1 << 1)
#define LP_UP1_ADV_6GB                              (1 << 2)
#define LP_UP1_ADV_10GB                             (1 << 3)
#define LP_UP1_ADV_10GB_CX4                         (1 << 4)
#define LP_UP1_ADV_12GB                             (1 << 5)
#define LP_UP1_ADV_12P5GB                           (1 << 6)
#define LP_UP1_ADV_13GB                             (1 << 7)
#define LP_UP1_ADV_15GB                             (1 << 8)
#define LP_UP1_ADV_16GB                             (1 << 9)


/***********************************************************************
 *
 * HELPER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcmi_combo65_serdes_stop
 * Purpose:
 *      Put PHY in or out of reset depending on conditions.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_combo65_serdes_stop(phy_ctrl_t *pc)
{
    uint32_t mii_ctrl;
    uint32_t f_any = PHY_F_PHY_DISABLE | PHY_F_PORT_DRAIN;
    uint32_t f_copper = PHY_F_MAC_DISABLE | PHY_F_SPEED_CHG | PHY_F_DUPLEX_CHG;
    int stop = 0;
    int ioerr = 0;

    if ((PHY_CTRL_FLAGS(pc) & f_any) ||
        ((PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) == 0 &&
         (PHY_CTRL_FLAGS(pc) & f_copper))) {
        stop = 1;
    }

    ioerr += _PHY_REG_READ(pc, CS_MII_CTRL_REG, &mii_ctrl);

    if (stop) {
        mii_ctrl |= MII_CTRL_PD;
    } else {
        mii_ctrl &= ~MII_CTRL_PD;
    }

    ioerr += _PHY_REG_WRITE(pc, CS_MII_CTRL_REG, mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcmi_combo65_serdes_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo65_serdes_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1, serdesid0;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += phy_brcm_serdes_id(pc, &phyid0, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCM_SERDES_PHY_ID0 && phyid1 == BCM_SERDES_PHY_ID1) {
        /* Common PHY ID found - read specific SerDes ID */
        ioerr += _PHY_REG_READ(pc, SERDES_ID0, &serdesid0);
        if ((serdesid0 & 0x3f) == SERDES_ID0_SERDES_CL73) {
            return ioerr ? CDK_E_IO : CDK_E_NONE;
        }
    }
    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcmi_combo65_serdes_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo65_serdes_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int ioerr = 0;
    uint32_t ctrl;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToPassthru:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) |= PHY_F_PASSTHRU;
        /* Put the Serdes in passthru mode */
        ioerr += _PHY_REG_READ(pc, DIGITAL_CTRL1, &ctrl);
        ctrl &= ~CTRL1_FIBER_MODE;
        ioerr += _PHY_REG_WRITE(pc, DIGITAL_CTRL1, ctrl);
        break;
    case PhyEvent_ChangeToFiber:
        PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_PASSTHRU;
        /* Put the Serdes in Fiber mode */
        ioerr += _PHY_REG_READ(pc, DIGITAL_CTRL1, &ctrl);
        ctrl |= CTRL1_FIBER_MODE;
        ioerr += _PHY_REG_WRITE(pc, DIGITAL_CTRL1, ctrl);
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
    bcmi_combo65_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;

}

/*
 * Function:
 *      bcmi_combo65_serdes_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo65_serdes_reset(phy_ctrl_t *pc)
{
    uint32_t ctrl;
    int cnt;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

   /* Reset PHY */
    ioerr += _PHY_REG_WRITE(pc, CS_MII_CTRL_REG, MII_CTRL_RESET);

    /* Wait for reset completion */
    for (cnt = 0; cnt < PHY_RESET_POLL_MAX; cnt++) {
        ioerr += _PHY_REG_READ(pc, CS_MII_CTRL_REG, &ctrl);
        if ((ctrl & MII_CTRL_RESET) == 0) {
            break;
        }
    }
    if (cnt >= PHY_RESET_POLL_MAX) {
        rv = CDK_E_TIMEOUT;
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      bcmi_combo65_serdes_init
 * Purpose:     
 *      Initialize PHY driver.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo65_serdes_init(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    int ioerr = 0;
    uint32_t xgxs0_ctrl, mii_ctrl;

    PHY_CTRL_CHECK(pc);

    /* Stop Sequencer */
    ioerr += _PHY_REG_READ(pc, XGXS_BLK0_CTRL, &xgxs0_ctrl);
    xgxs0_ctrl &= ~XGXS_CTRL_START_SEQUENCER;
    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK0_CTRL, xgxs0_ctrl);

    ioerr += _PHY_REG_READ(pc, CS_MII_CTRL_REG, &mii_ctrl);
    mii_ctrl |= MII_CTRL_FD | MII_CTRL_SS_1000 | MII_CTRL_FD | MII_CTRL_SS_1000;
    ioerr += _PHY_REG_WRITE(pc, CS_MII_CTRL_REG, mii_ctrl);

    /* Start Sequencer */
    xgxs0_ctrl |= XGXS_CTRL_START_SEQUENCER;
    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK0_CTRL, xgxs0_ctrl);

    /* Default mode is fiber */
    PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);

    return ioerr ? CDK_E_IO : rv;

}

/*
 * Function:    
 *      bcmi_combo65_serdes_link_get
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
bcmi_combo65_serdes_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    uint32_t mii_stat;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += _PHY_REG_READ(pc, CS_MII_STAT_REG, &mii_stat);

    if (link) {
        *link = ((mii_stat & MII_STAT_LA) != 0);
    }
    if (autoneg_done) {
        *autoneg_done = (mii_stat & MII_STAT_AN_DONE) != 0;
    }

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_combo65_serdes_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo65_serdes_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int ioerr = 0;
    uint32_t ctrl;

    PHY_CTRL_CHECK(pc);

    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) == 0) {
        /* Only support full duplex in non-passthru mode */
        return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
    }

    /* Enter reset state */
    PHY_CTRL_FLAGS(pc) |= PHY_F_DUPLEX_CHG;
    bcmi_combo65_serdes_stop(pc);

    ioerr += _PHY_REG_READ(pc, CS_MII_CTRL_REG, &ctrl);

    if (duplex) {
        ctrl |= MII_CTRL_FD;
    } else {
        ctrl &= ~MII_CTRL_FD;
    }

    ioerr += _PHY_REG_WRITE(pc, CS_MII_CTRL_REG, ctrl);

    /* Exit reset state */
    PHY_CTRL_FLAGS(pc) &= ~PHY_F_DUPLEX_CHG;
    bcmi_combo65_serdes_stop(pc);

    return ioerr;
}

/*
 * Function:    
 *      bcmi_combo65_serdes_duplex_get
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
bcmi_combo65_serdes_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    PHY_CTRL_CHECK(pc);

    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_combo65_serdes_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo65_serdes_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int ioerr = 0;
    int rv;
    int an;
    uint32_t cur_speed;
    uint32_t xgxs0_ctrl, mii_ctrl, misc1;

    PHY_CTRL_CHECK(pc);

    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) == 0 &&
        (speed == 10 || speed == 100)) {
        /* Copper only modes */
        return CDK_E_PARAM;
    }

    /* Leave hardware alone if auto-neg is enabled */
    rv = PHY_AUTONEG_GET(pc, &an);
    if (CDK_FAILURE(rv) || an) {
        return rv;
    }

    /* Leave hardware alone if speed is unchanged */
    rv = PHY_SPEED_GET(pc, &cur_speed);
    if (CDK_SUCCESS(rv) && speed == cur_speed) {
        return CDK_E_NONE;
    }

    /* Enter reset state */
    PHY_CTRL_FLAGS(pc) |= PHY_F_SPEED_CHG;
    bcmi_combo65_serdes_stop(pc);

    /* Stop Sequencer */
    ioerr += _PHY_REG_READ(pc, XGXS_BLK0_CTRL, &xgxs0_ctrl);
    xgxs0_ctrl &= ~XGXS_CTRL_START_SEQUENCER;
    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK0_CTRL, xgxs0_ctrl);

    ioerr += _PHY_REG_READ(pc, CS_MII_CTRL_REG, &mii_ctrl); 
    ioerr += _PHY_REG_READ(pc, DIGITAL_MISC1, &misc1);

    mii_ctrl &= ~MII_CTRL_SS_MASK;
    misc1 &= ~MISC1_FORCE_SPEED_SEL;

    switch (speed) {
    case 0:
    case 1000:  
        mii_ctrl |= MII_CTRL_SS_1000;
        break;
    case 2500:
        misc1 |= (MISC1_FORCE_SPEED_SEL | MISC1_FORCE_SPEED_2P5GB);
        break;
    case 100:  
        mii_ctrl |= MII_CTRL_SS_100;
        break;
    case 10:  
        mii_ctrl |= MII_CTRL_SS_10;
        break;
    default:
        rv = CDK_E_PARAM;
        break;
    } 

    ioerr += _PHY_REG_WRITE(pc, CS_MII_CTRL_REG, mii_ctrl);
    ioerr += _PHY_REG_WRITE(pc, DIGITAL_MISC1, misc1);

    /* Start Sequencer */
    xgxs0_ctrl |= XGXS_CTRL_START_SEQUENCER;
    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK0_CTRL, xgxs0_ctrl);

    /* Exit reset state */
    PHY_CTRL_FLAGS(pc) &= ~PHY_F_SPEED_CHG;
    bcmi_combo65_serdes_stop(pc);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_combo65_serdes_speed_get
 * Purpose:     
 *      Get the current operating speed. If autoneg is enabled, 
 *      then operating mode is returned, otherwise forced mode is returned.
 * Parameters:
 *      pc - PHY control structure
 *      speed - (OUT) current link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo65_serdes_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    uint32_t digi_stat;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += _PHY_REG_READ(pc, DIGITAL_STAT1, &digi_stat);
    switch (digi_stat & STAT1_SPEED_STATUS) {
    case STAT1_SPEED_10MB:
         *speed = 10;
         break;
    case STAT1_SPEED_100MB:
         *speed = 100;
         break;
    case STAT1_SPEED_2P5GB:
         *speed = 2500;
         break;
    default:
         *speed = 1000;
         break;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_combo65_serdes_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo65_serdes_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    uint32_t mii_ctrl, misc1, xgxs0_ctrl;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    /* In passthru mode we always disable autoneg */
    if (PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) {
        autoneg = 0;
    }

    ioerr += _PHY_REG_READ(pc, CS_MII_CTRL_REG, &mii_ctrl);

    if (autoneg) {
        /* Stop Sequencer */
        ioerr += _PHY_REG_READ(pc, XGXS_BLK0_CTRL, &xgxs0_ctrl);
        xgxs0_ctrl &= ~XGXS_CTRL_START_SEQUENCER;
        ioerr += _PHY_REG_WRITE(pc, XGXS_BLK0_CTRL, xgxs0_ctrl);

        ioerr += _PHY_REG_READ(pc, DIGITAL_MISC1, &misc1);
        misc1 &= ~(MISC1_FORCE_SPEED_SEL | MISC1_FORCE_SPEED);
        ioerr += _PHY_REG_WRITE(pc, DIGITAL_MISC1, misc1);

        /* Enable and restart autonegotiation (self-clearing bit) */
        mii_ctrl |= MII_CTRL_AE | MII_CTRL_RAN;
        ioerr += _PHY_REG_WRITE(pc, CS_MII_CTRL_REG, mii_ctrl);

        /* Start Sequencer */
        xgxs0_ctrl |= XGXS_CTRL_START_SEQUENCER;
        ioerr += _PHY_REG_WRITE(pc, XGXS_BLK0_CTRL, xgxs0_ctrl);

    } else {
        mii_ctrl &= ~MII_CTRL_AE;
        ioerr += _PHY_REG_WRITE(pc, CS_MII_CTRL_REG, mii_ctrl);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_combo65_serdes_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy).
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 * Notes:
 *      autoneg_done is undefined if autoneg is zero.
 */
static int
bcmi_combo65_serdes_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    uint32_t ctrl;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += _PHY_REG_READ(pc, CS_MII_CTRL_REG, &ctrl);

    *autoneg = (ctrl & MII_CTRL_AE) != 0;

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_combo65_serdes_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo65_serdes_loopback_set(phy_ctrl_t *pc, int enable)
{
    uint32_t ctrl;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += _PHY_REG_READ(pc, CS_MII_CTRL_REG, &ctrl);

    if (enable) {
        ctrl |= MII_CTRL_LE;
    } else {
        ctrl &= ~(MII_CTRL_LE);
    }
    ioerr += _PHY_REG_WRITE(pc, CS_MII_CTRL_REG, ctrl);
    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_combo65_serdes_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo65_serdes_loopback_get(phy_ctrl_t *pc, int *enable)
{
    uint32_t ctrl;
    int ioerr = 0;

    ioerr += _PHY_REG_READ(pc, CS_MII_CTRL_REG, &ctrl);

    *enable = (ctrl & MII_CTRL_LE) != 0;
    return ioerr ? CDK_E_IO : CDK_E_NONE;

}

/*
 * Function:    
 *      bcmi_combo65_serdes_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo65_serdes_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    *abil = (PHY_ABIL_1000MB | PHY_ABIL_PAUSE | PHY_ABIL_SERDES |
             PHY_ABIL_LOOPBACK | PHY_ABIL_GMII | PHY_ABIL_2500MB);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_combo65_serdes_config_set
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
bcmi_combo65_serdes_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        switch (val) {
        case PHY_IF_MII:
        case PHY_IF_GMII:
        case PHY_IF_SGMII:
        case PHY_IF_NOCXN:
            return CDK_E_NONE;
        default:
            break;
        }
        break;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcmi_combo65_serdes_config_get
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
bcmi_combo65_serdes_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = 1;
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        *val = PHY_IF_GMII;
        return CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/* Public PHY Driver Structure */
phy_driver_t bcmi_combo65_serdes_drv = {
    "bcmi_combo65_serdes", 
    "Internal 65nm Combo 2.5G/1.25G SerDes PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_combo65_serdes_probe,               /* pd_probe */
    bcmi_combo65_serdes_notify,              /* pd_notify */
    bcmi_combo65_serdes_reset,               /* pd_reset */
    bcmi_combo65_serdes_init,                /* pd_init */
    bcmi_combo65_serdes_link_get,            /* pd_link_get */
    bcmi_combo65_serdes_duplex_set,          /* pd_duplex_set */
    bcmi_combo65_serdes_duplex_get,          /* pd_duplex_get */
    bcmi_combo65_serdes_speed_set,           /* pd_speed_set */
    bcmi_combo65_serdes_speed_get,           /* pd_speed_get */
    bcmi_combo65_serdes_autoneg_set,         /* pd_autoneg_set */
    bcmi_combo65_serdes_autoneg_get,         /* pd_autoneg_get */
    bcmi_combo65_serdes_loopback_set,        /* pd_loopback_set */
    bcmi_combo65_serdes_loopback_get,        /* pd_loopback_get */
    bcmi_combo65_serdes_ability_get,         /* pd_ability_get */
    bcmi_combo65_serdes_config_set,          /* pd_config_set */
    bcmi_combo65_serdes_config_get,          /* pd_config_get */
    NULL,                                    /* pd_status_get */
    NULL                                     /* pd_cable_diag */
};
