/*
 * $Id: bcmi_quadsgmii_serdes_drv.c,v 1.2 Broadcom SDK $
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
 * PHY driver for internal Quad SGMII 2.5 Gbps PHY.
 *
 */

#include <phy/phy.h>
#include <phy/phy_xgs_iblk.h>
#include <phy/phy_brcm_serdes_id.h>

#include <phy/chip/bcmi_unicore13g_xgxs_defs.h>

#define BCM_SERDES_PHY_ID0              0x143
#define BCM_SERDES_PHY_ID1              0xbff0

#define PHY_ID1_REV_MASK                0x000f

#define SERDES_ID0_QUADSGMII            0x0f

/* Core modes */
#define FV_XGXS                         0x0
#define FV_XGXG_nCC                     0x1
#define FV_Indlanes                     0x6
#define FV_PCI                          0x7
#define FV_XGXS_nLQ                     0x8
#define FV_XGXS_nLQnCC                  0x9
#define FV_PBypass                      0xa
#define FV_PBypass_nDSK                 0xb
#define FV_ComboCoreMode                0xc
#define FV_Clocks_off                   0xf

/* Supported speeds */
#define FV_sdr_13G_4L                   (1 << 9)
#define FV_sdr_12p5G_4L                 (1 << 8)
#define FV_sdr_12G_4L                   (1 << 7)
#define FV_sdr_10G_4L                   (1 << 6)
#define FV_sdr_6G_4L                    (1 << 5)
#define FV_sdr_5G_4L                    (1 << 4)
#define FV_sdr_2p5G_SL                  (1 << 3)
#define FV_sdr_1G_SL                    (1 << 2)
#define FV_sdr_100M_SL                  (1 << 1)
#define FV_sdr_10M_SL                   (1 << 0)

/* Forced speeds */
#define FV_fdr_13G                      7
#define FV_fdr_12p5G                    6
#define FV_fdr_12G                      5
#define FV_fdr_10G_HiG                  4
#define FV_fdr_10G_CX4                  3
#define FV_fdr_6G                       2
#define FV_fdr_5G                       1
#define FV_fdr_2p5G                     0

/* Lane from PHY control instance */
#define LANE_NUM_MASK                   0x3

/***********************************************************************
 *
 * HELPER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcmi_quadsgmii_serdes_lane
 * Purpose:
 *      Retrieve XGXS lane number for this PHY instance.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      Lane number or -1 if lane is unknown
 */
static int
bcmi_quadsgmii_serdes_lane(phy_ctrl_t *pc)
{
    uint32_t inst = PHY_CTRL_INST(pc);

    if (inst & PHY_INST_VALID) {
        return inst & LANE_NUM_MASK;
    }
    return -1;
}

/*
 * Function:
 *      bcmi_quadsgmii_serdes_stop
 * Purpose:
 *      Put PHY in or out of reset depending on conditions.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_quadsgmii_serdes_stop(phy_ctrl_t *pc)
{
    int ioerr = 0;
    LANECTRL3r_t lane_ctrl3;
    uint32_t pwrdn_tx, pwrdn_rx, lane_mask;
    uint32_t f_any = PHY_F_PHY_DISABLE | PHY_F_PORT_DRAIN;
    uint32_t f_copper = PHY_F_MAC_DISABLE | PHY_F_SPEED_CHG | PHY_F_DUPLEX_CHG;
    int stop, lane;

    ioerr += READ_LANECTRL3r(pc, &lane_ctrl3);
    pwrdn_tx = LANECTRL3r_PWRDWN_TXf_GET(lane_ctrl3);

    stop = 0;
    lane_mask = 0xf;
    if ((PHY_CTRL_FLAGS(pc) & f_any) ||
        ((PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) == 0 &&
         (PHY_CTRL_FLAGS(pc) & f_copper))) {
        lane = bcmi_quadsgmii_serdes_lane(pc);
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
    LANECTRL3r_PWRDWN_RXf_SET(lane_ctrl3, pwrdn_rx);
    LANECTRL3r_PWRDWN_TXf_SET(lane_ctrl3, pwrdn_tx);
    ioerr += WRITE_LANECTRL3r(pc, lane_ctrl3);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
extern cdk_symbols_t bcmi_unicore13g_xgxs_symbols;
#define SET_SYMBOL_TABLE(_pc) \
    PHY_CTRL_SYMBOLS(_pc) = &bcmi_unicore13g_xgxs_symbols
#else
#define SET_SYMBOL_TABLE(_pc)
#endif

/*
 * Function:
 *      bcmi_quadsgmii_serdes_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_quadsgmii_serdes_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    SERDES_ID0r_t serdesid0;
    XGXSCONTROLr_t xgxs_ctrl;
    MMDSELECTr_t mmdselect;
    uint32_t model;
    int mode10g;
    int ioerr = 0;

    ioerr += phy_brcm_serdes_id(pc, &phyid0, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCM_SERDES_PHY_ID0 && phyid1 == BCM_SERDES_PHY_ID1) {
        /* Common PHY ID found - read specific SerDes ID */
        ioerr += READ_SERDES_ID0r(pc, &serdesid0);
        model = SERDES_ID0r_MODELf_GET(serdesid0);
        if (model == SERDES_ID0_QUADSGMII) {
            /* Check for independent lane mode */
            ioerr += READ_XGXSCONTROLr(pc, &xgxs_ctrl);
            mode10g = XGXSCONTROLr_MODE_10Gf_GET(xgxs_ctrl);
            if (mode10g == FV_ComboCoreMode) {
                return ioerr ? CDK_E_IO : CDK_E_NOT_FOUND;
            }
            /* Use clause 45 access if possible */
            ioerr += READ_MMDSELECTr(pc, &mmdselect);
            if (MMDSELECTr_MULTIMMDS_ENf_GET(mmdselect) == 1) {
                PHY_CTRL_FLAGS(pc) |= PHY_F_CLAUSE45;
            }
            SET_SYMBOL_TABLE(pc);
            return ioerr ? CDK_E_IO : CDK_E_NONE;
        }
    }
    return CDK_E_NOT_FOUND;
}


/*
 * Function:
 *      bcmi_quadsgmii_serdes_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_quadsgmii_serdes_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int ioerr = 0;
    CONTROL1000X1r_t ctrl_1000x1;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToPassthru:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) |= PHY_F_PASSTHRU;
        /* Put the Serdes in passthru mode */
        ioerr += READ_CONTROL1000X1r(pc, &ctrl_1000x1);
        CONTROL1000X1r_FIBER_MODE_1000Xf_SET(ctrl_1000x1, 0);
        ioerr += WRITE_CONTROL1000X1r(pc, ctrl_1000x1);
        break;
    case PhyEvent_ChangeToFiber:
        PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_PASSTHRU;
        /* Put the Serdes in fiber mode */
        ioerr += READ_CONTROL1000X1r(pc, &ctrl_1000x1);
        CONTROL1000X1r_FIBER_MODE_1000Xf_SET(ctrl_1000x1, 1);
        ioerr += WRITE_CONTROL1000X1r(pc, ctrl_1000x1);
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
    bcmi_quadsgmii_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_quadsgmii_serdes_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_quadsgmii_serdes_reset(phy_ctrl_t *pc)
{
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_quadsgmii_serdes_init
 * Purpose:     
 *      Initialize PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_NONE
 */
static int
bcmi_quadsgmii_serdes_init(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    LANETESTr_t lanetest;
    LOCALCONTROL0r_t lctrl;
    FXCONTROL1r_t fx100_ctrl1;
    FXCONTROL2r_t fx100_ctrl2;
    CONTROL1000X2r_t ctrl_1000x2;

    PHY_CTRL_CHECK(pc);

    /* Leave clocks enabled in power-down mode */
    ioerr += READ_LANETESTr(pc, &lanetest);
    LANETESTr_PWRDN_CLKS_ENf_SET(lanetest, 1);
    LANETESTr_LFCK_BYPASSf_SET(lanetest, 1);
    ioerr += WRITE_LANETESTr(pc, lanetest);

    /* Keep in-band MDIO in reset */
    READ_LOCALCONTROL0r(pc, &lctrl);
    LOCALCONTROL0r_RX_INBANDMDIO_RSTf_SET(lctrl, 1);
    WRITE_LOCALCONTROL0r(pc, lctrl);

    /* Configure 100FX mode */
    ioerr += READ_FXCONTROL1r(pc, &fx100_ctrl1);
    FXCONTROL1r_FX100_FAR_END_FAULT_ENf_SET(fx100_ctrl1, 1);
    FXCONTROL1r_FX100_AUTODET_ENf_SET(fx100_ctrl1, 0);
    ioerr += WRITE_FXCONTROL1r(pc, fx100_ctrl1);

    /* Enable 100FX extended packet size */
    ioerr += READ_FXCONTROL2r(pc, &fx100_ctrl2);
    FXCONTROL2r_EXTEND_PKT_SIZEf_SET(fx100_ctrl2, 1);
    ioerr += WRITE_FXCONTROL2r(pc, fx100_ctrl2);

    /* Disable 1000X parallel detect */
    ioerr += READ_CONTROL1000X2r(pc, &ctrl_1000x2);
    CONTROL1000X2r_ENABLE_PARALLEL_DETECTIONf_SET(ctrl_1000x2, 0);
    ioerr += WRITE_CONTROL1000X2r(pc, ctrl_1000x2);

    /* Default mode is fiber */
    PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_quadsgmii_serdes_link_get
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
bcmi_quadsgmii_serdes_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    int ioerr = 0;
    COMBO_MIISTATr_t miistat;

    PHY_CTRL_CHECK(pc);

    ioerr += READ_COMBO_MIISTATr(pc, &miistat);

    if (link) {
        *link = COMBO_MIISTATr_LINK_STATUSf_GET(miistat);
    }

    if (autoneg_done) {
        *autoneg_done = COMBO_MIISTATr_AUTONEG_COMPLETEf_GET(miistat);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_quadsgmii_serdes_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_quadsgmii_serdes_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int ioerr = 0;
    COMBO_MIICNTLr_t miictrl;

    PHY_CTRL_CHECK(pc);

    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) == 0) {
        /* Only support full duplex in non-passthru mode */
        return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
    }

    ioerr += READ_COMBO_MIICNTLr(pc, &miictrl);
    COMBO_MIICNTLr_FULL_DUPLEXf_SET(miictrl, duplex);
    ioerr += WRITE_COMBO_MIICNTLr(pc, miictrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_quadsgmii_serdes_duplex_get
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
bcmi_quadsgmii_serdes_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    int ioerr = 0;
    GP_TOPANSTATUS1r_t anstat;

    PHY_CTRL_CHECK(pc);

    ioerr += READ_GP_TOPANSTATUS1r(pc, &anstat);
    *duplex = GP_TOPANSTATUS1r_DUPLEX_STATUSf_GET(anstat);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_quadsgmii_serdes_speed_set
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
bcmi_quadsgmii_serdes_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int ioerr = 0;
    int rv;
    int autoneg;
    uint32_t force_speed, speed_val;
    uint32_t speed_mii_lsb, speed_mii_msb, fx100;
    RX0_RX_CONTROLr_t rx_ctrl;
    CONTROL1000X3r_t ctrl_1000x3;
    MISC1r_t misc1;
    STATUS1000X1r_t stat1;
    FXCONTROL1r_t fx100_ctrl1;
    COMBO_MIICNTLr_t mii_ctrl;

    /* Do not set speed if auto-negotiation is enabled */
    rv = PHY_AUTONEG_GET(pc, &autoneg);
    if (CDK_FAILURE(rv)) {
        return rv;
    }
    if (autoneg) {
        return CDK_E_NONE;
    }

    force_speed = 0;
    speed_val = FV_fdr_2p5G;
    speed_mii_lsb = 0;
    speed_mii_msb = 0;

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
        force_speed = 1;
        break;
    default:
        return CDK_E_PARAM;
    }

    /* Hold rxSeqStart */
    ioerr += READ_RX0_RX_CONTROLr(pc, &rx_ctrl);
    RX0_RX_CONTROLr_RXSEQRESTARTf_SET(rx_ctrl, 1);
    ioerr += WRITE_RX0_RX_CONTROLr(pc, rx_ctrl);

    /* Hold Tx FIFO in reset */
    ioerr += READ_CONTROL1000X3r(pc, &ctrl_1000x3);
    CONTROL1000X3r_TX_FIFO_RSTf_SET(ctrl_1000x3, 1);
    ioerr += WRITE_CONTROL1000X3r(pc, ctrl_1000x3);

    /* Set forced speed */
    ioerr += READ_MISC1r(pc, &misc1);
    MISC1r_FORCE_SPEED_SELf_SET(misc1, force_speed);
    MISC1r_FORCE_SPEEDf_SET(misc1, speed_val);
    ioerr += WRITE_MISC1r(pc, misc1);

    /* Set IEEE speed */
    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    COMBO_MIICNTLr_MANUAL_SPEED_0f_SET(mii_ctrl, speed_mii_lsb);
    COMBO_MIICNTLr_MANUAL_SPEED_1f_SET(mii_ctrl, speed_mii_msb);
    ioerr += WRITE_COMBO_MIICNTLr(pc, mii_ctrl);

    /* Check for 100FX mode */
    fx100 = 0;
    ioerr += READ_STATUS1000X1r(pc, &stat1);
    if (STATUS1000X1r_SGMII_MODEf_GET(stat1) == 0 && speed == 100) {
        fx100 = 1;
    }
    ioerr += READ_FXCONTROL1r(pc, &fx100_ctrl1);
    FXCONTROL1r_FX100_ENf_SET(fx100_ctrl1, fx100);
    ioerr += WRITE_FXCONTROL1r(pc, fx100_ctrl1);

    /* Release rxSeqStart */
    ioerr += READ_RX0_RX_CONTROLr(pc, &rx_ctrl);
    RX0_RX_CONTROLr_RXSEQRESTARTf_SET(rx_ctrl, 0);
    ioerr += WRITE_RX0_RX_CONTROLr(pc, rx_ctrl);

    /* Release Tx FIFO in reset */
    ioerr += READ_CONTROL1000X3r(pc, &ctrl_1000x3);
    CONTROL1000X3r_TX_FIFO_RSTf_SET(ctrl_1000x3, 0);
    ioerr += WRITE_CONTROL1000X3r(pc, ctrl_1000x3);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_quadsgmii_serdes_speed_get
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
bcmi_quadsgmii_serdes_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int ioerr = 0;
    uint32_t speed_mode;
    STATUS1000X1r_t stat_1000x1;

    PHY_CTRL_CHECK(pc);

    *speed = 0;

    ioerr += READ_STATUS1000X1r(pc, &stat_1000x1);
    speed_mode = STATUS1000X1r_SPEED_STATUSf_GET(stat_1000x1);

    switch (speed_mode) {
    case 3:
        *speed = 2500;
        break;
    case 2:
        *speed = 1000;
        break;
    case 1:
        *speed = 100;
        break;
    default:
        *speed = 10;
        break;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_quadsgmii_serdes_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */

static int
bcmi_quadsgmii_serdes_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int ioerr = 0;
    MISC1r_t misc1;
    CONTROL1000X1r_t ctrl1;
    COMBO_MIICNTLr_t mii_ctrl;

    PHY_CTRL_CHECK(pc);

    if (autoneg) {
        /* Disable forced speed if autoneg is enabled */
        ioerr += READ_MISC1r(pc, &misc1);
        MISC1r_FORCE_SPEEDf_SET(misc1, 0);
        ioerr += WRITE_MISC1r(pc, misc1);

        /* Used as field value, so cannot be any non-zero value */
        autoneg = 1;
    }

    /* Set 1000X auto detect */
    ioerr += READ_CONTROL1000X1r(pc, &ctrl1);
    CONTROL1000X1r_AUTODET_ENf_SET(ctrl1, autoneg);
    ioerr += WRITE_CONTROL1000X1r(pc, ctrl1);

    /* Configure IEEE auto-neg */
    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    COMBO_MIICNTLr_AUTONEG_ENABLEf_SET(mii_ctrl, autoneg);
    ioerr += WRITE_COMBO_MIICNTLr(pc, mii_ctrl);

    /* Restart autoneg if enabled */
    if (autoneg) {
        COMBO_MIICNTLr_RESTART_AUTONEGf_SET(mii_ctrl, 1);
        ioerr += WRITE_COMBO_MIICNTLr(pc, mii_ctrl);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_quadsgmii_serdes_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_quadsgmii_serdes_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    int ioerr = 0;
    COMBO_MIICNTLr_t mii_ctrl;

    PHY_CTRL_CHECK(pc);

    /* Read IEEE autoneg */
    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    *autoneg = COMBO_MIICNTLr_AUTONEG_ENABLEf_GET(mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE; 
}

/*
 * Function:    
 *      bcmi_quadsgmii_serdes_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_quadsgmii_serdes_loopback_set(phy_ctrl_t *pc, int enable)
{
    int ioerr = 0;
    COMBO_MIICNTLr_t mii_ctrl;

    /* Set loopback for SerDes core */
    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    COMBO_MIICNTLr_LOOPBACKf_SET(mii_ctrl, enable ? 1 : 0);
    ioerr += WRITE_COMBO_MIICNTLr(pc, mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_quadsgmii_serdes_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_quadsgmii_serdes_loopback_get(phy_ctrl_t *pc, int *enable)
{
    int ioerr = 0;
    COMBO_MIICNTLr_t mii_ctrl;

    PHY_CTRL_CHECK(pc);

    /* Get loopback mode from SerDes registers */
    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    *enable = COMBO_MIICNTLr_LOOPBACKf_GET(mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_quadsgmii_serdes_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_quadsgmii_serdes_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    *abil = (PHY_ABIL_PAUSE | PHY_ABIL_LOOPBACK | 
             PHY_ABIL_XAUI | PHY_ABIL_XGMII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_quadsgmii_serdes_config_set
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
bcmi_quadsgmii_serdes_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        if (val) {
            PHY_CTRL_FLAGS(pc) &= ~PHY_F_PHY_DISABLE;
        } else {
            PHY_CTRL_FLAGS(pc) |= PHY_F_PHY_DISABLE;
        }
        bcmi_quadsgmii_serdes_stop(pc);
        break;
    case PhyConfig_PortInterface:
        return CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcmi_quadsgmii_serdes_config_get
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
bcmi_quadsgmii_serdes_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = (PHY_CTRL_FLAGS(pc) & PHY_F_PHY_DISABLE) ? 0 : 1;
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        *val = PHY_IF_XGMII;
        return CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/* Public PHY Driver Structure */
phy_driver_t bcmi_quadsgmii_serdes_drv = {
    "bcmi_quadsgmii_serdes", 
    "Internal Quad SGMII 2.5G SerDes PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_quadsgmii_serdes_probe,        /* pd_probe */
    bcmi_quadsgmii_serdes_notify,       /* pd_notify */
    bcmi_quadsgmii_serdes_reset,        /* pd_reset */
    bcmi_quadsgmii_serdes_init,         /* pd_init */
    bcmi_quadsgmii_serdes_link_get,     /* pd_link_get */
    bcmi_quadsgmii_serdes_duplex_set,   /* pd_duplex_set */
    bcmi_quadsgmii_serdes_duplex_get,   /* pd_duplex_get */
    bcmi_quadsgmii_serdes_speed_set,    /* pd_speed_set */
    bcmi_quadsgmii_serdes_speed_get,    /* pd_speed_get */
    bcmi_quadsgmii_serdes_autoneg_set,  /* pd_autoneg_set */
    bcmi_quadsgmii_serdes_autoneg_get,  /* pd_autoneg_get */
    bcmi_quadsgmii_serdes_loopback_set, /* pd_loopback_set */
    bcmi_quadsgmii_serdes_loopback_get, /* pd_loopback_get */
    bcmi_quadsgmii_serdes_ability_get,  /* pd_ability_get */
    bcmi_quadsgmii_serdes_config_set,   /* pd_config_set */
    bcmi_quadsgmii_serdes_config_get,   /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
