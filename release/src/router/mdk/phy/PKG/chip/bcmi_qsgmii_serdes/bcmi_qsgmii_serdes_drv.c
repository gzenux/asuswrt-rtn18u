/*
 * $Id: bcmi_qsgmii_serdes_drv.c,v 1.1 Broadcom SDK $
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
 * PHY driver for internal QSGMII 1.25G SerDes.
 *
 */

#include <phy/phy.h>
#include <phy/phy_xgs_iblk.h>
#include <phy/phy_brcm_serdes_id.h>

#include <phy/chip/bcmi_qsgmii_serdes_defs.h>

#define BCM_SERDES_PHY_ID0              0x143
#define BCM_SERDES_PHY_ID1              0xbff0

#define PHY_ID1_REV_MASK                0x000f

#define SERDES_ID0_QSGMII               0x07

/* Lane from PHY control instance */
#define LANE_NUM_MASK                   0x7

/***********************************************************************
 *
 * HELPER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcmi_qsgmii_serdes_lane
 * Purpose:
 *      Retrieve XGXS lane number for this PHY instance.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      Lane number or -1 if lane is unknown
 */
static int
bcmi_qsgmii_serdes_lane(phy_ctrl_t *pc)
{
    uint32_t inst = PHY_CTRL_INST(pc);

    if (inst & PHY_INST_VALID) {
        return inst & LANE_NUM_MASK;
    }
    return -1;
}

/*
 * Function:
 *      bcmi_qsgmii_serdes_stop
 * Purpose:
 *      Put PHY in or out of reset depending on conditions.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_qsgmii_serdes_stop(phy_ctrl_t *pc)
{
    int ioerr = 0;
    MIICNTLr_t mii_ctrl;
    uint32_t f_any = PHY_F_PHY_DISABLE | PHY_F_PORT_DRAIN;
    uint32_t f_copper = PHY_F_MAC_DISABLE | PHY_F_SPEED_CHG | PHY_F_DUPLEX_CHG;
    int stop, lane;

    stop = 0;
    if ((PHY_CTRL_FLAGS(pc) & f_any) ||
        ((PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) == 0 &&
         (PHY_CTRL_FLAGS(pc) & f_copper))) {
        lane = bcmi_qsgmii_serdes_lane(pc);
        /* No power-down if lane is 0, 1 or unknown */
        if (lane > 1) {
            stop = 1;
        }
    }

    /* Set power-down for SerDes core */
    ioerr += READ_MIICNTLr(pc, &mii_ctrl);
    MIICNTLr_PWRDWN_SWf_SET(mii_ctrl, stop ? 1 : 0);
    ioerr += WRITE_MIICNTLr(pc, mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
extern cdk_symbols_t bcmi_qsgmii_serdes_symbols;
#define SET_SYMBOL_TABLE(_pc) \
    PHY_CTRL_SYMBOLS(_pc) = &bcmi_qsgmii_serdes_symbols
#else
#define SET_SYMBOL_TABLE(_pc)
#endif

/*
 * Function:
 *      bcmi_qsgmii_serdes_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_qsgmii_serdes_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    SERDES_ID0r_t serdesid0;
    uint32_t model;
    int ioerr = 0;

    ioerr += phy_brcm_serdes_id(pc, &phyid0, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCM_SERDES_PHY_ID0 && phyid1 == BCM_SERDES_PHY_ID1) {
        /* Common PHY ID found - read specific SerDes ID */
        ioerr += READ_SERDES_ID0r(pc, &serdesid0);
        model = SERDES_ID0r_MODELf_GET(serdesid0);
        if (model == SERDES_ID0_QSGMII) {
            /* All lanes are accessed from the same PHY address */
            PHY_CTRL_FLAGS(pc) |= PHY_F_ADDR_SHARE | PHY_F_SERDES_MODE;
            PHY_CTRL_LANE_MASK(pc) = LANE_NUM_MASK;
            SET_SYMBOL_TABLE(pc);
            return ioerr ? CDK_E_IO : CDK_E_NONE;
        }
    }
    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcmi_qsgmii_serdes_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_qsgmii_serdes_notify(phy_ctrl_t *pc, phy_event_t event)
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
    bcmi_qsgmii_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_qsgmii_serdes_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_qsgmii_serdes_reset(phy_ctrl_t *pc)
{
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_qsgmii_serdes_init
 * Purpose:     
 *      Initialize PHY driver.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_NONE
 */
static int
bcmi_qsgmii_serdes_init(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    int ioerr = 0;
    TX_DRIVERr_t tx_drv;
    INDCOMBCTRLr_t indcombctrl;
    RX_CONTROL_PCIEr_t rx_ctrl_pcie;

    PHY_CTRL_CHECK(pc);

    /* Adjust default Tx xdriver output for external PHY */
    ioerr += READ_TX_DRIVERr(pc, &tx_drv);
    TX_DRIVERr_DRIVER_FIXED_ENBf_SET(tx_drv, 1);
    TX_DRIVERr_DRV_AMPf_SET(tx_drv, 5);
    ioerr += WRITE_TX_DRIVERr(pc, tx_drv);

    /* Enable disparity error check */
    ioerr += READ_INDCOMBCTRLr(pc, &indcombctrl);
    INDCOMBCTRLr_DISPARITY_EN_VALf_SET(indcombctrl, 1);
    INDCOMBCTRLr_DISPERROR_EN_SYNC_VALf_SET(indcombctrl, 1);
    INDCOMBCTRLr_DISPERROR_EN_VALf_SET(indcombctrl, 1);
    INDCOMBCTRLr_DISPERROR_EN_FORCEf_SET(indcombctrl, 1);
    ioerr += WRITE_INDCOMBCTRLr(pc, indcombctrl);

    /* Enable comma adjustment */
    ioerr += READ_RX_CONTROL_PCIEr(pc, &rx_ctrl_pcie);
    RX_CONTROL_PCIEr_COMMA_ADJ_EN_Rf_SET(rx_ctrl_pcie, 1);
    RX_CONTROL_PCIEr_COMMA_ADJ_EN_FORCE_Rf_SET(rx_ctrl_pcie, 1);
    ioerr += WRITE_RX_CONTROL_PCIEr(pc, rx_ctrl_pcie);

    /* Default mode is fiber */
    PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);

    return ioerr ? CDK_E_IO : rv;
}


/*
 * Function:    
 *      bcmi_qsgmii_serdes_link_get
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
bcmi_qsgmii_serdes_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    int ioerr = 0;
    MIISTATr_t miistat;

    PHY_CTRL_CHECK(pc);

    ioerr += READ_MIISTATr(pc, &miistat);

    if (link) {
        *link = MIISTATr_LINK_STATUSf_GET(miistat);
    }

    if (autoneg_done) {
        *autoneg_done = MIISTATr_AUTONEG_COMPLETEf_GET(miistat);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_qsgmii_serdes_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_qsgmii_serdes_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int ioerr = 0;
    MIICNTLr_t miictrl;

    PHY_CTRL_CHECK(pc);

    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) == 0) {
        /* Only support full duplex in non-passthru mode */
        return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
    }

    ioerr += READ_MIICNTLr(pc, &miictrl);
    MIICNTLr_FULL_DUPLEXf_SET(miictrl, duplex);
    ioerr += WRITE_MIICNTLr(pc, miictrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_qsgmii_serdes_duplex_get
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
bcmi_qsgmii_serdes_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    int ioerr = 0;
    STATUS1000X1r_t stat1;
    MIICNTLr_t miictrl;

    PHY_CTRL_CHECK(pc);

    *duplex = 1;

    ioerr += READ_STATUS1000X1r(pc, &stat1);
    if (STATUS1000X1r_SGMII_MODEf_GET(stat1)) {
        ioerr += READ_MIICNTLr(pc, &miictrl);
        *duplex = MIICNTLr_FULL_DUPLEXf_GET(miictrl);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_qsgmii_serdes_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_qsgmii_serdes_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int ioerr = 0;
    int rv;
    int autoneg;
    uint32_t speed_mii_lsb, speed_mii_msb;
    STATUS1000X1r_t stat1;
    MIICNTLr_t mii_ctrl;

    /* Do not set speed if auto-negotiation is enabled */
    rv = PHY_AUTONEG_GET(pc, &autoneg);
    if (CDK_FAILURE(rv)) {
        return rv;
    }
    if (autoneg) {
        return CDK_E_NONE;
    }

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
    default:
        return CDK_E_PARAM;
    }

    ioerr += READ_STATUS1000X1r(pc, &stat1);
    if (STATUS1000X1r_SGMII_MODEf_GET(stat1) == 0 && speed != 1000) {
        return CDK_E_PARAM;
    }

    /* Set IEEE speed */
    ioerr += READ_MIICNTLr(pc, &mii_ctrl);
    MIICNTLr_MANUAL_SPEED_0f_SET(mii_ctrl, speed_mii_lsb);
    MIICNTLr_MANUAL_SPEED_1f_SET(mii_ctrl, speed_mii_msb);
    ioerr += WRITE_MIICNTLr(pc, mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_qsgmii_serdes_speed_get
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
bcmi_qsgmii_serdes_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int ioerr = 0;
    uint32_t speed_mode;
    STATUS1000X1r_t stat_1000x1;

    PHY_CTRL_CHECK(pc);

    *speed = 0;

    ioerr += READ_STATUS1000X1r(pc, &stat_1000x1);
    speed_mode = STATUS1000X1r_SPEED_STATUSf_GET(stat_1000x1);

    switch (speed_mode) {
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
 *      bcmi_qsgmii_serdes_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */

static int
bcmi_qsgmii_serdes_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int ioerr = 0;
    MISC1r_t misc1;
    CONTROL1000X1r_t ctrl1;
    MIICNTLr_t mii_ctrl;

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
    ioerr += READ_MIICNTLr(pc, &mii_ctrl);
    MIICNTLr_AUTONEG_ENABLEf_SET(mii_ctrl, autoneg);
    ioerr += WRITE_MIICNTLr(pc, mii_ctrl);

    /* Restart autoneg if enabled */
    if (autoneg) {
        MIICNTLr_RESTART_AUTONEGf_SET(mii_ctrl, 1);
        ioerr += WRITE_MIICNTLr(pc, mii_ctrl);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_qsgmii_serdes_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy).
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_qsgmii_serdes_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    int ioerr = 0;
    MIICNTLr_t mii_ctrl;

    PHY_CTRL_CHECK(pc);

    /* Read IEEE autoneg */
    ioerr += READ_MIICNTLr(pc, &mii_ctrl);
    *autoneg = MIICNTLr_AUTONEG_ENABLEf_GET(mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE; 
}

/*
 * Function:    
 *      bcmi_qsgmii_serdes_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_qsgmii_serdes_loopback_set(phy_ctrl_t *pc, int enable)
{
    int ioerr = 0;
    MIICNTLr_t mii_ctrl;

    /* Set loopback for SerDes core */
    ioerr += READ_MIICNTLr(pc, &mii_ctrl);
    MIICNTLr_LOOPBACKf_SET(mii_ctrl, enable ? 1 : 0);
    ioerr += WRITE_MIICNTLr(pc, mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_qsgmii_serdes_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_qsgmii_serdes_loopback_get(phy_ctrl_t *pc, int *enable)
{
    int ioerr = 0;
    MIICNTLr_t mii_ctrl;

    PHY_CTRL_CHECK(pc);

    /* Get loopback mode from SerDes registers */
    ioerr += READ_MIICNTLr(pc, &mii_ctrl);
    *enable = MIICNTLr_LOOPBACKf_GET(mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_qsgmii_serdes_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_qsgmii_serdes_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    *abil = (PHY_ABIL_2500MB | PHY_ABIL_1000MB | PHY_ABIL_PAUSE | 
             PHY_ABIL_SERDES | PHY_ABIL_LOOPBACK | PHY_ABIL_GMII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_qsgmii_serdes_config_set
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
bcmi_qsgmii_serdes_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        PHY_CTRL_FLAGS(pc) |= PHY_F_PHY_DISABLE;
        if (val) {
            PHY_CTRL_FLAGS(pc) &= ~PHY_F_PHY_DISABLE;
        }
        return bcmi_qsgmii_serdes_stop(pc);
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
 *      bcmi_qsgmii_serdes_config_get
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
bcmi_qsgmii_serdes_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = (PHY_CTRL_FLAGS(pc) & PHY_F_PHY_DISABLE) ? 0 : 1;
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
phy_driver_t bcmi_qsgmii_serdes_drv = {
    "bcmi_qsgmii_serdes", 
    "Internal Octal QSGMII 1.25G SerDes PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_qsgmii_serdes_probe,           /* pd_probe */
    bcmi_qsgmii_serdes_notify,          /* pd_notify */
    bcmi_qsgmii_serdes_reset,           /* pd_reset */
    bcmi_qsgmii_serdes_init,            /* pd_init */
    bcmi_qsgmii_serdes_link_get,        /* pd_link_get */
    bcmi_qsgmii_serdes_duplex_set,      /* pd_duplex_set */
    bcmi_qsgmii_serdes_duplex_get,      /* pd_duplex_get */
    bcmi_qsgmii_serdes_speed_set,       /* pd_speed_set */
    bcmi_qsgmii_serdes_speed_get,       /* pd_speed_get */
    bcmi_qsgmii_serdes_autoneg_set,     /* pd_autoneg_set */
    bcmi_qsgmii_serdes_autoneg_get,     /* pd_autoneg_get */
    bcmi_qsgmii_serdes_loopback_set,    /* pd_loopback_set */
    bcmi_qsgmii_serdes_loopback_get,    /* pd_loopback_get */
    bcmi_qsgmii_serdes_ability_get,     /* pd_ability_get */
    bcmi_qsgmii_serdes_config_set,      /* pd_config_set */
    bcmi_qsgmii_serdes_config_get,      /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
