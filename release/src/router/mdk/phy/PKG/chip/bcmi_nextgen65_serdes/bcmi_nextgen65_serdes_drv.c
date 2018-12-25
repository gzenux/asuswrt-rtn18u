/*
 * $Id: bcmi_nextgen65_serdes_drv.c,v 1.12 Broadcom SDK $
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
 * PHY driver for internal 65nm NextGen 1.25G SerDes PHY.
 *
 */

#include <phy/phy.h>
#include <phy/phy_xgs_iblk.h>
#include <phy/phy_brcm_serdes_id.h>
#include <phy/ge_phy.h>

#define BCM_SERDES_PHY_ID0              0x143
#define BCM_SERDES_PHY_ID1              0xbff0

#define PHY_ID1_REV_MASK                0x000f

#define SERDES_ID0_SERDES_125           0x05

#define _PHY_REG_READ(_pc, _r, _v)      phy_xgs_iblk_read(_pc, _r, _v)
#define _PHY_REG_WRITE(_pc, _r, _v)     phy_xgs_iblk_write(_pc, _r, _v)

/* MIIM block definitions for register 0x10-0x1f */
#define MIIM_BLK_DIGITAL                0x000
#define MIIM_BLK_SERDES_ID              0x100
#define MIIM_BLK_FX100                  0x200
#define MIIM_BLK_ANALOG                 0x300

/* 1000X Control #1 Register: Controls 10B/SGMII mode */
#define NG65_1000X_CTRL1_REG            0x10
#define NG65_1000X_FIBER_MODE           (1 << 0)
#define NG65_1000X_EN10B_MODE           (1 << 1)
#define NG65_1000X_SIGNAL_DETECT_EN     (1 << 2)
#define NG65_1000X_INVERT_SD            (1 << 3)
#define NG65_1000X_AUTO_DETECT          (1 << 4)
#define NG65_1000X_SGMII_MASTER_MODE    (1 << 5)
#define NG65_1000X_DISABLE_PLL_PWRDWN   (1 << 6)

/* 1000X Control #2 Register: */
#define NG65_1000X_CTRL2_REG            0x11
#define NG65_1000X_PAR_DET_EN           (1 << 0)
#define NG65_1000X_FALSE_LNK_DIS        (1 << 1)
#define NG65_1000X_FLT_FORCE_EN         (1 << 2)

/* 1000X Control #4 Register: */
#define NG65_1000X_CTRL4_REG            0x13
#define NG65_1000X_LINK_FORCE           (1 << 7)
#define NG65_1000X_DIG_RESET            (1 << 6)
#define NG65_1000X_ANA_SIG_DETECT       (1 << 0)

/* FX Control #1 Register: */
#define NG65_FX_CTRL1_REG               (0x10 | MIIM_BLK_FX100)
#define NG65_100FX_EN                   (1 << 0)
#define NG65_100FX_FULL_DUPLEX          (1 << 1)
#define NG65_100FX_AUTO_DET_EN          (1 << 2)

/* analog_tx (Analog register block) */
#define NG65_ANALOG_TX                  (0x10 | MIIM_BLK_ANALOG)

/***********************************************************************
 *
 * HELPER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcmi_nextgen65_serdes_stop
 * Purpose:
 *      Put PHY in or out of reset depending on conditions.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_nextgen65_serdes_stop(phy_ctrl_t *pc)
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

    ioerr += _PHY_REG_READ(pc, MII_CTRL_REG, &mii_ctrl);

    if (stop) {
        mii_ctrl |= MII_CTRL_PD;
    } else {
        mii_ctrl &= ~MII_CTRL_PD;
    }

    ioerr += _PHY_REG_WRITE(pc, MII_CTRL_REG, mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcmi_nextgen65_serdes_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen65_serdes_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1, serdesid0;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += phy_brcm_serdes_id(pc, &phyid0, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCM_SERDES_PHY_ID0 && phyid1 == BCM_SERDES_PHY_ID1) {
        /* Common PHY ID found - read specific SerDes ID */
        ioerr += _PHY_REG_READ(pc, SERDES_ID0, &serdesid0);
        if ((serdesid0 & 0x3f) == SERDES_ID0_SERDES_125) {
            return ioerr ? CDK_E_IO : CDK_E_NONE;
        }
    }
    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcmi_nextgen65_serdes_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen65_serdes_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int ioerr = 0;
    uint32_t ctrl;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToPassthru:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) |= PHY_F_PASSTHRU;
        /* Use default analog_tx value */
        ioerr += _PHY_REG_WRITE(pc, NG65_ANALOG_TX, 0xce20);
        /* Put the Serdes in passthru mode */
        ioerr += _PHY_REG_READ(pc, NG65_1000X_CTRL1_REG, &ctrl);
        ctrl &= ~NG65_1000X_FIBER_MODE;
        ioerr += _PHY_REG_WRITE(pc, NG65_1000X_CTRL1_REG, ctrl);
        break;
    case PhyEvent_ChangeToFiber:
        PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_PASSTHRU;
        /* Set fiber analog_tx with recommended amplitude */ 
        ioerr += _PHY_REG_WRITE(pc, NG65_ANALOG_TX, 0xfe20);
        /* Put the Serdes in fiber mode */
        ioerr += _PHY_REG_READ(pc, NG65_1000X_CTRL1_REG, &ctrl);
        ctrl |= NG65_1000X_FIBER_MODE;
        ioerr += _PHY_REG_WRITE(pc, NG65_1000X_CTRL1_REG, ctrl);
        break;
    case PhyEvent_MacDisable:
        PHY_CTRL_FLAGS(pc) |= PHY_F_MAC_DISABLE;
        break;
    case PhyEvent_MacEnable:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_MAC_DISABLE;
        /* Reset Tx FIFO after MAC exits reset if 100FX mode */
        ioerr += _PHY_REG_READ(pc, NG65_FX_CTRL1_REG, &ctrl);
        if (ctrl & NG65_100FX_EN) {
            ioerr += _PHY_REG_READ(pc, NG65_1000X_CTRL4_REG, &ctrl);
            ioerr += _PHY_REG_WRITE(pc, NG65_1000X_CTRL4_REG,
                                    ctrl | NG65_1000X_DIG_RESET);
            ioerr += _PHY_REG_WRITE(pc, NG65_1000X_CTRL4_REG, ctrl);
        }
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
    bcmi_nextgen65_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_nextgen65_serdes_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen65_serdes_reset(phy_ctrl_t *pc)
{
    return ge_phy_reset(pc);
}

/*
 * Function:
 *      bcmi_nextgen65_serdes_init
 * Purpose:     
 *      Initialize PHY driver.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen65_serdes_init(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    int ioerr = 0;
    uint32_t ctrl;

    PHY_CTRL_CHECK(pc);

    ioerr += _PHY_REG_READ(pc, NG65_1000X_CTRL1_REG, &ctrl);
    ctrl |= NG65_1000X_DISABLE_PLL_PWRDWN;
    ioerr += _PHY_REG_WRITE(pc, NG65_1000X_CTRL1_REG, ctrl);

    ioerr += _PHY_REG_READ(pc, NG65_1000X_CTRL2_REG, &ctrl);
    ctrl |= NG65_1000X_FALSE_LNK_DIS | NG65_1000X_FLT_FORCE_EN;
    ioerr += _PHY_REG_WRITE(pc, NG65_1000X_CTRL2_REG, ctrl);

    /* Ensure that 100FX mode is disabled */
    ioerr += _PHY_REG_READ(pc, NG65_FX_CTRL1_REG, &ctrl);
    ctrl &= ~(NG65_100FX_EN | NG65_100FX_AUTO_DET_EN);
    ioerr += _PHY_REG_WRITE(pc, NG65_FX_CTRL1_REG, ctrl);

    /* Ensure the signal detect is disabled */
    ioerr += _PHY_REG_READ(pc, NG65_1000X_CTRL1_REG, &ctrl);
    ctrl &= ~NG65_1000X_SIGNAL_DETECT_EN;
    ioerr += _PHY_REG_WRITE(pc, NG65_1000X_CTRL1_REG, ctrl);

    /* Default mode is fiber */
    PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_nextgen65_serdes_link_get
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
bcmi_nextgen65_serdes_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    return ge_phy_link_get(pc, link, autoneg_done);
}

/*
 * Function:    
 *      bcmi_nextgen65_serdes_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen65_serdes_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int ioerr = 0;
    uint32_t ctrl, o_ctrl;

    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) {
        /* Only support full duplex in fiber mode */
        return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
    }

    ioerr += _PHY_REG_READ(pc, MII_CTRL_REG, &ctrl);
    o_ctrl = ctrl;

    if (duplex) {
	ctrl |= MII_CTRL_FD;
    } else {
	ctrl &= ~MII_CTRL_FD;
    }

    if (ctrl == o_ctrl) {
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }

    /* Enter reset state */
    PHY_CTRL_FLAGS(pc) |= PHY_F_DUPLEX_CHG;
    bcmi_nextgen65_serdes_stop(pc);

    ioerr += _PHY_REG_WRITE(pc, MII_CTRL_REG, ctrl);

    /* Exit reset state */
    PHY_CTRL_FLAGS(pc) &= ~PHY_F_DUPLEX_CHG;
    bcmi_nextgen65_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_nextgen65_serdes_duplex_get
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
bcmi_nextgen65_serdes_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_nextgen65_serdes_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen65_serdes_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int ioerr = 0;
    uint32_t ctrl, fx_ctrl;

    PHY_CTRL_CHECK(pc);

    if (speed == 0) {
        return CDK_E_NONE;
    }

    ioerr += _PHY_REG_READ(pc, MII_CTRL_REG, &ctrl);
    ioerr += _PHY_REG_READ(pc, NG65_FX_CTRL1_REG, &fx_ctrl);

    ctrl &= ~(MII_CTRL_SS_LSB | MII_CTRL_SS_MSB);
    switch(speed) {
    case 10:
        if (PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) {
            /* No support for 10 Mbps in SerDes mode */
            return CDK_E_PARAM;
        }
	ctrl |= MII_CTRL_SS_10;
	break;
    case 100:
	ctrl |= MII_CTRL_SS_100;
	break;
    case 1000:	
	ctrl |= MII_CTRL_SS_1000;
	break;
    default:
	return CDK_E_PARAM;
    }

    /* Enable 100FX if fiber mode at 100 Mbps */
    fx_ctrl &= ~NG65_100FX_EN;
    if ((PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) && speed == 100) {
        fx_ctrl |= NG65_100FX_EN;
    }

    /* Enter reset state */
    PHY_CTRL_FLAGS(pc) |= PHY_F_SPEED_CHG;
    bcmi_nextgen65_serdes_stop(pc);

    ioerr += _PHY_REG_WRITE(pc, MII_CTRL_REG, ctrl);
    ioerr += _PHY_REG_WRITE(pc, NG65_FX_CTRL1_REG, fx_ctrl);

    /* Exit reset state */
    PHY_CTRL_FLAGS(pc) &= ~PHY_F_SPEED_CHG;
    bcmi_nextgen65_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_nextgen65_serdes_speed_get
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
bcmi_nextgen65_serdes_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int ioerr = 0;
    uint32_t fx_ctrl;

    *speed = 1000;

    ioerr += _PHY_REG_READ(pc, NG65_FX_CTRL1_REG, &fx_ctrl);
    if (fx_ctrl & NG65_100FX_EN) {
        *speed = 100;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_nextgen65_serdes_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen65_serdes_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    uint32_t ctrl1, ctrl2, fx_ctrl;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* In passthru mode we always disable autoneg */
    if (PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) {
        autoneg = 0;
    }

    ioerr += _PHY_REG_READ(pc, NG65_1000X_CTRL1_REG, &ctrl1);
    ioerr += _PHY_REG_READ(pc, NG65_1000X_CTRL2_REG, &ctrl2);

    if (autoneg) {
        /* Enable medium auto-detect */
        ctrl1 |= NG65_1000X_AUTO_DETECT;
        /* Enable parallel detect */
        ctrl2 |= NG65_1000X_PAR_DET_EN;
        /* Ensure that 100FX mode is disabled */
        ioerr += _PHY_REG_READ(pc, NG65_FX_CTRL1_REG, &fx_ctrl);
        if (fx_ctrl & NG65_100FX_EN) {
            fx_ctrl &= ~NG65_100FX_EN;
            ioerr += _PHY_REG_WRITE(pc, NG65_FX_CTRL1_REG, fx_ctrl);
        }
    } else {
        ctrl1 &= ~NG65_1000X_AUTO_DETECT;
        ctrl2 &= ~NG65_1000X_PAR_DET_EN;
    }

    ioerr += _PHY_REG_WRITE(pc, NG65_1000X_CTRL1_REG, ctrl1);
    ioerr += _PHY_REG_WRITE(pc, NG65_1000X_CTRL2_REG, ctrl2);

    rv = ge_phy_autoneg_set(pc, autoneg);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_nextgen65_serdes_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy).
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen65_serdes_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    uint32_t ctrl;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += _PHY_REG_READ(pc, MII_CTRL_REG, &ctrl);
    *autoneg = (ctrl & MII_CTRL_AE) != 0;

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_nextgen65_serdes_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen65_serdes_loopback_set(phy_ctrl_t *pc, int enable)
{
    return ge_phy_loopback_set(pc, enable);
}

/*
 * Function:    
 *      bcmi_nextgen65_serdes_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen65_serdes_loopback_get(phy_ctrl_t *pc, int *enable)
{
    return ge_phy_loopback_get(pc, enable);
}

/*
 * Function:    
 *      bcmi_nextgen65_serdes_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen65_serdes_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    *abil = (PHY_ABIL_1000MB | PHY_ABIL_PAUSE | PHY_ABIL_SERDES |
             PHY_ABIL_LOOPBACK | PHY_ABIL_GMII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_nextgen65_serdes_config_set
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
bcmi_nextgen65_serdes_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
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
 *      bcmi_nextgen65_serdes_config_get
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
bcmi_nextgen65_serdes_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
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
phy_driver_t bcmi_nextgen65_serdes_drv = {
    "bcmi_nextgen65_serdes", 
    "Internal 65nm NextGen 1.25G SerDes PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_nextgen65_serdes_probe,        /* pd_probe */
    bcmi_nextgen65_serdes_notify,       /* pd_notify */
    bcmi_nextgen65_serdes_reset,        /* pd_reset */
    bcmi_nextgen65_serdes_init,         /* pd_init */
    bcmi_nextgen65_serdes_link_get,     /* pd_link_get */
    bcmi_nextgen65_serdes_duplex_set,   /* pd_duplex_set */
    bcmi_nextgen65_serdes_duplex_get,   /* pd_duplex_get */
    bcmi_nextgen65_serdes_speed_set,    /* pd_speed_set */
    bcmi_nextgen65_serdes_speed_get,    /* pd_speed_get */
    bcmi_nextgen65_serdes_autoneg_set,  /* pd_autoneg_set */
    bcmi_nextgen65_serdes_autoneg_get,  /* pd_autoneg_get */
    bcmi_nextgen65_serdes_loopback_set, /* pd_loopback_set */
    bcmi_nextgen65_serdes_loopback_get, /* pd_loopback_get */
    bcmi_nextgen65_serdes_ability_get,  /* pd_ability_get */
    bcmi_nextgen65_serdes_config_set,   /* pd_config_set */
    bcmi_nextgen65_serdes_config_get,   /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
