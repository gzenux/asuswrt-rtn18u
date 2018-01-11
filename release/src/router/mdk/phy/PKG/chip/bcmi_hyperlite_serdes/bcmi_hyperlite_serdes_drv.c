/*
 * $Id: bcmi_hyperlite_serdes_drv.c,v 1.10 Broadcom SDK $
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
 * PHY driver for internal Hyperlite 2.5G/1.25G SerDes.
 *
 */

#include <phy/phy.h>
#include <phy/phy_xgs_iblk.h>
#include <phy/phy_brcm_serdes_id.h>
#include <phy/ge_phy.h>

#define BCM_SERDES_PHY_ID0              0x143
#define BCM_SERDES_PHY_ID1              0xbff0

#define PHY_ID1_REV_MASK                0x000f

#define SERDES_ID0_HYPERLITE            0x03

#define _PHY_REG_READ(_pc, _r, _v)      phy_xgs_iblk_read(_pc, _r, _v)
#define _PHY_REG_WRITE(_pc, _r, _v)     phy_xgs_iblk_write(_pc, _r, _v)

/* Transform datasheet mapped address to MIIM address used by software API */
#define XGS_MIIM_REG(_b) \
    ((((_b) & 0x7ff0) << 8) | (((_b) & 0x8000) >> 11) | ((_b) & 0xf))

/* XGXS BLOCK0 xgxsControl Register */
#define XGXS_BLK0_XGXS_CTRL_REG         XGS_MIIM_REG(0x8000)
#define XGXS_CTRL_START_SEQ             (1 << 13)
#define XGXS_CTRL_MODE_10G_GET(_r)      ((_r >> 8) & 0xf)
#define XGXS_CTRL_MODE_10G_SET(_r,_v)   _r = ((_r & ~(0xf << 8)) | (((_v) & 0xf) << 8))
#define MODE_10G_IND_LN_OS5             5
#define MODE_10G_IND_LN                 6
#define MODE_10G_COMBO                  12

/* XGXS BLOCK1 laneCtrl3 Register */
#define XGXS_BLK1_LANE_CTRL3_REG        XGS_MIIM_REG(0x8018)
#define LANE_CTRL3_PWRDWN_FORCE         (1 << 11)

/* XGXS BLOCK1 laneTest Register */
#define XGXS_BLK1_LANE_TEST_REG         XGS_MIIM_REG(0x801a)
#define LANE_TEST_PWRDWN_CLKS_EN        (1 << 8)
#define LANE_TEST_LFCK_BYPASS           (1 << 5)

/* SerDes Digital 1000XControl1 Register */
#define DIGITAL_1000X_CTRL1_REG         XGS_MIIM_REG(0x8300)
#define D1000X_CTRL1_DIS_PLL_PWRDWN     (1 << 6)
#define D1000X_CTRL1_AUTO_DETECT        (1 << 4)
#define D1000X_CTRL1_FIBER_MODE         (1 << 0)

/* SerDes Digital 1000XControl2 Register */
#define DIGITAL_1000X_CTRL2_REG         XGS_MIIM_REG(0x8301)
#define D1000X_CTRL2_PAR_DET_EN         (1 << 0)

/* SerDes Digital 1000XControl3 Register */
#define DIGITAL_1000X_CTRL3_REG         XGS_MIIM_REG(0x8302)
#define D1000X_CTRL3_TX_FIFO_RST        (1 << 0)

/* SerDes Digital 1000XStatus1 Register */
#define DIGITAL_1000X_STAT1_REG         XGS_MIIM_REG(0x8304)
#define D1000X_STAT1_SPEED_GET(_r)      ((_r >> 3) & 0x3)
#define D1000X_STAT1_SPEED_SET(_r,_v)   _r = ((_r & ~(0x3 << 3)) | (((_v) & 0x3) << 3))
#define STAT1_SPEED_10                  0
#define STAT1_SPEED_100                 1
#define STAT1_SPEED_1000                2
#define STAT1_SPEED_2500                3

/* SerDes Digital Misc Register */
#define DIGITAL_MISC_REG                XGS_MIIM_REG(0x8308)
#define MISC_FORCE_SPEED_SEL            (1 << 4)
#define MISC_FORCE_SPEED_GET(_r)        ((_r >> 0) & 0xf)
#define MISC_FORCE_SPEED_SET(_r,_v)     _r = ((_r & ~(0xf << 0)) | (((_v) & 0xf) << 0))
#define MISC_SPEED_2500                 0

/* IEEE-B0 MII Control Register */
#define B0_MII_CTRL_REG                 XGS_MIIM_REG(0xffe0)

/* IEEE-B0 MII Status Register */
#define B0_MII_STAT_REG                 XGS_MIIM_REG(0xffe1)

/***********************************************************************
 *
 * HELPER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcmi_hyperlite_serdes_lane
 * Purpose:
 *      Retrieve XGXS lane number for this PHY instance.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      Lane number or -1 if lane is unknown
 */
static int
bcmi_hyperlite_serdes_lane(phy_ctrl_t *pc)
{
    uint32_t inst = PHY_CTRL_INST(pc);

    if (inst & PHY_INST_VALID) {
        return inst & 0x3;
    }
    return -1;
}

/*
 * Function:
 *      bcmi_hyperlite_serdes_stop
 * Purpose:
 *      Put PHY in or out of reset depending on conditions.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_serdes_stop(phy_ctrl_t *pc)
{
    uint32_t lane_ctrl3, lane_mask;
    uint32_t f_any = PHY_F_PHY_DISABLE | PHY_F_PORT_DRAIN;
    uint32_t f_copper = PHY_F_MAC_DISABLE | PHY_F_SPEED_CHG | PHY_F_DUPLEX_CHG;
    int stop = 0;
    int ioerr = 0;
    int lane;

    if ((PHY_CTRL_FLAGS(pc) & f_any) ||
        ((PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) == 0 &&
         (PHY_CTRL_FLAGS(pc) & f_copper))) {
        stop = 1;
    }

    lane = bcmi_hyperlite_serdes_lane(pc);

    if (lane < 0) {
        /* No power-down if lane is unknown */
        stop = 0;
        lane_mask = 0xff;
    } else {
        lane_mask = 0x11 << lane;
    }

    ioerr += _PHY_REG_READ(pc, XGXS_BLK1_LANE_CTRL3_REG, &lane_ctrl3);

    lane_ctrl3 &= ~lane_mask;
    if (stop) {
        lane_ctrl3 |= lane_mask;
    }
    lane_ctrl3 |= LANE_CTRL3_PWRDWN_FORCE;

    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK1_LANE_CTRL3_REG, lane_ctrl3);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcmi_hyperlite_serdes_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_serdes_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1, serdesid0, xgxs_ctrl, mode;
    int ioerr = 0;

    if (CDK_FAILURE(phy_brcm_serdes_id(pc, &phyid0, &phyid1))) {
        return CDK_E_IO;
    }

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCM_SERDES_PHY_ID0 && phyid1 == BCM_SERDES_PHY_ID1) {
        /* Common PHY ID found - read specific SerDes ID */
        ioerr += _PHY_REG_READ(pc, SERDES_ID0, &serdesid0);
        if ((serdesid0 & 0x3f) == SERDES_ID0_HYPERLITE) {
            /* Check for IndependentLaneOS5 mode */
            ioerr += _PHY_REG_READ(pc, XGXS_BLK0_XGXS_CTRL_REG, &xgxs_ctrl);
            mode = XGXS_CTRL_MODE_10G_GET(xgxs_ctrl);
            if (mode == MODE_10G_IND_LN || mode == MODE_10G_IND_LN_OS5) {
                return ioerr ? CDK_E_IO : CDK_E_NONE;
            }
        }
    }
    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcmi_hyperlite_serdes_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_serdes_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int ioerr = 0;
    uint32_t ctrl;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToPassthru:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) |= PHY_F_PASSTHRU;
        /* Put the Serdes in passthru mode */
        ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_CTRL1_REG, &ctrl);
        ctrl &= ~D1000X_CTRL1_FIBER_MODE;
        ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL1_REG, ctrl);
        break;
    case PhyEvent_ChangeToFiber:
        PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_PASSTHRU;
        /* Put the Serdes in Fiber mode */
        ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_CTRL1_REG, &ctrl);
        ctrl |= D1000X_CTRL1_FIBER_MODE;
        ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL1_REG, ctrl);
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
    bcmi_hyperlite_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_hyperlite_serdes_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_serdes_reset(phy_ctrl_t *pc)
{
    phy_xgs_iblk_map_ieee(pc);

    return ge_phy_reset(pc);
}

/*
 * Function:
 *      bcmi_hyperlite_serdes_init
 * Purpose:     
 *      Initialize PHY driver.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_NONE
 */
static int
bcmi_hyperlite_serdes_init(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    int ioerr = 0;
    uint32_t ctrl, lane_test;

    PHY_CTRL_CHECK(pc);

    /* Disable PLL power-down */
    ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_CTRL1_REG, &ctrl);
    ctrl |= D1000X_CTRL1_DIS_PLL_PWRDWN;
    ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL1_REG, ctrl);

    /* Leave clocks enabled in power-down mode */
    ioerr += _PHY_REG_READ(pc, XGXS_BLK1_LANE_TEST_REG, &lane_test);
    lane_test |= LANE_TEST_PWRDWN_CLKS_EN | LANE_TEST_LFCK_BYPASS;
    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK1_LANE_TEST_REG, lane_test);

    /* Default mode is fiber */
    PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);

    return ioerr ? CDK_E_IO : rv;
}


/*
 * Function:    
 *      bcmi_hyperlite_serdes_link_get
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
bcmi_hyperlite_serdes_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    phy_xgs_iblk_map_ieee(pc);

    return ge_phy_link_get(pc, link, autoneg_done);
}

/*
 * Function:    
 *      bcmi_hyperlite_serdes_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_serdes_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int ioerr = 0;
    uint32_t ctrl, o_ctrl;

    PHY_CTRL_CHECK(pc);

    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) == 0) {
        /* Only support full duplex in non-passthru mode */
        return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
    }

    ioerr += _PHY_REG_READ(pc, B0_MII_CTRL_REG, &ctrl);
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
    bcmi_hyperlite_serdes_stop(pc);

    ioerr += _PHY_REG_WRITE(pc, B0_MII_CTRL_REG, ctrl);

    /* Exit reset state */
    PHY_CTRL_FLAGS(pc) &= ~PHY_F_DUPLEX_CHG;
    bcmi_hyperlite_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hyperlite_serdes_duplex_get
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
bcmi_hyperlite_serdes_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hyperlite_serdes_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_serdes_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int rv;
    int ioerr = 0;
    uint32_t misc;
    uint32_t ctrl3;

    PHY_CTRL_CHECK(pc);

    if (speed == 0) {
        return CDK_E_NONE;
    }

    if (PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) {
        /* Only support speeds 2500/1000 in fiber mode */
        if (speed < 1000) {
            return CDK_E_PARAM;
        }
    } else {
        /* Only support speeds 1000/100/10 in copper mode */
        if (speed > 1000) {
            return CDK_E_PARAM;
        }
    }

    /* Hold Rx sequencer */

    /* Reset Tx FIFO */
    ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_CTRL3_REG, &ctrl3);
    ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL3_REG,
                            ctrl3 | D1000X_CTRL3_TX_FIFO_RST);

    ioerr += _PHY_REG_READ(pc, DIGITAL_MISC_REG, &misc);
    misc &= ~MISC_FORCE_SPEED_SEL;
    if (speed == 2500) {
        /* Force 2.5 Gbps */
        misc |= MISC_FORCE_SPEED_SEL;
        MISC_FORCE_SPEED_SET(misc, MISC_SPEED_2500);
    }
    ioerr += _PHY_REG_WRITE(pc, DIGITAL_MISC_REG, misc);

    /* Use standard functions to set speed in IEEE register */
    phy_xgs_iblk_map_ieee(pc);
    rv = ge_phy_speed_set(pc, speed);

    /* Release Rx sequencer */

    /* Enable Tx FIFO */
    ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL3_REG, ctrl3);

    return rv;
}

/*
 * Function:    
 *      bcmi_hyperlite_serdes_speed_get
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
bcmi_hyperlite_serdes_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int rv = CDK_E_NONE;
    int ioerr = 0;
    int autoneg = 0, autoneg_done = 0;
    uint32_t stat1;

    *speed = 0;

    rv = PHY_AUTONEG_GET(pc, &autoneg);

    if (CDK_SUCCESS(rv) && autoneg) {
        rv = PHY_LINK_GET(pc, NULL, &autoneg_done);
    }

    if (!autoneg || autoneg_done) {
        ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_STAT1_REG, &stat1);
        switch (D1000X_STAT1_SPEED_GET(stat1)) {
        case STAT1_SPEED_2500:
            *speed = 2500;
            break;
        case STAT1_SPEED_1000:
            *speed = 1000;
            break;
        case STAT1_SPEED_100:
            *speed = 100;
            break;
        default:
            *speed = 10;
            break;
        }
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_hyperlite_serdes_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */

static int
bcmi_hyperlite_serdes_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    uint32_t ctrl1, ctrl2;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* In passthru mode we always disable autoneg */
    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU)) {
        autoneg = 0;
    }

    ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_CTRL1_REG, &ctrl1);
    ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_CTRL2_REG, &ctrl2);

    if (autoneg) {
        /* Enable medium auto-detect */
        ctrl1 |= D1000X_CTRL1_AUTO_DETECT;
        /* Enable parallel detect */
        ctrl2 |= D1000X_CTRL2_PAR_DET_EN;
    } else {
        ctrl1 &= ~D1000X_CTRL1_AUTO_DETECT;
        ctrl2 &= ~D1000X_CTRL2_PAR_DET_EN;
    }

    ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL1_REG, ctrl1);
    ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL2_REG, ctrl2);

    phy_xgs_iblk_map_ieee(pc);

    rv = ge_phy_autoneg_set(pc, autoneg);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_hyperlite_serdes_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy).
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_serdes_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    phy_xgs_iblk_map_ieee(pc);

    return ge_phy_autoneg_get(pc, autoneg);
}

/*
 * Function:    
 *      bcmi_hyperlite_serdes_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_serdes_loopback_set(phy_ctrl_t *pc, int enable)
{
    phy_xgs_iblk_map_ieee(pc);

    return ge_phy_loopback_set(pc, enable);
}

/*
 * Function:    
 *      bcmi_hyperlite_serdes_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_serdes_loopback_get(phy_ctrl_t *pc, int *enable)
{
    phy_xgs_iblk_map_ieee(pc);

    return ge_phy_loopback_get(pc, enable);
}

/*
 * Function:    
 *      bcmi_hyperlite_serdes_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_serdes_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    *abil = (PHY_ABIL_2500MB | PHY_ABIL_1000MB | PHY_ABIL_PAUSE | 
             PHY_ABIL_SERDES | PHY_ABIL_LOOPBACK | PHY_ABIL_GMII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_hyperlite_serdes_config_set
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
bcmi_hyperlite_serdes_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        PHY_CTRL_FLAGS(pc) |= PHY_F_PHY_DISABLE;
        if (val) {
            PHY_CTRL_FLAGS(pc) &= ~PHY_F_PHY_DISABLE;
        }
        return bcmi_hyperlite_serdes_stop(pc);
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
 *      bcmi_hyperlite_serdes_config_get
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
bcmi_hyperlite_serdes_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
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
phy_driver_t bcmi_hyperlite_serdes_drv = {
    "bcmi_hyperlite_serdes", 
    "Internal Hyperlite 2.5G/1.25G SerDes PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_hyperlite_serdes_probe,        /* pd_probe */
    bcmi_hyperlite_serdes_notify,       /* pd_notify */
    bcmi_hyperlite_serdes_reset,        /* pd_reset */
    bcmi_hyperlite_serdes_init,         /* pd_init */
    bcmi_hyperlite_serdes_link_get,     /* pd_link_get */
    bcmi_hyperlite_serdes_duplex_set,   /* pd_duplex_set */
    bcmi_hyperlite_serdes_duplex_get,   /* pd_duplex_get */
    bcmi_hyperlite_serdes_speed_set,    /* pd_speed_set */
    bcmi_hyperlite_serdes_speed_get,    /* pd_speed_get */
    bcmi_hyperlite_serdes_autoneg_set,  /* pd_autoneg_set */
    bcmi_hyperlite_serdes_autoneg_get,  /* pd_autoneg_get */
    bcmi_hyperlite_serdes_loopback_set, /* pd_loopback_set */
    bcmi_hyperlite_serdes_loopback_get, /* pd_loopback_get */
    bcmi_hyperlite_serdes_ability_get,  /* pd_ability_get */
    bcmi_hyperlite_serdes_config_set,   /* pd_config_set */
    bcmi_hyperlite_serdes_config_get,   /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
