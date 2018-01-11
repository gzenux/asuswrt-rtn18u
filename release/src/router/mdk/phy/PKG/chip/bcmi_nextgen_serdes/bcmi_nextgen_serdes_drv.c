/*
 * $Id: bcmi_nextgen_serdes_drv.c,v 1.8 Broadcom SDK $
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
 * PHY driver for internal NextGen 1.25G SerDes PHY.
 *
 */

#include <phy/phy.h>
#include <phy/phy_xgs_iblk.h>
#include <phy/phy_brcm_serdes_id.h>
#include <phy/ge_phy.h>

#define BCMI_NEXTGEN_SERDES_ID0         0x0143
#define BCMI_NEXTGEN_SERDES_ID1_2X      0xbd60  /* "Dual" */
#define BCMI_NEXTGEN_SERDES_ID1_8X      0xbd70  /* "Octal" */
#define BCMI_NEXTGEN_SERDES_ID1_12X     0xbd80  /* "Dodeca" or "Dozen" */

#define PHY_ID1_REV_MASK                0x000f

#define _PHY_REG_READ(_pc, _r, _v)      phy_xgs_iblk_read(_pc, _r, _v)
#define _PHY_REG_WRITE(_pc, _r, _v)     phy_xgs_iblk_write(_pc, _r, _v)

#define BCM56504_RESET_POLL_MAX         10

/* MIIM block definitions for register 0x10-0x1f */
#define MIIM_BLK_DIGITAL                0x000
#define MIIM_BLK_ANALOG                 0x100
#define MIIM_BLK_FX100                  0x200

/* Bit defines for ANA register */
#define DDS_MII_ANA_HD                  (1 << 6)
#define DDS_MII_ANA_FD                  (1 << 5)
#define DDS_MII_ANA_PAUSE_NONE          (0 << 7)
#define DDS_MII_ANA_PAUSE_SYM           (1 << 7)
#define DDS_MII_ANA_PAUSE_ASYM          (1 << 8)
#define DDS_MII_ANA_PAUSE_MASK          (3 << 7)

/* Auto-Negotiation Link-Partner Ability Register */
#define DDS_ANP_REG                     0x05

#define DDS_MII_ANP_FIBER_NEXT_PG       (1 << 15)
#define DDS_MII_ANP_FIBER_ACK           (1 << 14)
#define DDS_MII_ANP_FIBER_RF_SHFT       12
#define DDS_MII_ANP_FIBER_RF_MASK       0x3000
#define DDS_MII_ANP_FIBER_PAUSE_ASYM    (1 << 8)
#define DDS_MII_ANP_FIBER_PAUSE_SYM     (1 << 7)
#define DDS_MII_ANP_FIBER_HD            (1 << 6)
#define DDS_MII_ANP_FIBER_FD            (1 << 5)

/* Auto-Negotiation Expansion Register */
#define DDS_ANA_EXPANSION_REG           MII_AN_EXP_REG
#define DDS_ANA_EXPANSION_PR            (1 << 1)

/* 1000X Control #1 Register: Controls 10B/SGMII mode */
#define DDS_1000X_CTRL1_REG             0x10
#define DDS_1000X_FIBER_MODE            (1 << 0)
#define DDS_1000X_EN10B_MODE            (1 << 1)
#define DDS_1000X_INVERT_SD             (1 << 3)
#define DDS_1000X_AUTO_DETECT           (1 << 4)

/* 1000X Control #2 Register: */
#define DDS_1000X_CTRL2_REG             0x11
#define DDS_1000X_PAR_DET_EN            (1 << 0)
#define DDS_1000X_FALSE_LNK_DIS         (1 << 1)
#define DDS_1000X_FLT_FORCE_EN          (1 << 2)

/* 1000X Control #3 Register: */
#define DDS_1000X_CTRL3_REG             0x12
#define DDS_1000X_TX_FIFO_RST           (1 << 0)
#define DDS_1000X_FIFO_ELASTICITY_MASK  (0x3 << 1)
#define DDS_1000X_FIFO_ELASTICITY_5K    (0x0 << 1)
#define DDS_1000X_FIFO_ELASTICITY_10K   (0x1 << 1)
#define DDS_1000X_FIFO_ELASTICITY_13_5K (0x2 << 1)
#define DDS_1000X_RX_FIFO_RST           (1 << 14)

/* 1000X Control #4 Register: */
#define DDS_1000X_CTRL4_REG             0x13
#define DDS_1000X_DIG_RESET             (1 << 6)

/* analog_tx (Analog register block) */
#define DDS1_ANALOG_TX                  (0x10 | MIIM_BLK_ANALOG)

/***********************************************************************
 *
 * HELPER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcmi_nextgen_serdes_stop
 * Purpose:
 *      Put PHY in or out of reset depending on conditions.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_nextgen_serdes_stop(phy_ctrl_t *pc)
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

#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
extern cdk_symbols_t bcmi_nextgen_serdes_symbols;
#endif

/*
 * Function:
 *      bcmi_nextgen_serdes_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen_serdes_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    int ioerr = 0;
    int rv = CDK_E_NOT_FOUND;

    PHY_CTRL_CHECK(pc);

    ioerr += phy_brcm_serdes_id(pc, &phyid0, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCMI_NEXTGEN_SERDES_ID0 &&
        (phyid1 == BCMI_NEXTGEN_SERDES_ID1_2X ||
         phyid1 == BCMI_NEXTGEN_SERDES_ID1_8X ||
         phyid1 == BCMI_NEXTGEN_SERDES_ID1_12X)) {

#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
        PHY_CTRL_SYMBOLS(pc) = &bcmi_nextgen_serdes_symbols;
#endif
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }

    return ioerr ? CDK_E_IO : rv;
}


/*
 * Function:
 *      bcmi_nextgen_serdes_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen_serdes_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int ioerr = 0;
    uint32_t ctrl;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToPassthru:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) |= PHY_F_PASSTHRU;
        /* Use default analog_tx value */
        ioerr += _PHY_REG_WRITE(pc, DDS1_ANALOG_TX, 0xce20);
        /* Put the Serdes in passthru mode */
        ioerr += _PHY_REG_READ(pc, DDS_1000X_CTRL1_REG, &ctrl);
        ctrl &= ~DDS_1000X_FIBER_MODE;
        ioerr += _PHY_REG_WRITE(pc, DDS_1000X_CTRL1_REG, ctrl);
        break;
    case PhyEvent_ChangeToFiber:
        PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_PASSTHRU;
        /* Set fiber analog_tx with recommended amplitude */ 
        ioerr += _PHY_REG_WRITE(pc, DDS1_ANALOG_TX, 0xfe20);
        /* Put the Serdes in fiber mode */
        ioerr += _PHY_REG_READ(pc, DDS_1000X_CTRL1_REG, &ctrl);
        ctrl |= DDS_1000X_FIBER_MODE;
        ioerr += _PHY_REG_WRITE(pc, DDS_1000X_CTRL1_REG, ctrl);
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
    bcmi_nextgen_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_nextgen_serdes_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen_serdes_reset(phy_ctrl_t *pc)
{
    return ge_phy_reset(pc);
}

/*
 * Function:
 *      bcmi_nextgen_serdes_init
 * Purpose:     
 *      Initialize PHY driver.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_NONE
 */
static int
bcmi_nextgen_serdes_init(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    int ioerr = 0;
    uint32_t ctrl;

    PHY_CTRL_CHECK(pc);

    ioerr += _PHY_REG_READ(pc, DDS_1000X_CTRL2_REG, &ctrl);
    ctrl |= DDS_1000X_FALSE_LNK_DIS | DDS_1000X_FLT_FORCE_EN;
    ioerr += _PHY_REG_WRITE(pc, DDS_1000X_CTRL2_REG, ctrl);

    /* Default mode is fiber */
    PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);

    return ioerr ? CDK_E_IO : rv;
}


/*
 * Function:    
 *      bcmi_nextgen_serdes_link_get
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
bcmi_nextgen_serdes_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    return ge_phy_link_get(pc, link, autoneg_done);
}

/*
 * Function:    
 *      bcmi_nextgen_serdes_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen_serdes_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int ioerr = 0;
    uint32_t ctrl, o_ctrl;

    PHY_CTRL_CHECK(pc);

    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) == 0) {
        /* Only support full duplex in non-passthru mode */
        return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
    }

    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
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
    bcmi_nextgen_serdes_stop(pc);

    ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl);

    /* Exit reset state */
    PHY_CTRL_FLAGS(pc) &= ~PHY_F_DUPLEX_CHG;
    bcmi_nextgen_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_nextgen_serdes_duplex_get
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
bcmi_nextgen_serdes_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_nextgen_serdes_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen_serdes_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int ioerr = 0;
    uint32_t ctrl, o_ctrl;

    PHY_CTRL_CHECK(pc);

    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) == 0) {
        /* Only support speed 1000 in non-passthru mode */
        return (speed == 0 || speed == 1000) ? CDK_E_NONE : CDK_E_PARAM;
    }

    if (speed == 0) {
        return CDK_E_NONE;
    }

    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
    o_ctrl = ctrl;

    ctrl &= ~(MII_CTRL_SS_LSB | MII_CTRL_SS_MSB);
    switch(speed) {
    case 10:
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

    if (ctrl == o_ctrl) {
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }

    /* Enter reset state */
    PHY_CTRL_FLAGS(pc) |= PHY_F_SPEED_CHG;
    bcmi_nextgen_serdes_stop(pc);

    ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl);

    /* Exit reset state */
    PHY_CTRL_FLAGS(pc) &= ~PHY_F_SPEED_CHG;
    bcmi_nextgen_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_nextgen_serdes_speed_get
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
bcmi_nextgen_serdes_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int rv;
    int autoneg = 0, autoneg_done = 0;

    *speed = 0;

    rv = PHY_AUTONEG_GET(pc, &autoneg);

    if (CDK_SUCCESS(rv) && autoneg) {
        rv = PHY_LINK_GET(pc, NULL, &autoneg_done);
    }

    if (!autoneg || autoneg_done) {
        *speed = 1000;
    }

    return rv;
}

/*
 * Function:    
 *      bcmi_nextgen_serdes_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */

static int
bcmi_nextgen_serdes_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    uint32_t ctrl1, ctrl2;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* In passthru mode we always disable autoneg */
    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU)) {
        autoneg = 0;
    }

    ioerr += _PHY_REG_READ(pc, DDS_1000X_CTRL1_REG, &ctrl1);
    ioerr += _PHY_REG_READ(pc, DDS_1000X_CTRL2_REG, &ctrl2);

    if (autoneg) {
        /* Enable medium auto-detect */
        ctrl1 |= DDS_1000X_AUTO_DETECT;
        /* Enable parallel detect */
        ctrl2 |= DDS_1000X_PAR_DET_EN;
    } else {
        ctrl1 &= ~DDS_1000X_AUTO_DETECT;
        ctrl2 &= ~DDS_1000X_PAR_DET_EN;
    }

    ioerr += _PHY_REG_WRITE(pc, DDS_1000X_CTRL1_REG, ctrl1);
    ioerr += _PHY_REG_WRITE(pc, DDS_1000X_CTRL2_REG, ctrl2);

    rv = ge_phy_autoneg_set(pc, autoneg);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_nextgen_serdes_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy).
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen_serdes_autoneg_get(phy_ctrl_t *pc, int *autoneg)
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
 *      bcmi_nextgen_serdes_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen_serdes_loopback_set(phy_ctrl_t *pc, int enable)
{
    return ge_phy_loopback_set(pc, enable);
}

/*
 * Function:    
 *      bcmi_nextgen_serdes_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen_serdes_loopback_get(phy_ctrl_t *pc, int *enable)
{
    return ge_phy_loopback_get(pc, enable);
}

/*
 * Function:    
 *      bcmi_nextgen_serdes_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_nextgen_serdes_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    *abil = (PHY_ABIL_1000MB | PHY_ABIL_PAUSE | PHY_ABIL_SERDES |
             PHY_ABIL_LOOPBACK | PHY_ABIL_GMII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_nextgen_serdes_config_set
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
bcmi_nextgen_serdes_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
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
 *      bcmi_nextgen_serdes_config_get
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
bcmi_nextgen_serdes_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
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
phy_driver_t bcmi_nextgen_serdes_drv = {
    "bcmi_nextgen_serdes", 
    "Internal NextGen 1.25G SerDes PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_nextgen_serdes_probe,          /* pd_probe */
    bcmi_nextgen_serdes_notify,         /* pd_notify */
    bcmi_nextgen_serdes_reset,          /* pd_reset */
    bcmi_nextgen_serdes_init,           /* pd_init */
    bcmi_nextgen_serdes_link_get,       /* pd_link_get */
    bcmi_nextgen_serdes_duplex_set,     /* pd_duplex_set */
    bcmi_nextgen_serdes_duplex_get,     /* pd_duplex_get */
    bcmi_nextgen_serdes_speed_set,      /* pd_speed_set */
    bcmi_nextgen_serdes_speed_get,      /* pd_speed_get */
    bcmi_nextgen_serdes_autoneg_set,    /* pd_autoneg_set */
    bcmi_nextgen_serdes_autoneg_get,    /* pd_autoneg_get */
    bcmi_nextgen_serdes_loopback_set,   /* pd_loopback_set */
    bcmi_nextgen_serdes_loopback_get,   /* pd_loopback_get */
    bcmi_nextgen_serdes_ability_get,    /* pd_ability_get */
    bcmi_nextgen_serdes_config_set,     /* pd_config_set */
    bcmi_nextgen_serdes_config_get,     /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
