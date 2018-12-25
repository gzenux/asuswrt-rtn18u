/*
 * $Id: bcmi_combo_serdes_drv.c,v 1.7 Broadcom SDK $
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
#include <phy/ge_phy.h>
#include <phy/phy_xgs_iblk.h>
#include <phy/phy_brcm_serdes_id.h>
#include <phy/phy_drvlist.h>

#define BCMI_COMBO_SERDES_ID0        0x0143
#define BCMI_COMBO_SERDES_ID1        0xbd50

#define PHY_ID1_REV_MASK                0x000f

#define _PHY_REG_READ(_pc, _r, _v)      phy_xgs_iblk_read(_pc, _r, _v)
#define _PHY_REG_WRITE(_pc, _r, _v)     phy_xgs_iblk_write(_pc, _r, _v)

/* MIIM block definitions for register 0x10-0x1f */
#define MIIM_BLK_DIGITAL                0x000
#define MIIM_BLK_TEST                   0x100
#define MIIM_BLK_DIGITAL3               0x200
#define MIIM_BLK_PLL                    0x300
#define MIIM_BLK_RX                     0x400
#define MIIM_BLK_TX_MISC                0x500

/* Bit defines for 1000X ANA register */
#define MIIX_ANA_PAUSE_ASYM             (1 << 8)
#define MIIX_ANA_PAUSE_NONE             (0 << 7)
#define MIIX_ANA_PAUSE_SYM              (1 << 7)
#define MIIX_ANA_PAUSE_MASK             (3 << 7)
#define MIIX_ANA_HD                     (1 << 6)
#define MIIX_ANA_FD                     (1 << 5)

/* 1000X Link-Partner Ability Register */
#define MIIX_ANP_FIBER_NEXT_PG          (1 << 15)
#define MIIX_ANP_FIBER_ACK              (1 << 14)
#define MIIX_ANP_FIBER_RF_SHFT          12
#define MIIX_ANP_FIBER_RF_MASK          0x3000
#define MIIX_ANP_FIBER_PAUSE_ASYM       (1 << 8)
#define MIIX_ANP_FIBER_PAUSE_SYM        (1 << 7)
#define MIIX_ANP_FIBER_HD               (1 << 6)
#define MIIX_ANP_FIBER_FD               (1 << 5)

/* 1000X Control 1 Register */
#define DIGI_CTRL1_REG                  (0x10 | MIIM_BLK_DIGITAL)
#define DIGI_CTRL1_INVERT_SD            (1 << 3)
#define DIGI_CTRL1_SD_EN                (1 << 2)
#define DIGI_CTRL1_TBI_MODE             (1 << 1)
#define DIGI_CTRL1_FIBER_MODE           (1 << 0)

/* 1000X Control 2 Register */
#define DIGI_CTRL2_REG                  (0x11 | MIIM_BLK_DIGITAL)
#define DIGI_CTRL2_FLT_FORCE_EN         (1 << 2)
#define DIGI_CTRL2_FALSE_LNK_DIS        (1 << 1)
#define DIGI_CTRL2_PAR_DET_EN           (1 << 0)

/* Over 1G  ANA Register */
#define DIGI3_CTRLB_REG                 (0x1b | MIIM_BLK_DIGITAL3)
#define DIGI3_CTRLB_2500                (1 << 0)

/* Over 1G  ANP Register */
#define DIGI3_CTRLD_REG                 (0x1d | MIIM_BLK_DIGITAL3)
#define DIGI3_CTRLD_2500                (1 << 0)

/* Tx Analog Control 3 */
#define TX_ACTRL3_REG                   (0x17 | MIIM_BLK_TX_MISC)
#define TX_ACTRL3_PREEMPH               (1 << 12)
#define TX_ACTRL3_PREEMPH_MASK          0xf000
#define TX_ACTRL3_IDRV                  (1 << 8)
#define TX_ACTRL3_IDRV_MASK             0x0f00
#define TX_ACTRL3_IPREDRV               (1 << 8)
#define TX_ACTRL3_IPREDRV_MASK          0x00f0

/* Misc. 2 */
#define MISC_MISC2_REG                  (0x1e | MIIM_BLK_TX_MISC)
#define MISC_MISC2_PLL_MODE_DIGI        (1 << 1)
#define MISC_MISC2_PLL_MODE_ANA         (1 << 0)

/***********************************************************************
 *
 * HELPER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcmi_combo_serdes_stop
 * Purpose:
 *      Put PHY in or out of reset depending on conditions.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_combo_serdes_stop(phy_ctrl_t *pc)
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
 *      bcmi_combo_serdes_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo_serdes_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    int ioerr = 0;
    int rv = CDK_E_NOT_FOUND;

    PHY_CTRL_CHECK(pc);

    ioerr += phy_brcm_serdes_id(pc, &phyid0, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCMI_COMBO_SERDES_ID0 &&
        phyid1 == BCMI_COMBO_SERDES_ID1) {

        rv = CDK_E_NONE;
    }

    return ioerr ? CDK_E_IO : rv;
}


/*
 * Function:
 *      bcmi_combo_serdes_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo_serdes_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int ioerr = 0;
    uint32_t ctrl;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToPassthru:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) |= PHY_F_PASSTHRU;
        /* Set copper default Tx preemph, idrv and ipredrv */
        ioerr += _PHY_REG_WRITE(pc, TX_ACTRL3_REG, 0x9e90);
        /* Put the Serdes in Copper mode */
        ioerr += _PHY_REG_READ(pc, DIGI_CTRL1_REG, &ctrl);
        ctrl &= ~DIGI_CTRL1_FIBER_MODE;
        ioerr += _PHY_REG_WRITE(pc, DIGI_CTRL1_REG, ctrl);
        break;
    case PhyEvent_ChangeToFiber:
        PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_PASSTHRU;
        /* Set fiber default Tx preemph, idrv and ipredrv */
        ioerr += _PHY_REG_WRITE(pc, TX_ACTRL3_REG, 0x9e90);
        /* Put the Serdes in fiber mode */
        ioerr += _PHY_REG_READ(pc, DIGI_CTRL1_REG, &ctrl);
        ctrl |= DIGI_CTRL1_FIBER_MODE;
        ioerr += _PHY_REG_WRITE(pc, DIGI_CTRL1_REG, ctrl);
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
    bcmi_combo_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_combo_serdes_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo_serdes_reset(phy_ctrl_t *pc)
{
    return ge_phy_reset(pc);
}

/*
 * Function:
 *      bcmi_combo_serdes_init
 * Purpose:     
 *      Initialize PHY driver.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_NONE
 */
static int
bcmi_combo_serdes_init(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    int ioerr = 0;
    uint32_t ctrl;

    PHY_CTRL_CHECK(pc);

    ioerr += _PHY_REG_READ(pc, DIGI_CTRL2_REG, &ctrl);
    ctrl |= DIGI_CTRL2_FALSE_LNK_DIS | DIGI_CTRL2_FLT_FORCE_EN;
    ioerr += _PHY_REG_WRITE(pc, DIGI_CTRL2_REG, ctrl);

    /* Default mode is fiber */
    PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);

    return ioerr ? CDK_E_IO : rv;
}


/*
 * Function:    
 *      bcmi_combo_serdes_link_get
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
bcmi_combo_serdes_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    return ge_phy_link_get(pc, link, autoneg_done);
}

/*
 * Function:    
 *      bcmi_combo_serdes_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo_serdes_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int rv;

    PHY_CTRL_CHECK(pc);

    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) == 0) {
        /* Only support full duplex in non-passthru mode */
        return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
    }

    /* Enter reset state */
    PHY_CTRL_FLAGS(pc) |= PHY_F_DUPLEX_CHG;
    bcmi_combo_serdes_stop(pc);

    /* Use standard functions */
    rv = ge_phy_duplex_set(pc, duplex);

    /* Exit reset state */
    PHY_CTRL_FLAGS(pc) &= ~PHY_F_DUPLEX_CHG;
    bcmi_combo_serdes_stop(pc);

    return rv;
}

/*
 * Function:    
 *      bcmi_combo_serdes_duplex_get
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
bcmi_combo_serdes_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    PHY_CTRL_CHECK(pc);

    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_combo_serdes_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo_serdes_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int rv = CDK_E_NONE;
    int ioerr = 0;
    uint32_t mii_ctrl, misc2;

    PHY_CTRL_CHECK(pc);

    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) == 0) {
        /* Only support speeds 1000 and 2500 in non-passthru mode */
        if (speed != 0 && speed != 1000 && speed != 2500) {
            return CDK_E_PARAM;
        }
    }

    /* Enter reset state */
    PHY_CTRL_FLAGS(pc) |= PHY_F_SPEED_CHG;
    bcmi_combo_serdes_stop(pc);

    /* Get current forced 2.5 Gbps setting */
    ioerr += _PHY_REG_READ(pc, MISC_MISC2_REG, &misc2);
    misc2 &= ~(MISC_MISC2_PLL_MODE_DIGI | MISC_MISC2_PLL_MODE_ANA);

    if (speed == 2500) {
        ioerr += _PHY_REG_READ(pc, MII_CTRL_REG, &mii_ctrl);
        /* Do not force 2.5 Gbps if autoneg */
        if ((mii_ctrl & MII_CTRL_AE) == 0) {
            misc2 |= MISC_MISC2_PLL_MODE_DIGI | MISC_MISC2_PLL_MODE_ANA;
        }
    } else {
        /* Use standard functions */
        rv = ge_phy_speed_set(pc, speed);
    }

    /* Update forced 2.5 Gbps setting */
    ioerr += _PHY_REG_WRITE(pc, MISC_MISC2_REG, misc2);

    /* Exit reset state */
    PHY_CTRL_FLAGS(pc) &= ~PHY_F_SPEED_CHG;
    bcmi_combo_serdes_stop(pc);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_combo_serdes_speed_get
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
bcmi_combo_serdes_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int rv;
    int ioerr = 0;
    int link;
    int autoneg = 0, autoneg_done = 0;
    uint32_t misc2, ctrlb, ctrld;

    PHY_CTRL_CHECK(pc);

    *speed = 0;

    rv = bcmi_nextgen_serdes_drv.pd_autoneg_get(pc, &autoneg);
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    if (autoneg) {
        rv = bcmi_nextgen_serdes_drv.pd_link_get(pc, &link, &autoneg_done);
        if (CDK_FAILURE(rv) || !autoneg_done) {
            return rv;
        }
        ioerr += _PHY_REG_READ(pc, DIGI3_CTRLB_REG, &ctrlb);
        ioerr += _PHY_REG_READ(pc, DIGI3_CTRLD_REG, &ctrld);
        if ((ctrlb & DIGI3_CTRLB_2500) && (ctrld & DIGI3_CTRLD_2500)) {
            *speed = 2500;
        }
    } else {
        /* Get current forced 2.5 Gbps setting */
        ioerr += _PHY_REG_READ(pc, MISC_MISC2_REG, &misc2);
        if (misc2 & (MISC_MISC2_PLL_MODE_DIGI | MISC_MISC2_PLL_MODE_ANA)) {
            *speed = 2500;
        }
    }

    if (CDK_SUCCESS(rv) && *speed == 0) {
        /* Use standard functions */
        rv = ge_phy_speed_get(pc, speed);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_combo_serdes_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */

static int
bcmi_combo_serdes_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int rv;
    int ioerr = 0;
    uint32_t misc2;

    PHY_CTRL_CHECK(pc);

    if (autoneg) {
        /* Do not force 2.5 Gbps if autoneg */
        ioerr += _PHY_REG_READ(pc, MISC_MISC2_REG, &misc2);
        misc2 &= ~(MISC_MISC2_PLL_MODE_DIGI | MISC_MISC2_PLL_MODE_ANA);
        ioerr += _PHY_REG_WRITE(pc, MISC_MISC2_REG, misc2);
    }

    rv = bcmi_nextgen_serdes_drv.pd_autoneg_set(pc, autoneg);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_combo_serdes_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy).
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo_serdes_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    return bcmi_nextgen_serdes_drv.pd_autoneg_get(pc, autoneg);
}

/*
 * Function:    
 *      bcmi_combo_serdes_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo_serdes_loopback_set(phy_ctrl_t *pc, int enable)
{
    return ge_phy_loopback_set(pc, enable);
}

/*
 * Function:    
 *      bcmi_combo_serdes_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo_serdes_loopback_get(phy_ctrl_t *pc, int *enable)
{
    return ge_phy_loopback_get(pc, enable);
}

/*
 * Function:    
 *      bcmi_combo_serdes_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_combo_serdes_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    *abil = (PHY_ABIL_1000MB | PHY_ABIL_PAUSE | PHY_ABIL_SERDES |
             PHY_ABIL_LOOPBACK | PHY_ABIL_GMII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_combo_serdes_config_set
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
bcmi_combo_serdes_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
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
 *      bcmi_combo_serdes_config_get
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
bcmi_combo_serdes_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
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
phy_driver_t bcmi_combo_serdes_drv = {
    "bcmi_combo_serdes",
    "Internal Combo 2.5G/1.25G SerDes PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_combo_serdes_probe,            /* pd_probe */
    bcmi_combo_serdes_notify,           /* pd_notify */
    bcmi_combo_serdes_reset,            /* pd_reset */
    bcmi_combo_serdes_init,             /* pd_init */
    bcmi_combo_serdes_link_get,         /* pd_link_get */
    bcmi_combo_serdes_duplex_set,       /* pd_duplex_set */
    bcmi_combo_serdes_duplex_get,       /* pd_duplex_get */
    bcmi_combo_serdes_speed_set,        /* pd_speed_set */
    bcmi_combo_serdes_speed_get,        /* pd_speed_get */
    bcmi_combo_serdes_autoneg_set,      /* pd_autoneg_set */
    bcmi_combo_serdes_autoneg_get,      /* pd_autoneg_get */
    bcmi_combo_serdes_loopback_set,     /* pd_loopback_set */
    bcmi_combo_serdes_loopback_get,     /* pd_loopback_get */
    bcmi_combo_serdes_ability_get,      /* pd_ability_get */
    bcmi_combo_serdes_config_set,       /* pd_config_set */
    bcmi_combo_serdes_config_get,       /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
