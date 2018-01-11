/*
 * $Id: bcm54640_drv.c,v 1.7 Broadcom SDK $
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
 * PHY driver for BCM54640.
 *
 */

#include <phy/phy.h>
#include <phy/ge_phy.h>

#define BCM54640_PHY_ID0                0x0362
#define BCM54640_PHY_ID1                0x5db0

#define PHY_ID1_REV_MASK                0x000f

/* Default LED control */
#define BCM54640_LED1_SEL(_pc)          0x0
#define BCM54640_LED2_SEL(_pc)          0x1
#define BCM54640_LED3_SEL(_pc)          0x3
#define BCM54640_LED4_SEL(_pc)          0x6
#define BCM54640_LEDCTRL(_pc)           0x8
#define BCM54640_LEDSELECT(_pc)         0x0

/* Access to shadowed registers at offset 0x18 */
#define REG_18_SEL(_s)                  (((_s) << 12) | 0x7)
#define REG_18_WR(_s,_v)                (((_s) == 7 ? 0x8000 : 0) | (_v) | (_s))

/* Access to shadowed registers at offset 0x1c */
#define REG_1C_SEL(_s)                  ((_s) << 10)
#define REG_1C_WR(_s,_v)                (REG_1C_SEL(_s) | (_v) | 0x8000)

/* Access expansion registers at offset 0x15 */
#define MII_EXP_MAP_REG(_r)             ((_r) | 0x0f00)
#define MII_EXP_UNMAP                   (0)

/*
 * Non-standard MII Registers
 */
#define MII_ECR_REG             0x10 /* MII Extended Control Register */
#define MII_EXP_REG             0x15 /* MII Expansion registers */
#define MII_EXP_SEL             0x17 /* MII Expansion register select */

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcm54640_phy_probe
 * Purpose:     
 *      Probe for PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640_phy_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, MII_PHY_ID0_REG, &phyid0);
    ioerr += PHY_BUS_READ(pc, MII_PHY_ID1_REG, &phyid1);

    if (phyid0 == BCM54640_PHY_ID0 && 
        (phyid1 & ~PHY_ID1_REV_MASK) == BCM54640_PHY_ID1) {

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcm54640_phy_notify
 * Purpose:     
 *      Handle PHY notifications
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640_phy_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToCopper:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_FIBER_MODE;
        /* Upstream PHY should operate in passthru mode */
        event = PhyEvent_ChangeToPassthru;
        break;
    case PhyEvent_ChangeToFiber:
        PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;
        /* Upstream PHY should remain in SGMII mode */
        event = PhyEvent_ChangeToPassthru;
        break;
    default:
        break;
    }

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_NOTIFY(PHY_CTRL_NEXT(pc), event);
    }

    /* Upstream PHY must disable autoneg in passthru mode */
    if (event == PhyEvent_ChangeToPassthru) {
        rv = PHY_AUTONEG_SET(PHY_CTRL_NEXT(pc), 0);
    }

    return rv;
}

/*
 * Function:
 *      bcm54640_phy_reset
 * Purpose:     
 *      Reset PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640_phy_reset(phy_ctrl_t *pc)
{
    int rv;

    rv = ge_phy_reset(pc);

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_RESET(PHY_CTRL_NEXT(pc));
    }

    return rv;
}

/*
 * Function:
 *      bcm54640_phy_init
 * Purpose:     
 *      Initialize PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640_phy_init(phy_ctrl_t *pc)
{
    int ioerr = 0;
    uint32_t mode_ctrl, tmp, ctrl;
    uint32_t sgmii_slave;
    uint32_t auto_medium;

    /* SGMII to copper mode */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_SEL(0x1f));
    ioerr += PHY_BUS_READ(pc, 0x1c, &mode_ctrl);
    mode_ctrl &= ~0x06;
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1f, mode_ctrl));

    /* Power up copper registers */
    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
    ctrl &= ~MII_CTRL_PD;
    ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl);

    /* Set port mode */
    ctrl = MII_GB_CTRL_PT;
    ioerr += PHY_BUS_WRITE(pc, MII_GB_CTRL_REG, ctrl);

    /* Advertise 1000BASE-T full-duplex */
    ctrl |= MII_GB_CTRL_ADV_1000FD;
    ioerr += PHY_BUS_WRITE(pc, MII_GB_CTRL_REG, ctrl);

    /* Adjust timing and enable link speed led mode */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_SEL(0x02));
    ioerr += PHY_BUS_READ(pc, 0x1c, &tmp);
    tmp |= 0x0006;
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x02, tmp));

    /* Invert 10BT TX clock */
    ioerr += PHY_BUS_WRITE(pc, 0x18, 0x1007);
    ioerr += PHY_BUS_READ(pc, 0x18, &tmp);
    tmp |= 0x0800;
    ioerr += PHY_BUS_WRITE(pc, 0x18, tmp);

    /* Initiale upstream PHY */
    PHY_INIT(PHY_CTRL_NEXT(pc));

    /* Power up fiber */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1f, mode_ctrl | 0x01));
    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
    ctrl &= ~MII_CTRL_PD;
    ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl);

    /* Advertise 1000BASE-X full-duplex only */
    ioerr += PHY_BUS_READ(pc, MII_ANA_REG, &ctrl);
    ctrl &= ~(1 << 6);
    ctrl |= (1 << 5);
    ioerr += PHY_BUS_WRITE(pc, MII_ANA_REG, ctrl);
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1f, mode_ctrl));

    /* Enable auto-detection between SGMII-slave and 1000BASE-X */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_SEL(0x15));
    ioerr += PHY_BUS_READ(pc, 0x1c, &sgmii_slave);
    sgmii_slave |= 1;
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x15, sgmii_slave));

    /* Change LED2 pin into an input */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_SEL(0x0f));
    ioerr += PHY_BUS_READ(pc, 0x1c, &ctrl);
    ctrl |= 0x08;
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x0f, ctrl));

    /* Disable amplitude signal detect */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_SEL(0x17));
    ioerr += PHY_BUS_READ(pc, 0x1c, &ctrl);
    ctrl &= ~0x20;
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x17, ctrl));

    /* Set SGMII mode */
    mode_ctrl &= 0x06;
    mode_ctrl |= 0x02;
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1f, mode_ctrl));

    /* Configure auto-medium detect */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_SEL(0x1e));
    ioerr += PHY_BUS_READ(pc, 0x1c, &auto_medium);
    auto_medium &= ~0x001f;
    auto_medium |= 0x0001; /* Enable auto-medium detect */
    auto_medium |= 0x0002; /* Prefer SerDes if both media active */
    auto_medium |= 0x0004; /* Prefer SerDes if no medium active */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1e, auto_medium));

    /*
     * Relax the receiver thresholds used in acquiring link during
     * auto-negotiation.
     *
     * Without this adjustment, a port may under certain conditions
     * auto-negotiate to 100BASE-TX instead of 1000BASE-T or have
     * long link acquisition time.
     */
    ioerr += PHY_BUS_WRITE(pc, 0x18, 0x0c00);
    ioerr += PHY_BUS_WRITE(pc, 0x17, 0x000e);
    ioerr += PHY_BUS_WRITE(pc, 0x15, 0x0752);
    ioerr += PHY_BUS_WRITE(pc, 0x17, 0x000f);
    ioerr += PHY_BUS_WRITE(pc, 0x15, 0xe04e);
    ioerr += PHY_BUS_WRITE(pc, 0x18, 0x0400);

    /* Set default medium */
    PHY_NOTIFY(pc, PhyEvent_ChangeToCopper);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm54640_phy_link_get
 * Purpose:     
 *      Determine the current link up/down status
 * Parameters:
 *      pc - PHY control structure
 *      link - (OUT) non-zero indicates link established.
 *      autoneg_done - (OUT) if true, auto-negotiation is complete
 * Returns:
 *      CDK_E_xxx
 * Notes:
 *      MII_STATUS bit 2 reflects link state.
 */
static int
bcm54640_phy_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int autoneg;
    uint32_t mode_ctrl;

    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_SEL(0x1f));
    ioerr += PHY_BUS_READ(pc, 0x1c, &mode_ctrl);

    rv = PHY_AUTONEG_GET(pc, &autoneg);
    if (CDK_SUCCESS(rv) && autoneg == 0) {
        /* Forced mode */
        if (PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) {
            PHY_NOTIFY(pc, PhyEvent_ChangeToCopper);
        }
    } else if ((mode_ctrl & 0x30) == 0x20) {
        /* Copper energy detect */
        if (PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) {
            PHY_NOTIFY(pc, PhyEvent_ChangeToCopper);
        }
    } else {
        /* Fiber signal detect (or no link) */
        if ((PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) == 0) {
            PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);
        }
    }

    if (PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) {
        /* Select fiber registers */
        ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1f, mode_ctrl | 0x01));
    }

    if (CDK_SUCCESS(rv)) {
        rv = ge_phy_link_get(pc, link, autoneg_done);
    }

    if (PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) {
        /* Select copper registers */
        ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1f, mode_ctrl));
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm54640_phy_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640_phy_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_DUPLEX_SET(PHY_CTRL_NEXT(pc), duplex);
    }

    if (CDK_SUCCESS(rv)) {
        if ((PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) == 0) {
            rv = ge_phy_duplex_set(pc, duplex);
        }
    }

    return rv;
}

/*
 * Function:    
 *      bcm54640_phy_duplex_get
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
bcm54640_phy_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) {
        *duplex = TRUE;
        return CDK_E_NONE;
    }

    return ge_phy_duplex_get(pc, duplex);
}

/*
 * Function:    
 *      bcm54640_phy_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640_phy_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_SPEED_SET(PHY_CTRL_NEXT(pc), speed);
    }

    /* Set copper speed */
    if (CDK_SUCCESS(rv)) {
        rv = ge_phy_speed_set(pc, speed);
    }

    return rv;
}

/*
 * Function:    
 *      bcm54640_phy_speed_get
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
bcm54640_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int rv;
    int autoneg, link;

    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) {
        *speed = 1000;
        rv = PHY_AUTONEG_GET(pc, &autoneg);
        if (CDK_SUCCESS(rv) && autoneg) {
            rv = PHY_LINK_GET(pc, &link, NULL);
            if (CDK_SUCCESS(rv) && link == 0) {
                *speed = 0;
            }
        }
        return rv;
    }

    return ge_phy_speed_get(pc, speed);
}

/*
 * Function:    
 *      bcm54640_phy_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640_phy_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    uint32_t mode_ctrl, ctrl;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_SEL(0x1f));
    ioerr += PHY_BUS_READ(pc, 0x1c, &mode_ctrl);

    /* Select fiber registers */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1f, mode_ctrl | 0x01));
 
    /* Enable autoneg on fiber interface */
    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
    ctrl &= ~(MII_CTRL_AE | MII_CTRL_PD);
    if (autoneg) {
        ctrl |= MII_CTRL_AE;
    } else {
        ctrl |= MII_CTRL_PD;
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_FIBER_MODE;
    }
    ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl);

    /* Select copper registers */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1f, mode_ctrl));

    if (CDK_SUCCESS(rv)) {
        rv = ge_phy_autoneg_set(pc, autoneg);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm54640_phy_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640_phy_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    return ge_phy_autoneg_get(pc, autoneg);
}

/*
 * Function:    
 *      bcm54640_phy_loopback_set
 * Purpose:     
 *      Set the internal PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640_phy_loopback_set(phy_ctrl_t *pc, int enable)
{
    return ge_phy_loopback_set(pc, enable);
}

/*
 * Function:    
 *      bcm54640_phy_loopback_get
 * Purpose:     
 *      Get the local PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640_phy_loopback_get(phy_ctrl_t *pc, int *enable)
{
    return ge_phy_loopback_get(pc, enable);
}

/*
 * Function:    
 *      bcm54640_phy_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640_phy_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    *abil = (PHY_ABIL_1000MB | PHY_ABIL_100MB | PHY_ABIL_10MB | 
             PHY_ABIL_LOOPBACK | PHY_ABIL_GMII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcm54640_phy_config_set
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
bcm54640_phy_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    int ioerr = 0;
    uint32_t sgmii_lb, ana, gb_ctrl, ctrl;

    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        switch (val) {
        case PHY_IF_GMII:
        case PHY_IF_SGMII:
            return CDK_E_NONE;
        default:
            break;
        }
        break;
    case PhyConfig_RemoteLoopback:
        /* Read SGMII loopback setting from expansion register 0x44 */
        ioerr += PHY_BUS_WRITE(pc, 0x17, 0x0f44);
        ioerr += PHY_BUS_READ(pc, 0x15, &sgmii_lb);
        /* Leave autoneg untouched if disable and already disabled */
        if (!val && !sgmii_lb) {
            return ioerr ? CDK_E_IO : CDK_E_NONE;
        }
        /* Save current configuration */
        ioerr += PHY_BUS_READ(pc, MII_ANA_REG, &ana);
        ioerr += PHY_BUS_READ(pc, MII_GB_CTRL_REG, &gb_ctrl);
        ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
        /* Force link down by doing autoneg with no abilities */
        ioerr += PHY_BUS_WRITE(pc, MII_ANA_REG, 0x0001);
        ioerr += PHY_BUS_WRITE(pc, MII_GB_CTRL_REG, 0x0000);
        ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, MII_CTRL_AE | MII_CTRL_RAN);
        /* Set SGMII loopback with Rx suppress in expansion register 0x44 */
        ioerr += PHY_BUS_WRITE(pc, 0x15, val ? 0x000b : 0x0000);
        /* Restore configuration and restart autoneg */
        ioerr += PHY_BUS_WRITE(pc, MII_ANA_REG, ana);
        ioerr += PHY_BUS_WRITE(pc, MII_GB_CTRL_REG, gb_ctrl);
        ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl | MII_CTRL_RAN);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcm54640_phy_config_get
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
bcm54640_phy_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    int ioerr = 0;
    uint32_t sgmii_lb;

    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = 1;
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        *val = PHY_IF_GMII;
        return CDK_E_NONE;
    case PhyConfig_RemoteLoopback:
        /* Read SGMII loopback setting from expansion register 0x44 */
        ioerr += PHY_BUS_WRITE(pc, 0x17, 0x0f44);
        ioerr += PHY_BUS_READ(pc, 0x15, &sgmii_lb);
        *val = (sgmii_lb) ? 1 : 0;
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Variable:    bcm54640_phy drv
 * Purpose:     PHY Driver for BCM54640.
 */
phy_driver_t bcm54640_drv = {
    "bcm54640",
    "BCM54640 Gigabit PHY Driver",  
    0,
    bcm54640_phy_probe,                 /* pd_probe */
    bcm54640_phy_notify,                /* pd_notify */
    bcm54640_phy_reset,                 /* pd_reset */
    bcm54640_phy_init,                  /* pd_init */
    bcm54640_phy_link_get,              /* pd_link_get */
    bcm54640_phy_duplex_set,            /* pd_duplex_set */
    bcm54640_phy_duplex_get,            /* pd_duplex_get */
    bcm54640_phy_speed_set,             /* pd_speed_set */
    bcm54640_phy_speed_get,             /* pd_speed_get */
    bcm54640_phy_autoneg_set,           /* pd_autoneg_set */
    bcm54640_phy_autoneg_get,           /* pd_autoneg_get */
    bcm54640_phy_loopback_set,          /* pd_loopback_set */
    bcm54640_phy_loopback_get,          /* pd_loopback_get */
    bcm54640_phy_ability_get,           /* pd_ability_get */
    bcm54640_phy_config_set,            /* pd_config_set */
    bcm54640_phy_config_get,            /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
