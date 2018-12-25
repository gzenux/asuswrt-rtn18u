/*
 * $Id: bcm54980_drv.c,v 1.6 Broadcom SDK $
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
 * PHY driver for BCM54980.
 *
 */

#include <phy/phy.h>
#include <phy/phy_drvlist.h>

#define BCM54980_PHY_ID0                0x0143
#define BCM54980_PHY_ID1                0xbe80
#define BCM54980C_PHY_ID1               0xbe90
#define BCM54980V_PHY_ID1               0xbea0
#define BCM54980VC_PHY_ID1              0xbeb0

#define PHY_ID1_REV_MASK                0x000f

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcm54980_phy_probe
 * Purpose:     
 *      Probe for 54980 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54980_phy_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, MII_PHY_ID0_REG, &phyid0);
    ioerr += PHY_BUS_READ(pc, MII_PHY_ID1_REG, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCM54980_PHY_ID0 && 
        (phyid1 == BCM54980_PHY_ID1 || 
         phyid1 == BCM54980C_PHY_ID1 || 
         phyid1 == BCM54980V_PHY_ID1 || 
         phyid1 == BCM54980VC_PHY_ID1)) {
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcm54980_phy_notify
 * Purpose:     
 *      Handle PHY notifications
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54980_phy_notify(phy_ctrl_t *pc, phy_event_t event)
{
    return bcm5488_drv.pd_notify(pc, event);
}

/*
 * Function:
 *      bcm54980_phy_reset
 * Purpose:     
 *      Reset 54980 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54980_phy_reset(phy_ctrl_t *pc)
{
    return bcm5488_drv.pd_reset(pc);
}

/*
 * Function:
 *      bcm54980_phy_init
 * Purpose:     
 *      Initialize 54980 PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54980_phy_init(phy_ctrl_t *pc)
{
    return bcm5488_drv.pd_init(pc);
}

/*
 * Function:    
 *      bcm54980_phy_link_get
 * Purpose:     
 *      Determine the current link up/down status
 * Parameters:
 *      pc - PHY control structure
 *      link - (OUT) non-zero indicates link established.
 *      autoneg_done - (OUT) if true, auto-negotiation is complete
 * Returns:
 *      CDK_E_xxx
 */
static int
bcm54980_phy_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    return bcm5488_drv.pd_link_get(pc, link, autoneg_done);
}

/*
 * Function:    
 *      bcm54980_phy_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54980_phy_duplex_set(phy_ctrl_t *pc, int duplex)
{
    return bcm5488_drv.pd_duplex_set(pc, duplex);
}

/*
 * Function:    
 *      bcm54980_phy_duplex_get
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
bcm54980_phy_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    return bcm5488_drv.pd_duplex_get(pc, duplex);
}

/*
 * Function:    
 *      bcm54980_phy_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54980_phy_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    return bcm5488_drv.pd_speed_set(pc, speed);
}

/*
 * Function:    
 *      bcm54980_phy_speed_get
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
bcm54980_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    return bcm5488_drv.pd_speed_get(pc, speed);
}

/*
 * Function:    
 *      bcm54980_phy_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54980_phy_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    return bcm5488_drv.pd_autoneg_set(pc, autoneg);
}

/*
 * Function:    
 *      bcm54980_phy_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54980_phy_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    return bcm5488_drv.pd_autoneg_get(pc, autoneg);
}

/*
 * Function:    
 *      bcm54980_phy_loopback_set
 * Purpose:     
 *      Set the internal PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54980_phy_loopback_set(phy_ctrl_t *pc, int enable)
{
    return bcm5488_drv.pd_loopback_set(pc, enable);
}

/*
 * Function:    
 *      bcm54980_phy_loopback_get
 * Purpose:     
 *      Get the local PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54980_phy_loopback_get(phy_ctrl_t *pc, int *enable)
{
    return bcm5488_drv.pd_loopback_get(pc, enable);
}

/*
 * Function:    
 *      bcm54980_phy_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54980_phy_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    return bcm5488_drv.pd_ability_get(pc, abil);
}

/*
 * Function:
 *      bcm54980_phy_config_set
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
bcm54980_phy_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    int ioerr = 0;
    uint32_t sgmii_lb, ana, gb_ctrl, ctrl;

    PHY_CTRL_CHECK(pc);

    switch (cfg) {
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

    return bcm5488_drv.pd_config_set(pc, cfg, val, cd);
}

/*
 * Function:
 *      bcm54980_phy_config_get
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
bcm54980_phy_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    int ioerr = 0;
    uint32_t sgmii_lb;

    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_RemoteLoopback:
        /* Read SGMII loopback setting from expansion register 0x44 */
        ioerr += PHY_BUS_WRITE(pc, 0x17, 0x0f44);
        ioerr += PHY_BUS_READ(pc, 0x15, &sgmii_lb);
        *val = (sgmii_lb) ? 1 : 0;
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    default:
        break;
    }

    return bcm5488_drv.pd_config_get(pc, cfg, val, cd);
}

/*
 * Variable:    bcm54980_phy drv
 * Purpose:     PHY driver for BCM54980.
 */
phy_driver_t bcm54980_drv = {
    "bcm54980",
    "BCM54980 Gigabit PHY Driver",  
    0,
    bcm54980_phy_probe,                 /* pd_probe */
    bcm54980_phy_notify,                /* pd_notify */
    bcm54980_phy_reset,                 /* pd_reset */
    bcm54980_phy_init,                  /* pd_init */
    bcm54980_phy_link_get,              /* pd_link_get */
    bcm54980_phy_duplex_set,            /* pd_duplex_set */
    bcm54980_phy_duplex_get,            /* pd_duplex_get */
    bcm54980_phy_speed_set,             /* pd_speed_set */
    bcm54980_phy_speed_get,             /* pd_speed_get */
    bcm54980_phy_autoneg_set,           /* pd_autoneg_set */
    bcm54980_phy_autoneg_get,           /* pd_autoneg_get */
    bcm54980_phy_loopback_set,          /* pd_loopback_set */
    bcm54980_phy_loopback_get,          /* pd_loopback_get */
    bcm54980_phy_ability_get,           /* pd_ability_get */
    bcm54980_phy_config_set,            /* pd_config_set */
    bcm54980_phy_config_get,            /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
