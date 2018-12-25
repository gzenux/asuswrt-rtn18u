/*
 * $Id: unknown_drv.c,v 1.7 Broadcom SDK $
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
 * PHY driver for unknown PHY.
 * Serves mainly as an indicator of a missing real PHY driver.
 *
 * The driver should be transparent to an upstream serdes in order
 * to allow loopback tests to run as if this driver was not present.
 *
 */

#include <phy/phy.h>
#include <phy/phy_drvlist.h>

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      unknown_phy_probe
 * Purpose:     
 *      Probe for unknown PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
unknown_phy_probe(phy_ctrl_t *pc)
{
    uint32_t id0reg;
    uint32_t id1reg;
    uint32_t phyid0;
    uint32_t phyid1;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    /* Try standard ID reg */
    id0reg = MII_PHY_ID0_REG;
    ioerr += PHY_BUS_READ(pc, id0reg, &phyid0);
    id1reg = MII_PHY_ID1_REG;
    ioerr += PHY_BUS_READ(pc, id1reg, &phyid1);

    if (phyid0 != 0 && phyid0 != 0xffff &&
        (phyid0 & 0x3fff) != (phyid1 & 0x3fff)) {
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }

    /* Try clause 45 DEVAD ID reg */
    id0reg |= LSHIFT32(MII_C45_DEV_PMA_PMD, 16);
    ioerr += PHY_BUS_READ(pc, id0reg, &phyid0);
    id1reg |= LSHIFT32(MII_C45_DEV_PMA_PMD, 16);
    ioerr += PHY_BUS_READ(pc, id1reg, &phyid1);

    if (phyid0 != 0 && phyid0 != 0xffff && phyid0 != phyid1) {
        PHY_CTRL_FLAGS(pc) |= PHY_F_CLAUSE45;
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }

    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      unknown_phy_notify
 * Purpose:     
 *      Handle PHY notifications
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
unknown_phy_notify(phy_ctrl_t *pc, phy_event_t event)
{
    return PHY_NOTIFY(PHY_CTRL_NEXT(pc), event);
}

/*
 * Function:
 *      unknown_phy_reset
 * Purpose:     
 *      Reset PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
unknown_phy_reset(phy_ctrl_t *pc)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_NEXT(pc)) {
        return PHY_RESET(PHY_CTRL_NEXT(pc));
    }
    return CDK_E_NONE;
}

/*
 * Function:
 *      unknown_phy_init
 * Purpose:     
 *      Initialize PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
unknown_phy_init(phy_ctrl_t *pc)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_NEXT(pc)) {
        return PHY_INIT(PHY_CTRL_NEXT(pc));
    }
    return CDK_E_NONE;
}

/*
 * Function:    
 *      unknown_phy_link_get
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
unknown_phy_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_NEXT(pc)) {
        return PHY_LINK_GET(PHY_CTRL_NEXT(pc), link, autoneg_done);
    }
    if (link) {
        *link = 0;
    }
    if (autoneg_done) {
        *autoneg_done = 0;
    }
    return CDK_E_NONE;
}

/*
 * Function:    
 *      unknown_phy_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
unknown_phy_duplex_set(phy_ctrl_t *pc, int duplex)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_NEXT(pc)) {
        return PHY_DUPLEX_SET(PHY_CTRL_NEXT(pc), duplex);
    }
    return CDK_E_NONE;
}

/*
 * Function:    
 *      unknown_phy_duplex_get
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
unknown_phy_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_NEXT(pc)) {
        return PHY_DUPLEX_GET(PHY_CTRL_NEXT(pc), duplex);
    }

    *duplex = 0;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      unknown_phy_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
unknown_phy_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_NEXT(pc)) {
        return PHY_SPEED_SET(PHY_CTRL_NEXT(pc), speed);
    }
    return CDK_E_NONE;
}

/*
 * Function:    
 *      unknown_phy_speed_get
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
unknown_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_NEXT(pc)) {
        return PHY_SPEED_GET(PHY_CTRL_NEXT(pc), speed);
    }

    *speed = 0;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      unknown_phy_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
unknown_phy_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_NEXT(pc)) {
        return PHY_AUTONEG_SET(PHY_CTRL_NEXT(pc), autoneg);
    }
    return CDK_E_NONE;
}

/*
 * Function:    
 *      unknown_phy_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
unknown_phy_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_NEXT(pc)) {
        return PHY_AUTONEG_GET(PHY_CTRL_NEXT(pc), autoneg);
    }

    *autoneg = 0;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      unknown_phy_loopback_set
 * Purpose:     
 *      Set the internal PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
unknown_phy_loopback_set(phy_ctrl_t *pc, int enable)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_NEXT(pc)) {
        return PHY_LOOPBACK_SET(PHY_CTRL_NEXT(pc), enable);
    }
    return (enable) ? CDK_E_UNAVAIL : CDK_E_NONE;
}

/*
 * Function:    
 *      unknown_phy_loopback_get
 * Purpose:     
 *      Get the local PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
unknown_phy_loopback_get(phy_ctrl_t *pc, int *enable)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_NEXT(pc)) {
        return PHY_LOOPBACK_GET(PHY_CTRL_NEXT(pc), enable);
    }

    *enable = 0;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      unknown_phy_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
unknown_phy_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_NEXT(pc)) {
        return PHY_ABILITY_GET(PHY_CTRL_NEXT(pc), abil);
    }

    *abil = 0;

    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_hyperlite_xgxs_config_get
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
unknown_phy_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Clause45Devs:
        if (PHY_CTRL_FLAGS(pc) & PHY_F_CLAUSE45) {
            *val = 0xbe;
            return CDK_E_NONE;
        }
        return CDK_E_UNAVAIL;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Variable:    unknown_phy drv
 * Purpose:     PHY Driver for unknown PHY.
 */
phy_driver_t unknown_drv = {
    "unknown",
    "Unknown PHY Driver",  
    0,
    unknown_phy_probe,                  /* pd_probe */
    unknown_phy_notify,                 /* pd_notify */
    unknown_phy_reset,                  /* pd_reset */
    unknown_phy_init,                   /* pd_init */
    unknown_phy_link_get,               /* pd_link_get */
    unknown_phy_duplex_set,             /* pd_duplex_set */
    unknown_phy_duplex_get,             /* pd_duplex_get */
    unknown_phy_speed_set,              /* pd_speed_set */
    unknown_phy_speed_get,              /* pd_speed_get */
    unknown_phy_autoneg_set,            /* pd_autoneg_set */
    unknown_phy_autoneg_get,            /* pd_autoneg_get */
    unknown_phy_loopback_set,           /* pd_loopback_set */
    unknown_phy_loopback_get,           /* pd_loopback_get */
    unknown_phy_ability_get,            /* pd_ability_get */
    NULL,                               /* pd_config_set */
    unknown_phy_config_get,             /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
