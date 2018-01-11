/*
 * $Id: bcm8705_drv.c,v 1.9 Broadcom SDK $
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
 * PHY driver for BCM8705.
 *
 */

#include <phy/phy.h>
#include <phy/ge_phy.h>

#define BCM8705_PMA_PMD_ID0             0x0020
#define BCM8705_PMA_PMD_ID1             0x6034

#define C45_DEVAD(_a)                   LSHIFT32((_a),16)
#define DEVAD_PMA_PMD                   C45_DEVAD(MII_C45_DEV_PMA_PMD)
#define DEVAD_WIS                       C45_DEVAD(MII_C45_DEV_WIS)
#define DEVAD_PCS                       C45_DEVAD(MII_C45_DEV_PCS)
#define DEVAD_PHY_XS                    C45_DEVAD(MII_C45_DEV_PHY_XS)

/* PMA/PMD registers */
#define PMA_PMD_CTRL_REG                (DEVAD_PMA_PMD + MII_CTRL_REG)
#define PMA_PMD_STAT_REG                (DEVAD_PMA_PMD + MII_STAT_REG)
#define PMA_PMD_ID0_REG                 (DEVAD_PMA_PMD + MII_PHY_ID0_REG)
#define PMA_PMD_ID1_REG                 (DEVAD_PMA_PMD + MII_PHY_ID1_REG)
#define PMA_PMD_SPEED_ABIL              (DEVAD_PMA_PMD + 0x0005)
#define PMA_PMD_DEV_IN_PKG              (DEVAD_PMA_PMD + 0x0006)

/* WIS registers */
#define WIS_CTRL_REG                    (DEVAD_WIS + MII_CTRL_REG)
#define WIS_STAT_REG                    (DEVAD_WIS + MII_STAT_REG)
#define WIS_ID0_REG                     (DEVAD_WIS + MII_PHY_ID0_REG)
#define WIS_ID1_REG                     (DEVAD_WIS + MII_PHY_ID1_REG)
#define WIS_SPEED_ABIL                  (DEVAD_WIS + 0x0005)
#define WIS_DEV_IN_PKG                  (DEVAD_WIS + 0x0006)

/* PCS registers */
#define PCS_CTRL_REG                    (DEVAD_PCS + MII_CTRL_REG)
#define PCS_STAT_REG                    (DEVAD_PCS + MII_STAT_REG)
#define PCS_ID0_REG                     (DEVAD_PCS + MII_PHY_ID0_REG)
#define PCS_ID1_REG                     (DEVAD_PCS + MII_PHY_ID1_REG)
#define PCS_SPEED_ABIL                  (DEVAD_PCS + 0x0005)
#define PCS_DEV_IN_PKG                  (DEVAD_PCS + 0x0006)

/* PHY XS registers */
#define PHY_XS_CTRL_REG                 (DEVAD_PHY_XS + MII_CTRL_REG)
#define PHY_XS_STAT_REG                 (DEVAD_PHY_XS + MII_STAT_REG)
#define PHY_XS_ID0_REG                  (DEVAD_PHY_XS + MII_PHY_ID0_REG)
#define PHY_XS_ID1_REG                  (DEVAD_PHY_XS + MII_PHY_ID1_REG)
#define PHY_XS_SPEED_ABIL               (DEVAD_PHY_XS + 0x0005)
#define PHY_XS_DEV_IN_PKG               (DEVAD_PHY_XS + 0x0006)

/* User-defined registers */
#define BCM8705_OVERRIDE_CTRL           (DEVAD_PMA_PMD + 0xca09)
#define BCM8705_MISC_CTRL               (DEVAD_PMA_PMD + 0xca0a)

/* PMA/PMD control register */
#define PMA_PMD_CTRL_RESET              (1L << 15)
#define PMA_PMD_CTRL_LO_PWR             (1L << 6)
#define PMA_PMD_CTRL_LE                 (1L << 0)

/* WIS control register */
#define WIS_CTRL_RESET                  (1L << 15)
#define WIS_CTRL_LO_PWR                 (1L << 6)
#define WIS_CTRL_LE                     (1L << 0)

/* Devices in package register 1 */
#define DEV_IN_PKG_DTE_XS               (1L << 5)
#define DEV_IN_PKG_PHY_XS               (1L << 4)
#define DEV_IN_PKG_PCS                  (1L << 3)
#define DEV_IN_PKG_WIS                  (1L << 2)
#define DEV_IN_PKG_PMA_PMD              (1L << 1)
#define DEV_IN_PKG_C22                  (1L << 0)

/* Override control register */
#define OVERRIDE_CTRL_FORCE_PLL_LOCK    (1L << 8)

/* Misc. control register */
#define MISC_CTRL_LOL_OPT_LOS_EN        (1L << 9)
#define MISC_CTRL_P_IN_MUXSEL           (1L << 7)
#define MISC_CTRL_X_IN_MUXSEL           (1L << 6)
#define MISC_CTRL_CLUPLL_EN             (1L << 5)
#define MISC_CTRL_XCLKMODE_OVRD         (1L << 4)
#define MISC_CTRL_XFP_CLK_EN            (1L << 3)
#define MISC_CTRL_REFOUTFREQ            (7L << 0)

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcm8705_phy_probe
 * Purpose:     
 *      Probe for 8705 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8705_phy_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, PMA_PMD_ID0_REG, &phyid0);
    ioerr += PHY_BUS_READ(pc, PMA_PMD_ID1_REG, &phyid1);

    if (phyid0 == BCM8705_PMA_PMD_ID0 && 
        phyid1 == BCM8705_PMA_PMD_ID1) {
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcm8705_phy_notify
 * Purpose:     
 *      Handle PHY notifications
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8705_phy_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_NOTIFY(PHY_CTRL_NEXT(pc), event);
    }

    return rv;
}

/*
 * Function:
 *      bcm8705_phy_reset
 * Purpose:     
 *      Reset 8705 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8705_phy_reset(phy_ctrl_t *pc)
{
    uint32_t dev_in_pkg;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, PMA_PMD_DEV_IN_PKG, &dev_in_pkg);

    /* Reset all internal devices (if present) */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, MII_CTRL_RESET);
    if (dev_in_pkg & DEV_IN_PKG_WIS) {
        ioerr += PHY_BUS_WRITE(pc, WIS_CTRL_REG, MII_CTRL_RESET);
    }
    ioerr += PHY_BUS_WRITE(pc, PCS_CTRL_REG, MII_CTRL_RESET);
    ioerr += PHY_BUS_WRITE(pc, PHY_XS_CTRL_REG, MII_CTRL_RESET);

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_RESET(PHY_CTRL_NEXT(pc));
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcm8705_phy_init
 * Purpose:     
 *      Initialize 8705 PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8705_phy_init(phy_ctrl_t *pc)
{
    uint32_t misc_ctrl, override_ctrl;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* Reset PHY */
    if (CDK_SUCCESS(rv)) {
        rv =  PHY_RESET(pc);
    }

    PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;
    PHY_CTRL_FLAGS(pc) &= ~PHY_F_WAN_MODE;

    /* Set default operating mode */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_CONFIG_SET(pc, PhyConfig_Mode, PHY_MODE_LAN, NULL);
    }

    /* Enable XFP clock output */
    ioerr += PHY_BUS_READ(pc, BCM8705_MISC_CTRL, &misc_ctrl);
    misc_ctrl |= MISC_CTRL_XFP_CLK_EN;
    ioerr += PHY_BUS_WRITE(pc, BCM8705_MISC_CTRL, misc_ctrl);

    /* Override PMD PLL lock detect to avoid false lock loss (rev A)  */
    ioerr += PHY_BUS_READ(pc, BCM8705_OVERRIDE_CTRL, &override_ctrl);
    override_ctrl |= OVERRIDE_CTRL_FORCE_PLL_LOCK;
    ioerr += PHY_BUS_WRITE(pc, BCM8705_OVERRIDE_CTRL, override_ctrl);

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_INIT(PHY_CTRL_NEXT(pc));
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm8705_phy_link_get
 * Purpose:     
 *      Determine the current link up/down status
 * Parameters:
 *      pc - PHY control structure
 *      link - (OUT) non-zero indicates link established.
 *      autoneg_done - (OUT) not supported
 * Returns:
 *      CDK_E_xxx
 */
static int
bcm8705_phy_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    uint32_t pma_pmd_stat, pcs_stat, phy_xs_stat, wis_stat;
    uint32_t link_stat;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    if (link) {
        /* Link must be up in all devices */
        ioerr += PHY_BUS_READ(pc, PMA_PMD_STAT_REG, &pma_pmd_stat);
        ioerr += PHY_BUS_READ(pc, PCS_STAT_REG, &pcs_stat);
        ioerr += PHY_BUS_READ(pc, PHY_XS_STAT_REG, &phy_xs_stat);
        link_stat = (pma_pmd_stat & pcs_stat & phy_xs_stat);
        if (PHY_CTRL_FLAGS(pc) & PHY_F_WAN_MODE) {
            ioerr += PHY_BUS_READ(pc, WIS_STAT_REG, &wis_stat);
            link_stat &= wis_stat;
        }
        *link = ((link_stat & MII_STAT_LA) != 0);
    }

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcm8705_phy_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8705_phy_duplex_set(phy_ctrl_t *pc, int duplex)
{
    return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
}

/*
 * Function:    
 *      bcm8705_phy_duplex_get
 * Purpose:     
 *      Get the current operating duplex mode.
 * Parameters:
 *      pc - PHY control structure
 *      duplex - (OUT) non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8705_phy_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcm8705_phy_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8705_phy_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    return (speed == 10000) ? CDK_E_NONE : CDK_E_PARAM;
}

/*
 * Function:    
 *      bcm8705_phy_speed_get
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
bcm8705_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    *speed = 10000;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcm8705_phy_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8705_phy_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcm8705_phy_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8705_phy_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    *autoneg = 0;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcm8705_phy_loopback_set
 * Purpose:     
 *      Set the internal PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8705_phy_loopback_set(phy_ctrl_t *pc, int enable)
{
    uint32_t pma_pmd_ctrl, wis_ctrl;
    int ioerr = 0;

    /* Read loopback control registers */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);
    ioerr += PHY_BUS_READ(pc, WIS_CTRL_REG, &wis_ctrl);

    if (PHY_CTRL_FLAGS(pc) & PHY_F_WAN_MODE) {
        /* Always clear PMA loopback in WAN mode */
        pma_pmd_ctrl &= ~PMA_PMD_CTRL_LE;
        wis_ctrl &= ~WIS_CTRL_LE;
        if (enable) {
            wis_ctrl |= PMA_PMD_CTRL_LE;
        }
    } else {
        /* Always clear WIS loopback in LAN mode */
        wis_ctrl &= ~WIS_CTRL_LE;
        pma_pmd_ctrl &= ~PMA_PMD_CTRL_LE;
        if (enable) {
            pma_pmd_ctrl |= PMA_PMD_CTRL_LE;
        }
    }

    /* Write updated loopback control registers */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, pma_pmd_ctrl);
    ioerr += PHY_BUS_WRITE(pc, WIS_CTRL_REG, wis_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm8705_phy_loopback_get
 * Purpose:     
 *      Get the local PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8705_phy_loopback_get(phy_ctrl_t *pc, int *enable)
{
    uint32_t pma_pmd_ctrl, wis_ctrl;
    int ioerr = 0;

    /* Read loopback control registers */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);
    ioerr += PHY_BUS_READ(pc, WIS_CTRL_REG, &wis_ctrl);

    *enable = 0;
    if ((pma_pmd_ctrl & PMA_PMD_CTRL_LE) || (wis_ctrl & WIS_CTRL_LE)) {
        *enable = 1;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm8705_phy_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8705_phy_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    *abil = (PHY_ABIL_10GB | 
             PHY_ABIL_LOOPBACK | PHY_ABIL_XGMII);

    return CDK_E_NONE;
}

/*
 * Function:
 *      bcm8705_phy_config_set
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
bcm8705_phy_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    uint32_t dev_in_pkg;
    uint32_t misc_ctrl;
    int ioerr = 0;

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
    case PhyConfig_Mode:
        if (val == 1) {
            /* Enter WAN mode */
            if (PHY_CTRL_FLAGS(pc) & PHY_F_WAN_MODE) {
                return CDK_E_NONE;
            }
            /* Check WAN capability */
            ioerr += PHY_BUS_READ(pc, PMA_PMD_DEV_IN_PKG, &dev_in_pkg);
            if ((dev_in_pkg & DEV_IN_PKG_WIS) == 0) {
                return CDK_E_UNAVAIL;
            }
            /* 
             * Configure WAN mode clock.
             * Note that in addidtion to the register change, the
             * MODE_SEL pin must be pulled high (3.3V) as well.
             */
            ioerr += PHY_BUS_READ(pc, BCM8705_MISC_CTRL, &misc_ctrl);
            misc_ctrl &= ~(MISC_CTRL_P_IN_MUXSEL | MISC_CTRL_X_IN_MUXSEL);
            misc_ctrl |= MISC_CTRL_XCLKMODE_OVRD;
            ioerr += PHY_BUS_WRITE(pc, BCM8705_MISC_CTRL, misc_ctrl);
            PHY_CTRL_FLAGS(pc) |= PHY_F_WAN_MODE;
        } else {
            /* Enter LAN mode */
            if ((PHY_CTRL_FLAGS(pc) & PHY_F_WAN_MODE) == 0) {
                return CDK_E_NONE;
            }
            /* 
             * Configure LAN mode clock.
             * Note that in addidtion to the register change, the
             * MODE_SEL pin must be pulled high (3.3V) as well.
             */
            ioerr += PHY_BUS_READ(pc, BCM8705_MISC_CTRL, &misc_ctrl);
            misc_ctrl &= ~(MISC_CTRL_XCLKMODE_OVRD | MISC_CTRL_X_IN_MUXSEL);
            misc_ctrl |= MISC_CTRL_P_IN_MUXSEL;
            ioerr += PHY_BUS_WRITE(pc, BCM8705_MISC_CTRL, misc_ctrl);
            PHY_CTRL_FLAGS(pc) |= PHY_F_WAN_MODE;
        }
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcm8705_phy_config_get
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
bcm8705_phy_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = 1;
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        *val = PHY_IF_XAUI;
        return CDK_E_NONE;
    case PhyConfig_Mode:
        *val = PHY_MODE_LAN;
        if (PHY_CTRL_FLAGS(pc) & PHY_F_WAN_MODE) {
            *val = PHY_MODE_WAN;
        }
        return CDK_E_NONE;
    case PhyConfig_Clause45Devs:
        *val = 0x1e;
        return CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Variable:    bcm8705_phy drv
 * Purpose:     PHY Driver for BCM8705.
 */
phy_driver_t bcm8705_drv = {
    "bcm8705",
    "BCM8705 10-Gigabit PHY Driver",  
    0,
    bcm8705_phy_probe,                  /* pd_probe */
    bcm8705_phy_notify,                 /* pd_notify */
    bcm8705_phy_reset,                  /* pd_reset */
    bcm8705_phy_init,                   /* pd_init */
    bcm8705_phy_link_get,               /* pd_link_get */
    bcm8705_phy_duplex_set,             /* pd_duplex_set */
    bcm8705_phy_duplex_get,             /* pd_duplex_get */
    bcm8705_phy_speed_set,              /* pd_speed_set */
    bcm8705_phy_speed_get,              /* pd_speed_get */
    bcm8705_phy_autoneg_set,            /* pd_autoneg_set */
    bcm8705_phy_autoneg_get,            /* pd_autoneg_get */
    bcm8705_phy_loopback_set,           /* pd_loopback_set */
    bcm8705_phy_loopback_get,           /* pd_loopback_get */
    bcm8705_phy_ability_get,            /* pd_ability_get */
    bcm8705_phy_config_set,             /* pd_config_set */
    bcm8705_phy_config_get,             /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
