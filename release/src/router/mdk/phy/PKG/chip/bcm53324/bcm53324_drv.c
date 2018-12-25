/*
 * $Id: bcm53324_drv.c,v 1.3 Broadcom SDK $
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
 * PHY driver for BCM53324.
 *
 */

#include <phy/phy.h>
#include <phy/ge_phy.h>

#define BCM53324_PHY_ID0                0x0362
#define BCM53324_PHY_ID1                0x5d20

#define PHY_ID1_REV_MASK                0x000f

/* Default LED control */
#define BCM53324_LED1_SEL(_pc)          0x0
#define BCM53324_LED2_SEL(_pc)          0x1
#define BCM53324_LED3_SEL(_pc)          0x3
#define BCM53324_LED4_SEL(_pc)          0x6
#define BCM53324_LEDCTRL(_pc)           0x8
#define BCM53324_LEDSELECT(_pc)         0x0

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
#define MII_TEST_REG            0x1e /* MII Test Register 1 */

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
extern cdk_symbols_t bcm53324_symbols;
#endif

/*
 * Function:
 *      bcm53324_phy_probe
 * Purpose:     
 *      Probe for PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm53324_phy_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    uint32_t stat;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, MII_PHY_ID0_REG, &phyid0);
    ioerr += PHY_BUS_READ(pc, MII_PHY_ID1_REG, &phyid1);

    if (phyid0 == BCM53324_PHY_ID0 && 
        (phyid1 & ~PHY_ID1_REV_MASK) == BCM53324_PHY_ID1) {

        /*
         * BCM54685 PHY has same PHY ID, so we also need to check the
         * unidirectional transmit capability to tell the difference.
         */
        ioerr += PHY_BUS_READ(pc, MII_STAT_REG, &stat);
        if (stat & MII_STAT_UT_CAP) {
            return CDK_E_NOT_FOUND;
        }

#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
        PHY_CTRL_SYMBOLS(pc) = &bcm53324_symbols;
#endif
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcm53324_phy_notify
 * Purpose:     
 *      Handle PHY notifications
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm53324_phy_notify(phy_ctrl_t *pc, phy_event_t event)
{
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcm53324_phy_reset
 * Purpose:     
 *      Reset PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm53324_phy_reset(phy_ctrl_t *pc)
{
    return ge_phy_reset(pc);
}

/*
 * Function:
 *      bcm53324_phy_init
 * Purpose:     
 *      Initialize PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm53324_phy_init(phy_ctrl_t *pc)
{
    uint32_t ctrl, tmp, sgmii;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* Reset PHY */
    if (CDK_SUCCESS(rv)) {
        rv =  PHY_RESET(pc);
    }

    /* Set port mode */
    ioerr += PHY_BUS_READ(pc, MII_GB_CTRL_REG, &ctrl);
    ctrl |= MII_GB_CTRL_PT;
    ioerr += PHY_BUS_WRITE(pc, MII_GB_CTRL_REG, ctrl);

    /* Select GMII/copper mode */
    sgmii = 0;

    /* Select fiber registers */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1f, sgmii | 0x01));
 
    /* Power down fiber interface */
    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
    ctrl |= MII_CTRL_PD;
    ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl);

    /* Select copper registers */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1f, sgmii));

    /* Power up copper interface */
    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
    ctrl &= ~MII_CTRL_PD;
    ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl);

    /* Disable auto-medium detect */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_SEL(0x1e));
    ioerr += PHY_BUS_READ(pc, 0x1c, &tmp);
    tmp &= ~0x001f;
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1e, tmp));

    /* Disable carrier extension (to prevent Intel 7131 NIC CRC errors) */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_SEL(0x1b));
    ioerr += PHY_BUS_READ(pc, 0x1c, &tmp);
    tmp |= 0x0040;
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1b, tmp));

    /* Configure Extended Control Register */
    ioerr += PHY_BUS_READ(pc, MII_ECR_REG, &tmp);
    /* Enable LEDs to indicate traffic status */
    tmp |= 0x0020;
    /* Set high FIFO elasticity to support jumbo frames */
    tmp |= 0x0001;
    ioerr += PHY_BUS_WRITE(pc, MII_ECR_REG, tmp);

    /* Enable extended packet length (4.5k through 25k) */
    ioerr += PHY_BUS_WRITE(pc, 0x18, 0x0007);
    ioerr += PHY_BUS_READ(pc, 0x18, &tmp);
    tmp |= 0x4000;
    ioerr += PHY_BUS_WRITE(pc, 0x18, tmp);

    /* Configure LED selectors */
    ioerr += PHY_BUS_WRITE(pc, 0x1c,
                           REG_1C_WR(0x0d, BCM53324_LED1_SEL(pc) |
                                     (BCM53324_LED2_SEL(pc) << 4)));
    ioerr += PHY_BUS_WRITE(pc, 0x1c,
                           REG_1C_WR(0x0e, BCM53324_LED3_SEL(pc) |
                                     (BCM53324_LED4_SEL(pc) << 4)));
    ioerr += PHY_BUS_WRITE(pc, 0x1c,
                           REG_1C_WR(0x09, BCM53324_LEDCTRL(pc)));
    ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_MAP_REG(0x4));
    ioerr += PHY_BUS_WRITE(pc, MII_EXP_REG, BCM53324_LEDSELECT(pc));
    ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_UNMAP);
    /* If using LED link/activity mode, disable LED traffic mode */
    if ((BCM53324_LEDCTRL(pc) & 0x10) || BCM53324_LEDSELECT(pc) == 0x01) {
        ioerr += PHY_BUS_READ(pc, MII_ECR_REG, &tmp);
        tmp &= ~0x0020;
        ioerr += PHY_BUS_WRITE(pc, MII_ECR_REG, tmp);
    }

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_INIT(PHY_CTRL_NEXT(pc));
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm53324_phy_link_get
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
bcm53324_phy_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    return ge_phy_link_get(pc, link, autoneg_done);
}

/*
 * Function:    
 *      bcm53324_phy_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm53324_phy_duplex_set(phy_ctrl_t *pc, int duplex)
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
 *      bcm53324_phy_duplex_get
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
bcm53324_phy_duplex_get(phy_ctrl_t *pc, int *duplex)
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
 *      bcm53324_phy_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm53324_phy_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_SPEED_SET(PHY_CTRL_NEXT(pc), speed);
    }

    if (CDK_SUCCESS(rv)) {
        if ((PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) == 0) {
            rv = ge_phy_speed_set(pc, speed);
        }
    }

    return rv;
}

/*
 * Function:    
 *      bcm53324_phy_speed_get
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
bcm53324_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) {
        *speed = 1000;
        return CDK_E_NONE;
    }

    return ge_phy_speed_get(pc, speed);
}

/*
 * Function:    
 *      bcm53324_phy_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm53324_phy_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    return ge_phy_autoneg_set(pc, autoneg);
}

/*
 * Function:    
 *      bcm53324_phy_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 * Notes:
 *      autoneg_done is undefined if autoneg is zero.
 */
static int
bcm53324_phy_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    return ge_phy_autoneg_get(pc, autoneg);
}

/*
 * Function:    
 *      bcm53324_phy_loopback_set
 * Purpose:     
 *      Set the internal PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm53324_phy_loopback_set(phy_ctrl_t *pc, int enable)
{
    uint32_t test;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* The following is required for 10/100 loopback to work */
    ioerr += PHY_BUS_READ(pc, MII_TEST_REG, &test);
    if (enable) {
        test |= 0x1000;
    } else {
        test &= ~0x1000;
    }
    ioerr += PHY_BUS_WRITE(pc, MII_TEST_REG, test);

    rv = ge_phy_loopback_set(pc, enable);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm53324_phy_loopback_get
 * Purpose:     
 *      Get the local PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm53324_phy_loopback_get(phy_ctrl_t *pc, int *enable)
{
    return ge_phy_loopback_get(pc, enable);
}

/*
 * Function:    
 *      bcm53324_phy_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm53324_phy_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    *abil = (PHY_ABIL_1000MB | PHY_ABIL_100MB | PHY_ABIL_10MB | 
             PHY_ABIL_LOOPBACK | PHY_ABIL_GMII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcm53324_phy_config_set
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
bcm53324_phy_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    int ioerr = 0;
    uint32_t next_abil;

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
        if (val) {
            /* Select copper mode and copper registers */
            ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1f, 0x00));
            /* Enable remote loopback in register 0x18 shadow 100b */
            ioerr += PHY_BUS_WRITE(pc, 0x18, REG_18_WR(0x4, 0x8800));
        } else {
            /* Get upstream PHY abilities */
            next_abil = 0;
            PHY_ABILITY_GET(PHY_CTRL_NEXT(pc), &next_abil);
            /* Select SGMII mode if SerDes */
            if (next_abil & PHY_ABIL_SERDES) {
                ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1f, 0x04));
            }
            /* Disable remote loopback in register 0x18 shadow 100b */
            ioerr += PHY_BUS_WRITE(pc, 0x18, REG_18_WR(0x4, 0));
        }
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcm53324_phy_config_get
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
bcm53324_phy_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    int ioerr = 0;
    uint32_t misc_test;

    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = 1;
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        *val = PHY_IF_GMII;
        return CDK_E_NONE;
    case PhyConfig_RemoteLoopback:
        /* Read remote loopback from register 0x18 shadow 100b */
        ioerr += PHY_BUS_WRITE(pc, 0x18, REG_18_SEL(0x4));
        ioerr += PHY_BUS_READ(pc, 0x18, &misc_test);
        *val = (misc_test & 0x8000) ? 1 : 0;
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Variable:    bcm53324_phy drv
 * Purpose:     PHY Driver for BCM53324.
 */
phy_driver_t bcm53324_drv = {
    "bcm53324",
    "BCM53324 Gigabit PHY Driver",  
    PHY_DRIVER_F_INTERNAL, 
    bcm53324_phy_probe,                 /* pd_probe */
    bcm53324_phy_notify,                /* pd_notify */
    bcm53324_phy_reset,                 /* pd_reset */
    bcm53324_phy_init,                  /* pd_init */
    bcm53324_phy_link_get,              /* pd_link_get */
    bcm53324_phy_duplex_set,            /* pd_duplex_set */
    bcm53324_phy_duplex_get,            /* pd_duplex_get */
    bcm53324_phy_speed_set,             /* pd_speed_set */
    bcm53324_phy_speed_get,             /* pd_speed_get */
    bcm53324_phy_autoneg_set,           /* pd_autoneg_set */
    bcm53324_phy_autoneg_get,           /* pd_autoneg_get */
    bcm53324_phy_loopback_set,          /* pd_loopback_set */
    bcm53324_phy_loopback_get,          /* pd_loopback_get */
    bcm53324_phy_ability_get,           /* pd_ability_get */
    bcm53324_phy_config_set,            /* pd_config_set */
    bcm53324_phy_config_get,            /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
