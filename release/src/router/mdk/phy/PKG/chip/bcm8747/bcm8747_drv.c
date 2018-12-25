/*
 * $Id: bcm8747_drv.c,v 1.5 Broadcom SDK $
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
 * PHY driver for BCM8747.
 *
 */

#include <phy/phy.h>
#include <phy/phy_drvlist.h>

#define PHY_RESET_POLL_MAX              10
#define PHY_ROM_LOAD_POLL_MAX           500
#define PHY_LANES_POLL_MAX              500

#define BCM8747_PMA_PMD_ID0             0x0020
#define BCM8747_PMA_PMD_ID1             0x6037
#define BCM8747_CHIP_ID                 0x8747

#define C45_DEVAD(_a)                   LSHIFT32((_a),16)
#define DEVAD_PMA_PMD                   C45_DEVAD(MII_C45_DEV_PMA_PMD)
#define DEVAD_PCS                       C45_DEVAD(MII_C45_DEV_PCS)
#define DEVAD_PHY_XS                    C45_DEVAD(MII_C45_DEV_PHY_XS)
#define DEVAD_AN                        C45_DEVAD(MII_C45_DEV_AN)

/* PMA/PMD registers */
#define PMA_PMD_CTRL_REG                (DEVAD_PMA_PMD + MII_CTRL_REG)
#define PMA_PMD_STAT_REG                (DEVAD_PMA_PMD + MII_STAT_REG)
#define PMA_PMD_ID0_REG                 (DEVAD_PMA_PMD + MII_PHY_ID0_REG)
#define PMA_PMD_ID1_REG                 (DEVAD_PMA_PMD + MII_PHY_ID1_REG)
#define PMA_PMD_SPEED_ABIL              (DEVAD_PMA_PMD + 0x0005)
#define PMA_PMD_DEV_IN_PKG              (DEVAD_PMA_PMD + 0x0006)
#define PMA_PMD_CTRL2_REG               (DEVAD_PMA_PMD + 0x0007)
#define PMA_PMD_CHIP_ID_REG             (DEVAD_PMA_PMD + 0xc802)
#define PMA_PMD_GPIO_CTRL0              (DEVAD_PMA_PMD + 0xc840)
#define PMA_PMD_GPIO_CTRL1              (DEVAD_PMA_PMD + 0xc841)
#define PMA_PMD_GPIO_CTRL2              (DEVAD_PMA_PMD + 0xc842)
#define PMA_PMD_GPIO_CTRL3              (DEVAD_PMA_PMD + 0xc843)
#define PMA_PMD_SPI_PORT_CTRL           (DEVAD_PMA_PMD + 0xc848)
#define PMA_PMD_GEN_CTRL                (DEVAD_PMA_PMD + 0xca10)
#define PMA_PMD_GP_REG1                 (DEVAD_PMA_PMD + 0xca19)
#define PMA_PMD_GP_REG2                 (DEVAD_PMA_PMD + 0xca1a)
#define PMA_PMD_GP_REG3                 (DEVAD_PMA_PMD + 0xca1b)
#define PMA_PMD_GP_REG4                 (DEVAD_PMA_PMD + 0xca1c)
#define PMA_PMD_MISC_CTRL2              (DEVAD_PMA_PMD + 0xca85)

/* PCS registers */
#define PCS_CTRL_REG                    (DEVAD_PCS + MII_CTRL_REG)
#define PCS_STAT_REG                    (DEVAD_PCS + MII_STAT_REG)
#define PCS_ID0_REG                     (DEVAD_PCS + MII_PHY_ID0_REG)
#define PCS_ID1_REG                     (DEVAD_PCS + MII_PHY_ID1_REG)
#define PCS_SPEED_ABIL                  (DEVAD_PCS + 0x0005)
#define PCS_DEV_IN_PKG                  (DEVAD_PCS + 0x0006)
#define PCS_POLARITY                    (DEVAD_PCS + 0xc808)

/* PHY XS registers */
#define PHY_XS_CTRL_REG                 (DEVAD_PHY_XS + MII_CTRL_REG)
#define PHY_XS_STAT_REG                 (DEVAD_PHY_XS + MII_STAT_REG)
#define PHY_XS_ID0_REG                  (DEVAD_PHY_XS + MII_PHY_ID0_REG)
#define PHY_XS_ID1_REG                  (DEVAD_PHY_XS + MII_PHY_ID1_REG)
#define PHY_XS_SPEED_ABIL               (DEVAD_PHY_XS + 0x0005)
#define PHY_XS_DEV_IN_PKG               (DEVAD_PHY_XS + 0x0006)
#define PHY_XS_XGXS_LANE_STAT           (DEVAD_PHY_XS + 0x0018)
#define PHY_XS_XGXS_TX_POLARITY         (DEVAD_PHY_XS + 0x80a1)
#define PHY_XS_XGXS_RX_POLARITY         (DEVAD_PHY_XS + 0x80fa)
#define PHY_XS_XGXS_RX_LANE_SWAP        (DEVAD_PHY_XS + 0x8100)
#define PHY_XS_XGXS_TX_LANE_SWAP        (DEVAD_PHY_XS + 0x8101)

/* AN registers */
#define AN_CTRL_REG                     (DEVAD_AN + MII_CTRL_REG)
#define AN_STAT_REG                     (DEVAD_AN + MII_STAT_REG)
#define AN_CLAUSE_73_ADVERT_REG         (DEVAD_AN + 0x11)
#define AN_LINK_STAT_REG                (DEVAD_AN + 0x8304)
#define AN_CLAUSE_37_73_ALLOW_REG       (DEVAD_AN + 0x8370)
#define AN_CLAUSE_37_ENABLE_REG         (DEVAD_AN + 0xffe0)
#define AN_CLAUSE_37_ADVERT_REG         (DEVAD_AN + 0xffe4)

/* PMA/PMD control register */
#define PMA_PMD_CTRL_RESET              (1L << 15)
#define PMA_PMD_CTRL_LO_PWR             (1L << 6)
#define PMA_PMD_CTRL_LE                 (1L << 0)

/* PMA/PMD control2 register */
#define PMA_PMD_CTRL2r_PMA_TYPE_MASK    0xF
#define PMA_PMD_CTRL2r_PMA_TYPE_1G      0xD
#define PMA_PMD_CTRL2r_PMA_TYPE_10G     0x8

/* XS polarity registers */
#define XS_TX_POLARITY_INVERT           (1L << 5)
#define XS_RX_POLARITY_INVERT           ((1L << 3) | (1L << 2))

/* XS lane swap registers */
#define XS_TX_LANE_SWAP                 (1L << 15)
#define XS_RX_LANE_SWAP                 ((1L << 15) | (1L << 14))

/* Devices in package register 1 */
#define DEV_IN_PKG_AN                   (1L << 7)
#define DEV_IN_PKG_DTE_XS               (1L << 5)
#define DEV_IN_PKG_PHY_XS               (1L << 4)
#define DEV_IN_PKG_PCS                  (1L << 3)
#define DEV_IN_PKG_WIS                  (1L << 2)
#define DEV_IN_PKG_PMA_PMD              (1L << 1)
#define DEV_IN_PKG_C22                  (1L << 0)

/*PCS polarity registers */
#define PCS_TX_POLARITY_INVERT          (1L << 10)
#define PCS_RX_POLARITY_INVERT          (1L << 9)

/* Misc. control register */
#define MISC_CTRL_LOL_OPT_LOS_EN        (1L << 9)
#define MISC_CTRL_P_IN_MUXSEL           (1L << 7)
#define MISC_CTRL_X_IN_MUXSEL           (1L << 6)
#define MISC_CTRL_CLUPLL_EN             (1L << 5)
#define MISC_CTRL_XCLKMODE_OVRD         (1L << 4)
#define MISC_CTRL_XFP_CLK_EN            (1L << 3)
#define MISC_CTRL_REFOUTFREQ            (7L << 0)

/* Gen Reg 1 values */
#define GEN_REG_1_LANES                 0x1234
#define GEN_REG_1_LANES_REV             0x4321

/* AN Control register */
#define AN_CTRL_EXT_NXT_PAGE            (1L << 13)
#define AN_CTRL_ENABLE                  (1L << 12)
#define AN_CTRL_RESTART                 (1L << 9)

/* AN Status register */
#define AN_STAT_AN_DONE                 (1L << 5)

/* AN Link Status register */
#define AN_LINK_STATUS_1G               (1L << 1)

/* AN Clause 37-73 allow register */
#define AN_CLAUSE_37_73_VALUE           0x040c

/* AN Clause 37 enable register */
#define AN_CLAUSE_37_ENABLE_VALUE       0x1000

/* AN Clause 37 & 73 advert registers */
#define AN_CLAUSE_37_73_ADVERT_FULL_DUPLEX  (1L << 5)

/* Low level debugging (off by default) */
#ifdef BCM8747_DEBUG_ENABLE
#define BCM8747_DBG(_pc, _str) \
    CDK_WARN(("bcm8747[%d.%d]: " _str "\n", \
               PHY_CTRL_UNIT(_pc), PHY_CTRL_PORT(_pc)));
#else
#define BCM8747_DBG(_pc, _str)
#endif

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcm8747_phy_probe
 * Purpose:     
 *      Probe for PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8747_phy_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1, chip_id;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, PMA_PMD_ID0_REG, &phyid0);
    ioerr += PHY_BUS_READ(pc, PMA_PMD_ID1_REG, &phyid1);

    if (phyid0 == BCM8747_PMA_PMD_ID0 && 
        phyid1 == BCM8747_PMA_PMD_ID1) {
        ioerr += PHY_BUS_READ(pc, PMA_PMD_CHIP_ID_REG, &chip_id);
        if (chip_id == BCM8747_CHIP_ID) {
            return ioerr ? CDK_E_IO : CDK_E_NONE;
        }
    }

    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcm8747_phy_notify
 * Purpose:     
 *      Handle PHY notifications
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8747_phy_notify(phy_ctrl_t *pc, phy_event_t event)
{
    return bcm8727_drv.pd_notify(pc, event);
}

/*
 * Function:
 *      bcm8747_phy_reset
 * Purpose:     
 *      Reset PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8747_phy_reset(phy_ctrl_t *pc)
{
    return bcm8727_drv.pd_reset(pc);
}

/*
 * Function:
 *      bcm8747_phy_real_init
 * Purpose:     
 *      Initialize PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8747_phy_real_init(phy_ctrl_t *pc)
{
    uint32_t lane_stat;
    int sleep_time = 1000;
    int cnt;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;

#if PHY_CONFIG_EXTERNAL_BOOT_ROM
    if (CDK_SUCCESS(rv)) {
        uint32_t gp_reg4;

        /*
         * Load microcode from external ROM.
         */

        /* Enable SPI interface */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GPIO_CTRL3, 0x0000);
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GPIO_CTRL0, 0x0000);

        /* Remove all resets */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GEN_CTRL, 0x0188);

        /* Wait for at least 60ms for download to complete */
        PHY_SYS_USLEEP(100000);

        /* Make sure SPI-ROM load is complete */
        for (cnt = 0; ioerr == 0 && cnt < PHY_ROM_LOAD_POLL_MAX; cnt++) {
            ioerr += PHY_BUS_READ(pc, PMA_PMD_GP_REG4, &gp_reg4);
            if (gp_reg4 == 0x600d) {
                BCM8747_DBG(pc, "rom ok");
                break;
            }
            PHY_SYS_USLEEP(sleep_time);
        }
        if (cnt >= PHY_ROM_LOAD_POLL_MAX) {
            BCM8747_DBG(pc, "rom load timeout");
            rv = CDK_E_TIMEOUT;
        }

        /* Disable SPI interface */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GPIO_CTRL3, 0x000f);
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GPIO_CTRL0, 0x000c);
    }
#endif

    if (CDK_SUCCESS(rv)) {
        BCM8747_DBG(pc, "lane sync start");
        /* Make sure 8747 XAUI lanes are synchronized with the SOC XAUI */
        for (cnt = 0; cnt < PHY_LANES_POLL_MAX; cnt++) {
            ioerr += PHY_BUS_READ(pc, PHY_XS_XGXS_LANE_STAT, &lane_stat);
            if ((lane_stat & 0xf) == 0xf) {
                BCM8747_DBG(pc, "lane sync ok");
                break;
            }
            PHY_SYS_USLEEP(sleep_time);
        }
        if (cnt >= PHY_LANES_POLL_MAX) {
            BCM8747_DBG(pc, "lane sync timeout");
            rv = CDK_E_TIMEOUT;
        }
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      bcm8747_phy_init
 * Purpose:     
 *      Initialize PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8747_phy_init(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;

#if PHY_CONFIG_EXTERNAL_BOOT_ROM
    /*
     * When downloading code from a shared SPI ROM, we need
     * to put all ROM-sharing PHY instances into reset before
     * a download can be performed on any ROM-sharing PHY.
     * Since the PHY driver instances are independent we rely
     * on the upper software layers to initialize all PHYs
     * before the port mode is set. When the port mode is set
     * the first time (see autoneg_set), the SPI download
     * will be done and the init sequence will be finalized.
     */

    /* Place processor in reset */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GEN_CTRL, 0x018f);

    /* Configure  SPI interface for download */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_SPI_PORT_CTRL, 0xc0f1);

    /* Disable SPI interface */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GPIO_CTRL3, 0x000f);
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GPIO_CTRL0, 0x000c);
#else
    if (CDK_SUCCESS(rv)) {
        rv = bcm8747_phy_real_init(pc);
    }
#endif

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_INIT(PHY_CTRL_NEXT(pc));
    }

    /* Always disable autoneg in PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_AUTONEG_SET(PHY_CTRL_NEXT(pc), 0);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm8747_phy_link_get
 * Purpose:     
 *      Determine the current link up/down status
 * Parameters:
 *      pc - PHY control structure
 *      link - (OUT) non-zero indicates link established.
 * Returns:
 *      CDK_E_xxx
 */
static int
bcm8747_phy_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    return bcm8727_drv.pd_link_get(pc, link, autoneg_done);
}

/*
 * Function:    
 *      bcm8747_phy_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8747_phy_duplex_set(phy_ctrl_t *pc, int duplex)
{
    return bcm8727_drv.pd_duplex_set(pc, duplex);
}

/*
 * Function:    
 *      bcm8747_phy_duplex_get
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
bcm8747_phy_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    return bcm8727_drv.pd_duplex_get(pc, duplex);
}

/*
 * Function:    
 *      bcm8747_phy_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8747_phy_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    return bcm8727_drv.pd_speed_set(pc, speed);
}

/*
 * Function:    
 *      bcm8747_phy_speed_get
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
bcm8747_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    return bcm8727_drv.pd_speed_get(pc, speed);
}

/*
 * Function:    
 *      bcm8747_phy_autoneg_set
 * Purpose:     
 *      Enable or disable auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8747_phy_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int rv = CDK_E_NONE;

#if PHY_CONFIG_EXTERNAL_BOOT_ROM
    /*
     * The following code finalizes the init sequence
     * the first time autoneg_set is called.
     */
    if ((PHY_CTRL_FLAGS(pc) & PHY_F_ENABLE) == 0) {
        rv = bcm8747_phy_real_init(pc);
        PHY_CTRL_FLAGS(pc) |= PHY_F_ENABLE;
    }
#endif

    if (CDK_SUCCESS(rv)) {
        rv = bcm8727_drv.pd_autoneg_set(pc, autoneg);
    }
    return rv;
}

/*
 * Function:    
 *      bcm8747_phy_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation setting.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8747_phy_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    return bcm8727_drv.pd_autoneg_get(pc, autoneg);
}

/*
 * Function:    
 *      bcm8747_phy_loopback_set
 * Purpose:     
 *      Set the internal PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8747_phy_loopback_set(phy_ctrl_t *pc, int enable)
{
    return bcm8727_drv.pd_loopback_set(pc, enable);
}

/*
 * Function:    
 *      bcm8747_phy_loopback_get
 * Purpose:     
 *      Get the local PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8747_phy_loopback_get(phy_ctrl_t *pc, int *enable)
{
    return bcm8727_drv.pd_loopback_get(pc, enable);
}

/*
 * Function:    
 *      bcm8747_phy_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8747_phy_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    return bcm8727_drv.pd_ability_get(pc, abil);
}

/*
 * Function:
 *      bcm8747_phy_config_set
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
bcm8747_phy_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    return bcm8727_drv.pd_config_set(pc, cfg, val, cd);
}

/*
 * Function:
 *      bcm8747_phy_config_get
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
bcm8747_phy_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    return bcm8727_drv.pd_config_get(pc, cfg, val, cd);
}

/*
 * Variable:    bcm8747_drv
 * Purpose:     PHY Driver for BCM8747.
 */
phy_driver_t bcm8747_drv = {
    "bcm8747",
    "BCM8747 10-Gigabit PHY Driver",  
    0,
    bcm8747_phy_probe,                  /* pd_probe */
    bcm8747_phy_notify,                 /* pd_notify */
    bcm8747_phy_reset,                  /* pd_reset */
    bcm8747_phy_init,                   /* pd_init */
    bcm8747_phy_link_get,               /* pd_link_get */
    bcm8747_phy_duplex_set,             /* pd_duplex_set */
    bcm8747_phy_duplex_get,             /* pd_duplex_get */
    bcm8747_phy_speed_set,              /* pd_speed_set */
    bcm8747_phy_speed_get,              /* pd_speed_get */
    bcm8747_phy_autoneg_set,            /* pd_autoneg_set */
    bcm8747_phy_autoneg_get,            /* pd_autoneg_get */
    bcm8747_phy_loopback_set,           /* pd_loopback_set */
    bcm8747_phy_loopback_get,           /* pd_loopback_get */
    bcm8747_phy_ability_get,            /* pd_ability_get */
    bcm8747_phy_config_set,             /* pd_config_set */
    bcm8747_phy_config_get,             /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
