/*
 * $Id: bcm8754_drv.c,v 1.6 Broadcom SDK $
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
 * PHY driver for BCM8754.
 *
 */

#include <phy/phy.h>
#include <phy/ge_phy.h>
#include <phy/phy_drvlist.h>

#define PHY_RESET_MSEC                  20

#define BCM8754_PMA_PMD_ID0             0x0362
#define BCM8754_PMA_PMD_ID1             0x5fa0

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
#define PMA_PMD_PHY_ID_REG              (DEVAD_PMA_PMD + 0xc800)
#define PMA_PMD_CHIP_REV_REG            (DEVAD_PMA_PMD + 0xc801)
#define PMA_PMD_CHIP_ID_REG             (DEVAD_PMA_PMD + 0xc802)
#define PMA_PMD_OPTICAL_CFG_REG         (DEVAD_PMA_PMD + 0xc8e4)
#define PMA_PMD_MISC_CTRL_REG_3         (DEVAD_PMA_PMD + 0xca85)
#define PMA_PMD_GEN_CTRL_STAT_REG       (DEVAD_PMA_PMD + 0xca10)
#define PMA_PMD_GEN_REG_0               (DEVAD_PMA_PMD + 0xca18)
#define PMA_PMD_GEN_REG_1               (DEVAD_PMA_PMD + 0xca19)
#define PMA_PMD_GEN_REG_2               (DEVAD_PMA_PMD + 0xca1a)
#define PMA_PMD_GEN_REG_3               (DEVAD_PMA_PMD + 0xca1b)
#define PMA_PMD_GEN_REG_4               (DEVAD_PMA_PMD + 0xca1c)

#define SPI_PORT_CTRL_STAT_REG          (DEVAD_PMA_PMD + 0xc848)
#define XFI_TX_CTRL_REG_1               (DEVAD_PMA_PMD + 0xc90b)
#define XFI_TX_CTRL_REG_2               (DEVAD_PMA_PMD + 0xc90c)
#define XFI_RX_CTRL_REG_0               (DEVAD_PMA_PMD + 0xc900)

#define PMA_PMD_GP_REG_0                (DEVAD_PMA_PMD + 0xc840)
#define PMA_PMD_C843_REG                (DEVAD_PMA_PMD + 0xc843)
#define PMA_PMD_MISC2_REG               (DEVAD_PMA_PMD + 0x8309)
#define PMA_PMD_CD17_REG                (DEVAD_PMA_PMD + 0xcd17)
#define PMA_PMD_FFFF_REG                (DEVAD_PMA_PMD + 0xffff)

/* PCS registers */
#define PCS_CTRL_REG                    (DEVAD_PCS + MII_CTRL_REG)
#define PCS_STAT_REG                    (DEVAD_PCS + MII_STAT_REG)
#define PCS_ID0_REG                     (DEVAD_PCS + MII_PHY_ID0_REG)
#define PCS_ID1_REG                     (DEVAD_PCS + MII_PHY_ID1_REG)
#define PCS_SPEED_ABIL                  (DEVAD_PCS + 0x0005)
#define PCS_DEV_IN_PKG                  (DEVAD_PCS + 0x0006)
#define PCS_POLARITY                    (DEVAD_PCS + 0xcd08)

/* AN registers */
#define AN_CTRL_REG                     (DEVAD_AN + MII_CTRL_REG)
#define AN_STAT_REG                     (DEVAD_AN + MII_STAT_REG)
#define AN_MII_CTRL_REG                 (DEVAD_AN + 0xFFE0)
#define AN_MII_STAT_REG                 (DEVAD_AN + 0xFFE1)

/* PMA/PMD control register */
#define PMA_PMD_CTRL_SPEED_10G          (1L << 13)
#define PMA_PMD_CTRL_LO_PWR             (1L << 11)
#define PMA_PMD_CTRL_LB                 (1L << 0)

/* PMA/PMD control2 register */
#define PMA_PMD_CTRL2_TYPE_MASK         0xf
#define PMA_PMD_CTRL2_TYPE_1G_KX        0xd
#define PMA_PMD_CTRL2_TYPE_10G_KR       0xb
#define PMA_PMD_CTRL2_TYPE_10G_LRM      0x8

/* Devices in package register 1 */
#define DEV_IN_PKG_AN                   (1L << 7)
#define DEV_IN_PKG_DTE_XS               (1L << 5)
#define DEV_IN_PKG_PHY_XS               (1L << 4)
#define DEV_IN_PKG_PCS                  (1L << 3)
#define DEV_IN_PKG_WIS                  (1L << 2)
#define DEV_IN_PKG_PMA_PMD              (1L << 1)
#define DEV_IN_PKG_C22                  (1L << 0)

/* PCS polarity registers */
#define PCS_TX_POLARITY_INVERT_L        (1L << 10)
#define PCS_RX_POLARITY_INVERT          (1L << 9)

/* AN Control register */
#define AN_CTRL_EXT_NXT_PAGE            (1L << 13)
#define AN_CTRL_ENABLE                  (1L << 12)
#define AN_CTRL_RESTART                 (1L << 9)

/* AN Status register */
#define AN_STAT_AN_DONE                 (1L << 5)

/* AN Link Status register */
#define AN_LINK_STATUS_1G               (1L << 1)

/* Low level debugging (off by default) */
#ifdef PHY_DEBUG_ENABLE
#define _PHY_DBG(_pc, _stuff) \
    PHY_VERB(_pc, _stuff)
#else
#define _PHY_DBG(_pc, _stuff)
#endif

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcm8754_phy_probe
 * Purpose:     
 *      Probe for 8754 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8754_phy_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, PMA_PMD_ID0_REG, &phyid0);
    ioerr += PHY_BUS_READ(pc, PMA_PMD_ID1_REG, &phyid1);

    if (ioerr) {
        return CDK_E_IO;
    }

    if ((phyid0 == BCM8754_PMA_PMD_ID0) && 
        ((phyid1 & ~0xf) == (BCM8754_PMA_PMD_ID1 & ~0xf))) {
        return CDK_E_NONE;
    }
    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcm8754_phy_notify
 * Purpose:     
 *      Handle PHY notifications
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8754_phy_notify(phy_ctrl_t *pc, phy_event_t event)
{
    return bcm8752_drv.pd_notify(pc, event);
}

/*
 * Function:
 *      bcm8754_phy_reset
 * Purpose:     
 *      Reset 8754 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8754_phy_reset(phy_ctrl_t *pc)
{
    return bcm8752_drv.pd_reset(pc);
}

/*
 * Function:
 *      bcm8754_phy_init
 * Purpose:     
 *      Initialize 8754 PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8754_phy_init(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int msec;
    uint32_t data, crc;

    PHY_CTRL_CHECK(pc);

    PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;

    ioerr += PHY_BUS_READ(pc, SPI_PORT_CTRL_STAT_REG, &data);
    data &= ~0x6000;
    ioerr += PHY_BUS_WRITE(pc, SPI_PORT_CTRL_STAT_REG, data);

    ioerr += PHY_BUS_READ(pc, PMA_PMD_MISC_CTRL_REG_3, &data);
    data &= ~0x0001;
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_MISC_CTRL_REG_3, data);

    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, MII_CTRL_RESET);
    ioerr += PHY_BUS_WRITE(pc, PCS_CTRL_REG, MII_CTRL_RESET);

    for (msec = 0; msec < PHY_RESET_MSEC; msec++) {
        ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &data);
        if ((data & MII_CTRL_RESET) == 0) {
            break;
        }
        PHY_SYS_USLEEP(1000);
    }
    if (msec >= PHY_RESET_MSEC) {
        PHY_WARN(pc, ("reset timeout\n"));
    }

#if PHY_CONFIG_EXTERNAL_BOOT_ROM
    {
        int inst;
        int orig_inst = PHY_CTRL_PHY_INST(pc);

        for (inst = 0; inst < 4; inst++) {
            phy_ctrl_change_inst(pc, inst, NULL);
            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_C843_REG, 0x000f);
            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GP_REG_0, 0x000c);
            ioerr += PHY_BUS_WRITE(pc, SPI_PORT_CTRL_STAT_REG, 0xc0f1);
        }
        phy_ctrl_change_inst(pc, orig_inst, NULL);
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GEN_CTRL_STAT_REG, 0x018f);
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_C843_REG, 0x0000);
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GP_REG_0, 0x0000);
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GEN_CTRL_STAT_REG, 0x0188);
        PHY_SYS_USLEEP(100000);
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_C843_REG, 0x000f);
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GP_REG_0, 0x000c);
    }
#endif
    ioerr += PHY_BUS_READ(pc, PMA_PMD_GEN_REG_2, &data);

    if (data > 0x0301) {
        ioerr += PHY_BUS_READ(pc, PMA_PMD_GEN_REG_4, &crc);
        if (crc != 0x600d) {
            PHY_WARN(pc, ("bad checksum"));
        } else {
            PHY_VERB(pc, ("SPI-ROM version = 0x%04"PRIx32"\n", data));
        }
    } else {
        PHY_WARN(pc, ("invalid firmware version"));
    }

    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_FFFF_REG, 0x0000);

#if PHY_CONFIG_LONG_XFI
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_FFFF_REG, 0x0001);

    ioerr += PHY_BUS_WRITE(pc, XFI_TX_CTRL_REG_1, 0xb000);
    ioerr += PHY_BUS_WRITE(pc, XFI_TX_CTRL_REG_2, 0x1052);
    ioerr += PHY_BUS_WRITE(pc, XFI_RX_CTRL_REG_0, 0xec91);

    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_FFFF_REG, 0x0000);
#endif

    /* Disable SyncE */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GP_REG_0, 0x0000);
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CD17_REG, 0x0000);
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_FFFF_REG, 0x0001);
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CD17_REG, 0x0000);
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_FFFF_REG, 0x0000);

    /* Configure optical interface */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_OPTICAL_CFG_REG, &data);
    data &= ~(1L << 4);
    data |= (1L << 12);
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_OPTICAL_CFG_REG, data);

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_INIT(PHY_CTRL_NEXT(pc));
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm8754_phy_link_get
 * Purpose:     
 *      Determine the current link up/down status
 * Parameters:
 *      pc - PHY control structure
 *      link - (OUT) non-zero indicates link established.
 * Returns:
 *      CDK_E_xxx
 * Notes:
 *      MII_STATUS bit 2 reflects link state.
 */
static int
bcm8754_phy_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    return bcm8752_drv.pd_link_get(pc, link, autoneg_done);
}

/*
 * Function:    
 *      bcm8754_phy_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8754_phy_duplex_set(phy_ctrl_t *pc, int duplex)
{
    return bcm8752_drv.pd_duplex_set(pc, duplex);
}

/*
 * Function:    
 *      bcm8754_phy_duplex_get
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
bcm8754_phy_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    return bcm8752_drv.pd_duplex_get(pc, duplex);
}

/*
 * Function:    
 *      bcm8754_phy_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8754_phy_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    return bcm8752_drv.pd_speed_set(pc, speed);
}

/*
 * Function:    
 *      bcm8754_phy_speed_get
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
bcm8754_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    return bcm8752_drv.pd_speed_get(pc, speed);
}

/*
 * Function:    
 *      bcm8754_phy_autoneg_set
 * Purpose:     
 *      Enable or disable auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8754_phy_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    return bcm8752_drv.pd_autoneg_set(pc, autoneg);
}

/*
 * Function:    
 *      bcm8754_phy_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation setting.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8754_phy_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    return bcm8752_drv.pd_autoneg_get(pc, autoneg);
}

/*
 * Function:    
 *      bcm8754_phy_loopback_set
 * Purpose:     
 *      Set the internal PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8754_phy_loopback_set(phy_ctrl_t *pc, int enable)
{
    return bcm8752_drv.pd_loopback_set(pc, enable);
}

/*
 * Function:    
 *      bcm8754_phy_loopback_get
 * Purpose:     
 *      Get the local PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8754_phy_loopback_get(phy_ctrl_t *pc, int *enable)
{
    return bcm8752_drv.pd_loopback_get(pc, enable);
}

/*
 * Function:    
 *      bcm8754_phy_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8754_phy_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    return bcm8752_drv.pd_ability_get(pc, abil);
}

/*
 * Function:
 *      bcm8754_phy_config_set
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
bcm8754_phy_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    return bcm8752_drv.pd_config_set(pc, cfg, val, cd);
}

/*
 * Function:
 *      bcm8754_phy_config_get
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
bcm8754_phy_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    return bcm8752_drv.pd_config_get(pc, cfg, val, cd);
}

/*
 * Variable:    bcm8754_drv
 * Purpose:     PHY Driver for BCM8754.
 */
phy_driver_t bcm8754_drv = {
    "bcm8754",
    "BCM8754 10-Gigabit PHY Driver",  
    0,
    bcm8754_phy_probe,                  /* pd_probe */
    bcm8754_phy_notify,                 /* pd_notify */
    bcm8754_phy_reset,                  /* pd_reset */
    bcm8754_phy_init,                   /* pd_init */
    bcm8754_phy_link_get,               /* pd_link_get */
    bcm8754_phy_duplex_set,             /* pd_duplex_set */
    bcm8754_phy_duplex_get,             /* pd_duplex_get */
    bcm8754_phy_speed_set,              /* pd_speed_set */
    bcm8754_phy_speed_get,              /* pd_speed_get */
    bcm8754_phy_autoneg_set,            /* pd_autoneg_set */
    bcm8754_phy_autoneg_get,            /* pd_autoneg_get */
    bcm8754_phy_loopback_set,           /* pd_loopback_set */
    bcm8754_phy_loopback_get,           /* pd_loopback_get */
    bcm8754_phy_ability_get,            /* pd_ability_get */
    bcm8754_phy_config_set,             /* pd_config_set */
    bcm8754_phy_config_get,             /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
