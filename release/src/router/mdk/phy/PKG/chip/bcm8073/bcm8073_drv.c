/*
 * $Id: bcm8073_drv.c,v 1.12 Broadcom SDK $
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
 * PHY driver for BCM8073.
 *
 */

#include <phy/phy.h>
#include <phy/phy_drvlist.h>

#define PHY_RESET_POLL_MAX              10
#define PHY_ROM_LOAD_POLL_MAX           500

#define BCM8073_PMA_PMD_ID0             0x0020
#define BCM8073_PMA_PMD_ID1             0x6036
#define BCM8073_CHIP_ID                 0x8073

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
#define PMA_PMD_10G_CTRL_REG            (DEVAD_PMA_PMD + 0x0096)
#define PMA_PMD_CHIP_ID_REG             (DEVAD_PMA_PMD + 0xc802)
#define PMA_PMD_USR_STAT                (DEVAD_PMA_PMD + 0xc820)
#define PMA_PMD_GPIO_CTRL0              (DEVAD_PMA_PMD + 0xc840)
#define PMA_PMD_GPIO_CTRL1              (DEVAD_PMA_PMD + 0xc841)
#define PMA_PMD_GPIO_CTRL2              (DEVAD_PMA_PMD + 0xc842)
#define PMA_PMD_GPIO_CTRL3              (DEVAD_PMA_PMD + 0xc843)
#define PMA_PMD_SPI_PORT_CTRL           (DEVAD_PMA_PMD + 0xc848)
#define PMA_PMD_TX_CTRL1                (DEVAD_PMA_PMD + 0xca02)
#define PMA_PMD_TX_CTRL2                (DEVAD_PMA_PMD + 0xca05)
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
#define AN_ETH_STAT_REG                 (DEVAD_AN + 0x30)
#define AN_LINK_STAT_REG                (DEVAD_AN + 0x8304)
#define AN_MODE_CTRL_REG                (DEVAD_AN + 0x8308)
#define AN_MISC_CTRL_REG                (DEVAD_AN + 0x8309)
#define AN_CLAUSE_37_73_ALLOW_REG       (DEVAD_AN + 0x8370)
#define AN_MII_CTRL_REG                 (DEVAD_AN + 0xffe0)
#define AN_CLAUSE_37_ADVERT_REG         (DEVAD_AN + 0xffe4)

/* PMA/PMD control register */
#define PMA_PMD_CTRL_RESET              (1L << 15)
#define PMA_PMD_CTRL_SPEED_10G          (1L << 13)
#define PMA_PMD_CTRL_LO_PWR             (1L << 6)
#define PMA_PMD_CTRL_LE                 (1L << 0)

/* PMA/PMD control2 register */
#define CTRL2_TYPE_MASK                 0xf
#define CTRL2_TYPE_1000BASE_KX          0xd
#define CTRL2_TYPE_10GBASE_KR           0xb

/* PMA/PMD user status register */
#define USR_STAT_PCS_LKDWN10G           (1L << 15)
#define USR_STAT_PCS_LKDWN2P5G          (1L << 14)
#define USR_STAT_PCS_LKDWN1G            (1L << 13)
#define USR_STAT_AN_ENABLED             (1L << 11)
#define USR_STAT_AN_DONE                (1L << 10)
#define USR_STAT_MODE_10G               (1L << 6)
#define USR_STAT_MODE_2P5G              (1L << 5)
#define USR_STAT_MODE_1G                (1L << 4)
#define USR_STAT_PCS_SPEED10G           (1L << 2)
#define USR_STAT_PCS_SPEED2P5G          (1L << 1)
#define USR_STAT_PCS_SPEED1G            (1L << 0)
#define USR_STAT_AN_10G(_s)             (((_s) & 0xec44) == 0x6c44)
#define USR_STAT_AN_2P5G(_s)            (((_s) & 0x8c22) == 0x8c22)

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

/* PCS polarity registers */
#define PCS_TX_POLARITY_INVERT_L        (1L << 10)
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
#define AN_LINK_STAT_1G                 (1L << 1)

/* AN Ethernet status register */
#define AN_SPEED_1000BASE_KX            (1L << 1)
#define AN_SPEED_10GBASE_KR             (1L << 3)

/* AN Clause 37-73 allow register */
#define AN_CLAUSE_37_73_VALUE           0x040c

/* AN MII Control register */
#define AN_MII_CL37_EN                  (1L << 12)

/* AN Clause 37 & 73 advert registers */
#define AN_CLAUSE_37_73_ADVERT_FULL_DUPLEX  (1L << 5)

/* Low level debugging (off by default) */
#ifdef BCM8073_DEBUG_ENABLE
#define BCM8073_DBG(_pc, _str) \
    CDK_WARN(("bcm8073[%d.%d]: " _str "\n", \
               PHY_CTRL_UNIT(_pc), PHY_CTRL_PORT(_pc)));
#else
#define BCM8073_DBG(_pc, _str)
#endif

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcm8073_phy_probe
 * Purpose:     
 *      Probe for 8073 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8073_phy_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1, chip_id;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, PMA_PMD_ID0_REG, &phyid0);
    ioerr += PHY_BUS_READ(pc, PMA_PMD_ID1_REG, &phyid1);

    if (phyid0 == BCM8073_PMA_PMD_ID0 && 
        phyid1 == BCM8073_PMA_PMD_ID1) {
        ioerr += PHY_BUS_READ(pc, PMA_PMD_CHIP_ID_REG, &chip_id);
        if (chip_id == BCM8073_CHIP_ID) {
            return ioerr ? CDK_E_IO : CDK_E_NONE;
        }
    }

    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcm8073_phy_notify
 * Purpose:     
 *      Handle PHY notifications
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8073_phy_notify(phy_ctrl_t *pc, phy_event_t event)
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
 *      bcm8073_phy_reset
 * Purpose:     
 *      Reset 8073 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8073_phy_reset(phy_ctrl_t *pc)
{
    uint32_t pma_pmd_ctrl, pcs_ctrl;
    int cnt;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* Reset all internal devices */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, MII_CTRL_RESET);
    ioerr += PHY_BUS_WRITE(pc, PCS_CTRL_REG, MII_CTRL_RESET);

    /* Wait for reset completion */
    for (cnt = 0; cnt < PHY_RESET_POLL_MAX; cnt++) {
        ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);
        ioerr += PHY_BUS_READ(pc, PCS_CTRL_REG, &pcs_ctrl);
        if ((pma_pmd_ctrl & MII_CTRL_RESET) == 0 &&
            (pcs_ctrl & MII_CTRL_RESET) == 0) {
            break;
        }
    }
    if (cnt >= PHY_RESET_POLL_MAX) {
        BCM8073_DBG(pc, "reset timeout");
        rv = CDK_E_TIMEOUT;
    }

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_RESET(PHY_CTRL_NEXT(pc));
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      bcm8073_phy_init
 * Purpose:     
 *      Initialize 8073 PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8073_phy_init(phy_ctrl_t *pc)
{
    uint32_t tx_ctrl1, gp_reg3;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;

#if PHY_CONFIG_EXTERNAL_BOOT_ROM
    if (CDK_SUCCESS(rv)) {
        uint32_t gp_reg1;
        int sleep_time = 1000;
        int cnt;

        /*
         * Load microcode from external ROM.
         */

        /* Global reset */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GEN_CTRL, 0x0001);

        /* Configure SPI and place processor in reset */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GEN_CTRL, 0x008c);

        /* Enable serial boot */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_MISC_CTRL2, 0x0001);

        /* Remove processor reset and enter soft reset */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GEN_CTRL, 0x018a);

        /* Remove all resets */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GEN_CTRL, 0x0188);

        /* Wait for at least 100ms for download to complete */
        PHY_SYS_USLEEP(200000);

        /* Disable serial boot */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_MISC_CTRL2, 0x0000);

        /* Make sure SPI-ROM load is complete */
        for (cnt = 0; ioerr == 0 && cnt < PHY_ROM_LOAD_POLL_MAX; cnt++) {
            ioerr += PHY_BUS_READ(pc, PMA_PMD_GP_REG1, &gp_reg1);
            if ((gp_reg1 & 0xfff0) == 0xbaa0) {
                BCM8073_DBG(pc, "rom ok");
                break;
            }
            PHY_SYS_USLEEP(sleep_time);
        }
        if (cnt >= PHY_ROM_LOAD_POLL_MAX) {
            BCM8073_DBG(pc, "rom load timeout");
            rv = CDK_E_TIMEOUT;
        }
    }
#endif

    /* Disable/enable Tx to avoid auto-neg getting stuck */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_TX_CTRL1, &tx_ctrl1);
    tx_ctrl1 |= 0x0400;
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_TX_CTRL1, tx_ctrl1);
    tx_ctrl1 &= ~0x0400;
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_TX_CTRL1, tx_ctrl1);

    /* Enable autoneg watchdog */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_GP_REG3, &gp_reg3);
    gp_reg3 |= 0x1000;
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_GP_REG3, gp_reg3);

    /* Restart auto-neg */
    ioerr += PHY_BUS_WRITE(pc, AN_CTRL_REG, AN_CTRL_ENABLE | AN_CTRL_RESTART);
    PHY_SYS_USLEEP(500000);

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
 *      bcm8073_phy_link_get
 * Purpose:     
 *      Determine the current link up/down status
 * Parameters:
 *      pc - PHY control structure
 *      link - (OUT) non-zero indicates link established.
 * Returns:
 *      CDK_E_xxx
 */
static int
bcm8073_phy_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    int ioerr = 0;
    uint32_t stat;

    PHY_CTRL_CHECK(pc);

    /* Check autoneg status before link status */
    if (autoneg_done) {
        ioerr += PHY_BUS_READ(pc, AN_STAT_REG, &stat);
        *autoneg_done = (stat & AN_STAT_AN_DONE);
    }

    *link = 0;
    ioerr += PHY_BUS_READ(pc, PMA_PMD_STAT_REG, &stat);
    if (stat & MII_STAT_LA) {
        *link = 1;
    }

    ioerr += PHY_BUS_READ(pc, PMA_PMD_USR_STAT, &stat);
    if (stat & USR_STAT_MODE_10G) {
        /* 10G link must be up in all devices */
        ioerr += PHY_BUS_READ(pc, PCS_STAT_REG, &stat);
        if ((stat & MII_STAT_LA) == 0) {
            *link = 0;
        }
    } else {
        /* Check AN status to eliminate false link */
        ioerr += PHY_BUS_READ(pc, AN_LINK_STAT_REG, &stat);
        if ((stat & AN_LINK_STAT_1G) == 0) {
            *link = 0;
        }
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm8073_phy_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8073_phy_duplex_set(phy_ctrl_t *pc, int duplex)
{
    return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
}

/*
 * Function:    
 *      bcm8073_phy_duplex_get
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
bcm8073_phy_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcm8073_phy_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8073_phy_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    uint32_t cur_speed;
    int cur_lb;
    uint32_t pma_pmd_ctrl, an_ctrl, misc_ctrl;

    PHY_CTRL_CHECK(pc);

    switch (speed) {
    case 10000:
        /* Leave autoneg registers unchanged if no speed change */
        rv = PHY_SPEED_GET(pc, &cur_speed);
        if (CDK_SUCCESS(rv) && speed == cur_speed) {
            break;
        }

        /* Disable training */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_10G_CTRL_REG, 0);

        /* Enable forced speed */
        ioerr += PHY_BUS_READ(pc, AN_MISC_CTRL_REG, &misc_ctrl);
        misc_ctrl |= (1L << 5);
        ioerr += PHY_BUS_WRITE(pc, AN_MISC_CTRL_REG, misc_ctrl);

        /* Select 10G mode */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL2_REG, CTRL2_TYPE_10GBASE_KR);

        /* Select 10G speed */
        ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);
        pma_pmd_ctrl |= PMA_PMD_CTRL_SPEED_10G;
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, pma_pmd_ctrl);

        ioerr += PHY_BUS_WRITE(pc, AN_MODE_CTRL_REG, 0x1c);

        /* Restart auto-neg and wait */
        ioerr += PHY_BUS_READ(pc, AN_CTRL_REG, &an_ctrl);
        ioerr += PHY_BUS_WRITE(pc, AN_CTRL_REG,
                               AN_CTRL_ENABLE | AN_CTRL_RESTART);
        PHY_SYS_USLEEP(40000);

        /* Restore auto-neg setting */
        ioerr += PHY_BUS_WRITE(pc, AN_CTRL_REG, an_ctrl);
        break;
    case 1000:
        /* Enable forced speed */
        ioerr += PHY_BUS_READ(pc, AN_MISC_CTRL_REG, &misc_ctrl);
        misc_ctrl |= (1L << 5);
        ioerr += PHY_BUS_WRITE(pc, AN_MISC_CTRL_REG, misc_ctrl);

        /* Select 1G mode */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL2_REG, CTRL2_TYPE_1000BASE_KX);

        /* Select 1G speed */
        ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);
        pma_pmd_ctrl &= ~PMA_PMD_CTRL_SPEED_10G;
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, pma_pmd_ctrl);

        break;
    case 2500:
        /* Leave autoneg registers unchanged if no speed change */
        rv = PHY_SPEED_GET(pc, &cur_speed);
        if (CDK_SUCCESS(rv) && speed == cur_speed) {
            break;
        }

        /* Select 1G mode */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL2_REG, CTRL2_TYPE_1000BASE_KX);

        /* Restart auto-neg and wait */
        ioerr += PHY_BUS_READ(pc, AN_CTRL_REG, &an_ctrl);
        ioerr += PHY_BUS_WRITE(pc, AN_CTRL_REG,
                               AN_CTRL_ENABLE | AN_CTRL_RESTART);
        PHY_SYS_USLEEP(40000);

        /* Restore auto-neg setting */
        ioerr += PHY_BUS_WRITE(pc, AN_CTRL_REG, an_ctrl);

        /* Disable clause 37 autoneg */
        ioerr += PHY_BUS_WRITE(pc, AN_MII_CTRL_REG, 0);

        /* Disable forced speed */
        ioerr += PHY_BUS_READ(pc, AN_MISC_CTRL_REG, &misc_ctrl);
        misc_ctrl &= ~(1L << 5);
        ioerr += PHY_BUS_WRITE(pc, AN_MISC_CTRL_REG, misc_ctrl);
        PHY_SYS_USLEEP(10000);

        ioerr += PHY_BUS_WRITE(pc, AN_MODE_CTRL_REG, 0x10);

        break;
    default:
        return CDK_E_PARAM;
    }

    /* Adjust loopback as needed */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_LOOPBACK_GET(pc, &cur_lb);
        if (CDK_SUCCESS(rv) && cur_lb) {
            rv = PHY_LOOPBACK_SET(pc, cur_lb);
        }
    }

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_SPEED_SET(PHY_CTRL_NEXT(pc), speed);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm8073_phy_speed_get
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
bcm8073_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int rv;
    int ioerr = 0;
    int an;
    uint32_t usr_stat, eth_stat, link_stat, ctrl2;

    PHY_CTRL_CHECK(pc);

    *speed = 0;

    rv = PHY_AUTONEG_GET(pc, &an);
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    if (an) {
        /* Autoneg speed */
        ioerr += PHY_BUS_READ(pc, PMA_PMD_USR_STAT, &usr_stat);
        ioerr += PHY_BUS_READ(pc, AN_ETH_STAT_REG, &eth_stat);

        if (eth_stat & AN_SPEED_10GBASE_KR) {
            *speed = 10000;
        } else if (USR_STAT_AN_2P5G(usr_stat)) {
            *speed = 2500;
        } else if (eth_stat & AN_SPEED_1000BASE_KX) {
            *speed = 1000;
        } else {
            ioerr += PHY_BUS_READ(pc, AN_LINK_STAT_REG, &link_stat);
            if (link_stat & AN_LINK_STAT_1G) {
                *speed = 1000;
            }
        }
    } else {
        /* Forced speed */
        ioerr += PHY_BUS_READ(pc, PMA_PMD_USR_STAT, &usr_stat);

        if (usr_stat & USR_STAT_MODE_2P5G) {
            *speed = 2500;
        } else {
            ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL2_REG, &ctrl2);
            if ((ctrl2 & CTRL2_TYPE_MASK) == CTRL2_TYPE_1000BASE_KX) {
                *speed = 1000;
            } else {
                *speed = 10000;
            }
        }
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm8073_phy_autoneg_set
 * Purpose:     
 *      Enable or disable auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8073_phy_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    uint32_t an_ctrl;

    PHY_CTRL_CHECK(pc);

    if (autoneg) {
        /* Enable training */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_10G_CTRL_REG, 0x2);

        /* Enable clause 37 autoneg */
        ioerr += PHY_BUS_WRITE(pc, AN_MII_CTRL_REG, AN_MII_CL37_EN | 0x100);

        /* Restart autoneg */
        an_ctrl = AN_CTRL_EXT_NXT_PAGE | AN_CTRL_ENABLE | AN_CTRL_RESTART;
        ioerr += PHY_BUS_WRITE(pc, AN_CTRL_REG, an_ctrl);

    } else {
        /* Disable training */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_10G_CTRL_REG, 0);

        /* Disable autoneg */
        ioerr += PHY_BUS_WRITE(pc, AN_MII_CTRL_REG, 0);
        ioerr += PHY_BUS_WRITE(pc, AN_CTRL_REG, 0);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm8073_phy_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation setting.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8073_phy_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    uint32_t ctrl;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    if (autoneg) {
        ioerr += PHY_BUS_READ(pc, AN_CTRL_REG, &ctrl);
        *autoneg = (ctrl & AN_CTRL_ENABLE);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm8073_phy_loopback_set
 * Purpose:     
 *      Set the internal PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8073_phy_loopback_set(phy_ctrl_t *pc, int enable)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int serdes_lb;
    uint32_t pma_pmd_ctrl, stat;

    /* Read loopback control registers */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);

    pma_pmd_ctrl &= ~PMA_PMD_CTRL_LE;
    if (enable) {
        pma_pmd_ctrl |= PMA_PMD_CTRL_LE;
    }

    /* Write updated loopback control registers */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, pma_pmd_ctrl);

    /* 1G loopback is not supported, so we push it to the serdes */
    if (CDK_SUCCESS(rv)) {
        serdes_lb = enable;
        if (serdes_lb) {
            ioerr += PHY_BUS_READ(pc, PMA_PMD_USR_STAT, &stat);
            if (stat & USR_STAT_MODE_10G) {
                serdes_lb = 0;
            }
        }
        rv = PHY_LOOPBACK_SET(PHY_CTRL_NEXT(pc), serdes_lb);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm8073_phy_loopback_get
 * Purpose:     
 *      Get the local PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8073_phy_loopback_get(phy_ctrl_t *pc, int *enable)
{
    uint32_t pma_pmd_ctrl;
    int ioerr = 0;

    /* Read loopback control registers */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);

    *enable = 0;
    if ((pma_pmd_ctrl & PMA_PMD_CTRL_LE)) {
        *enable = 1;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm8073_phy_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8073_phy_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    *abil = (PHY_ABIL_1000MB | PHY_ABIL_2500MB | PHY_ABIL_10GB | 
             PHY_ABIL_LOOPBACK | PHY_ABIL_XGMII);

    return CDK_E_NONE;
}

/*
 * Function:
 *      bcm8073_phy_config_set
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
bcm8073_phy_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
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
        if (val == 0) {
            return CDK_E_NONE;
        }
        break;
#if PHY_CONFIG_INCLUDE_XAUI_TX_LANE_MAP_SET
    case PhyConfig_XauiTxLaneRemap: {
        int ioerr = 0;
        int do_swap = 0;
        uint32_t ln_swap;

        if ((val == 0x0123) || (val == 0)) {
            do_swap = 0;
        } else if (val == 0x3210) {
            do_swap = 1;
        } else {
            /* Can't do arbitrary remap */
            break;
        }
        ioerr += PHY_BUS_READ(pc, PHY_XS_XGXS_TX_LANE_SWAP, &ln_swap);
        if (do_swap) {
            ln_swap |= XS_TX_LANE_SWAP;
        } else {
            ln_swap &= ~XS_TX_LANE_SWAP;
        }
        ioerr += PHY_BUS_WRITE(pc, PHY_XS_XGXS_TX_LANE_SWAP, ln_swap);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_RX_LANE_MAP_SET
    case PhyConfig_XauiRxLaneRemap: {
        int ioerr = 0;
        int do_swap = 0;
        uint32_t ln_swap;

        if ((val == 0x0123) || (val == 0)) {
            do_swap = 0;
        } else if (val == 0x3210) {
            do_swap = 1;
        } else {
            /* Can't do arbitrary remap */
            break;
        }
        ioerr += PHY_BUS_READ(pc, PHY_XS_XGXS_RX_LANE_SWAP, &ln_swap);
        if (do_swap) {
            ln_swap |= XS_RX_LANE_SWAP;
        } else {
            ln_swap &= ~XS_RX_LANE_SWAP;
        }
        ioerr += PHY_BUS_WRITE(pc, PHY_XS_XGXS_RX_LANE_SWAP, ln_swap);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_TX_POLARITY_SET
    case PhyConfig_XauiTxPolInvert: {
        int ioerr = 0;
        uint32_t tx_invert;
        ioerr += PHY_BUS_READ(pc, PHY_XS_XGXS_TX_POLARITY, &tx_invert);
        if (val) {
            tx_invert |= XS_TX_POLARITY_INVERT;
        } else {
            tx_invert &= ~XS_TX_POLARITY_INVERT;
        }
        ioerr += PHY_BUS_WRITE(pc, PHY_XS_XGXS_TX_POLARITY, tx_invert);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_RX_POLARITY_SET
    case PhyConfig_XauiRxPolInvert: {
        int ioerr = 0;
        uint32_t rx_invert;
        ioerr += PHY_BUS_READ(pc, PHY_XS_XGXS_RX_POLARITY, &rx_invert);
        if (val) {
            rx_invert |= XS_RX_POLARITY_INVERT;
        } else {
            rx_invert &= ~XS_RX_POLARITY_INVERT;
        }
        ioerr += PHY_BUS_WRITE(pc, PHY_XS_XGXS_RX_POLARITY, rx_invert);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_PCS_TX_POLARITY_SET
    case PhyConfig_PcsTxPolInvert: {
        int ioerr = 0;
        uint32_t pcs_invert;
        ioerr += PHY_BUS_READ(pc, PCS_POLARITY, &pcs_invert);
        /* Note that 0 means invert */
        if (val) {
            pcs_invert &= ~PCS_TX_POLARITY_INVERT_L;
        } else {
            pcs_invert |= PCS_TX_POLARITY_INVERT_L;
        }
        ioerr += PHY_BUS_WRITE(pc, PCS_POLARITY, pcs_invert);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_PCS_RX_POLARITY_SET
    case PhyConfig_PcsRxPolInvert: {
        int ioerr = 0;
        uint32_t pcs_invert;
        ioerr += PHY_BUS_READ(pc, PCS_POLARITY, &pcs_invert);
        if (val) {
            pcs_invert |= PCS_RX_POLARITY_INVERT;
        } else {
            pcs_invert &= ~PCS_RX_POLARITY_INVERT;
        }
        ioerr += PHY_BUS_WRITE(pc, PCS_POLARITY, pcs_invert);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcm8073_phy_config_get
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
bcm8073_phy_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
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
        return CDK_E_NONE;
    case PhyConfig_Clause45Devs:
        *val = 0x9a;
        return CDK_E_NONE;
#if PHY_CONFIG_INCLUDE_XAUI_TX_LANE_MAP_SET
    case PhyConfig_XauiTxLaneRemap: {
        int ioerr = 0;
        uint32_t ln_swap;

        ioerr += PHY_BUS_READ(pc, PHY_XS_XGXS_TX_LANE_SWAP, &ln_swap);
        *val = (ln_swap & XS_TX_LANE_SWAP) ? 0x3210 : 0x0123;
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_RX_LANE_MAP_SET
    case PhyConfig_XauiRxLaneRemap: {
        int ioerr = 0;
        uint32_t ln_swap;

        ioerr += PHY_BUS_READ(pc, PHY_XS_XGXS_RX_LANE_SWAP, &ln_swap);
        *val = (ln_swap & XS_RX_LANE_SWAP) ? 0x3210 : 0x0123;
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_TX_POLARITY_SET
    case PhyConfig_XauiTxPolInvert: {
        int ioerr = 0;
        uint32_t tx_invert;

        ioerr += PHY_BUS_READ(pc, PHY_XS_XGXS_TX_POLARITY, &tx_invert);
        *val = (tx_invert & XS_TX_POLARITY_INVERT) ? 1 : 0;
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_RX_POLARITY_SET
    case PhyConfig_XauiRxPolInvert: {
        int ioerr = 0;
        uint32_t rx_invert;

        ioerr += PHY_BUS_READ(pc, PHY_XS_XGXS_RX_POLARITY, &rx_invert);
        *val = (rx_invert & XS_RX_POLARITY_INVERT) ? 1 : 0;
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_PCS_TX_POLARITY_SET
    case PhyConfig_PcsTxPolInvert: {
        int ioerr = 0;
        uint32_t pcs_invert;

        /* Note that 0 means invert */
        ioerr += PHY_BUS_READ(pc, PCS_POLARITY, &pcs_invert);
        *val = (pcs_invert & PCS_TX_POLARITY_INVERT_L) ? 0 : 1;
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_PCS_RX_POLARITY_SET
    case PhyConfig_PcsRxPolInvert: {
        int ioerr = 0;
        uint32_t pcs_invert;

        ioerr += PHY_BUS_READ(pc, PCS_POLARITY, &pcs_invert);
        *val = (pcs_invert & PCS_RX_POLARITY_INVERT) ? 1 : 0;
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Variable:    bcm8073_drv
 * Purpose:     PHY Driver for BCM8073.
 */
phy_driver_t bcm8073_drv = {
    "bcm8073",
    "BCM8073 10-Gigabit PHY Driver",  
    0,
    bcm8073_phy_probe,                  /* pd_probe */
    bcm8073_phy_notify,                 /* pd_notify */
    bcm8073_phy_reset,                  /* pd_reset */
    bcm8073_phy_init,                   /* pd_init */
    bcm8073_phy_link_get,               /* pd_link_get */
    bcm8073_phy_duplex_set,             /* pd_duplex_set */
    bcm8073_phy_duplex_get,             /* pd_duplex_get */
    bcm8073_phy_speed_set,              /* pd_speed_set */
    bcm8073_phy_speed_get,              /* pd_speed_get */
    bcm8073_phy_autoneg_set,            /* pd_autoneg_set */
    bcm8073_phy_autoneg_get,            /* pd_autoneg_get */
    bcm8073_phy_loopback_set,           /* pd_loopback_set */
    bcm8073_phy_loopback_get,           /* pd_loopback_get */
    bcm8073_phy_ability_get,            /* pd_ability_get */
    bcm8073_phy_config_set,             /* pd_config_set */
    bcm8073_phy_config_get,             /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
