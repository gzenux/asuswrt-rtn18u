/*
 * $Id: bcm8752_drv.c,v 1.7 Broadcom SDK $
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
 * PHY driver for BCM8752.
 *
 */

#include <phy/phy.h>
#include <phy/ge_phy.h>

#define PHY_RESET_POLL_MAX              10
#define PHY_ROM_LOAD_POLL_MAX           500
#define PHY_LANES_POLL_MAX              1000

#define BCM8752_PMA_PMD_ID0             0x0362
#define BCM8752_PMA_PMD_ID1             0x5f90
#define BCM8752_CHIP_ID                 0x8752

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
#define AN_MISC2_REG                    (DEVAD_AN + 0x8309)

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
#define AN_CTRL_ENABLE                  (1L << 12)
#define AN_CTRL_RESTART                 (1L << 9)

/* AN Status register */
#define AN_STAT_AN_DONE                 (1L << 5)

/* AN Link Status register */
#define AN_LINK_STATUS_1G               (1L << 2)

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
 *      bcm8752_phy_probe
 * Purpose:     
 *      Probe for 8752 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8752_phy_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, PMA_PMD_ID0_REG, &phyid0);
    ioerr += PHY_BUS_READ(pc, PMA_PMD_ID1_REG, &phyid1);

    if (ioerr) {
        return CDK_E_IO;
    }

    if ((phyid0 == BCM8752_PMA_PMD_ID0) &&
        ((phyid1 & ~0xf) == (BCM8752_PMA_PMD_ID1 & ~0xf))) {
        return CDK_E_NONE;
    }

    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcm8752_phy_notify
 * Purpose:     
 *      Handle PHY notifications
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8752_phy_notify(phy_ctrl_t *pc, phy_event_t event)
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
 *      bcm8752_phy_reset
 * Purpose:     
 *      Reset 8752 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8752_phy_reset(phy_ctrl_t *pc)
{
    uint32_t mmf_pma_pmd_ctrl, mmf_pcs_ctrl;
    uint32_t xfi_pma_pmd_ctrl, xfi_pcs_ctrl;
    int cnt;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* Reset all internal devices */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, MII_CTRL_RESET);
    ioerr += PHY_BUS_WRITE(pc, PCS_CTRL_REG, MII_CTRL_RESET);
    /* Switch to XFI */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_FFFF_REG, 0x0001);
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, MII_CTRL_RESET);
    ioerr += PHY_BUS_WRITE(pc, PCS_CTRL_REG, MII_CTRL_RESET);
    /* Switch to MMF */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_FFFF_REG, 0x0000);

    /* Wait for reset completion */
    for (cnt = 0; cnt < PHY_RESET_POLL_MAX; cnt++) {
        ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &mmf_pma_pmd_ctrl);
        ioerr += PHY_BUS_READ(pc, PCS_CTRL_REG, &mmf_pcs_ctrl);
        /* Switch to XFI */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_FFFF_REG, 0x0001);
        ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &xfi_pma_pmd_ctrl);
        ioerr += PHY_BUS_READ(pc, PCS_CTRL_REG, &xfi_pcs_ctrl);
        /* Switch to MMF */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_FFFF_REG, 0x0000);
        if (((mmf_pma_pmd_ctrl | mmf_pma_pmd_ctrl | 
              xfi_pma_pmd_ctrl | xfi_pcs_ctrl) & MII_CTRL_RESET) == 0) {
            break;
        }
    }
    if (cnt >= PHY_RESET_POLL_MAX) {
        PHY_WARN(pc, ("reset timeout"));
    }

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_RESET(PHY_CTRL_NEXT(pc));
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      bcm8752_phy_init
 * Purpose:     
 *      Initialize 8752 PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8752_phy_init(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    uint32_t data;

    PHY_CTRL_CHECK(pc);

    PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;

#if PHY_CONFIG_EXTERNAL_BOOT_ROM
    ioerr += PHY_BUS_READ(pc, SPI_PORT_CTRL_STAT_REG, &data);
    data |= 0xc000;
    ioerr += PHY_BUS_WRITE(pc, SPI_PORT_CTRL_STAT_REG, data);

    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, MII_CTRL_RESET);
    PHY_SYS_USLEEP(200000);
#endif
    ioerr += PHY_BUS_READ(pc, PMA_PMD_GEN_REG_2, &data);
    if (data > 0x0301) {
        ioerr += PHY_BUS_READ(pc, PMA_PMD_GEN_REG_4, &data);
        if (data != 0x600d) {
            PHY_WARN(pc, ("bad checksum"));
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

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_INIT(PHY_CTRL_NEXT(pc));
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm8752_phy_link_get
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
bcm8752_phy_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    uint32_t stat;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    /* Check autoneg status before link status */
    if (autoneg_done) {
        ioerr += PHY_BUS_READ(pc, AN_MII_STAT_REG, &stat);
        *autoneg_done = (stat & AN_STAT_AN_DONE);
    }


    /* 10G link must be up in all devices */
    *link = 0;
    ioerr += PHY_BUS_READ(pc, PMA_PMD_STAT_REG, &stat);
    if (stat & MII_STAT_LA) {
        ioerr += PHY_BUS_READ(pc, PCS_STAT_REG, &stat);
        if (stat & MII_STAT_LA) {
            *link = 1;
        }
    }

    /* Check 1G link only if no 10G link */
    if (*link == 0) {
        ioerr += PHY_BUS_READ(pc, AN_MII_STAT_REG, &stat);
        *link = ((stat & MII_STAT_LA) != 0);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm8752_phy_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8752_phy_duplex_set(phy_ctrl_t *pc, int duplex)
{
    return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
}

/*
 * Function:    
 *      bcm8752_phy_duplex_get
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
bcm8752_phy_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcm8752_phy_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8752_phy_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    uint32_t pma_pmd_ctrl;
    uint32_t cur_speed;
    int an;
    int ioerr = 0;
    int rv;

    PHY_CTRL_CHECK(pc);

    /* Call up the PHY chain */
    rv = PHY_SPEED_SET(PHY_CTRL_NEXT(pc), speed);
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    /* Leave hardware alone if speed is unchanged */
    rv = PHY_SPEED_GET(pc, &cur_speed);
    if (CDK_SUCCESS(rv) && speed == cur_speed) {
        return CDK_E_NONE;
    }

    if (CDK_SUCCESS(rv)) {
        rv = PHY_AUTONEG_GET(pc, &an);
    }

    /* Leave hardware alone if auto-neg is enabled */
    if (CDK_SUCCESS(rv) && an == 0) {
        switch (speed) {
        case 10000:
            /* Select 10G mode */
            ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);
            pma_pmd_ctrl |= PMA_PMD_CTRL_SPEED_10G;
            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, pma_pmd_ctrl);

            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL2_REG,
                                   PMA_PMD_CTRL2_TYPE_10G_LRM);

            /* Restart auto-neg and wait */
            ioerr += PHY_BUS_WRITE(pc, AN_CTRL_REG,
                                   AN_CTRL_ENABLE |
                                   AN_CTRL_RESTART);
            PHY_SYS_USLEEP(40000);

            /* Restore auto-neg setting */
            ioerr += PHY_BUS_WRITE(pc, AN_CTRL_REG, 0);
            break;

        case 1000:
            /* Select 1G by-pass mode */
            ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);
            pma_pmd_ctrl &= ~PMA_PMD_CTRL_SPEED_10G;
            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, pma_pmd_ctrl);

            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL2_REG,
                                   PMA_PMD_CTRL2_TYPE_1G_KX);
            break;
        default:
            return CDK_E_PARAM;
        }
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm8752_phy_speed_get
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
bcm8752_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    uint32_t pma_pmd_ctrl2, link_stat;
    int an;
    int ioerr = 0;
    int rv;

    PHY_CTRL_CHECK(pc);

    *speed = 0;

    rv = PHY_AUTONEG_GET(pc, &an);
    if (CDK_SUCCESS(rv)) {
        if (an) {
            ioerr += PHY_BUS_READ(pc, AN_MII_STAT_REG, &link_stat);
            if (link_stat & AN_LINK_STATUS_1G) {
                *speed = 1000;
            }
        } else {
            ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL2_REG, &pma_pmd_ctrl2);
            if ((pma_pmd_ctrl2 & PMA_PMD_CTRL2_TYPE_MASK) 
                               == PMA_PMD_CTRL2_TYPE_1G_KX) {
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
 *      bcm8752_phy_autoneg_set
 * Purpose:     
 *      Enable or disable auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8752_phy_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;

    if (autoneg) {
        ioerr += PHY_BUS_WRITE(pc, AN_MISC2_REG, 0);
        ioerr += PHY_BUS_WRITE(pc, AN_MII_CTRL_REG, 0x1300);
                               
    } else {
        ioerr += PHY_BUS_WRITE(pc, AN_MII_CTRL_REG, 0);
        ioerr += PHY_BUS_WRITE(pc, AN_MISC2_REG, 0x0020);
    }

    /* Disable autoneg in upstream PHY */
    rv = PHY_AUTONEG_SET(PHY_CTRL_NEXT(pc), 0);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm8752_phy_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation setting.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8752_phy_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    uint32_t ctrl;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    if (autoneg) {
        ioerr += PHY_BUS_READ(pc, AN_MII_CTRL_REG, &ctrl);
        *autoneg = (ctrl & AN_CTRL_ENABLE);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm8752_phy_loopback_set
 * Purpose:     
 *      Set the internal PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8752_phy_loopback_set(phy_ctrl_t *pc, int enable)
{
    uint32_t pma_pmd_ctrl;
    int ioerr = 0;

    /* Read loopback control registers */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);

    pma_pmd_ctrl &= ~PMA_PMD_CTRL_LB;
    if (enable) {
        pma_pmd_ctrl |= PMA_PMD_CTRL_LB;
    }

    /* Write updated loopback control registers */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, pma_pmd_ctrl);

    return ioerr ? CDK_E_IO : 0;
}

/*
 * Function:    
 *      bcm8752_phy_loopback_get
 * Purpose:     
 *      Get the local PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8752_phy_loopback_get(phy_ctrl_t *pc, int *enable)
{
    uint32_t pma_pmd_ctrl;
    int ioerr = 0;

    /* Read loopback control registers */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);
    *enable = (pma_pmd_ctrl & PMA_PMD_CTRL_LB) ? 1 : 0;

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm8752_phy_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm8752_phy_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    *abil = (PHY_ABIL_10GB | 
             PHY_ABIL_LOOPBACK | PHY_ABIL_1000MB_FD);

    return CDK_E_NONE;
}

/*
 * Function:
 *      bcm8752_phy_config_set
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
bcm8752_phy_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        switch (val) {
        case PHY_IF_XFI:
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
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcm8752_phy_config_get
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
bcm8752_phy_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = 1;
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        *val = PHY_IF_XFI;
        return CDK_E_NONE;
    case PhyConfig_Mode:
        *val = PHY_MODE_LAN;
        return CDK_E_NONE;
    case PhyConfig_Clause45Devs:
        *val = 0x8a;
        return CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Variable:    bcm8752_drv
 * Purpose:     PHY Driver for BCM8752.
 */
phy_driver_t bcm8752_drv = {
    "bcm8752",
    "BCM8752 10-Gigabit PHY Driver",  
    0,
    bcm8752_phy_probe,                  /* pd_probe */
    bcm8752_phy_notify,                 /* pd_notify */
    bcm8752_phy_reset,                  /* pd_reset */
    bcm8752_phy_init,                   /* pd_init */
    bcm8752_phy_link_get,               /* pd_link_get */
    bcm8752_phy_duplex_set,             /* pd_duplex_set */
    bcm8752_phy_duplex_get,             /* pd_duplex_get */
    bcm8752_phy_speed_set,              /* pd_speed_set */
    bcm8752_phy_speed_get,              /* pd_speed_get */
    bcm8752_phy_autoneg_set,            /* pd_autoneg_set */
    bcm8752_phy_autoneg_get,            /* pd_autoneg_get */
    bcm8752_phy_loopback_set,           /* pd_loopback_set */
    bcm8752_phy_loopback_get,           /* pd_loopback_get */
    bcm8752_phy_ability_get,            /* pd_ability_get */
    bcm8752_phy_config_set,             /* pd_config_set */
    bcm8752_phy_config_get,             /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
