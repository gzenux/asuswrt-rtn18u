/*
 * $Id: bcmi_unicore16g_xgxs_drv.c,v 1.14 Broadcom SDK $
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
 * PHY driver for internal Unicore 16G XGXS PHY.
 *
 */

#include <phy/phy.h>
#include <phy/phy_xgs_iblk.h>
#include <phy/phy_brcm_serdes_id.h>
#include <phy/ge_phy.h>

#include <phy/chip/bcmi_unicore16g_xgxs_defs.h>

#define BCM_SERDES_PHY_ID0              0x143
#define BCM_SERDES_PHY_ID1              0xbff0

#define PHY_ID1_REV_MASK                0x000f

#define SERDES_ID0_XGXS_16G             0x01

#define _PHY_REG_READ(_pc, _r, _v)      phy_xgs_iblk_read(_pc, _r, _v)
#define _PHY_REG_WRITE(_pc, _r, _v)     phy_xgs_iblk_write(_pc, _r, _v)

/* Transform datasheet mapped address to MIIM address used by software API */
#define XGS_MIIM_REG(_b) \
    ((((_b) & 0x7ff0) << 8) | (((_b) & 0x8000) >> 11) | ((_b) & 0xf))

/* IEEE MII Control Register */
#define XGXS_IEEE_CTRL_SW_RST           (1 << 15)
#define XGXS_IEEE_CTRL_LB               (1 << 14)
#define XGXS_IEEE_CTRL_SW_PD            (1 << 13)
#define XGXS_IEEE_CTRL_PMD_LB           (1 << 0)

/* XGXS BLOCK0 xgxsControl Register */
#define XGXS_BLK0_XGXS_CTRL_REG         XGS_MIIM_REG(0x8000)
#define XGXS_CTRL_START_SEQ             (1 << 13)
#define XGXS_CTRL_MODE_10G_GET(_r)      ((_r >> 8) & 0xf)
#define XGXS_CTRL_MODE_10G_SET(_r,_v)   _r = ((_r & ~(0xf << 8)) | (((_v) & 0xf) << 8))
#define MODE_10G_IND_LN_OS5             5
#define MODE_10G_IND_LN                 6
#define MODE_10G_COMBO                  12

/* XGXS BLOCK0 miscControl1 Register */
#define XGXS_BLK0_MISC_CTRL1_REG        XGS_MIIM_REG(0x800e)
#define MISC_CTRL1_PMD_EN               (1 << 9)
#define MISC_CTRL1_IEEE_AUTO            (1 << 1)
#define MISC_CTRL1_IEEE_XAUI            (1 << 0)

/* Tx LaneX/All TxAControl0 Register */
#define TX_LN0_TX_CTRL_REG              XGS_MIIM_REG(0x8061)
#define TX_LN1_TX_CTRL_REG              XGS_MIIM_REG(0x8071)
#define TX_LN2_TX_CTRL_REG              XGS_MIIM_REG(0x8081)
#define TX_LN3_TX_CTRL_REG              XGS_MIIM_REG(0x8091)
#define TX_ALL_TX_CTRL_REG              XGS_MIIM_REG(0x80a1)
#define TX_CTRL_TXPOL_FLIP              (1 << 5)

/* XGXS BLOCK2 rxLnSwap Register */
#define XGXS_BLK2_RX_LN_SWAP_REG        XGS_MIIM_REG(0x8100)
#define RX_LN_SWAP_EN                   (1 << 15)
#define RX_LN_SWAP_FORCE                (1 << 14)
#define RX_LN_SWAP_MAP_GET(_r)          ((_r >> 0) & 0xff)
#define RX_LN_SWAP_MAP_SET(_r,_v)       _r = ((_r & ~(0xff << 0)) | (((_v) & 0xff) << 0))

/* XGXS BLOCK2 txLnSwap Register */
#define XGXS_BLK2_TX_LN_SWAP_REG        XGS_MIIM_REG(0x8101)
#define TX_LN_SWAP_EN                   (1 << 15)
#define TX_LN_SWAP_MAP_GET(_r)          ((_r >> 0) & 0xff)
#define TX_LN_SWAP_MAP_SET(_r,_v)       _r = ((_r & ~(0xff << 0)) | (((_v) & 0xff) << 0))

/* GP Status xgxsStatus1 Register */
#define GP_STAT_XGXS_STAT1_REG          XGS_MIIM_REG(0x8122)
#define XGXS_STAT1_LINK_10G             (1 << 9)
#define XGXS_STAT1_LINK_STAT            (1 << 8)
#define XGXS_STAT1_AUTONEG_DONE         (1 << 7)
#define XGXS_STAT1_SPEED_GET(_r)        ((_r >> 0) & 0xf)
#define XGXS_STAT1_SPEED_SET(_r,_v)     _r = ((_r & ~(0xf << 0)) | (((_v) & 0xf) << 0))
#define STAT1_SPEED_10                  0
#define STAT1_SPEED_100                 1
#define STAT1_SPEED_1000                2
#define STAT1_SPEED_2500                3
#define STAT1_SPEED_10000_HG            6
#define STAT1_SPEED_10000_CX4           7
#define STAT1_SPEED_12000               8
#define STAT1_SPEED_13000               10
#define STAT1_SPEED_16000               12

/* GP Status xgxsStatus3 Register */
#define GP_STAT_XGXS_STAT3_REG          XGS_MIIM_REG(0x8129)
#define XGXS_STAT3_LINK                 (1 << 15)
#define XGXS_STAT3_LINK_LATCHLOW        (1 << 14)

/* Rx All Rx Control Register */
#define RX_ALL_RX_CTRL_REG              XGS_MIIM_REG(0x80f1)
#define XGXS_RX_CTRL_RX_SEQ_DONE        (1 << 4)

/*  10G Parallel Detect parDet10GControl Register */
#define PAR_DET_10G_CTRL_REG            XGS_MIIM_REG(0x8131)
#define PAR_DET_10G_EN                  (1 << 0)

/* SerDes Digital 1000XControl1 Register */
#define DIGITAL_1000X_CTRL1_REG         XGS_MIIM_REG(0x8300)
#define D1000X_CTRL1_AUTO_DETECT        (1 << 4)
#define D1000X_CTRL1_FIBER_MODE         (1 << 0)

/* SerDes Digital 1000XControl2 Register */
#define DIGITAL_1000X_CTRL2_REG         XGS_MIIM_REG(0x8301)
#define D1000X_CTRL2_PAR_DET_EN         (1 << 0)

/* SerDes Digital Misc1 Register */
#define DIGITAL_MISC1_REG               XGS_MIIM_REG(0x8308)
#define MISC1_FORCE_SPEED_SEL           (1 << 4)
#define MISC1_FORCE_SPEED_GET(_r)       ((_r >> 0) & 0xf)
#define MISC1_FORCE_SPEED_SET(_r,_v)    _r = ((_r & ~(0xf << 0)) | (((_v) & 0xf) << 0))
#define MISC1_SPEED_2500                0
#define MISC1_SPEED_10000_HG            3
#define MISC1_SPEED_10000_CX4           4
#define MISC1_SPEED_12000               5
#define MISC1_SPEED_13000               7
#define MISC1_SPEED_16000               9

/* IEEE-B0 MII Control Register */
#define B0_MII_CTRL_REG                 XGS_MIIM_REG(0xffe0)

/* IEEE-B0 MII Status Register */
#define B0_MII_STAT_REG                 XGS_MIIM_REG(0xffe1)

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
extern cdk_symbols_t bcmi_unicore16g_xgxs_symbols;
#define SET_SYMBOL_TABLE(_pc) \
    PHY_CTRL_SYMBOLS(_pc) = &bcmi_unicore16g_xgxs_symbols
#else
#define SET_SYMBOL_TABLE(_pc)
#endif

/*
 * Function:
 *      bcmi_unicore16g_xgxs_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore16g_xgxs_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1, serdesid0, serdesid2, xgxs_ctrl;
    int ioerr = 0;

    ioerr += phy_brcm_serdes_id(pc, &phyid0, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCM_SERDES_PHY_ID0 && phyid1 == BCM_SERDES_PHY_ID1) {
        /* Common PHY ID found - read specific SerDes ID */
        ioerr += _PHY_REG_READ(pc, SERDES_ID0, &serdesid0);
        if ((serdesid0 & 0x3f) == SERDES_ID0_XGXS_16G) {
            /* Check for similar cores by reading supported speeds */
            ioerr += _PHY_REG_READ(pc, SERDES_ID2, &serdesid2);
            if ((serdesid2 & (1 << 11)) == 0) {
                /* 16G not supported */
                return ioerr ? CDK_E_IO : CDK_E_NOT_FOUND;
            }
            /* Check for ComboCore mode */
            ioerr += _PHY_REG_READ(pc, XGXS_BLK0_XGXS_CTRL_REG, &xgxs_ctrl);
            if (XGXS_CTRL_MODE_10G_GET(xgxs_ctrl) != MODE_10G_COMBO) {
                return ioerr ? CDK_E_IO : CDK_E_NOT_FOUND;
            }
            SET_SYMBOL_TABLE(pc);
            return ioerr ? CDK_E_IO : CDK_E_NONE;
        }
    }
    return CDK_E_NOT_FOUND;
}


/*
 * Function:
 *      bcmi_unicore16g_xgxs_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore16g_xgxs_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int ioerr = 0;
    uint32_t ctrl1;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToPassthru:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) |= PHY_F_PASSTHRU;
        /* Put Gigabit Serdes in passthru mode */
        ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_CTRL1_REG, &ctrl1);
        ctrl1 &= ~D1000X_CTRL1_FIBER_MODE;
        ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL1_REG, ctrl1);
        break;
    case PhyEvent_ChangeToFiber:
        PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_PASSTHRU;
        /* Put Gigabit Serdes in fiber mode */
        ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_CTRL1_REG, &ctrl1);
        ctrl1 |= D1000X_CTRL1_FIBER_MODE;
        ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL1_REG, ctrl1);
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

    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_unicore16g_xgxs_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore16g_xgxs_reset(phy_ctrl_t *pc)
{
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_unicore16g_xgxs_init
 * Purpose:     
 *      Initialize PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_NONE
 */
static int
bcmi_unicore16g_xgxs_init(phy_ctrl_t *pc)
{
    /* Default mode is fiber */
    PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore16g_xgxs_link_get
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
bcmi_unicore16g_xgxs_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    uint32_t xgxs_stat1, xgxs_stat3;

    PHY_CTRL_CHECK(pc);

    if (link) {
        ioerr += _PHY_REG_READ(pc, GP_STAT_XGXS_STAT3_REG, &xgxs_stat3);
        *link = (xgxs_stat3 & XGXS_STAT3_LINK_LATCHLOW) ? 1 : 0;
    }

    if (autoneg_done) {
        ioerr += _PHY_REG_READ(pc, GP_STAT_XGXS_STAT1_REG, &xgxs_stat1);
        *autoneg_done = (xgxs_stat1 & XGXS_STAT1_AUTONEG_DONE) ? 1 : 0;
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_unicore16g_xgxs_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore16g_xgxs_duplex_set(phy_ctrl_t *pc, int duplex)
{
    return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
}

/*
 * Function:    
 *      bcmi_unicore16g_xgxs_duplex_get
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
bcmi_unicore16g_xgxs_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore16g_xgxs_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 * Notes:
 *      The actual speed is controlled elsewhere, so we accept any value.
 */
static int
bcmi_unicore16g_xgxs_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int ioerr = 0;
    int speed_val;
    uint32_t misc1, mii_ctrl;

    switch (speed) {
    case 16000:
        speed_val = MISC1_SPEED_16000;
        break;
    case 13000:
        speed_val = MISC1_SPEED_13000;
        break;
    case 12000:
        speed_val = MISC1_SPEED_12000;
        break;
    case 10000:
        speed_val = MISC1_SPEED_10000_CX4;
        break;
    case 2500:
        speed_val = MISC1_SPEED_2500;
        break;
    case 1000:
    case 100:
    case 10:
        speed_val = -1;
        break;
    case 0:
        return CDK_E_NONE;
    default:
        return CDK_E_PARAM;
    }

    ioerr += _PHY_REG_READ(pc, DIGITAL_MISC1_REG, &misc1);
    misc1 &= ~MISC1_FORCE_SPEED_SEL;
    if (speed_val >= 0) {
        misc1 |= MISC1_FORCE_SPEED_SEL;
        MISC1_FORCE_SPEED_SET(misc1, speed_val);
    }
    ioerr += _PHY_REG_WRITE(pc, DIGITAL_MISC1_REG, misc1);

    /* Speeds of 2.5 Gbps and below must be set in IEEE registers */
    if (speed <= 2500) {
        ioerr += _PHY_REG_READ(pc, B0_MII_CTRL_REG, &mii_ctrl);
        mii_ctrl &= ~(MII_CTRL_SS_MASK | MII_CTRL_FS_2500);
        if (speed == 2500) {
            /* Force 2.5 Gbps */
            mii_ctrl |= MII_CTRL_FS_2500;
        } else if (speed == 1000) {
            mii_ctrl |= MII_CTRL_SS_1000;
        } else if (speed == 100) {
            mii_ctrl |= MII_CTRL_SS_100;
        } else {
            mii_ctrl |= MII_CTRL_SS_10;
        }
        ioerr += _PHY_REG_WRITE(pc, B0_MII_CTRL_REG, mii_ctrl);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore16g_xgxs_speed_get
 * Purpose:     
 *      Get the current operating speed.
 * Parameters:
 *      pc - PHY control structure
 *      speed - (OUT) current link speed
 * Returns:     
 *      CDK_E_xxx
 * Notes:
 *      The actual speed is controlled elsewhere, so always return 10000
 *      for sanity purposes.
 */

static int
bcmi_unicore16g_xgxs_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int ioerr = 0;
    int rv;
    int autoneg = 0, autoneg_done = 0;
    uint32_t xgxs_stat1;

    *speed = 0;

    rv = PHY_AUTONEG_GET(pc, &autoneg);

    if (CDK_SUCCESS(rv) && autoneg) {
        rv = PHY_LINK_GET(pc, NULL, &autoneg_done);
    }

    if (!autoneg || autoneg_done) {
        ioerr += _PHY_REG_READ(pc, GP_STAT_XGXS_STAT1_REG, &xgxs_stat1);
        switch (XGXS_STAT1_SPEED_GET(xgxs_stat1)) {
        case STAT1_SPEED_16000:
            *speed = 16000;
            break;
        case STAT1_SPEED_13000:
            *speed = 13000;
            break;
        case STAT1_SPEED_12000:
            *speed = 12000;
            break;
        case STAT1_SPEED_10000_CX4:
            *speed = 10000;
            break;
        case STAT1_SPEED_10000_HG:
            *speed = 10000;
            break;
        case STAT1_SPEED_2500:
            *speed = 2500;
            break;
        case STAT1_SPEED_1000:
            *speed = 1000;
            break;
        case STAT1_SPEED_100:
            *speed = 100;
            break;
        case STAT1_SPEED_10:
            *speed = 10;
            break;
        default:
            break;
        }
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore16g_xgxs_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */

static int
bcmi_unicore16g_xgxs_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int ioerr = 0;
    uint32_t mii_ctrl, pd10g_ctrl, d1000x_ctrl1, d1000x_ctrl2;

    PHY_CTRL_CHECK(pc);

    /* In passthru mode we always disable autoneg */
    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU)) {
        autoneg = 0;
    }

    /* Set autoneg and parallel detect bits*/
    ioerr += _PHY_REG_READ(pc, B0_MII_CTRL_REG, &mii_ctrl);
    ioerr += _PHY_REG_READ(pc, PAR_DET_10G_CTRL_REG, &pd10g_ctrl);
    ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_CTRL1_REG, &d1000x_ctrl1);
    ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_CTRL2_REG, &d1000x_ctrl2);
    mii_ctrl &= ~MII_CTRL_AE;
    pd10g_ctrl &= ~PAR_DET_10G_EN;
    d1000x_ctrl1 &= ~D1000X_CTRL1_AUTO_DETECT;
    d1000x_ctrl2 &= ~D1000X_CTRL2_PAR_DET_EN;
    if (autoneg) {
        mii_ctrl |= MII_CTRL_AE | MII_CTRL_RAN;
        pd10g_ctrl |= PAR_DET_10G_EN;
        d1000x_ctrl1 |= D1000X_CTRL1_AUTO_DETECT;
        d1000x_ctrl2 |= D1000X_CTRL2_PAR_DET_EN;
    }
    ioerr += _PHY_REG_WRITE(pc, B0_MII_CTRL_REG, mii_ctrl);
    ioerr += _PHY_REG_WRITE(pc, PAR_DET_10G_CTRL_REG, pd10g_ctrl);
    ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL1_REG, d1000x_ctrl1);
    ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL2_REG, d1000x_ctrl2);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore16g_xgxs_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore16g_xgxs_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    int ioerr = 0;
    uint32_t mii_ctrl;

    ioerr += _PHY_REG_READ(pc, B0_MII_CTRL_REG, &mii_ctrl);
    *autoneg = (mii_ctrl & MII_CTRL_AE) ? 1 : 0;

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore16g_xgxs_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore16g_xgxs_loopback_set(phy_ctrl_t *pc, int enable)
{
    int ioerr = 0;
    uint32_t rx_ctrl, misc_ctrl1, o_misc_ctrl1, mii_ctrl;

    /* Control RX signal detect, so that a cable is not needed for loopback */
    ioerr += _PHY_REG_READ(pc, RX_ALL_RX_CTRL_REG, &rx_ctrl);
    if (enable) {
        /* Disable signal detect on all lanes */
        rx_ctrl |= XGXS_RX_CTRL_RX_SEQ_DONE;
    } else {
        /* Enable signal detect on all lanes (default) */
        rx_ctrl &= ~XGXS_RX_CTRL_RX_SEQ_DONE;
    }
    ioerr += _PHY_REG_WRITE(pc, RX_ALL_RX_CTRL_REG, rx_ctrl);
    
    /* Set loopback mode for SerDes */
    ioerr += _PHY_REG_READ(pc, B0_MII_CTRL_REG, &mii_ctrl);
    mii_ctrl &= ~MII_CTRL_LE;
    if (enable) {
        mii_ctrl |= MII_CTRL_LE;
    }
    ioerr += _PHY_REG_WRITE(pc, B0_MII_CTRL_REG, mii_ctrl);

    /* Force mapping of XAUI IEEE registers */
    ioerr += _PHY_REG_READ(pc, XGXS_BLK0_MISC_CTRL1_REG, &misc_ctrl1);
    o_misc_ctrl1 = misc_ctrl1;
    misc_ctrl1 &= ~MISC_CTRL1_IEEE_AUTO;
    misc_ctrl1 |= MISC_CTRL1_IEEE_XAUI;
    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK0_MISC_CTRL1_REG, misc_ctrl1);

    /* Set loopback mode for XAUI */
    ioerr += _PHY_REG_READ(pc, MII_CTRL_REG, &mii_ctrl);
    mii_ctrl &= ~XGXS_IEEE_CTRL_LB;
    if (enable) {
        mii_ctrl |= XGXS_IEEE_CTRL_LB;
    }
    ioerr += _PHY_REG_WRITE(pc, MII_CTRL_REG, mii_ctrl);

    /* Restore IEEE register mapping */
    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK0_MISC_CTRL1_REG, o_misc_ctrl1);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore16g_xgxs_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore16g_xgxs_loopback_get(phy_ctrl_t *pc, int *enable)
{
    int ioerr = 0;
    uint32_t mii_ctrl;

    /* Get loopback mode from SerDes registers */
    ioerr += _PHY_REG_READ(pc, B0_MII_CTRL_REG, &mii_ctrl);
    *enable = (mii_ctrl & MII_CTRL_LE) ? 1 : 0;

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore16g_xgxs_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore16g_xgxs_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    *abil = (PHY_ABIL_16GB | PHY_ABIL_13GB | PHY_ABIL_10GB | 
             PHY_ABIL_PAUSE | PHY_ABIL_LOOPBACK | 
             PHY_ABIL_XAUI | PHY_ABIL_XGMII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_unicore16g_xgxs_config_set
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
bcmi_unicore16g_xgxs_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
    case PhyConfig_PortInterface:
        return CDK_E_NONE;
#if PHY_CONFIG_INCLUDE_XAUI_TX_LANE_MAP_SET
    case PhyConfig_XauiTxLaneRemap: {
        int ioerr = 0;
        uint32_t ln_swap, ln_map;
        ioerr += _PHY_REG_READ(pc, XGXS_BLK2_TX_LN_SWAP_REG, &ln_swap);
        ln_swap &= ~TX_LN_SWAP_EN;
        if (val == 0xffffffff) {
            ln_swap |= TX_LN_SWAP_EN;
        } else if (val > 0) {
            ln_swap |= TX_LN_SWAP_EN;
            ln_map = 0;
            ln_map |= (val >> 12) & 0x03;
            ln_map |= (val >> 6)  & 0x0c;
            ln_map |= (val << 0)  & 0x30;
            ln_map |= (val << 6)  & 0xc0;
            TX_LN_SWAP_MAP_SET(ln_swap, ln_map);
        }
        ioerr += _PHY_REG_WRITE(pc, XGXS_BLK2_TX_LN_SWAP_REG, ln_swap);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_RX_LANE_MAP_SET
    case PhyConfig_XauiRxLaneRemap: {
        int ioerr = 0;
        uint32_t ln_swap, ln_map;
        ioerr += _PHY_REG_READ(pc, XGXS_BLK2_RX_LN_SWAP_REG, &ln_swap);
        ln_swap &= ~(RX_LN_SWAP_EN | RX_LN_SWAP_FORCE);
        if (val == 0xffffffff) {
            /* Auto-remap */
            ln_swap |= RX_LN_SWAP_EN;
        } else if (val > 0) {
            ln_swap |= (RX_LN_SWAP_EN | RX_LN_SWAP_FORCE);
            ln_map = 0;
            ln_map |= (val >> 12) & 0x03;
            ln_map |= (val >> 6)  & 0x0c;
            ln_map |= (val << 0)  & 0x30;
            ln_map |= (val << 6)  & 0xc0;
            RX_LN_SWAP_MAP_SET(ln_swap, ln_map);
        }
        ioerr += _PHY_REG_WRITE(pc, XGXS_BLK2_RX_LN_SWAP_REG, ln_swap);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_TX_POLARITY_SET
    case PhyConfig_XauiTxPolInvert: {
        int ioerr = 0;
        int lane;
        uint32_t txln_reg[] = { TX_LN0_TX_CTRL_REG, 
                                TX_LN1_TX_CTRL_REG, 
                                TX_LN2_TX_CTRL_REG, 
                                TX_LN3_TX_CTRL_REG };
        uint32_t tx_ctrl;
        for (lane = 0; lane <= 3; lane++) {
            ioerr += _PHY_REG_READ(pc, txln_reg[lane], &tx_ctrl);
            tx_ctrl &= ~TX_CTRL_TXPOL_FLIP;
            if (val & (1 << (lane * 4))) {
                tx_ctrl |= TX_CTRL_TXPOL_FLIP;
            }
            ioerr += _PHY_REG_WRITE(pc, txln_reg[lane], tx_ctrl);
        }
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
    case PhyConfig_TxPreemp: {
        int ioerr = 0;
        TX_ALL_TX_DRIVERr_t tx_drv;

        ioerr += READ_TX_ALL_TX_DRIVERr(pc, &tx_drv);
        TX_ALL_TX_DRIVERr_PREEMPHASISf_SET(tx_drv, val);
        ioerr += WRITE_TX_ALL_TX_DRIVERr(pc, tx_drv);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxIDrv: {
        int ioerr = 0;
        TX_ALL_TX_DRIVERr_t tx_drv;

        ioerr += READ_TX_ALL_TX_DRIVERr(pc, &tx_drv);
        TX_ALL_TX_DRIVERr_IDRIVERf_SET(tx_drv, val);
        ioerr += WRITE_TX_ALL_TX_DRIVERr(pc, tx_drv);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxPreIDrv: {
        int ioerr = 0;
        TX_ALL_TX_DRIVERr_t tx_drv;

        ioerr += READ_TX_ALL_TX_DRIVERr(pc, &tx_drv);
        TX_ALL_TX_DRIVERr_IPREDRIVERf_SET(tx_drv, val);
        ioerr += WRITE_TX_ALL_TX_DRIVERr(pc, tx_drv);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcmi_unicore16g_xgxs_config_get
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
bcmi_unicore16g_xgxs_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = 1;
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        *val = PHY_IF_XGMII;
        return CDK_E_NONE;
    case PhyConfig_TxPreemp: {
        int ioerr = 0;
        TX_ALL_TX_DRIVERr_t tx_drv;

        ioerr += READ_TX_ALL_TX_DRIVERr(pc, &tx_drv);
        *val = TX_ALL_TX_DRIVERr_PREEMPHASISf_GET(tx_drv);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxIDrv: {
        int ioerr = 0;
        TX_ALL_TX_DRIVERr_t tx_drv;

        ioerr += READ_TX_ALL_TX_DRIVERr(pc, &tx_drv);
        *val = TX_ALL_TX_DRIVERr_IDRIVERf_GET(tx_drv);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxPreIDrv: {
        int ioerr = 0;
        TX_ALL_TX_DRIVERr_t tx_drv;

        ioerr += READ_TX_ALL_TX_DRIVERr(pc, &tx_drv);
        *val = TX_ALL_TX_DRIVERr_IPREDRIVERf_GET(tx_drv);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/* Public PHY Driver Structure */
phy_driver_t bcmi_unicore16g_xgxs_drv = {
    "bcmi_unicore16g_xgxs", 
    "Internal Unicore 16G XGXS PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_unicore16g_xgxs_probe,         /* pd_probe */
    bcmi_unicore16g_xgxs_notify,        /* pd_notify */
    bcmi_unicore16g_xgxs_reset,         /* pd_reset */
    bcmi_unicore16g_xgxs_init,          /* pd_init */
    bcmi_unicore16g_xgxs_link_get,      /* pd_link_get */
    bcmi_unicore16g_xgxs_duplex_set,    /* pd_duplex_set */
    bcmi_unicore16g_xgxs_duplex_get,    /* pd_duplex_get */
    bcmi_unicore16g_xgxs_speed_set,     /* pd_speed_set */
    bcmi_unicore16g_xgxs_speed_get,     /* pd_speed_get */
    bcmi_unicore16g_xgxs_autoneg_set,   /* pd_autoneg_set */
    bcmi_unicore16g_xgxs_autoneg_get,   /* pd_autoneg_get */
    bcmi_unicore16g_xgxs_loopback_set,  /* pd_loopback_set */
    bcmi_unicore16g_xgxs_loopback_get,  /* pd_loopback_get */
    bcmi_unicore16g_xgxs_ability_get,   /* pd_ability_get */
    bcmi_unicore16g_xgxs_config_set,    /* pd_config_set */
    bcmi_unicore16g_xgxs_config_get,    /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
