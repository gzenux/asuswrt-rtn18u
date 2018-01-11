/*
 * $Id: bcmi_unicore13g_xgxs_drv.c,v 1.6 Broadcom SDK $
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
 * PHY driver for internal Unicore 13G XGXS PHY.
 *
 */

#include <phy/phy.h>
#include <phy/phy_xgs_iblk.h>
#include <phy/phy_brcm_serdes_id.h>

#include <phy/chip/bcmi_unicore13g_xgxs_defs.h>

#define BCM_SERDES_PHY_ID0              0x143
#define BCM_SERDES_PHY_ID1              0xbff0

#define PHY_ID1_REV_MASK                0x000f

#define SERDES_ID0_XGXS_16G             0x01

/* Core modes */
#define FV_XGXS                         0x0
#define FV_XGXG_nCC                     0x1
#define FV_Indlanes                     0x6
#define FV_PCI                          0x7
#define FV_XGXS_nLQ                     0x8
#define FV_XGXS_nLQnCC                  0x9
#define FV_PBypass                      0xa
#define FV_PBypass_nDSK                 0xb
#define FV_ComboCoreMode                0xc
#define FV_Clocks_off                   0xf

/* Supported speeds */
#define FV_sdr_16G_4L                   (1 << 11)
#define FV_sdr_15G_4L                   (1 << 10)
#define FV_sdr_13G_4L                   (1 << 9)
#define FV_sdr_12p5G_4L                 (1 << 8)
#define FV_sdr_12G_4L                   (1 << 7)
#define FV_sdr_10G_4L                   (1 << 6)
#define FV_sdr_6G_4L                    (1 << 5)
#define FV_sdr_5G_4L                    (1 << 4)
#define FV_sdr_2p5G_SL                  (1 << 3)
#define FV_sdr_1G_SL                    (1 << 2)
#define FV_sdr_100M_SL                  (1 << 1)
#define FV_sdr_10M_SL                   (1 << 0)

/* Forced speeds */
#define FV_fdr_2p5G                     0
#define FV_fdr_5G                       1
#define FV_fdr_6G                       2
#define FV_fdr_10G_CX4                  3
#define FV_fdr_10G_HiG                  4
#define FV_fdr_12G                      5
#define FV_fdr_12p5G                    6
#define FV_fdr_13G                      7

/* Actual speeds */
#define FV_adr_10M                      0
#define FV_adr_100M                     1
#define FV_adr_1G                       2
#define FV_adr_2p5G                     3
#define FV_adr_5G                       4
#define FV_adr_6G                       5
#define FV_adr_10G_HiG                  6
#define FV_adr_10G_CX4                  7
#define FV_adr_12G_HiG                  8
#define FV_adr_12p5G                    9
#define FV_adr_13G                      10
#define FV_adr_1G_KX                    13
#define FV_adr_10G_KX4                  14

#define PLL_LOCK_MSEC                   200

static const uint32_t _fdr[] = {
    /* FV_fdr_13G            */ 13000,
    /* FV_fdr_12p5G          */ 12500,
    /* FV_fdr_12G            */ 12000,
    /* FV_fdr_10G_HiG        */ 10000,
    /* FV_fdr_10G_CX4        */ 10000,
    /* FV_fdr_6G             */ 6000,
    /* FV_fdr_5G             */ 5000,
    /* FV_fdr_2p5G           */ 2500
};

static const uint32_t _adr[] = {
    /* FV_fdr_2p5G           */ 2500,
    /* FV_fdr_5G             */ 5000,
    /* FV_fdr_6G             */ 6000,
    /* FV_fdr_10G_CX4        */ 10000,
    /* FV_fdr_10G_HiG        */ 10000,
    /* FV_fdr_12G            */ 12000,
    /* FV_fdr_12p5G          */ 12500,
    /* FV_fdr_13G            */ 13000,
};

/* Low level debugging (off by default) */
#ifdef BCM_UC13G_DEBUG_ENABLE
#undef static
#define static
#define BCM_UC13G_DBG(_p) \
    CDK_WARN(_p)
#else
#define BCM_UC13G_DBG(_p)
#endif

/***********************************************************************
 *
 * HELPER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      _warpcore_pll_lock_wait
 * Purpose:
 *      Wait for PLL lock after sequencer (re)start.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_unicore13g_xgxs_pll_lock_wait(phy_ctrl_t *pc)
{
    int ioerr = 0;
    XGXSSTATUSr_t xgxs_stat;
    int cnt;
    int lock = 0;
    
    for (cnt = 0; ioerr == 0 && cnt < PLL_LOCK_MSEC; cnt++) {
        ioerr += READ_XGXSSTATUSr(pc, &xgxs_stat); 
        if (ioerr) {
            return CDK_E_IO;
        }
        lock = XGXSSTATUSr_TXPLL_LOCKf_GET(xgxs_stat);
        if (lock) {
            break;
        }
        PHY_SYS_USLEEP(1000);
    }
    if (lock == 0) {
        BCM_UC13G_DBG(("UC13G port: %d TXPLL did not lock\n", PHY_CTRL_PORT(pc)));
        return CDK_E_TIMEOUT;
    }
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_unicore13g_xgxs_stop
 * Purpose:
 *      Put PHY in or out of reset depending on conditions.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_unicore13g_xgxs_stop(phy_ctrl_t *pc)
{
    int ioerr = 0;
    LANECTRL3r_t lane_ctrl3;
    uint32_t pwrdn_tx, pwrdn_rx;
    uint32_t f_any = PHY_F_PHY_DISABLE | PHY_F_PORT_DRAIN;
    uint32_t f_copper = PHY_F_MAC_DISABLE | PHY_F_SPEED_CHG | PHY_F_DUPLEX_CHG;
    int stop;

    ioerr += READ_LANECTRL3r(pc, &lane_ctrl3);
    pwrdn_tx = LANECTRL3r_PWRDWN_TXf_GET(lane_ctrl3);

    stop = 0;
    if ((PHY_CTRL_FLAGS(pc) & f_any) ||
        ((PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) == 0 &&
         (PHY_CTRL_FLAGS(pc) & f_copper))) {
        stop = 1;
    }
    /* Disable Tx only as disabling Rx may affect 10G rx_ck */
    pwrdn_rx = 0;
    pwrdn_tx = 0;
    if (stop) {
        pwrdn_tx |= 0xf;
    }
    LANECTRL3r_PWRDWN_RXf_SET(lane_ctrl3, pwrdn_rx);
    LANECTRL3r_PWRDWN_TXf_SET(lane_ctrl3, pwrdn_tx);
    ioerr += WRITE_LANECTRL3r(pc, lane_ctrl3);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
extern cdk_symbols_t bcmi_unicore13g_xgxs_symbols;
#define SET_SYMBOL_TABLE(_pc) \
    PHY_CTRL_SYMBOLS(_pc) = &bcmi_unicore13g_xgxs_symbols
#else
#define SET_SYMBOL_TABLE(_pc)
#endif

/*
 * Function:
 *      bcmi_unicore13g_xgxs_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore13g_xgxs_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    SERDES_ID0r_t serdesid0;
    SERDES_ID2r_t serdesid2;
    XGXSCONTROLr_t xgxs_ctrl;
    MMDSELECTr_t mmdselect;
    uint32_t model;
    uint32_t speeds;
    int mode10g;
    int ioerr = 0;

    ioerr += phy_brcm_serdes_id(pc, &phyid0, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCM_SERDES_PHY_ID0 && phyid1 == BCM_SERDES_PHY_ID1) {
        /* Common PHY ID found - read specific SerDes ID */
        ioerr += READ_SERDES_ID0r(pc, &serdesid0);
        model = SERDES_ID0r_MODELf_GET(serdesid0);
        if (model == SERDES_ID0_XGXS_16G) {
            /* Check supported speeds (to distinguish from 16G version) */
            ioerr += READ_SERDES_ID2r(pc, &serdesid2);
            speeds = SERDES_ID2r_SPEEDf_GET(serdesid2);
            if (speeds & FV_sdr_16G_4L) {
                return ioerr ? CDK_E_IO : CDK_E_NOT_FOUND;
            }
            /* Check for independent lane mode */
            ioerr += READ_XGXSCONTROLr(pc, &xgxs_ctrl);
            mode10g = XGXSCONTROLr_MODE_10Gf_GET(xgxs_ctrl);
            if (mode10g != FV_ComboCoreMode) {
                return ioerr ? CDK_E_IO : CDK_E_NOT_FOUND;
            }
            /* Use clause 45 access if possible */
            ioerr += READ_MMDSELECTr(pc, &mmdselect);
            if (MMDSELECTr_MULTIMMDS_ENf_GET(mmdselect) == 1) {
                PHY_CTRL_FLAGS(pc) |= PHY_F_CLAUSE45;
            }
            SET_SYMBOL_TABLE(pc);
            return ioerr ? CDK_E_IO : CDK_E_NONE;
        }
    }
    return CDK_E_NOT_FOUND;
}


/*
 * Function:
 *      bcmi_unicore13g_xgxs_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore13g_xgxs_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int ioerr = 0;
    CONTROL1000X1r_t ctrl_1000x1;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToPassthru:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) |= PHY_F_PASSTHRU;
        /* Put the Serdes in passthru mode */
        ioerr += READ_CONTROL1000X1r(pc, &ctrl_1000x1);
        CONTROL1000X1r_FIBER_MODE_1000Xf_SET(ctrl_1000x1, 0);
        ioerr += WRITE_CONTROL1000X1r(pc, ctrl_1000x1);
        break;
    case PhyEvent_ChangeToFiber:
        PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_PASSTHRU;
        /* Put the Serdes in fiber mode */
        ioerr += READ_CONTROL1000X1r(pc, &ctrl_1000x1);
        CONTROL1000X1r_FIBER_MODE_1000Xf_SET(ctrl_1000x1, 1);
        ioerr += WRITE_CONTROL1000X1r(pc, ctrl_1000x1);
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

    /* Update power-down state */
    bcmi_unicore13g_xgxs_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_unicore13g_xgxs_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore13g_xgxs_reset(phy_ctrl_t *pc)
{
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_unicore13g_xgxs_init
 * Purpose:     
 *      Initialize PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_NONE
 */
static int
bcmi_unicore13g_xgxs_init(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    int ioerr = 0;
    LANETESTr_t lanetest;
    XGXSCONTROLr_t xgxsctrl;
    LOCALCONTROL0r_t lctrl;
    FXCONTROL1r_t fx100_ctrl1;
    FXCONTROL2r_t fx100_ctrl2;
    CONTROL1000X2r_t ctrl_1000x2;
    CONTROL1000X3r_t ctrl_1000x3;
    PARDET10GLINKr_t pd10g_link;

    PHY_CTRL_CHECK(pc);

    /* Stop sequencer */
    ioerr += READ_XGXSCONTROLr(pc, &xgxsctrl);
    XGXSCONTROLr_START_SEQUENCERf_SET(xgxsctrl, 0);
    ioerr += WRITE_XGXSCONTROLr(pc, xgxsctrl);

    /* Leave clocks enabled in power-down mode */
    ioerr += READ_LANETESTr(pc, &lanetest);
    LANETESTr_PWRDN_CLKS_ENf_SET(lanetest, 1);
    LANETESTr_LFCK_BYPASSf_SET(lanetest, 1);
    ioerr += WRITE_LANETESTr(pc, lanetest);

    /* Keep in-band MDIO in reset */
    READ_LOCALCONTROL0r(pc, &lctrl);
    LOCALCONTROL0r_RX_INBANDMDIO_RSTf_SET(lctrl, 1);
    WRITE_LOCALCONTROL0r(pc, lctrl);

    /* Configure 100FX mode */
    ioerr += READ_FXCONTROL1r(pc, &fx100_ctrl1);
    FXCONTROL1r_FX100_FAR_END_FAULT_ENf_SET(fx100_ctrl1, 1);
    FXCONTROL1r_FX100_AUTODET_ENf_SET(fx100_ctrl1, 0);
    ioerr += WRITE_FXCONTROL1r(pc, fx100_ctrl1);

    /* Enable 100FX extended packet size */
    ioerr += READ_FXCONTROL2r(pc, &fx100_ctrl2);
    FXCONTROL2r_EXTEND_PKT_SIZEf_SET(fx100_ctrl2, 1);
    ioerr += WRITE_FXCONTROL2r(pc, fx100_ctrl2);

    /* Disable 1000X parallel detect */
    ioerr += READ_CONTROL1000X2r(pc, &ctrl_1000x2);
    CONTROL1000X2r_ENABLE_PARALLEL_DETECTIONf_SET(ctrl_1000x2, 0);
    ioerr += WRITE_CONTROL1000X2r(pc, ctrl_1000x2);

    /* Set elasticity FIFO size to 13.5k to support 12k jumbo packets */
    ioerr += READ_CONTROL1000X3r(pc, &ctrl_1000x3);
    CONTROL1000X3r_FIFO_ELASTICITY_TX_RXf_SET(ctrl_1000x3, 2);
    ioerr += WRITE_CONTROL1000X3r(pc, ctrl_1000x3);

    /* Adjust parallel detect link timer to 60ms */
    PARDET10GLINKr_SET(pd10g_link, 0x16e2);
    WRITE_PARDET10GLINKr(pc, pd10g_link);

    /* Start sequencer */
    XGXSCONTROLr_START_SEQUENCERf_SET(xgxsctrl, 1);
    ioerr += WRITE_XGXSCONTROLr(pc, xgxsctrl);
    (void)bcmi_unicore13g_xgxs_pll_lock_wait(pc);

    /* Default mode is fiber */
    PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_unicore13g_xgxs_link_get
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
bcmi_unicore13g_xgxs_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    int ioerr = 0;
    uint32_t an_done;
    GP_XGXSSTATUS3r_t xgxs_stat3;
    COMBO_MIISTATr_t miistat;
    GP_TOPANSTATUS1r_t anstat;

    PHY_CTRL_CHECK(pc);

    if (link) {
        READ_GP_XGXSSTATUS3r(pc, &xgxs_stat3);
        *link = GP_XGXSSTATUS3r_LINK_LATCHDOWNf_GET(xgxs_stat3);
    }

    if (autoneg_done) {
        an_done = 0;
        ioerr += READ_COMBO_MIISTATr(pc, &miistat);
        an_done |= COMBO_MIISTATr_AUTONEG_COMPLETEf_GET(miistat);
        if (an_done == 0) {
            ioerr += READ_GP_TOPANSTATUS1r(pc, &anstat);
            an_done |= GP_TOPANSTATUS1r_CL37_AUTONEG_COMPLETEf_GET(anstat);
            an_done |= GP_TOPANSTATUS1r_CL73_AUTONEG_COMPLETEf_GET(anstat);
        }
        *autoneg_done = an_done;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore13g_xgxs_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore13g_xgxs_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int ioerr = 0;
    COMBO_MIICNTLr_t miictrl;

    PHY_CTRL_CHECK(pc);

    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) == 0) {
        /* Only support full duplex in non-passthru mode */
        return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
    }

    ioerr += READ_COMBO_MIICNTLr(pc, &miictrl);
    COMBO_MIICNTLr_FULL_DUPLEXf_SET(miictrl, duplex);
    ioerr += WRITE_COMBO_MIICNTLr(pc, miictrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore13g_xgxs_duplex_get
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
bcmi_unicore13g_xgxs_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    int ioerr = 0;
    GP_TOPANSTATUS1r_t anstat;

    PHY_CTRL_CHECK(pc);

    ioerr += READ_GP_TOPANSTATUS1r(pc, &anstat);
    *duplex = GP_TOPANSTATUS1r_DUPLEX_STATUSf_GET(anstat);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore13g_xgxs_speed_set
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
bcmi_unicore13g_xgxs_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int ioerr = 0;
    int rv;
    int autoneg;
    uint32_t force_speed, speed_val;
    uint32_t speed_mii_lsb, speed_mii_msb, fx100;
    XGXSCONTROLr_t xgxsctrl;
    MISC1r_t misc1;
    STATUS1000X1r_t stat1;
    FXCONTROL1r_t fx100_ctrl1;
    COMBO_MIICNTLr_t mii_ctrl;

    /* Do not set speed if auto-negotiation is enabled */
    rv = PHY_AUTONEG_GET(pc, &autoneg);
    if (CDK_FAILURE(rv)) {
        return rv;
    }
    if (autoneg) {
        return CDK_E_NONE;
    }

    force_speed = 0;
    speed_val = FV_fdr_2p5G;
    speed_mii_lsb = 0;
    speed_mii_msb = 0;

    switch (speed) {
    case 0:
        return CDK_E_NONE;
    case 10:
        if (PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) {
            return CDK_E_PARAM;
        }
        break;
    case 100:
        speed_mii_lsb = 1;
        break;
    case 1000:
        speed_mii_msb = 1;
        break;
    case 2500:
        force_speed = 1;
        break;
    case 10000:
        force_speed = 1;
        speed_val = FV_fdr_10G_CX4;
        break;
    case 12000:
        force_speed = 1;
        speed_val = FV_fdr_12G;
        break;
    case 12500:
        force_speed = 1;
        speed_val = FV_fdr_12p5G;
        break;
    case 13000:
        force_speed = 1;
        speed_val = FV_fdr_13G;
        break;
    default:
        return CDK_E_PARAM;
    }

    /* Stop sequencer */
    ioerr += READ_XGXSCONTROLr(pc, &xgxsctrl);
    XGXSCONTROLr_START_SEQUENCERf_SET(xgxsctrl, 0);
    ioerr += WRITE_XGXSCONTROLr(pc, xgxsctrl);

    /* Set forced speed */
    ioerr += READ_MISC1r(pc, &misc1);
    MISC1r_FORCE_SPEED_SELf_SET(misc1, force_speed);
    MISC1r_FORCE_SPEEDf_SET(misc1, speed_val);
    ioerr += WRITE_MISC1r(pc, misc1);

    /* Set IEEE speed */
    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    COMBO_MIICNTLr_MANUAL_SPEED_0f_SET(mii_ctrl, speed_mii_lsb);
    COMBO_MIICNTLr_MANUAL_SPEED_1f_SET(mii_ctrl, speed_mii_msb);
    ioerr += WRITE_COMBO_MIICNTLr(pc, mii_ctrl);

    /* Check for 100FX mode */
    fx100 = 0;
    ioerr += READ_STATUS1000X1r(pc, &stat1);
    if (STATUS1000X1r_SGMII_MODEf_GET(stat1) == 0 && speed == 100) {
        fx100 = 1;
    }
    ioerr += READ_FXCONTROL1r(pc, &fx100_ctrl1);
    FXCONTROL1r_FX100_ENf_SET(fx100_ctrl1, fx100);
    ioerr += WRITE_FXCONTROL1r(pc, fx100_ctrl1);

    /* Start sequencer */
    XGXSCONTROLr_START_SEQUENCERf_SET(xgxsctrl, 1);
    ioerr += WRITE_XGXSCONTROLr(pc, xgxsctrl);
    (void)bcmi_unicore13g_xgxs_pll_lock_wait(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore13g_xgxs_speed_get
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
bcmi_unicore13g_xgxs_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int ioerr = 0;
    int rv;
    int autoneg;
    uint32_t force_speed, speed_val;
    uint32_t speed_mii_lsb, speed_mii_msb;
    GP_TOPANSTATUS1r_t anstat;
    MISC1r_t misc1;
    COMBO_MIICNTLr_t mii_ctrl;

    *speed = 0;

    rv = PHY_AUTONEG_GET(pc, &autoneg);
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    /* Use actual speed if auto-negotiation is enabled */
    if (autoneg) {
        ioerr += READ_GP_TOPANSTATUS1r(pc, &anstat);
        speed_val = GP_TOPANSTATUS1r_ACTUAL_SPEEDf_GET(anstat);
        if (speed_val < COUNTOF(_adr)) {
            *speed = _adr[speed_val];
        }
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }

    /* Get forced speed */
    ioerr += READ_MISC1r(pc, &misc1);
    force_speed = MISC1r_FORCE_SPEED_SELf_GET(misc1);
    speed_val = MISC1r_FORCE_SPEEDf_GET(misc1);

    if (force_speed) {
        if (speed_val < COUNTOF(_fdr)) {
            *speed = _fdr[speed_val];
        }
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }

    /* Get IEEE speed */
    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    speed_mii_lsb = COMBO_MIICNTLr_MANUAL_SPEED_0f_GET(mii_ctrl);
    speed_mii_msb = COMBO_MIICNTLr_MANUAL_SPEED_1f_GET(mii_ctrl);
    if (speed_mii_msb) {
        *speed = 1000;
    } else if (speed_mii_lsb) {
        *speed = 100;
    } else {
        *speed = 10;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore13g_xgxs_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */

static int
bcmi_unicore13g_xgxs_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int ioerr = 0;
    XGXSCONTROLr_t xgxsctrl;
    MISC1r_t misc1;
    CONTROL1000X1r_t ctrl1;
    PARDET10GCONTROLr_t pd10_ctrl;
    MP5_NEXTPAGECTRLr_t mp5_np_ctrl;
    COMBO_MIICNTLr_t mii_ctrl;
    CL73_BAMCTRL1r_t bam_ctrl;
    CL73_AN_CONTROLr_t cl73_ctrl;

    PHY_CTRL_CHECK(pc);

    /* Stop sequencer */
    ioerr += READ_XGXSCONTROLr(pc, &xgxsctrl);
    XGXSCONTROLr_START_SEQUENCERf_SET(xgxsctrl, 0);
    ioerr += WRITE_XGXSCONTROLr(pc, xgxsctrl);

    if (autoneg) {
        /* Disable forced speed if autoneg is enabled */
        ioerr += READ_MISC1r(pc, &misc1);
        MISC1r_FORCE_SPEEDf_SET(misc1, 0);
        ioerr += WRITE_MISC1r(pc, misc1);

        /* Used as field value, so cannot be any non-zero value */
        autoneg = 1;
    }

    /* Set 1000X auto detect */
    ioerr += READ_CONTROL1000X1r(pc, &ctrl1);
    CONTROL1000X1r_AUTODET_ENf_SET(ctrl1, autoneg);
    ioerr += WRITE_CONTROL1000X1r(pc, ctrl1);

    /* Set 10G parallel detect */
    ioerr += READ_PARDET10GCONTROLr(pc, &pd10_ctrl);
    PARDET10GCONTROLr_PARDET10G_ENf_SET(pd10_ctrl, autoneg);
    ioerr += WRITE_PARDET10GCONTROLr(pc, pd10_ctrl);

    /* Set BAM/TETON enable */
    ioerr += READ_MP5_NEXTPAGECTRLr(pc, &mp5_np_ctrl);
    MP5_NEXTPAGECTRLr_BAM_MODEf_SET(mp5_np_ctrl, autoneg);
    MP5_NEXTPAGECTRLr_TETON_MODEf_SET(mp5_np_ctrl, autoneg);
    MP5_NEXTPAGECTRLr_TETON_MODE_UP3_ENf_SET(mp5_np_ctrl, autoneg);
    ioerr += WRITE_MP5_NEXTPAGECTRLr(pc, mp5_np_ctrl);

    /* Configure IEEE auto-neg */
    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    COMBO_MIICNTLr_AUTONEG_ENABLEf_SET(mii_ctrl, autoneg);
    ioerr += WRITE_COMBO_MIICNTLr(pc, mii_ctrl);

    /* Configure Broadcom auto-neg */
    ioerr += READ_CL73_BAMCTRL1r(pc, &bam_ctrl);
    CL73_BAMCTRL1r_CL73_BAMENf_SET(bam_ctrl, autoneg);
    ioerr += WRITE_CL73_BAMCTRL1r(pc, bam_ctrl);

    /* Configure clause 73 auto-neg */
    ioerr += READ_CL73_AN_CONTROLr(pc, &cl73_ctrl);
    CL73_AN_CONTROLr_MR_AUTONEG_ENf_SET(cl73_ctrl, autoneg);
    ioerr += WRITE_CL73_AN_CONTROLr(pc, cl73_ctrl);

    /* Start sequencer */
    XGXSCONTROLr_START_SEQUENCERf_SET(xgxsctrl, 1);
    ioerr += WRITE_XGXSCONTROLr(pc, xgxsctrl);
    (void)bcmi_unicore13g_xgxs_pll_lock_wait(pc);

    /* Restart autoneg if enabled */
    if (autoneg) {
        COMBO_MIICNTLr_RESTART_AUTONEGf_SET(mii_ctrl, 1);
        ioerr += WRITE_COMBO_MIICNTLr(pc, mii_ctrl);

        ioerr += READ_CL73_AN_CONTROLr(pc, &cl73_ctrl);
        CL73_AN_CONTROLr_MR_RES_NEGOTIATIONf_SET(cl73_ctrl, 1);
        ioerr += WRITE_CL73_AN_CONTROLr(pc, cl73_ctrl);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore13g_xgxs_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore13g_xgxs_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    int ioerr = 0;
    COMBO_MIICNTLr_t mii_ctrl;

    PHY_CTRL_CHECK(pc);

    /* Read IEEE autoneg */
    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    *autoneg = COMBO_MIICNTLr_AUTONEG_ENABLEf_GET(mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE; 
}

/*
 * Function:    
 *      bcmi_unicore13g_xgxs_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore13g_xgxs_loopback_set(phy_ctrl_t *pc, int enable)
{
    int ioerr = 0;
    PMD_IEEECONTROL1r_t pmd_mii_ctrl;
    COMBO_MIICNTLr_t mii_ctrl;

    PHY_CTRL_CHECK(pc);

    if (enable) {
        /* Used as field value, so cannot be any non-zero value */
        enable = 1;
    }

    /* Set loopback XGXS core */
    ioerr += READ_PMD_IEEECONTROL1r(pc, &pmd_mii_ctrl);
    PMD_IEEECONTROL1r_GLOOPBACKf_SET(pmd_mii_ctrl, enable);
    ioerr += WRITE_PMD_IEEECONTROL1r(pc, pmd_mii_ctrl);

    /* Set loopback for SerDes core */
    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    COMBO_MIICNTLr_LOOPBACKf_SET(mii_ctrl, enable);
    ioerr += WRITE_COMBO_MIICNTLr(pc, mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore13g_xgxs_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore13g_xgxs_loopback_get(phy_ctrl_t *pc, int *enable)
{
    int ioerr = 0;
    COMBO_MIICNTLr_t mii_ctrl;

    PHY_CTRL_CHECK(pc);

    /* Get loopback mode from SerDes registers */
    ioerr += READ_COMBO_MIICNTLr(pc, &mii_ctrl);
    *enable = COMBO_MIICNTLr_LOOPBACKf_GET(mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_unicore13g_xgxs_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_unicore13g_xgxs_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    *abil = (PHY_ABIL_PAUSE | PHY_ABIL_LOOPBACK | 
             PHY_ABIL_XAUI | PHY_ABIL_XGMII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_unicore13g_xgxs_config_set
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
bcmi_unicore13g_xgxs_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        if (val) {
            PHY_CTRL_FLAGS(pc) &= ~PHY_F_PHY_DISABLE;
        } else {
            PHY_CTRL_FLAGS(pc) |= PHY_F_PHY_DISABLE;
        }
        bcmi_unicore13g_xgxs_stop(pc);
        break;
    case PhyConfig_PortInterface:
        return CDK_E_NONE;
#if PHY_CONFIG_INCLUDE_XAUI_TX_LANE_MAP_SET
    case PhyConfig_XauiTxLaneRemap: {
        int ioerr = 0;
        TXLNSWAP1r_t txlnswap1;

        ioerr += READ_TXLNSWAP1r(pc, &txlnswap1);
        TXLNSWAP1r_TX0_LNSWAP_SELf_SET(txlnswap1, val & 0x3);
        TXLNSWAP1r_TX1_LNSWAP_SELf_SET(txlnswap1, (val >> 4) & 0x3);
        TXLNSWAP1r_TX2_LNSWAP_SELf_SET(txlnswap1, (val >> 8) & 0x3);
        TXLNSWAP1r_TX3_LNSWAP_SELf_SET(txlnswap1, (val >> 12) & 0x3);
        ioerr += WRITE_TXLNSWAP1r(pc, txlnswap1);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_RX_LANE_MAP_SET
    case PhyConfig_XauiRxLaneRemap: {
        int ioerr = 0;
        RXLNSWAP1r_t rxlnswap1;

        ioerr += READ_RXLNSWAP1r(pc, &rxlnswap1);
        RXLNSWAP1r_RX0_LNSWAP_SELf_SET(rxlnswap1, val & 0x3);
        RXLNSWAP1r_RX1_LNSWAP_SELf_SET(rxlnswap1, (val >> 4) & 0x3);
        RXLNSWAP1r_RX2_LNSWAP_SELf_SET(rxlnswap1, (val >> 8) & 0x3);
        RXLNSWAP1r_RX3_LNSWAP_SELf_SET(rxlnswap1, (val >> 12) & 0x3);
        ioerr += WRITE_RXLNSWAP1r(pc, rxlnswap1);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_TX_POLARITY_SET
    case PhyConfig_XauiTxPolInvert: {
        int ioerr = 0;
        TX_ACONTROL_0r_t tx_ctrl;
        int idx, fval;

        for (idx = 0; idx <= 3; idx++) {
            fval = (val >> (idx * 4));
            ioerr += READ_TX_ACONTROL_0r(pc, idx, &tx_ctrl);
            TX_ACONTROL_0r_TXPOL_FLIPf_SET(tx_ctrl, fval);
            ioerr += WRITE_TX_ACONTROL_0r(pc, idx, tx_ctrl);
        }
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
    case PhyConfig_TxPreemp: {
        int ioerr = 0;
        TX_ALL_TX_ACONTROL1r_t tx_actrl1;

        ioerr += READ_TX_ALL_TX_ACONTROL1r(pc, &tx_actrl1);
        TX_ALL_TX_ACONTROL1r_POSTCURSOR_TAPf_SET(tx_actrl1, val);
        ioerr += WRITE_TX_ALL_TX_ACONTROL1r(pc, tx_actrl1);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxIDrv: {
        int ioerr = 0;
        TX_ALL_TX_ACONTROL1r_t tx_actrl1;

        ioerr += READ_TX_ALL_TX_ACONTROL1r(pc, &tx_actrl1);
        TX_ALL_TX_ACONTROL1r_TX_AMPLf_SET(tx_actrl1, val);
        ioerr += WRITE_TX_ALL_TX_ACONTROL1r(pc, tx_actrl1);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcmi_unicore13g_xgxs_config_get
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
bcmi_unicore13g_xgxs_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = (PHY_CTRL_FLAGS(pc) & PHY_F_PHY_DISABLE) ? 0 : 1;
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        *val = PHY_IF_XGMII;
        return CDK_E_NONE;
    case PhyConfig_TxPreemp: {
        int ioerr = 0;
        TX_ALL_TX_ACONTROL1r_t tx_actrl1;

        ioerr += READ_TX_ALL_TX_ACONTROL1r(pc, &tx_actrl1);
        *val = TX_ALL_TX_ACONTROL1r_POSTCURSOR_TAPf_GET(tx_actrl1);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxIDrv: {
        int ioerr = 0;
        TX_ALL_TX_ACONTROL1r_t tx_actrl1;

        ioerr += READ_TX_ALL_TX_ACONTROL1r(pc, &tx_actrl1);
        *val = TX_ALL_TX_ACONTROL1r_TX_AMPLf_GET(tx_actrl1);

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/* Public PHY Driver Structure */
phy_driver_t bcmi_unicore13g_xgxs_drv = {
    "bcmi_unicore13g_xgxs", 
    "Internal Unicore 13G XGXS PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_unicore13g_xgxs_probe,         /* pd_probe */
    bcmi_unicore13g_xgxs_notify,        /* pd_notify */
    bcmi_unicore13g_xgxs_reset,         /* pd_reset */
    bcmi_unicore13g_xgxs_init,          /* pd_init */
    bcmi_unicore13g_xgxs_link_get,      /* pd_link_get */
    bcmi_unicore13g_xgxs_duplex_set,    /* pd_duplex_set */
    bcmi_unicore13g_xgxs_duplex_get,    /* pd_duplex_get */
    bcmi_unicore13g_xgxs_speed_set,     /* pd_speed_set */
    bcmi_unicore13g_xgxs_speed_get,     /* pd_speed_get */
    bcmi_unicore13g_xgxs_autoneg_set,   /* pd_autoneg_set */
    bcmi_unicore13g_xgxs_autoneg_get,   /* pd_autoneg_get */
    bcmi_unicore13g_xgxs_loopback_set,  /* pd_loopback_set */
    bcmi_unicore13g_xgxs_loopback_get,  /* pd_loopback_get */
    bcmi_unicore13g_xgxs_ability_get,   /* pd_ability_get */
    bcmi_unicore13g_xgxs_config_set,    /* pd_config_set */
    bcmi_unicore13g_xgxs_config_get,    /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
