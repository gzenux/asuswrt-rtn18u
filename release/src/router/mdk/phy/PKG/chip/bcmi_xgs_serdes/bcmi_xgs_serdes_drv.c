/*
 * $Id: bcmi_xgs_serdes_drv.c,v 1.7 Broadcom SDK $
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
 * PHY driver for internal XGS SerDes PHY.
 *
 */

#include <phy/phy.h>
#include <phy/ge_phy.h>

#define BCMI_XGS_SERDES_ID0             0
#define BCMI_XGS_SERDES_ID1             0

#define BCM5695_RESET_POLL_MAX          10

/* Auto-negotiation advertisement register */
#define QS_MII_ANA_REG                  MII_ANA_REG
#define QS_MII_ANA_HD                   (1 << 6)
#define QS_MII_ANA_FD                   (1 << 5)

/* Auto-Negotiation Link-Partner Ability Register */
#define QS_ANP_REG                      0x05
#define QS_MII_ANP_SGMII_LINK		(1 << 15)
#define QS_MII_ANP_SGMII_FD		(1 << 12)
#define QS_MII_ANP_SGMII_SPEED_SHFT   	10
#define QS_MII_ANP_SGMII_SPEED_MASK   	0x0c00

#define QS_MII_ANP_FIBER_NEXT_PG        (1 << 15)
#define QS_MII_ANP_FIBER_ACK            (1 << 14)
#define QS_MII_ANP_FIBER_RF_SHFT        12
#define QS_MII_ANP_FIBER_RF_MASK        0x3000
#define QS_MII_ANP_FIBER_PAUSE_ASYM     (1 << 8)
#define QS_MII_ANP_FIBER_PAUSE_SYM      (1 << 7)
#define QS_MII_ANP_FIBER_HD             (1 << 6)
#define QS_MII_ANP_FIBER_FD             (1 << 5)

/* Auto-Negotiation Expansion Register */
#define QS_ANA_EXPANSION_REG            MII_AN_EXP_REG
#define QS_ANA_EXPANSION_PR             (1 << 1)

/* SGMII Control register */
#define QS_SGMII_CTRL_REG               0x0b
#define QS_SGMII_FORCE_DATA             (1 << 15)
#define QS_SGMII_RF_SHFT                13
#define QS_SGMII_RF_MASK                0x6000
#define QS_SGMII_PAUSE_ASYM             (1 << 12)
#define QS_SGMII_PAUSE_SYM              (1 << 11)
#define QS_SGMII_AN_SEL                 (1 << 10)
#define QS_SGMII_RX_PRE_EXT             (1 << 9)
#define QS_SGMII_ERR_TIMER_EN           (1 << 8)
#define QS_SGMII_REV_PHASE              (1 << 7)
#define QS_SGMII_EXT_CTRL               (1 << 6)
#define QS_SGMII_TX_PRE_EXT             (1 << 5)
#define QS_SGMII_CDET_DISABLE           (1 << 4)
#define QS_SGMII_AN_TEST_MODE           (1 << 3)
#define QS_SGMII_AN_DISABLE             (1 << 2)
#define QS_SGMII_REMOTE_LOOP            (1 << 1)
#define QS_SGMII_TBI_LOOP               (1 << 0)

/* SGMII Status Register */
#define QS_SGMII_STAT_REG               0x0c
#define QS_SGMII_ANA_COMPLETE           (1 << 1)
#define QS_SGMII_ANA_ERROR              (1 << 0)

/* SGMII CRC Register */
#define QS_SGMII_CRC_REG                0x0d

/* SGMII Misc Control Register */
#define QS_SGMII_MISC_REG               0x0e
#define QS_SGMII_ANA_RESTART            (1 << 0)

/* SGMII Control #2 Register */
#define QS_SGMII_CTRL2_REG              0x0f
#define QS_SGMII_EN10B_MODE             (1 << 1)
#define QS_SGMII_FIBER_MODE             (1 << 0)

/* Serdes TX Control register */
#define QS_SERDES_TX_CTRL_REG           0x10
#define QS_SERDES_TX_PD                 (1 << 15)
#define QS_SERDES_BIAS_REFH             (1 << 14)
#define QS_SERDES_BIAS_REFL             (1 << 13)
#define QS_SERDES_CPM_ENABLE            (1 << 12)
#define QS_SERDES_RXW_SEL               (1 << 11)

/* Serdes RX Control register */
#define QS_SERDES_RX_CTRL_REG           0x11
#define QS_SERDES_RX_PD                 (1 << 15)
#define QS_SERDES_PE_ENA                (1 << 14)
#define QS_SERDES_TX_CRS_LB             (1 << 13)
#define QS_SERDES_PL_CLK_EDGE           (1 << 12)

/* Phase Control and Status Registers */
#define QS_PHASE_CTRL_REG               0x12
#define QS_PHASE_STAT_REG               0x13

/* SGMII Misc control register */
#define QS_SGMII_MISC_CTRL_REG          0x14
#define QS_SGMII_IDDQ_MODE              (1 << 5)
#define QS_SGMII_SIGNAL_DETECT          (1 << 3)
#define QS_SGMII_SGMII_ENABLE           (1 << 2)
#define QS_SGMII_MAC_MODE               (1 << 1)

/* External PHY link status */
#define QS_SGMII_LINK_STATUS            (1 << 0)

/* Misc SGMII control definitions */
#define QS_SGMII_MISC_STAT_REG          0x15
#define QS_SGMII_MISC_PRLE              (1 << 2)
#define QS_SGMII_PLL_LOCK               (1 << 1)

/* Common registers: Shares for all 4-ports on Serdes Module */
#define QS_PLL_CTRL_REG                 0x16     
#define QS_HW_RESET                     (1 << 7)
#define QS_PLL_TEST_ENA                 (1 << 2)
#define QS_PLL_RESET                    (1 << 1)
#define QS_PLL_PD                       (1 << 0)

/* Other test and Control registers */
#define QS_TEST_MUX_CTRL_REG            0x17
#define QS_PRBS_TEST_CTRL_REG           0x18
#define QS_PRBS_TEST_STAT_REG           0x19
#define QS_BERT_IPG_REG                 0x1a
#define QS_BERT_CTRL_REG                0x1b
#define QS_BERT_OVERFLOW_REG            0x1c
#define QS_BERT_MDIO_CTRL_REG           0x1d
#define QS_BERT_MDIO_DATA_REG           0x1e

/***********************************************************************
 *
 * HELPER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcmi_xgs_serdes_stop
 * Purpose:
 *      Put PHY in or out of reset depending on conditions.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_xgs_serdes_stop(phy_ctrl_t *pc)
{
    uint32_t mii_ctrl;
    uint32_t f_any = PHY_F_PHY_DISABLE | PHY_F_PORT_DRAIN;
    uint32_t f_copper = PHY_F_MAC_DISABLE | PHY_F_SPEED_CHG | PHY_F_DUPLEX_CHG;
    int stop = 0;
    int ioerr = 0;

    if ((PHY_CTRL_FLAGS(pc) & f_any) ||
        ((PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) == 0 &&
         (PHY_CTRL_FLAGS(pc) & f_copper))) {
        stop = 1;
    }

    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &mii_ctrl);

    if (stop) {
        mii_ctrl |= MII_CTRL_PD;
    } else {
        mii_ctrl &= ~MII_CTRL_PD;
    }

    ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcmi_xgs_serdes_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_xgs_serdes_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1, ana;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, MII_PHY_ID0_REG, &phyid0);
    ioerr += PHY_BUS_READ(pc, MII_PHY_ID1_REG, &phyid1);
    ioerr += PHY_BUS_READ(pc, MII_ANA_REG, &ana);

    /* 
     * Since the PHY ID is all zeros, we also check the auto-negotiation
     * advertisement register for a non-zero value in order to prevent 
     * false positives.
     */
    if (phyid0 == BCMI_XGS_SERDES_ID0 && phyid1 == BCMI_XGS_SERDES_ID1 &&
        ana != 0) {
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    return CDK_E_NOT_FOUND;
}


/*
 * Function:
 *      bcmi_xgs_serdes_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_xgs_serdes_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToPassthru:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) |= PHY_F_PASSTHRU;
        /* Put the Serdes in passthru mode */
        ioerr += PHY_BUS_WRITE(pc, 
                               QS_SGMII_CTRL2_REG, 0);
        break;
    case PhyEvent_ChangeToFiber:
        PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_PASSTHRU;
        /* Put the Serdes in fiber mode */
        ioerr += PHY_BUS_WRITE(pc, 
                               QS_SGMII_CTRL2_REG, QS_SGMII_FIBER_MODE);
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
    bcmi_xgs_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_xgs_serdes_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_xgs_serdes_reset(phy_ctrl_t *pc)
{
    uint32_t ctrl;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    /*
     * The reset bit must be held high for at least 1 usec and 
     * is not self-clearing.
     */
    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
    ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl | MII_CTRL_RESET);
    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
    ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl & ~MII_CTRL_RESET);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_xgs_serdes_init
 * Purpose:     
 *      Initialize PHY driver.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_NONE
 */
static int
bcmi_xgs_serdes_init(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* Reset PHY */
    rv =  bcmi_xgs_serdes_reset(pc);

    /* Default mode is fiber */
    PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);

    return rv;
}

/*
 * Function:    
 *      bcmi_xgs_serdes_link_get
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
bcmi_xgs_serdes_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    uint32_t mii_stat, sgmii_stat;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    if (link) {
        ioerr += PHY_BUS_READ(pc, MII_STAT_REG, &mii_stat);
        *link = ((mii_stat & MII_STAT_LA) != 0);
    }

    if (autoneg_done) {
        ioerr += PHY_BUS_READ(pc, QS_SGMII_STAT_REG, &sgmii_stat);
        *autoneg_done = (sgmii_stat & QS_SGMII_ANA_COMPLETE) != 0;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_xgs_serdes_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_xgs_serdes_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int rv;

    PHY_CTRL_CHECK(pc);

    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) == 0) {
        /* Only support full duplex in non-passthru mode */
        return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
    }

    /* Enter reset state */
    PHY_CTRL_FLAGS(pc) |= PHY_F_DUPLEX_CHG;
    bcmi_xgs_serdes_stop(pc);

    /* Use standard functions */
    rv = ge_phy_duplex_set(pc, duplex);

    /* Exit reset state */
    PHY_CTRL_FLAGS(pc) &= ~PHY_F_DUPLEX_CHG;
    bcmi_xgs_serdes_stop(pc);

    return rv;
}

/*
 * Function:    
 *      bcmi_xgs_serdes_duplex_get
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
bcmi_xgs_serdes_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    PHY_CTRL_CHECK(pc);

    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_xgs_serdes_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_xgs_serdes_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int rv;

    PHY_CTRL_CHECK(pc);

    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) == 0) {
        /* Only support speed 1000 in non-passthru mode */
        return (speed == 0 || speed == 1000) ? CDK_E_NONE : CDK_E_PARAM;
    }

    /* Enter reset state */
    PHY_CTRL_FLAGS(pc) |= PHY_F_SPEED_CHG;
    bcmi_xgs_serdes_stop(pc);

    /* Use standard functions */
    rv = ge_phy_speed_set(pc, speed);

    /* Exit reset state */
    PHY_CTRL_FLAGS(pc) &= ~PHY_F_SPEED_CHG;
    bcmi_xgs_serdes_stop(pc);

    return rv;
}

/*
 * Function:    
 *      bcmi_xgs_serdes_speed_get
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
bcmi_xgs_serdes_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    PHY_CTRL_CHECK(pc);

    *speed = 1000;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_xgs_serdes_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */

static int
bcmi_xgs_serdes_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    uint32_t sgmii_ctrl, misc_ctrl;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    /* In passthru mode we always disable autoneg */
    if ((PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU)) {
        autoneg = 0;
    }

    ioerr += PHY_BUS_READ(pc, QS_SGMII_CTRL_REG, &sgmii_ctrl);
    ioerr += PHY_BUS_READ(pc, QS_SGMII_MISC_CTRL_REG, &misc_ctrl);

    if (autoneg) {
	sgmii_ctrl |= QS_SGMII_AN_SEL;
	sgmii_ctrl &= ~QS_SGMII_AN_DISABLE;
	misc_ctrl |= QS_SGMII_MAC_MODE;
    } else {
	sgmii_ctrl &= ~QS_SGMII_AN_SEL;
	sgmii_ctrl |= QS_SGMII_AN_DISABLE;
	misc_ctrl &= ~QS_SGMII_MAC_MODE;
    }

    ioerr += PHY_BUS_WRITE(pc, QS_SGMII_CTRL_REG, sgmii_ctrl);
    ioerr += PHY_BUS_WRITE(pc, QS_SGMII_MISC_CTRL_REG, misc_ctrl);

    if (autoneg) {
	/* Restart autonegotiation (not a self-clearing bit) */
        ioerr += PHY_BUS_WRITE(pc, 
                               QS_SGMII_MISC_REG, QS_SGMII_ANA_RESTART);
        ioerr += PHY_BUS_WRITE(pc, QS_SGMII_CTRL_REG, 0);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_xgs_serdes_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy).
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_xgs_serdes_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    uint32_t sgmii_ctrl;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, QS_SGMII_CTRL_REG, &sgmii_ctrl);
    *autoneg = (sgmii_ctrl & QS_SGMII_AN_DISABLE) == 0;

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_xgs_serdes_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_xgs_serdes_loopback_set(phy_ctrl_t *pc, int enable)
{
    uint32_t sgmii_ctrl;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, QS_SGMII_CTRL_REG, &sgmii_ctrl);

    if (enable) {
	sgmii_ctrl |= QS_SGMII_TBI_LOOP | QS_SGMII_REV_PHASE;
    } else {
	sgmii_ctrl &= ~(QS_SGMII_TBI_LOOP | QS_SGMII_REV_PHASE);
    }

    ioerr += PHY_BUS_WRITE(pc, QS_SGMII_CTRL_REG, sgmii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_xgs_serdes_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_xgs_serdes_loopback_get(phy_ctrl_t *pc, int *enable)
{
    uint32_t sgmii_ctrl;
    int ioerr = 0;

    ioerr += PHY_BUS_READ(pc, QS_SGMII_CTRL_REG, &sgmii_ctrl);

    *enable = (sgmii_ctrl & QS_SGMII_TBI_LOOP) != 0;

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_xgs_serdes_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_xgs_serdes_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    *abil = (PHY_ABIL_1000MB | PHY_ABIL_PAUSE | PHY_ABIL_SERDES |
             PHY_ABIL_LOOPBACK | PHY_ABIL_GMII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_xgs_serdes_config_set
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
bcmi_xgs_serdes_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        switch (val) {
        case PHY_IF_MII:
        case PHY_IF_GMII:
        case PHY_IF_SGMII:
        case PHY_IF_NOCXN:
            return CDK_E_NONE;
        default:
            break;
        }
        break;
#if PHY_CONFIG_INCLUDE_LINK_ABILITIES
    case PhyConfig_AdvLocal: {
        uint32_t an_adv, sgmii_ctrl;
        int ioerr = 0;

        ioerr += PHY_BUS_READ(pc, MII_ANA_REG, &an_adv);

        /* Set advertised duplex (only FD supported) */
        an_adv &= ~(QS_MII_ANA_HD | QS_MII_ANA_FD);
        if (val & PHY_ABIL_1000MB_FD) {
            an_adv |= QS_MII_ANA_FD;
        }
        ioerr += PHY_BUS_WRITE(pc, MII_ANA_REG, an_adv);

        /* Set advertised pause bits in link code word */
        ioerr += PHY_BUS_READ(pc, QS_SGMII_CTRL_REG, &sgmii_ctrl);
        sgmii_ctrl &= ~(QS_SGMII_PAUSE_SYM | QS_SGMII_PAUSE_ASYM);
        switch (val & PHY_ABIL_PAUSE) {
        case PHY_ABIL_PAUSE_TX:
            sgmii_ctrl |= QS_SGMII_PAUSE_ASYM;
            break;
        case PHY_ABIL_PAUSE_RX:
            sgmii_ctrl |= QS_SGMII_PAUSE_SYM | QS_SGMII_PAUSE_ASYM;
            break;
        case PHY_ABIL_PAUSE:
            sgmii_ctrl |= QS_SGMII_PAUSE_SYM;
            break;
        }
        ioerr += PHY_BUS_WRITE(pc, QS_SGMII_CTRL_REG, sgmii_ctrl);

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
 *      bcmi_xgs_serdes_config_get
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
bcmi_xgs_serdes_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = 1;
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        *val = PHY_IF_GMII;
        return CDK_E_NONE;
#if PHY_CONFIG_INCLUDE_LINK_ABILITIES
    case PhyConfig_AdvLocal: {
        uint32_t an_adv, sgmii_ctrl;
        int ioerr = 0;

        *val = 0;

        ioerr += PHY_BUS_READ(pc, MII_ANA_REG, &an_adv);
        if (an_adv & QS_MII_ANA_FD) {
            *val |= PHY_ABIL_1000MB_FD;
        }

        ioerr += PHY_BUS_READ(pc, QS_SGMII_CTRL_REG, &sgmii_ctrl);
        switch (sgmii_ctrl & (QS_SGMII_PAUSE_SYM | QS_SGMII_PAUSE_ASYM)) {
        case QS_SGMII_PAUSE_SYM:
            *val |= PHY_ABIL_PAUSE;
            break;
        case QS_SGMII_PAUSE_ASYM:
            *val |= PHY_ABIL_PAUSE_TX;
            break;
        case QS_SGMII_PAUSE_SYM | QS_SGMII_PAUSE_ASYM:
            *val |= PHY_ABIL_PAUSE_RX;
            break;
        }
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_AdvRemote: {
        uint32_t anlpa;
        int ioerr = 0;

        *val = 0;

        ioerr += PHY_BUS_READ(pc, QS_ANP_REG, &anlpa);
        if (anlpa & QS_MII_ANP_FIBER_FD) {
            *val |= PHY_ABIL_1000MB_FD;
        }
        if (anlpa & QS_MII_ANP_FIBER_HD) {
            *val |= PHY_ABIL_1000MB_HD;
        }

        switch (anlpa &
                (QS_MII_ANP_FIBER_PAUSE_SYM | QS_MII_ANP_FIBER_PAUSE_ASYM)) {
        case QS_MII_ANP_FIBER_PAUSE_SYM:
            *val |= PHY_ABIL_PAUSE;
            break;
        case QS_MII_ANP_FIBER_PAUSE_ASYM:
            *val |= PHY_ABIL_PAUSE_TX;
            break;
        case QS_MII_ANP_FIBER_PAUSE_SYM | QS_MII_ANP_FIBER_PAUSE_ASYM:
            *val |= PHY_ABIL_PAUSE_RX;
            break;
        }

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/* Public PHY Driver Structure */
phy_driver_t bcmi_xgs_serdes_drv = {
    "bcmi_xgs_serdes", 
    "Internal XGS SerDes PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_xgs_serdes_probe,              /* pd_probe */
    bcmi_xgs_serdes_notify,             /* pd_notify */
    bcmi_xgs_serdes_reset,              /* pd_reset */
    bcmi_xgs_serdes_init,               /* pd_init */
    bcmi_xgs_serdes_link_get,           /* pd_link_get */
    bcmi_xgs_serdes_duplex_set,         /* pd_duplex_set */
    bcmi_xgs_serdes_duplex_get,         /* pd_duplex_get */
    bcmi_xgs_serdes_speed_set,          /* pd_speed_set */
    bcmi_xgs_serdes_speed_get,          /* pd_speed_get */
    bcmi_xgs_serdes_autoneg_set,        /* pd_autoneg_set */
    bcmi_xgs_serdes_autoneg_get,        /* pd_autoneg_get */
    bcmi_xgs_serdes_loopback_set,       /* pd_loopback_set */
    bcmi_xgs_serdes_loopback_get,       /* pd_loopback_get */
    bcmi_xgs_serdes_ability_get,        /* pd_ability_get */
    bcmi_xgs_serdes_config_set,         /* pd_config_set */
    bcmi_xgs_serdes_config_get,         /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
