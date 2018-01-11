/*
 * $Id: bcm89500_drv.c,v 1.9 Broadcom SDK $
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
 * PHY driver for BCM89500.
 *
 */

#include <phy/phy.h>
#include <phy/ge_phy.h>

#define BCM89500_PHY_ID0                0x0362
#define BCM89500_PHY_ID1                0x5d30

#define PHY_ID1_REV_MASK                0x000f

/* Default LED control */
#define BCM89500_LED1_SEL(_pc)          0x0
#define BCM89500_LED2_SEL(_pc)          0x1
#define BCM89500_LED3_SEL(_pc)          0x3
#define BCM89500_LED4_SEL(_pc)          0x6
#define BCM89500_LEDCTRL(_pc)           0x8
#define BCM89500_LEDSELECT(_pc)         0x0

#define BR_MODE_EN                      0x4  

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
#define MII_AUX_CTL_REG         0x18 /* MII Auxiliary Control Register */
#define BR_ACC_REG              0x0e /* BroadReach Access Control Register */

#define MII_CTRL_MASTER         (1L << 3)  /* Set to Master */

#define BR_ACC_LDS_EN           (1 << 12)  /* LDS Enable */

#define BR_SS_MASK              0xf /* Speed Selection Mask */
#define BR_SS_10                0   /*  10 Mbps */
#define BR_SS_50                1   /*  50 Mbps */
#define BR_SS_33                2   /*  33 Mbps */
#define BR_SS_25                3   /*  25 Mbps */
#define BR_SS_20                4   /*  20 Mbps */
#define BR_SS_100               8   /* 100 Mbps */

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcm89500_phy_probe
 * Purpose:     
 *      Probe for PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm89500_phy_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, MII_PHY_ID0_REG, &phyid0);
    ioerr += PHY_BUS_READ(pc, MII_PHY_ID1_REG, &phyid1);

    if (phyid0 == BCM89500_PHY_ID0 && 
        (phyid1 & ~PHY_ID1_REV_MASK) == BCM89500_PHY_ID1) {

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcm89500_phy_notify
 * Purpose:     
 *      Handle PHY notifications
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm89500_phy_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToCopper:
        event = PhyEvent_ChangeToPassthru;
        break;
    default:
        break;
    }

    return rv;
}

/*
 * Function:
 *      bcm89500_phy_reset
 * Purpose:     
 *      Reset PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm89500_phy_reset(phy_ctrl_t *pc)
{
    return ge_phy_reset(pc);
}

/*
 * Function:
 *      bcm89500_phy_init
 * Purpose:     
 *      Initialize PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm89500_phy_init(phy_ctrl_t *pc)
{
    uint32_t ctrl, led_traffic_en, aux_ctl, fifo_txrx;
    uint32_t dis_carr_ext, br_mode;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* Reset PHY */
    if (CDK_SUCCESS(rv)) {
        rv =  PHY_RESET(pc);
    }

    /* Select copper registers and QSGMII copper only */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1f, 0));

    /* Power up copper interface */
    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
    ctrl &= ~MII_CTRL_PD;
    ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl);

    /* Configure Extended Control Register */
    ioerr += PHY_BUS_READ(pc, MII_ECR_REG, &led_traffic_en);
    /* Enable LEDs to indicate traffic status */
    led_traffic_en |= 0x0020;
    ioerr += PHY_BUS_WRITE(pc, MII_ECR_REG, led_traffic_en);

    /* Enable extended packet length (4.5k through 25k) */
    ioerr += PHY_BUS_WRITE(pc, MII_AUX_CTL_REG, REG_18_SEL(0x00));
    ioerr += PHY_BUS_READ(pc, MII_AUX_CTL_REG, &aux_ctl);
    aux_ctl |= 0x4000;
    ioerr += PHY_BUS_WRITE(pc, MII_AUX_CTL_REG, REG_18_WR(0x00, aux_ctl));

    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_SEL(0x16));
    ioerr += PHY_BUS_READ(pc, 0x1c, &fifo_txrx);
    fifo_txrx |= 0x0001;
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x16, fifo_txrx));

    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_SEL(0x1B));
    ioerr += PHY_BUS_READ(pc, 0x1c, &fifo_txrx);
    fifo_txrx |= 0x0002;
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1B, fifo_txrx));

    /* Configure LED selectors */
    ioerr += PHY_BUS_WRITE(pc, 0x1c,
                           REG_1C_WR(0x0d, BCM89500_LED1_SEL(pc) |
                                     (BCM89500_LED2_SEL(pc) << 4)));
    ioerr += PHY_BUS_WRITE(pc, 0x1c,
                           REG_1C_WR(0x0e, BCM89500_LED3_SEL(pc) |
                                     (BCM89500_LED4_SEL(pc) << 4)));
    ioerr += PHY_BUS_WRITE(pc, 0x1c,
                           REG_1C_WR(0x09, BCM89500_LEDCTRL(pc)));
    ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_MAP_REG(0x4));
    ioerr += PHY_BUS_WRITE(pc, MII_EXP_REG, BCM89500_LEDSELECT(pc));
    ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_UNMAP);

    /* LDS parameters */
    ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_MAP_REG(0x94));
    ioerr += PHY_BUS_WRITE(pc, MII_EXP_REG, 0x0e1b);
    ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_UNMAP);

    ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_MAP_REG(0x9f));
    ioerr += PHY_BUS_WRITE(pc, MII_EXP_REG, 0x0306);
    ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_UNMAP);

    /* Configure Auxiliary control register to turn off
     * carrier extension.  The Intel 7131 NIC does not accept carrier
     * extension and gets CRC errors.
     */
    /* Disable carrier extension */
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_SEL(0x1B));
    ioerr += PHY_BUS_READ(pc, 0x1c, &dis_carr_ext);
    dis_carr_ext |= 0x0040;
    ioerr += PHY_BUS_WRITE(pc, 0x1c, REG_1C_WR(0x1B, dis_carr_ext));
    ioerr += PHY_BUS_READ(pc, BR_ACC_REG, &br_mode);
    if (br_mode & BR_MODE_EN) {
        /* Disable an */
        ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
        ctrl &= ~(0x3000);
        ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl);
    }

    /* Set default medium */
    if (CDK_SUCCESS(rv)) {
        PHY_NOTIFY(pc, PhyEvent_ChangeToCopper);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm89500_phy_link_get
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
bcm89500_phy_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
        return ge_phy_link_get(pc, link, autoneg_done);
}

/*
 * Function:    
 *      bcm89500_phy_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm89500_phy_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int ioerr = 0;
    uint32_t br_mode;
    
    ioerr += PHY_BUS_READ(pc, BR_ACC_REG, &br_mode);
    if (br_mode & BR_MODE_EN) {
        /* BR mode */
        if (!duplex) {
            return CDK_E_CONFIG;
        }
    } else {
        /* IEEE mode */
        PHY_CTRL_CHECK(pc);
        return ge_phy_duplex_set(pc, duplex);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm89500_phy_duplex_get
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
bcm89500_phy_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    int ioerr = 0;
    uint32_t br_mode;
    
    ioerr += PHY_BUS_READ(pc, BR_ACC_REG, &br_mode);
    if (br_mode & BR_MODE_EN) {
        *duplex = 1;
    } else {    
        return ge_phy_duplex_get(pc, duplex);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm89500_phy_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm89500_phy_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int ioerr = 0;
    int speed_val;
    uint32_t mii_ctrl, br_mode;

    ioerr += PHY_BUS_READ(pc, BR_ACC_REG, &br_mode);
    if (!(br_mode & BR_MODE_EN)) {
        /* IEEE mode */
        return ge_phy_speed_set(pc, speed);
    }

    /* BR mode */
    switch (speed) {
        case 10:
            speed_val = BR_SS_10;
            break;
        case 20:
            speed_val = BR_SS_20;
            break;
        case 25:
            speed_val = BR_SS_25;
            break;
        case 33:
            speed_val = BR_SS_33;
            break;
        case 50:
            speed_val = BR_SS_50;
            break;
        case 100:
            speed_val = BR_SS_100;
            break;
        default:
            return CDK_E_CONFIG;
    }
    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &mii_ctrl);
    mii_ctrl &= ~(BR_SS_MASK << 6);
    mii_ctrl |= (speed_val << 6);
    ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm89500_phy_speed_get
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
bcm89500_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int ioerr = 0;
    int speed_val = -1;
    uint32_t mii_stat, br_mode, br_lds_scan;

    ioerr += PHY_BUS_READ(pc, BR_ACC_REG, &br_mode);
    if ((br_mode & BR_MODE_EN) == 0) {
        /* IEEE mode */
        return ge_phy_speed_get(pc, speed);
    }
    
    if (br_mode & BR_ACC_LDS_EN) {
        /* LDS enabled */
        ioerr += PHY_BUS_READ(pc, MII_STAT_REG, &mii_stat);
        if ((mii_stat & MII_STAT_AN_DONE) == 0) {
            /* LDS NOT complete */
            *speed = 0;
        } else {
            /* Examine the BR EXP regs */
            ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_MAP_REG(0x96));
            ioerr += PHY_BUS_READ(pc, MII_EXP_REG, &br_lds_scan);
            ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_UNMAP);
            speed_val = (br_lds_scan & BR_SS_MASK);
        }
    } else {
        /* LDS disabled - return forced speed */
        speed_val = ((br_mode >> 6) & BR_SS_MASK);
    }

    switch (speed_val) {
    case BR_SS_10:
        *speed = 10;
        break;
    case BR_SS_20:
        *speed = 20;
        break;
    case BR_SS_25:
        *speed = 25;
        break;
    case BR_SS_33:
        *speed = 33;
        break;
    case BR_SS_50:
        *speed = 50;
        break;
    case BR_SS_100:
        *speed = 100;
        break;
    default:
        *speed = 0;
        break;
    }
    
    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm89500_phy_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm89500_phy_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    uint32_t br_mode;
    int ioerr = 0;
    
    ioerr += PHY_BUS_READ(pc, BR_ACC_REG, &br_mode);
    if (!(br_mode & BR_MODE_EN)) {
        /* IEEE mode */
        return ge_phy_autoneg_set(pc, autoneg);
    }

    /* BR mode */
    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm89500_phy_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm89500_phy_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    uint32_t ctrl, br_mode;
    int ioerr = 0;

    ioerr += PHY_BUS_READ(pc, BR_ACC_REG, &br_mode);
    if (!(br_mode & BR_MODE_EN)) {
        return ge_phy_autoneg_get(pc, autoneg);
    }

    /* BR mode */
    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
    if (ctrl & MII_CTRL_AE) {
        *autoneg = 1;
    } else {
        *autoneg = 0;
    }
    
    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm89500_phy_loopback_set
 * Purpose:     
 *      Set the internal PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm89500_phy_loopback_set(phy_ctrl_t *pc, int enable)
{
    uint32_t ctrl, br_mode;
    int ioerr = 0;

    ioerr += PHY_BUS_READ(pc, BR_ACC_REG, &br_mode);
    if (!(br_mode & BR_MODE_EN)) {
        return ge_phy_loopback_set(pc, enable);
    }

    /* BR mode */
    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);

    if (enable) {
        ctrl |= MII_CTRL_LE; 
    } else {
        ctrl &= ~MII_CTRL_LE; 
    }
    ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl);
    
    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm89500_phy_loopback_get
 * Purpose:     
 *      Get the local PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm89500_phy_loopback_get(phy_ctrl_t *pc, int *enable)
{
    uint32_t ctrl, br_mode;
    int ioerr = 0;

    ioerr += PHY_BUS_READ(pc, BR_ACC_REG, &br_mode);
    if (!(br_mode & BR_MODE_EN)) {
        return ge_phy_loopback_get(pc, enable);
    }

    /* BR mode */
    ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
    if (ctrl & MII_CTRL_LE) {
        *enable = 1;
    } else {
        *enable = 0;
    }
    
    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm89500_phy_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm89500_phy_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    *abil = (PHY_ABIL_100MB | PHY_ABIL_10MB | 
             PHY_ABIL_LOOPBACK | PHY_ABIL_MII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcm89500_phy_config_set
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
bcm89500_phy_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    int ioerr = 0;
    uint32_t ctrl, br_mode;
    uint32_t gmii_lb, ana, gb_ctrl;

    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        switch (val) {
        case PHY_IF_MII:
            return CDK_E_NONE;
        default:
            break;
        }
        break;
    case PhyConfig_RemoteLoopback:
        if (val == 1) {
            /* Set an=1 */
            ioerr += PHY_BUS_READ(pc, BR_ACC_REG, &br_mode);
            if (br_mode & BR_MODE_EN) {
                /* BR mode */
                ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
                ctrl &= ~(0x3000);
                ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl);
   
                /* Set to master */
                ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
                ctrl |= MII_CTRL_MASTER;
                ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl);
            } else {
                /* IEEE mode */
                /* Read SGMII loopback setting from expansion register 0x44 */
                ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_MAP_REG(0x44));
                ioerr += PHY_BUS_READ(pc, MII_EXP_REG, &gmii_lb);
                
                /* Leave autoneg untouched if disable and already disabled */
                if (!val && !gmii_lb) {
                    return ioerr ? CDK_E_IO : CDK_E_NONE;
                }
                /* Save current configuration */
                ioerr += PHY_BUS_READ(pc, MII_ANA_REG, &ana);
                ioerr += PHY_BUS_READ(pc, MII_GB_CTRL_REG, &gb_ctrl);
                ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
                /* Force link down by doing autoneg with no abilities */
                ioerr += PHY_BUS_WRITE(pc, MII_ANA_REG, 0x0001);
                ioerr += PHY_BUS_WRITE(pc, MII_GB_CTRL_REG, 0x0000);
                ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, MII_CTRL_AE | MII_CTRL_RAN);
                /* Set SGMII loopback with Rx suppress in expansion register 0x44 */
                ioerr += PHY_BUS_WRITE(pc, MII_EXP_REG, val ? 0x000b : 0x0000);
                ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_UNMAP);
                /* Restore configuration and restart autoneg */
                ioerr += PHY_BUS_WRITE(pc, MII_ANA_REG, ana);
                ioerr += PHY_BUS_WRITE(pc, MII_GB_CTRL_REG, gb_ctrl);
                ioerr += PHY_BUS_WRITE(pc, MII_CTRL_REG, ctrl | MII_CTRL_RAN);
            }             
        }

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcm89500_phy_config_get
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
bcm89500_phy_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    int ioerr = 0;
    uint32_t ctrl, br_mode;
    uint32_t gmii_lb;

    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = 1;
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        *val = PHY_IF_MII;
        return CDK_E_NONE;
    case PhyConfig_RemoteLoopback:
        ioerr += PHY_BUS_READ(pc, BR_ACC_REG, &br_mode);
        if (!(br_mode & BR_MODE_EN)) {
            /* Read SGMII loopback setting from expansion register 0x44 */
            ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_MAP_REG(0x44));
            ioerr += PHY_BUS_READ(pc, MII_EXP_REG, &gmii_lb);
            ioerr += PHY_BUS_WRITE(pc, MII_EXP_SEL, MII_EXP_UNMAP);
            
            *val = (gmii_lb) ? 1 : 0;
        } else {
            ioerr += PHY_BUS_READ(pc, MII_CTRL_REG, &ctrl);
            if (ctrl & MII_CTRL_MASTER) {
                *val = 1;
            }
        }

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Variable:    bcm89500_phy drv
 * Purpose:     PHY Driver for BCM89500.
 */
phy_driver_t bcm89500_drv = {
    "bcm89500",
    "BCM89500 Gigabit PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcm89500_phy_probe,                 /* pd_probe */
    bcm89500_phy_notify,                /* pd_notify */
    bcm89500_phy_reset,                 /* pd_reset */
    bcm89500_phy_init,                  /* pd_init */
    bcm89500_phy_link_get,              /* pd_link_get */
    bcm89500_phy_duplex_set,            /* pd_duplex_set */
    bcm89500_phy_duplex_get,            /* pd_duplex_get */
    bcm89500_phy_speed_set,             /* pd_speed_set */
    bcm89500_phy_speed_get,             /* pd_speed_get */
    bcm89500_phy_autoneg_set,           /* pd_autoneg_set */
    bcm89500_phy_autoneg_get,           /* pd_autoneg_get */
    bcm89500_phy_loopback_set,          /* pd_loopback_set */
    bcm89500_phy_loopback_get,          /* pd_loopback_get */
    bcm89500_phy_ability_get,           /* pd_ability_get */
    bcm89500_phy_config_set,            /* pd_config_set */
    bcm89500_phy_config_get,            /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
