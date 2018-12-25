/*
 * $Id: bcm54640e_drv.c,v 1.7 Broadcom SDK $
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
 * PHY driver for BCM54640E.
 *
 */

#include <phy/phy.h>
#include <phy/ge_phy.h>
#include <phy/phy_brcm_shadow.h>
#include <phy/phy_drvlist.h>

#define BCM54640E_PHY_ID0               0x0362
#define BCM54640E_PHY_ID1               0x5e70

#define PHY_ID1_REV_MASK                0x0007

#define _PHY_REG_READ(_pc, _r, _v)      phy_brcm_shadow_read(_pc, _r, _v)
#define _PHY_REG_WRITE(_pc, _r, _v)     phy_brcm_shadow_write(_pc, _r, _v)

#define EEE_MODEr                       0x17803d0e
#define EEE_ADVr                        0x17003c0e
#define AUTOGREEN_CTRLr                 0x100d0715

/* Access to shadowed registers at offset 0x1c */
#define REG_1C_SEL(_s)                  ((_s) << 10)
#define REG_1C_WR(_s,_v)                (REG_1C_SEL(_s) | (_v) | 0x8000)

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      bcm54640e_phy_probe
 * Purpose:     
 *      Probe for PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640e_phy_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, MII_PHY_ID0_REG, &phyid0);
    ioerr += PHY_BUS_READ(pc, MII_PHY_ID1_REG, &phyid1);

    if (phyid0 == BCM54640E_PHY_ID0 && 
        (phyid1 & ~PHY_ID1_REV_MASK) == BCM54640E_PHY_ID1) {
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcm54640e_phy_notify
 * Purpose:     
 *      Handle PHY notifications
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640e_phy_notify(phy_ctrl_t *pc, phy_event_t event)
{
    return bcm54640_drv.pd_notify(pc, event);
}

/*
 * Function:
 *      bcm54640e_phy_reset
 * Purpose:     
 *      Reset PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640e_phy_reset(phy_ctrl_t *pc)
{
    return bcm54640_drv.pd_reset(pc);
}

/*
 * Function:
 *      bcm54640e_phy_init
 * Purpose:     
 *      Initialize PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640e_phy_init(phy_ctrl_t *pc)
{
    return bcm54640_drv.pd_init(pc);
}

/*
 * Function:    
 *      bcm54640e_phy_link_get
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
bcm54640e_phy_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    return bcm54640_drv.pd_link_get(pc, link, autoneg_done);
}

/*
 * Function:    
 *      bcm54640e_phy_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640e_phy_duplex_set(phy_ctrl_t *pc, int duplex)
{
    return bcm54640_drv.pd_duplex_set(pc, duplex);
}

/*
 * Function:    
 *      bcm54640e_phy_duplex_get
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
bcm54640e_phy_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    return bcm54640_drv.pd_duplex_get(pc, duplex);
}

/*
 * Function:    
 *      bcm54640e_phy_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640e_phy_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    return bcm54640_drv.pd_speed_set(pc, speed);
}

/*
 * Function:    
 *      bcm54640e_phy_speed_get
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
bcm54640e_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    return bcm54640_drv.pd_speed_get(pc, speed);
}

/*
 * Function:    
 *      bcm54640e_phy_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640e_phy_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    return bcm54640_drv.pd_autoneg_set(pc, autoneg);
}

/*
 * Function:    
 *      bcm54640e_phy_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640e_phy_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    return bcm54640_drv.pd_autoneg_get(pc, autoneg);
}

/*
 * Function:    
 *      bcm54640e_phy_loopback_set
 * Purpose:     
 *      Set the internal PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640e_phy_loopback_set(phy_ctrl_t *pc, int enable)
{
    return bcm54640_drv.pd_loopback_set(pc, enable);
}

/*
 * Function:    
 *      bcm54640e_phy_loopback_get
 * Purpose:     
 *      Get the local PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640e_phy_loopback_get(phy_ctrl_t *pc, int *enable)
{
    return bcm54640_drv.pd_loopback_get(pc, enable);
}

/*
 * Function:    
 *      bcm54640e_phy_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm54640e_phy_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    return bcm54640_drv.pd_ability_get(pc, abil);
}

/*
 * Function:
 *      bcm54640e_phy_config_set
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
bcm54640e_phy_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    int ioerr = 0;
    uint32_t adv_ability = 0, temp = 0;

    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_EEE:
        if (val == PHY_EEE_802_3) {      

            ioerr += _PHY_REG_READ(pc, EEE_MODEr, &temp);
            temp |= 0xc000;
            ioerr += _PHY_REG_WRITE(pc, EEE_MODEr, temp);

            ioerr += _PHY_REG_READ(pc, EEE_ADVr, &temp);
            temp |= 0x0006;
            ioerr += _PHY_REG_WRITE(pc, EEE_ADVr, temp);


            ioerr += PHY_BUS_WRITE(pc, 0x17, 0x0faf);
            ioerr += PHY_BUS_READ(pc, 0x15, &temp);
            temp |= 0x1;
            ioerr += PHY_BUS_WRITE(pc, 0x15, temp);

            ioerr += ge_phy_adv_local_get(pc, &adv_ability);
            adv_ability |= (PHY_ABIL_1000MB | PHY_ABIL_100MB);
            ioerr += ge_phy_adv_local_set(pc, adv_ability);
            ioerr += ge_phy_autoneg_set(pc, 1);

        } else if (val == PHY_EEE_AUTO) {

            ioerr += _PHY_REG_READ(pc, EEE_MODEr, &temp);
            temp |= 0xc000;
            ioerr += _PHY_REG_WRITE(pc, EEE_MODEr, temp);

            ioerr += _PHY_REG_READ(pc, EEE_ADVr, &temp);
            temp |= 0x0006;
            ioerr += _PHY_REG_WRITE(pc, EEE_ADVr, temp);

            ioerr += _PHY_REG_READ(pc, AUTOGREEN_CTRLr, &temp);
            temp =  (temp & ~0x3) | 0x1;
            ioerr += _PHY_REG_WRITE(pc, AUTOGREEN_CTRLr, temp);

             /* Expansion 0xaf [1:0] = 0x1 */
            ioerr += PHY_BUS_WRITE(pc, 0x17, 0x0faf);
            ioerr += PHY_BUS_READ(pc, 0x15, &temp);
            temp =  (temp & ~0x3) | 0x1;
            ioerr += PHY_BUS_WRITE(pc, 0x15, temp);

             /* Expansion 0x7f [2:0] = 0x1 */
            ioerr += PHY_BUS_WRITE(pc, 0x17, 0x0f7f);
            ioerr += PHY_BUS_READ(pc, 0x15, &temp);
            temp =  (temp & ~0x7) | 0x1;
            ioerr += PHY_BUS_WRITE(pc, 0x15, temp);

            ioerr += ge_phy_adv_local_get(pc, &adv_ability);
            adv_ability |= (PHY_ABIL_1000MB | PHY_ABIL_100MB);
            ioerr += ge_phy_adv_local_set(pc, adv_ability);
            ioerr += ge_phy_autoneg_set(pc, 1);

        } else if (val == PHY_EEE_NONE) {     

            ioerr += _PHY_REG_READ(pc, EEE_MODEr, &temp);
            temp &= ~0xc000;
            ioerr += _PHY_REG_WRITE(pc, EEE_MODEr, temp);

            ioerr += _PHY_REG_READ(pc, EEE_ADVr, &temp);
            temp &= ~0x0006;
            ioerr += _PHY_REG_WRITE(pc, EEE_ADVr, temp);

            ioerr += _PHY_REG_READ(pc, AUTOGREEN_CTRLr, &temp);
            temp &= ~0x0003;
            ioerr += _PHY_REG_WRITE(pc, AUTOGREEN_CTRLr, temp);

        } else {
            return CDK_E_PARAM;
        }
    default:
        return bcm54640_drv.pd_config_set(pc, cfg, val, cd);
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcm54640e_phy_config_get
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
bcm54640e_phy_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    int ioerr = 0;
    uint32_t temp;

    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_EEE:
        ioerr += _PHY_REG_READ(pc, EEE_MODEr, &temp);
        if ((temp & 0xc000) == 0xc000) {
            ioerr += _PHY_REG_READ(pc, AUTOGREEN_CTRLr, &temp);
            if ((temp & 0x0007) == 0x0001) {
                *val = PHY_EEE_AUTO;
            } else {
                *val = PHY_EEE_802_3;
            }
        } else {
            *val = PHY_EEE_NONE;
        }
        return ioerr ? CDK_E_IO : CDK_E_NONE;
        break;

    default:
        return bcm54640_drv.pd_config_get(pc, cfg, val, cd);
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Variable:    bcm54640e_phy drv
 * Purpose:     PHY Driver for BCM54640E.
 */
phy_driver_t bcm54640e_drv = {
    "bcm54640e",
    "BCM54640E Gigabit PHY Driver (EEE)",  
    0,
    bcm54640e_phy_probe,                /* pd_probe */
    bcm54640e_phy_notify,               /* pd_notify */
    bcm54640e_phy_reset,                /* pd_reset */
    bcm54640e_phy_init,                 /* pd_init */
    bcm54640e_phy_link_get,             /* pd_link_get */
    bcm54640e_phy_duplex_set,           /* pd_duplex_set */
    bcm54640e_phy_duplex_get,           /* pd_duplex_get */
    bcm54640e_phy_speed_set,            /* pd_speed_set */
    bcm54640e_phy_speed_get,            /* pd_speed_get */
    bcm54640e_phy_autoneg_set,          /* pd_autoneg_set */
    bcm54640e_phy_autoneg_get,          /* pd_autoneg_get */
    bcm54640e_phy_loopback_set,         /* pd_loopback_set */
    bcm54640e_phy_loopback_get,         /* pd_loopback_get */
    bcm54640e_phy_ability_get,          /* pd_ability_get */
    bcm54640e_phy_config_set,           /* pd_config_set */
    bcm54640e_phy_config_get,           /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
