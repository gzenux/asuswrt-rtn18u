/*
 * $Id: bcmi_hypercore_xgxs_drv.c,v 1.9 Broadcom SDK $
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
 * PHY driver for internal Hypercore 21G XGXS PHY.
 *
 */

#include <phy/phy.h>
#include <phy/phy_xgs_iblk.h>
#include <phy/phy_drvlist.h>
#include <phy/phy_brcm_serdes_id.h>

#define BCM_SERDES_PHY_ID0              0x143
#define BCM_SERDES_PHY_ID1              0xbff0

#define PHY_ID1_REV_MASK                0x000f

#define SERDES_ID0_XGXS_HYPERCORE       0x02

#define _PHY_REG_READ(_pc, _r, _v)      phy_xgs_iblk_read(_pc, _r, _v)
#define _PHY_REG_WRITE(_pc, _r, _v)     phy_xgs_iblk_write(_pc, _r, _v)

/* Transform datasheet mapped address to MIIM address used by software API */
#define XGS_MIIM_REG(_a) PHY_XGS_C45_TO_IBLK(_a)

/* XGXS BLOCK0 xgxsControl Register */
#define XGXS_BLK0_XGXS_CTRL_REG         XGS_MIIM_REG(0x8000)
#define XGXS_CTRL_START_SEQ             (1 << 13)
#define XGXS_CTRL_MODE_10G_GET(_r)      ((_r >> 8) & 0xf)
#define XGXS_CTRL_MODE_10G_SET(_r,_v)   _r = ((_r & ~(0xf << 8)) | (((_v) & 0xf) << 8))
#define MODE_10G_IND_LN_OS5             5
#define MODE_10G_IND_LN                 6
#define MODE_10G_COMBO                  12
#define XGXS_CTRL_TXCKO_DIV             (1 << 0)

/* XGXS BLOCK0 mmdSelect Register */
#define XGXS_BLK0_MMD_SEL_REG           XGS_MIIM_REG(0x800d)
#define MMD_SEL_MULTI_PRT_EN            (1 << 15)
#define MMD_SEL_MULTI_MMD_EN            (1 << 14)

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
extern cdk_symbols_t bcmi_hyperlite_xgxs_symbols;
#endif

/*
 * Function:
 *      bcmi_hypercore_xgxs_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_xgxs_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1, serdesid0, xgxs_ctrl, mmd_sel;
    int ioerr = 0;

    ioerr += phy_brcm_serdes_id(pc, &phyid0, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCM_SERDES_PHY_ID0 && phyid1 == BCM_SERDES_PHY_ID1) {
        /* Common PHY ID found - read specific SerDes ID */
        ioerr += _PHY_REG_READ(pc, SERDES_ID0, &serdesid0);
        if ((serdesid0 & 0x3f) == SERDES_ID0_XGXS_HYPERCORE) {
            /* Check for ComboCore mode */
            ioerr += _PHY_REG_READ(pc, XGXS_BLK0_XGXS_CTRL_REG, &xgxs_ctrl);
            if (XGXS_CTRL_MODE_10G_GET(xgxs_ctrl) == MODE_10G_COMBO) {
#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
                PHY_CTRL_SYMBOLS(pc) = &bcmi_hyperlite_xgxs_symbols;
#endif
                ioerr += _PHY_REG_READ(pc, XGXS_BLK0_MMD_SEL_REG, &mmd_sel);
                if (mmd_sel & MMD_SEL_MULTI_MMD_EN) {
                    PHY_CTRL_FLAGS(pc) |= PHY_F_CLAUSE45;
                }
                return ioerr ? CDK_E_IO : CDK_E_NONE;
            }
        }
    }
    return CDK_E_NOT_FOUND;
}


/*
 * Function:
 *      bcmi_hypercore_xgxs_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_xgxs_notify(phy_ctrl_t *pc, phy_event_t event)
{
    return bcmi_hyperlite_xgxs_drv.pd_notify(pc, event);
}

/*
 * Function:
 *      bcmi_hypercore_xgxs_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_xgxs_reset(phy_ctrl_t *pc)
{
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_hypercore_xgxs_init
 * Purpose:     
 *      Initialize PHY driver.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_NONE
 */
static int
bcmi_hypercore_xgxs_init(phy_ctrl_t *pc)
{
    return bcmi_hyperlite_xgxs_drv.pd_init(pc);
}

/*
 * Function:    
 *      bcmi_hypercore_xgxs_link_get
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
bcmi_hypercore_xgxs_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    return bcmi_hyperlite_xgxs_drv.pd_link_get(pc, link, autoneg_done);
}

/*
 * Function:    
 *      bcmi_hypercore_xgxs_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_xgxs_duplex_set(phy_ctrl_t *pc, int duplex)
{
    return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
}

/*
 * Function:    
 *      bcmi_hypercore_xgxs_duplex_get
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
bcmi_hypercore_xgxs_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hypercore_xgxs_speed_set
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
bcmi_hypercore_xgxs_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    return bcmi_hyperlite_xgxs_drv.pd_speed_set(pc, speed);
}

/*
 * Function:    
 *      bcmi_hypercore_xgxs_speed_get
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
bcmi_hypercore_xgxs_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    return bcmi_hyperlite_xgxs_drv.pd_speed_get(pc, speed);
}

/*
 * Function:    
 *      bcmi_hypercore_xgxs_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */

static int
bcmi_hypercore_xgxs_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    return bcmi_hyperlite_xgxs_drv.pd_autoneg_set(pc, autoneg);
}

/*
 * Function:    
 *      bcmi_hypercore_xgxs_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_xgxs_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    return bcmi_hyperlite_xgxs_drv.pd_autoneg_get(pc, autoneg);
}

/*
 * Function:    
 *      bcmi_hypercore_xgxs_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_xgxs_loopback_set(phy_ctrl_t *pc, int enable)
{
    return bcmi_hyperlite_xgxs_drv.pd_loopback_set(pc, enable);
}

/*
 * Function:    
 *      bcmi_hypercore_xgxs_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_xgxs_loopback_get(phy_ctrl_t *pc, int *enable)
{
    return bcmi_hyperlite_xgxs_drv.pd_loopback_get(pc, enable);
}

/*
 * Function:    
 *      bcmi_hypercore_xgxs_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_xgxs_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    *abil = (PHY_ABIL_21GB | PHY_ABIL_16GB | PHY_ABIL_13GB | PHY_ABIL_10GB | 
             PHY_ABIL_PAUSE | PHY_ABIL_LOOPBACK | 
             PHY_ABIL_XAUI | PHY_ABIL_XGMII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_hypercore_xgxs_config_set
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
bcmi_hypercore_xgxs_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    return bcmi_hyperlite_xgxs_drv.pd_config_set(pc, cfg, val, cd);
}

/*
 * Function:
 *      bcmi_hypercore_xgxs_config_get
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
bcmi_hypercore_xgxs_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    return bcmi_hyperlite_xgxs_drv.pd_config_get(pc, cfg, val, cd);
}

/* Public PHY Driver Structure */
phy_driver_t bcmi_hypercore_xgxs_drv = {
    "bcmi_hypercore_xgxs", 
    "Internal Hypercore 21G XGXS PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_hypercore_xgxs_probe,          /* pd_probe */
    bcmi_hypercore_xgxs_notify,         /* pd_notify */
    bcmi_hypercore_xgxs_reset,          /* pd_reset */
    bcmi_hypercore_xgxs_init,           /* pd_init */
    bcmi_hypercore_xgxs_link_get,       /* pd_link_get */
    bcmi_hypercore_xgxs_duplex_set,     /* pd_duplex_set */
    bcmi_hypercore_xgxs_duplex_get,     /* pd_duplex_get */
    bcmi_hypercore_xgxs_speed_set,      /* pd_speed_set */
    bcmi_hypercore_xgxs_speed_get,      /* pd_speed_get */
    bcmi_hypercore_xgxs_autoneg_set,    /* pd_autoneg_set */
    bcmi_hypercore_xgxs_autoneg_get,    /* pd_autoneg_get */
    bcmi_hypercore_xgxs_loopback_set,   /* pd_loopback_set */
    bcmi_hypercore_xgxs_loopback_get,   /* pd_loopback_get */
    bcmi_hypercore_xgxs_ability_get,    /* pd_ability_get */
    bcmi_hypercore_xgxs_config_set,     /* pd_config_set */
    bcmi_hypercore_xgxs_config_get,     /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
