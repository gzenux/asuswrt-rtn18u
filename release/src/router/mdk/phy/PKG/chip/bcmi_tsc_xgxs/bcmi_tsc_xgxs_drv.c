/*
 * $Id: bcmi_tsc_xgxs_drv.c,v 1.2 Broadcom SDK $
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
 * PHY driver for internal Tsc 40G XGXS PHY.
 *
 */

#include <phy/phy.h>
#include <phy/phy_drvlist.h>
#include <phy/phy_brcm_serdes_id.h>

#include <phy/chip/bcmi_tsc_xgxs_defs.h>

#define BCM_SERDES_PHY_ID0              0x600d
#define BCM_SERDES_PHY_ID1              0x8770

#define PHY_ID1_REV_MASK                0x000f

#define SERDES_ID_XGXS_TSC              0x11

/* Actual speeds */
#define FV_adr_10M                      0x00
#define FV_adr_100M                     0x01
#define FV_adr_1000M                    0x02
#define FV_adr_2p5G_X1                  0x03
#define FV_adr_5G_X4                    0x04
#define FV_adr_6G_X4                    0x05
#define FV_adr_10G_X4                   0x06
#define FV_adr_10G_CX4                  0x07
#define FV_adr_12G_X4                   0x08
#define FV_adr_12p5G_X4                 0x09
#define FV_adr_13G_X4                   0x0a
#define FV_adr_15G_X4                   0x0b
#define FV_adr_16G_X4                   0x0c
#define FV_adr_1G_KX1                   0x0d
#define FV_adr_10G_KX4                  0x0e
#define FV_adr_10G_KR1                  0x0f
#define FV_adr_5G_X1                    0x10
#define FV_adr_6p36G_X1                 0x11
#define FV_adr_20G_CX4                  0x12
#define FV_adr_21G_X4                   0x13
#define FV_adr_25p45G_X4                0x14
#define FV_adr_10G_X2_NOSCRAMBLE        0x15
#define FV_adr_10G_CX2_NOSCRAMBLE       0x16
#define FV_adr_10p5G_X2                 0x17
#define FV_adr_10p5G_CX2_NOSCRAMBLE     0x18
#define FV_adr_12p7G_X2                 0x19
#define FV_adr_12p7G_CX2                0x1a
#define FV_adr_10G_X1                   0x1b
#define FV_adr_40G_X4                   0x1c
#define FV_adr_20G_X2                   0x1d
#define FV_adr_20G_CX2                  0x1e
#define FV_adr_10G_SFI                  0x1f
#define FV_adr_31p5G_X4                 0x20
#define FV_adr_32p7G_X4                 0x21
#define FV_adr_20G_X4                   0x22
#define FV_adr_10G_X2                   0x23
#define FV_adr_10G_CX2                  0x24
#define FV_adr_12G_SCO_R2               0x25
#define FV_adr_10G_SCO_X2               0x26
#define FV_adr_40G_KR4                  0x27
#define FV_adr_40G_CR4                  0x28
#define FV_adr_100G_CR10                0x29
#define FV_adr_5G_X2                    0x2a
#define FV_adr_15p75G_X2                0x2c
#define FV_adr_2G_FC                    0x2e
#define FV_adr_4G_FC                    0x2f
#define FV_adr_8G_FC                    0x30
#define FV_adr_10G_CX1                  0x33
#define FV_adr_1G_CX1                   0x34
#define FV_adr_20G_KR2                  0x39
#define FV_adr_20G_CR2                  0x3a

/* Forced speeds */
#define FV_fdr_2500BRCM_X1              0x10
#define FV_fdr_5000BRCM_X4              0x11
#define FV_fdr_6000BRCM_X4              0x12
#define FV_fdr_10GHiGig_X4              0x13
#define FV_fdr_10GBASE_CX4              0x14
#define FV_fdr_12GHiGig_X4              0x15
#define FV_fdr_12p5GHiGig_X4            0x16
#define FV_fdr_13GHiGig_X4              0x17
#define FV_fdr_15GHiGig_X4              0x18
#define FV_fdr_16GHiGig_X4              0x19
#define FV_fdr_5000BRCM_X1              0x1a
#define FV_fdr_6363BRCM_X1              0x1b
#define FV_fdr_20GHiGig_X4              0x1c
#define FV_fdr_21GHiGig_X4              0x1d
#define FV_fdr_25p45GHiGig_X4           0x1e
#define FV_fdr_10G_HiG_DXGXS            0x1f
#define FV_fdr_10G_DXGXS                0x20
#define FV_fdr_10p5G_HiG_DXGXS          0x21
#define FV_fdr_10p5G_DXGXS              0x22
#define FV_fdr_12p773G_HiG_DXGXS        0x23
#define FV_fdr_12p773G_DXGXS            0x24
#define FV_fdr_10G_XFI                  0x25
#define FV_fdr_40G_X4                   0x26
#define FV_fdr_20G_HiG_DXGXS            0x27
#define FV_fdr_20G_DXGXS                0x28
#define FV_fdr_10G_SFI                  0x29
#define FV_fdr_31p5G                    0x2a
#define FV_fdr_32p7G                    0x2b /* not supported */
#define FV_fdr_20G_SCR                  0x2c
#define FV_fdr_10G_HiG_DXGXS_SCR        0x2d
#define FV_fdr_10G_DXGXS_SCR            0x2e
#define FV_fdr_12G_R2                   0x2f
#define FV_fdr_10G_X2                   0x30
#define FV_fdr_40G_KR4                  0x31
#define FV_fdr_40G_CR4                  0x32
#define FV_fdr_100G_CR10                0x33 /* not supported */
#define FV_fdr_5G_HiG_DXGXS             0x34 /* not supported */
#define FV_fdr_5G_DXGXS                 0x35 /* not supported */
#define FV_fdr_15p75G_HiG_DXGXS         0x36

/* PLL mode AFE */
#define FV_div32                        0x0
#define FV_div36                        0x1
#define FV_div40                        0x2
#define FV_div42                        0x3
#define FV_div48                        0x4
#define FV_div50                        0x5
#define FV_div52                        0x6
#define FV_div54                        0x7
#define FV_div60                        0x8
#define FV_div64                        0x9
#define FV_div66                        0xa
#define FV_div68                        0xb
#define FV_div70                        0xc
#define FV_div80                        0xd
#define FV_div92                        0xe
#define FV_div100                       0xf

/* Core modes */
#define FV_XGXS                         0x0
#define FV_XGXS_nCC                     0x1
#define FV_IndLane_OS8                  0x4
#define FV_IndLane_OS5                  0x5
#define FV_Indlanes                     0x6
#define FV_PCI                          0x7
#define FV_XGXS_nLQ                     0x8
#define FV_XGXS_nLQ_nCC                 0x9
#define FV_PBypass                      0xa
#define FV_PBypass_nDSK                 0xb
#define FV_ComboCoreMode                0xc
#define FV_Clocks_off                   0xf

/* Lane from PHY control instance */
#define LANE_NUM_MASK                   0x3

#define PLL_LOCK_MSEC                   200

#define IS_1LANE_PORT(_pc) \
    ((PHY_CTRL_FLAGS(_pc) & (PHY_F_SERDES_MODE | PHY_F_2LANE_MODE)) == PHY_F_SERDES_MODE)
#define IS_2LANE_PORT(_pc) \
    (PHY_CTRL_FLAGS(_pc) & PHY_F_2LANE_MODE)
#define IS_4LANE_PORT(_pc) \
    ((PHY_CTRL_FLAGS(_pc) & PHY_F_SERDES_MODE) == 0)

/*
 * Private driver data
 *
 * We use a single 32-bit word which is used like this:
 *
 * 31               16 15               8 7             0
 * +------------------+------------------+---------------+
 * |     Reserved     | Active interface | Lane polarity |
 * +------------------+------------------+---------------+
 */
#if PHY_CONFIG_PRIVATE_DATA_WORDS > 0

#define PRIV_DATA(_pc) ((_pc)->priv[0])

#define LANE_POLARITY_GET(_pc) (PRIV_DATA(_pc) & 0xff)
#define LANE_POLARITY_SET(_pc,_val) \
do { \
    PRIV_DATA(_pc) &= ~0xff; \
    PRIV_DATA(_pc) |= (_val) & 0xff; \
} while (0)

#define ACTIVE_INTERFACE_GET(_pc) ((PRIV_DATA(_pc) >> 8) & 0xff)
#define ACTIVE_INTERFACE_SET(_pc,_val) \
do { \
    PRIV_DATA(_pc) &= ~0xff00; \
    PRIV_DATA(_pc) |= LSHIFT32(_val, 8) & 0xff00; \
} while (0)

#else

#define LANE_POLARITY_GET(_pc) (0)
#define LANE_POLARITY_SET(_pc,_val)
#define ACTIVE_INTERFACE_GET(_pc) (0)
#define ACTIVE_INTERFACE_SET(_pc,_val)

#endif /* PHY_CONFIG_PRIVATE_DATA_WORDS */

/* Low level debugging (off by default) */
#ifdef PHY_DEBUG_ENABLE
#define _PHY_DBG(_pc, _stuff) \
    PHY_VERB(_pc, _stuff)
#else
#define _PHY_DBG(_pc, _stuff)
#endif

/***********************************************************************
 *
 * HELPER FUNCTIONS
 *
 ***********************************************************************/

/*
 * Function:
 *      _tsc_init_stage
 * Purpose:
 *      Execute specified init stage.
 * Parameters:
 *      pc - PHY control structure
 *      stage - init stage
 * Returns:
 *      CDK_E_xxx
 */
static int
_tsc_init_stage(phy_ctrl_t *pc, int stage)
{
    switch (stage) {
    default:
        break;
    }
    return CDK_E_UNAVAIL;
}

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
extern cdk_symbols_t bcmi_tsc_xgxs_symbols;
#define SET_SYMBOL_TABLE(_pc) \
    PHY_CTRL_SYMBOLS(_pc) = &bcmi_tsc_xgxs_symbols
#else
#define SET_SYMBOL_TABLE(_pc)
#endif

/*
 * Function:
 *      bcmi_tsc_xgxs_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_tsc_xgxs_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    SERDESIDr_t serdesid;
    uint32_t model;
    int ioerr = 0;

    ioerr += phy_brcm_serdes_id(pc, &phyid0, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCM_SERDES_PHY_ID0 && phyid1 == BCM_SERDES_PHY_ID1) {
        /* Common PHY ID found - read specific SerDes ID */
        ioerr += READ_SERDESIDr(pc, &serdesid);
        model = SERDESIDr_MODEL_NUMBERf_GET(serdesid);
        if (model == SERDES_ID_XGXS_TSC) {
            /* Always use clause 45 access */
            PHY_CTRL_FLAGS(pc) |= PHY_F_CLAUSE45;

            SET_SYMBOL_TABLE(pc);
            return ioerr ? CDK_E_IO : CDK_E_NONE;
        }
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    return CDK_E_NOT_FOUND;
}


/*
 * Function:
 *      bcmi_tsc_xgxs_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_tsc_xgxs_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      bcmi_tsc_xgxs_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_tsc_xgxs_reset(phy_ctrl_t *pc)
{
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_tsc_xgxs_init
 * Purpose:     
 *      Initialize PHY driver.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_NONE
 */
static int
bcmi_tsc_xgxs_init(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    int stage;

    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_FLAGS(pc) & PHY_F_STAGED_INIT) {
        return CDK_E_NONE;
    }

    for (stage = 0; CDK_SUCCESS(rv); stage++) {
        rv = _tsc_init_stage(pc, stage);
    }

    if (rv == CDK_E_UNAVAIL) {
        /* Successfully completed all stages */
        rv = CDK_E_NONE;
    }

    return rv;
}

/*
 * Function:    
 *      bcmi_tsc_xgxs_link_get
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
bcmi_tsc_xgxs_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    *link = FALSE;

    if (*link == FALSE) {
        ACTIVE_INTERFACE_SET(pc, 0);
    }
    
    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_tsc_xgxs_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_tsc_xgxs_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_tsc_xgxs_duplex_get
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
bcmi_tsc_xgxs_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_tsc_xgxs_speed_set
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
bcmi_tsc_xgxs_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_tsc_xgxs_speed_get
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
bcmi_tsc_xgxs_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int ioerr = 0;
    int rv;
    AN_ABIL_RESOLUTION_STATUSr_t an_res;
    CL72_MISC2_CONTROLr_t misc2_ctrl;
    int autoneg;
    uint32_t sp_val;

    PHY_CTRL_CHECK(pc);

    rv = PHY_AUTONEG_GET(pc, &autoneg);
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    *speed = 0;

    if (autoneg) {
        ioerr += READ_AN_ABIL_RESOLUTION_STATUSr(pc, &an_res);
        sp_val = AN_ABIL_RESOLUTION_STATUSr_AN_HCD_SPEEDf_GET(an_res);
    } else {
        ioerr += READ_CL72_MISC2_CONTROLr(pc, &misc2_ctrl);
        sp_val = CL72_MISC2_CONTROLr_SW_ACTUAL_SPEEDf_GET(misc2_ctrl);
    }

    switch (sp_val) {
    case FV_adr_10M:
        *speed = 10 ;
        break;
    case FV_adr_100M :
        *speed = 100 ;
        break;
    case FV_adr_1000M :
        *speed = 1000 ;
        break;
    case FV_adr_2p5G_X1 :
        *speed = 2500 ;
        break;
    case FV_adr_5G_X4 :
        *speed = 5000 ;
        break;
    case FV_adr_6G_X4 :
        *speed = 6000 ;
        break;
    case FV_adr_10G_X4:
        *speed = 10000 ;
        break;
    case FV_adr_10G_CX4:
        *speed = 10000 ;
        break;
    case FV_adr_12G_X4:
        *speed = 12000 ;
        break;
    case FV_adr_12p5G_X4:
        *speed = 12500 ;
        break;
    case FV_adr_13G_X4:
        *speed = 13000 ;
        break;
    case FV_adr_15G_X4:
        *speed = 15000 ;
        break;
    case FV_adr_16G_X4:
        *speed = 16000 ;
        break;
    case FV_adr_1G_KX1:
        *speed = 1000 ;
        break;
    case FV_adr_10G_KX4:
        *speed = 10000 ;
        break;
    case FV_adr_10G_KR1:
        *speed = 10000 ;
        ACTIVE_INTERFACE_SET(pc, PHY_IF_KR);
        break;
    case FV_adr_5G_X1:
        *speed = 5000 ;
        break;
    case FV_adr_6p36G_X1:
        *speed = 6360 ;
        break;
    case FV_adr_20G_CX4:
        *speed = 20000 ;
        break;
    case FV_adr_21G_X4:
        *speed = 21000 ;
        break;
    case FV_adr_25p45G_X4:
        *speed = 25450 ;
        break;
    case FV_adr_10G_X2_NOSCRAMBLE:
        *speed = 10000 ;
        break;
    case FV_adr_10G_CX2_NOSCRAMBLE:
        *speed = 10000 ;
        break;
    case FV_adr_10p5G_X2:
        *speed = 10500 ;
        break;
    case FV_adr_10p5G_CX2_NOSCRAMBLE:
        *speed = 10500 ;
        break;
    case FV_adr_12p7G_X2:
        *speed = 12700 ;
        break;
    case FV_adr_12p7G_CX2:
        *speed = 12700 ;
        break;
    case FV_adr_10G_X1:
        *speed = 10000 ;
        break;
    case FV_adr_40G_X4:
        *speed = 40000 ;
        break;
    case FV_adr_20G_X2:
        *speed = 20000 ;
        break;
    case FV_adr_20G_CX2:
        *speed = 20000 ;
        break;
    case FV_adr_10G_SFI:
        *speed = 10000 ;
        ACTIVE_INTERFACE_SET(pc, PHY_IF_XFI);
        break;
    case FV_adr_31p5G_X4:
        *speed = 31500 ;
        break;
    case FV_adr_32p7G_X4:
        *speed = 32700 ;
        break;
    case FV_adr_20G_X4:
        *speed = 20000 ;
        break;
    case FV_adr_10G_X2:
        *speed = 10000 ;
        break;
    case FV_adr_10G_CX2:
        *speed = 10000 ;
        break;
    case FV_adr_12G_SCO_R2:
        *speed = 12000 ;
        break;
    case FV_adr_10G_SCO_X2:
        *speed = 10000 ;
        break;
    case FV_adr_40G_KR4:
        *speed = 40000 ;
        ACTIVE_INTERFACE_SET(pc, PHY_IF_KR);
        break;
    case FV_adr_40G_CR4:
        *speed = 40000 ;
        ACTIVE_INTERFACE_SET(pc, PHY_IF_CR);
        break;
    case FV_adr_100G_CR10:
        *speed = 100000 ;
        ACTIVE_INTERFACE_SET(pc, PHY_IF_CR);
        break;
    case FV_adr_5G_X2:
        *speed = 5000 ;
        break;
    case FV_adr_15p75G_X2:
        *speed = 15750 ;
        break;
    case FV_adr_2G_FC:
        *speed = 2000 ;
        break;
    case FV_adr_4G_FC: 
        *speed = 4000 ;
        break;
    case FV_adr_8G_FC:
        *speed = 8000 ;
        break;
    case FV_adr_10G_CX1:
        *speed = 10000 ;
        break;
    case FV_adr_1G_CX1: 
        *speed = 1000 ;
        break;
    case FV_adr_20G_KR2:
        *speed = 20000 ;
        ACTIVE_INTERFACE_SET(pc, PHY_IF_KR);
        break;
    case FV_adr_20G_CR2:  
        *speed = 20000 ;
        ACTIVE_INTERFACE_SET(pc, PHY_IF_CR);
        break;
    default:
        break;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_tsc_xgxs_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */

static int
bcmi_tsc_xgxs_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_tsc_xgxs_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_tsc_xgxs_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    *autoneg = 0;

    return ioerr ? CDK_E_IO : CDK_E_NONE; 
}

/*
 * Function:    
 *      bcmi_tsc_xgxs_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_tsc_xgxs_loopback_set(phy_ctrl_t *pc, int enable)
{
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    if (enable) {
        /* Used as field value, so cannot be any non-zero value */
        enable = 1;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_tsc_xgxs_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_tsc_xgxs_loopback_get(phy_ctrl_t *pc, int *enable)
{
    int ioerr = 0;
    LOOPBACK_CONTROLr_t lb_ctrl;

    PHY_CTRL_CHECK(pc);

    ioerr += READ_LOOPBACK_CONTROLr(pc, &lb_ctrl);
    *enable = LOOPBACK_CONTROLr_LOCAL_PCS_LOOPBACK_ENABLEf_GET(lb_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_tsc_xgxs_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_tsc_xgxs_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    if (IS_4LANE_PORT(pc)) {
        *abil = (PHY_ABIL_40GB | PHY_ABIL_30GB | PHY_ABIL_25GB |
                 PHY_ABIL_21GB | PHY_ABIL_16GB | PHY_ABIL_13GB |
                 PHY_ABIL_10GB | PHY_ABIL_1000MB_FD |
                 PHY_ABIL_PAUSE | PHY_ABIL_LOOPBACK | 
                 PHY_ABIL_XAUI | PHY_ABIL_XGMII);
    } else if (PHY_CTRL_FLAGS(pc) & PHY_F_CUSTOM_MODE) {
        *abil = PHY_ABIL_10GB | PHY_ABIL_13GB | PHY_ABIL_LOOPBACK |
            PHY_ABIL_XAUI | PHY_ABIL_XGMII;
    } else {
        *abil = (PHY_ABIL_2500MB | PHY_ABIL_1000MB | PHY_ABIL_SERDES |
                 PHY_ABIL_PAUSE | PHY_ABIL_LOOPBACK |
                 PHY_ABIL_GMII);
    }
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_tsc_xgxs_config_set
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
bcmi_tsc_xgxs_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
    case PhyConfig_PortInterface:
        return CDK_E_NONE;
#if PHY_CONFIG_INCLUDE_XAUI_TX_LANE_MAP_SET
    case PhyConfig_XauiTxLaneRemap: {
        int ioerr = 0;

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_RX_LANE_MAP_SET
    case PhyConfig_XauiRxLaneRemap: {
        int ioerr = 0;

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_TX_POLARITY_SET
    case PhyConfig_XauiTxPolInvert: {
        int ioerr = 0;

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
#if PHY_CONFIG_INCLUDE_XAUI_RX_POLARITY_SET
    case PhyConfig_XauiRxPolInvert: {
        int ioerr = 0;

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
    case PhyConfig_TxPreemp: {
        int ioerr = 0;

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxIDrv: {
        int ioerr = 0;

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxPreIDrv: {
        int ioerr = 0;

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_InitStage: {
        return _tsc_init_stage(pc, val);
    }
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcmi_tsc_xgxs_config_get
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
bcmi_tsc_xgxs_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = 1;
        return CDK_E_NONE;
    case PhyConfig_Clause45Devs:
        *val = 0;
        if (PHY_CTRL_FLAGS(pc) & PHY_F_CLAUSE45) {
            *val = 0x8b;
        }
        return CDK_E_NONE;
    case PhyConfig_TxPreemp: {
        int ioerr = 0;

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxIDrv: {
        int ioerr = 0;

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxPreIDrv: {
        int ioerr = 0;

        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcmi_tsc_xgxs_status_get
 * Purpose:
 *      Get PHY status value.
 * Parameters:
 *      pc - PHY control structure
 *      stat - status parameter
 *      val - (OUT) status value
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_tsc_xgxs_status_get(phy_ctrl_t *pc, phy_status_t stat, uint32_t *val)
{
    PHY_CTRL_CHECK(pc);

    switch (stat) {
    case PhyStatus_LineInterface:
        *val = ACTIVE_INTERFACE_GET(pc);
        if (*val == 0) {
            *val = PHY_CTRL_LINE_INTF(pc);
        }
        if (*val == 0) {
            *val = PHY_IF_XGMII;
        }
        return CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/* Public PHY Driver Structure */
phy_driver_t bcmi_tsc_xgxs_drv = {
    "bcmi_tsc_xgxs", 
    "Internal TSC 40G XGXS PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_tsc_xgxs_probe,                /* pd_probe */
    bcmi_tsc_xgxs_notify,               /* pd_notify */
    bcmi_tsc_xgxs_reset,                /* pd_reset */
    bcmi_tsc_xgxs_init,                 /* pd_init */
    bcmi_tsc_xgxs_link_get,             /* pd_link_get */
    bcmi_tsc_xgxs_duplex_set,           /* pd_duplex_set */
    bcmi_tsc_xgxs_duplex_get,           /* pd_duplex_get */
    bcmi_tsc_xgxs_speed_set,            /* pd_speed_set */
    bcmi_tsc_xgxs_speed_get,            /* pd_speed_get */
    bcmi_tsc_xgxs_autoneg_set,          /* pd_autoneg_set */
    bcmi_tsc_xgxs_autoneg_get,          /* pd_autoneg_get */
    bcmi_tsc_xgxs_loopback_set,         /* pd_loopback_set */
    bcmi_tsc_xgxs_loopback_get,         /* pd_loopback_get */
    bcmi_tsc_xgxs_ability_get,          /* pd_ability_get */
    bcmi_tsc_xgxs_config_set,           /* pd_config_set */
    bcmi_tsc_xgxs_config_get,           /* pd_config_get */
    bcmi_tsc_xgxs_status_get,           /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
