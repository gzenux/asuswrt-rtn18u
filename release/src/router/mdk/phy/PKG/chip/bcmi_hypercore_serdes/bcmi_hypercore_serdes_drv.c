/*
 * $Id: bcmi_hypercore_serdes_drv.c,v 1.9 Broadcom SDK $
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
#include <phy/phy_aer_iblk.h>
#include <phy/phy_drvlist.h>
#include <phy/phy_brcm_serdes_id.h>

#define IS_DUAL_XGXS_PORT(_pc)          (PHY_CTRL_FLAGS(_pc) & (PHY_F_R2_MODE | \
					PHY_F_2LANE_MODE))

#define BCM_SERDES_PHY_ID0              0x143
#define BCM_SERDES_PHY_ID1              0xbff0

#define PHY_ID1_REV_MASK                0x000f

#define SERDES_ID0_XGXS_HYPERCORE       0x02

#define _PHY_REG_READ(_pc, _r, _v)      phy_xgs_iblk_read(_pc, (_r), _v)
#define _PHY_REG_WRITE(_pc, _r, _v)     phy_xgs_iblk_write(_pc, (_r), _v)
#define _PHY_REG_MODIFY(_pc,_r,_v,_m)   _phy_reg_modify(_pc, _r, _v, _m)

/* Transform datasheet mapped address to MIIM address used by software API */
#define XGS_MIIM_REG(_a) PHY_XGS_C45_TO_IBLK(_a)

/* XGXS BLOCK0 xgxsControl Register */
#define XGXS_BLK0_XGXS_CTRL_REG         XGS_MIIM_REG(0x8000)

#define XGXS_CTRL_START_SEQ             (1 << 13)
#define XGXS_CTRL_MODE_10G_GET(_r)      ((_r >> 8) & 0xf)
#define XGXS_CTRL_MODE_10G_SET(_r,_v)   _r = ((_r & ~(0xf << 8)) | (((_v) & 0xf) << 8))
#define XGXS_CTRL_MODE_10G_SHIFT 	8
#define XGXS_CTRL_MODE_10G_MASK 	(0xf << 8)
#define MODE_10G_IND_LN_OS5             5
#define MODE_10G_IND_LN                 6
#define MODE_10G_COMBO                  12
#define XGXS_CTRL_TXCKO_DIV             (1 << 0)

/* XGXS BLOCK0 XGXSSTATUSr */
#define XGXS_BLK0_XGXS_STATUS_REG      XGS_MIIM_REG(0x8001)
#define XGXS_STATUS_TXPLL_LOCK_MASK    0x0800       

/* XGXS BLOCK0 mmdSelect Register */
#define XGXS_BLK0_MMD_SEL_REG           XGS_MIIM_REG(0x800d)
#define MMD_SEL_MULTI_PRT_EN            (1 << 15)
#define MMD_SEL_MULTI_MMD_EN            (1 << 14)

/* XGXS BLOCK1 TestTx  Register */
#define XGXS_BLK1_TEST_TX		XGS_MIIM_REG(0x8013)
#define TESTTX_RX_CK4X1MUXSEL_MASK	0xc0

/* XGXS BLOCK1 laneCtrl3 Register */
#define XGXS_BLK1_LANE_CTRL3_REG        XGS_MIIM_REG(0x8018)
#define LANE_CTRL3_PWRDWN_FORCE         (1 << 11)

/* XGXS BLOCK1 laneTest Register */
#define XGXS_BLK1_LANE_TEST_REG         XGS_MIIM_REG(0x801a)
#define LANE_TEST_PWRDWN_CLKS_EN        (1 << 8)

/* Tx LaneX/All TxAControl0 Register */
#define TX_LN0_TXA_CTRL0_REG            XGS_MIIM_REG(0x8061)
#define TX_LN1_TXA_CTRL0_REG            XGS_MIIM_REG(0x8071)
#define TX_LN2_TXA_CTRL0_REG            XGS_MIIM_REG(0x8081)
#define TX_LN3_TXA_CTRL0_REG            XGS_MIIM_REG(0x8091)
#define TXPOL_FLIP_MASK                 (1 << 5)

#define TX0_ANA_TXA_CTRL1_REG		XGS_MIIM_REG(0x8065)
#define TXA_CTRL1_HALFRATE_MASK		(1 << 3)

#define TX_ALL_TX_CTRL_REG              XGS_MIIM_REG(0x80a1)
#define TX_CTRL_TXPOL_FLIP              (1 << 5) 

/*  Rx PCI Control register */ 
#define RX0_ANARXCONTROLPCI		XGS_MIIM_REG(0x80ba)
#define RX1_ANARXCONTROLPCI		XGS_MIIM_REG(0x80ca)
#define RX2_ANARXCONTROLPCI		XGS_MIIM_REG(0x80da)
#define RX3_ANARXCONTROLPCI		XGS_MIIM_REG(0x80ea)
#define RX_POLARITY_FORCE_SM_MASK       (1 << 3)
#define RX_POLARITY_R_MASK		(1 << 2)

#define XGXSBLK2_UNICOREMODE10G_REG     XGS_MIIM_REG(0x8104)

/* Rx div/16 clock */
#define XGXSBLK2_TESTMODEMUX_REG        XGS_MIIM_REG(0x8108)

/*  10G Parallel Detect parDet10GControl Register */
#define PAR_DET_10G_CTRL_REG            XGS_MIIM_REG(0x8131)
#define PAR_DET_10G_EN                  (1 << 0)

/* DSC Misc Control 0 Register */
#define DSC2B0_DSC_MISC_CTRL0_REG       XGS_MIIM_REG(0x826e)
#define DSC2B0_DSC_MISC_CTRL0_BASE	0x826e
#define DSC2B0_DSC_MISC_CTRL0_RXSEQSTART_MASK                      0x8000

/* BRCM 64b/66b RX Register block */
#define RX66_CONTROL_REG                XGS_MIIM_REG(0x81b0)
#define RX66_CONTROL_CC_EN_MASK                                    0x2000
#define RX66_CONTROL_CC_DATA_SEL_MASK                              0x4000
#define BRCM_RX66_SCW0_REG              XGS_MIIM_REG(0x81f2)
#define BRCM_RX66_SCW1_REG              XGS_MIIM_REG(0x81f3)
#define BRCM_RX66_SCW2_REG              XGS_MIIM_REG(0x81f4)
#define BRCM_RX66_SCW3_REG              XGS_MIIM_REG(0x81f5)
#define BRCM_RX66_SCW0_MASK_REG         XGS_MIIM_REG(0x81f6)
#define BRCM_RX66_SCW1_MASK_REG         XGS_MIIM_REG(0x81f7)
#define BRCM_RX66_SCW2_MASK_REG         XGS_MIIM_REG(0x81f8)
#define BRCM_RX66_SCW3_MASK_REG         XGS_MIIM_REG(0x81f9)

/* SerDes Digital 1000XControl1 Register */
#define DIGITAL_1000X_CTRL1_REG         XGS_MIIM_REG(0x8300)
#define D1000X_CTRL1_FIBER_MODE    	(1 << 0)
#define D1000X_CTRL1_AUTO_DET_ENABLE    (1 << 4)
#define D1000X_CTRL1_DIS_PLL_PWRDWN     (1 << 6)
#define SERDESDIGITAL_CONTROL1000X1_FIBER_MODE_1000X_MASK          0x0001
#define SERDESDIGITAL_CONTROL1000X1_AUTODET_EN_MASK                0x0010

/* SerDes Digital 1000XControl2 Register */
#define DIGITAL_1000X_CTRL2_REG         XGS_MIIM_REG(0x8301)
#define D1000X_CTRL2_PAR_DET_EN         (1 << 0)
#define D1000X_CTRL2_DISABLE_FALSE_LINK	(1 << 1)
#define D1000X_CTRL2_FILTER_FORCE_LINK	(1 << 2)
#define SERDESDIGITAL_CONTROL1000X2_ENABLE_PARALLEL_DETECTION_MASK 0x0001

#define DIGITAL_1000X_CTRL3_REG         XGS_MIIM_REG(0x8302)
#define SERDESDIGITAL_CONTROL1000X3_TX_FIFO_RST_MASK               0x0001

/* SerDes Digital 1000XSTATUS1 Register */
#define DIGITAL_1000X_STATUS1_REG         XGS_MIIM_REG(0x8304)
#define SERDESDIGITAL_STATUS1000X1_SGMII_MODE_MASK                 0x0001

/* SerDes Digital Misc1 Register */
#define DIGITAL_MISC1_REG               XGS_MIIM_REG(0x8308)
#define MISC1_FORCE_SPEED_SEL           (1 << 4)
#define MISC1_FORCE_SPEED_MASK          0x001f
#define MISC1_SPEED_2500                0

/* Serdes ID 0 register */
#define TEST_SERDESID0			XGS_MIIM_REG(0x8310)

#define DIGITAL_MISC3_REG               XGS_MIIM_REG(0x833C)
#define DIGITAL4_MISC3_FORCE_SPEED_B5_MASK                         0x0080

#define FX100_CONTROL1_REG              XGS_MIIM_REG(0x8400)
#define FX100_CONTROL1_AUTODET_EN_MASK  0x0004
#define FX100_CONTROL1_FULL_DUPLEX_MASK 0x0002
#define FX100_CONTROL1_ENABLE_MASK      0x0001
#define FX100_CONTROL1_FAR_END_FAULT_EN_MASK                       0x0008

#define FX100_CONTROL2_REG              XGS_MIIM_REG(0x8401)
#define FX100_CONTROL2_EXTEND_PKT_SIZE_MASK                        0x0001 
#define FX100_CONTROL3_REG              XGS_MIIM_REG(0x8402)
#define FX100_CONTROL3_CORRELATOR_DISABLE_MASK                     0x0080

#define XGXS_IEEE0BLK_MIICNTL_REG       XGS_MIIM_REG(0x0000)

/* Address Expansion Register */
#define AER_BLK_AER_REG                 XGS_MIIM_REG(0xFFDE)
#define AERBLK_AER_MMD_DEVICETYPE_MASK  0xf800
#define AERBLK_AER_MMD_DEVICETYPE_SHIFT 11
#define AERBLK_AER_MMD_DEVICETYPE_DTE   5
#define AERBLK_AER_MMD_PORT_MASK        0x07ff
#define HC_AER_BCST_OFS_STRAP           0x3ff

#define DTE_IEEE0BLK_DTE_IEEECONTROL1   XGS_MIIM_REG(0x28000000)
/* IEEE MII control register */
#define COMBO_IEEE0_MII_CTRL       	XGS_MIIM_REG(0xFFE0)

/* IEEE MII status register */
#define COMBO_IEEE0_MII_STATUS		XGS_MIIM_REG(0xFFE1)

/* IEEE MII status register */
#define COMBO_IEEE0_MII_ADV   		XGS_MIIM_REG(0xFFE4)

/* Lane from PHY control instance */
#define LANE_NUM_MASK                   0x3

/* Vco frequency values for 10.5G/12.773G and 1G/2.5G */
#define HC_VCO_FREQ_HD127               0x7800
#define HC_VCO_FREQ_HD25                0x7700

/*
 * Private driver data
 *
 * We use a single 32-bit word which is used like this:
 *
 * 31                                   8 7             0
 * +------------------+------------------+---------------+
 * |              Reserved               | Lane polarity |
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

#else

#define LANE_POLARITY_GET(_pc) (0)
#define LANE_POLARITY_SET(_pc,_val)

#endif /* PHY_CONFIG_PRIVATE_DATA_WORDS */

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

static int _phy_reg_modify(phy_ctrl_t *pc, uint32_t reg_addr,
               uint32_t reg_data, uint32_t reg_mask);
/*
 * Function:
 *      bcmi_hypercore_serdes_lane
 * Purpose:
 *      Retrieve XGXS lane number for this PHY instance.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      Lane number or -1 if lane is unknown
 */
static int
_hypercore_serdes_lane(phy_ctrl_t *pc)
{
    uint32_t inst = PHY_CTRL_INST(pc);

    if (inst & PHY_INST_VALID) {
        return inst & LANE_NUM_MASK;
    }

    return CDK_E_INTERNAL;
}

static
int _hypercore_soft_reset(phy_ctrl_t  *pc)
{
    int ioerr = 0;

    /* Set AER to PCS */
    ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, 0x2800);

    /* select multi mmd */
    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK0_MMD_SEL_REG, 0x400F);

    /* soft reset via PCS  */
    ioerr += _PHY_REG_WRITE(pc, XGXS_IEEE0BLK_MIICNTL_REG, 0xA040);

    /* restore the AER to default */
    ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, 0);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      _hypercore_serdes_stop
 * Purpose:
 *      Put PHY in or out of reset depending on conditions.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_hypercore_serdes_stop(phy_ctrl_t *pc)
{
    uint32_t lane_ctrl3, lane_mask;
    uint32_t f_any = PHY_F_PHY_DISABLE | PHY_F_PORT_DRAIN;
    uint32_t f_copper = PHY_F_MAC_DISABLE | PHY_F_SPEED_CHG | PHY_F_DUPLEX_CHG;
    int stop = 0;
    int ioerr = 0;
    int lane;

    if ((PHY_CTRL_FLAGS(pc) & f_any) ||
        ((PHY_CTRL_FLAGS(pc) & PHY_F_FIBER_MODE) == 0 &&
         (PHY_CTRL_FLAGS(pc) & f_copper))) {
        stop = 1;
    }

    lane = _hypercore_serdes_lane(pc);


    if (lane < 0) {
        /* No power-down if lane is unknown */
        stop = 0;
        lane_mask = 0xff;
    } else {
       /* XXX disable tx only for now. rx  may affect 10g rx_ck */
       /*    lane_mask = 0x11 << lane; */
        lane_mask = 0x10 << lane;
    }

    ioerr += _PHY_REG_READ(pc, XGXS_BLK1_LANE_CTRL3_REG, &lane_ctrl3);

    lane_ctrl3 &= ~lane_mask;
    if (stop) {
        lane_ctrl3 |= lane_mask;
    }
    lane_ctrl3 |= LANE_CTRL3_PWRDWN_FORCE;

    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK1_LANE_CTRL3_REG, lane_ctrl3);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      _hypercore_rx_pol_set
 * Purpose:
 *      Set Rx polarity
 * Parameters:
 *      pc - PHY control structure
 *      inverse - flip Rx polarity if non-zero
 * Returns:
 *      CDK_E_xxx
 */
static int
_hypercore_rx_pol_set(phy_ctrl_t *pc, uint32_t inverse)
{
    int ioerr = 0;
    int lane;
    uint32_t reg, val, mask;

    lane = _hypercore_serdes_lane(pc);

    if (lane < 0) {
        /* No polarity if lane is unknown */
        return CDK_E_NONE;
    }

    mask = RX_POLARITY_FORCE_SM_MASK | RX_POLARITY_R_MASK;
    val = (inverse) ? mask : 0;

    reg = RX0_ANARXCONTROLPCI + XGS_MIIM_REG(lane * 0x10);
    ioerr += _PHY_REG_MODIFY(pc, reg, val, mask);

    if (PHY_CTRL_FLAGS(pc) & PHY_F_R2_MODE) { 
        reg += XGS_MIIM_REG(lane * 0x10);
        ioerr += _PHY_REG_MODIFY(pc, reg, val, mask);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

static int
_phy_reg_modify(phy_ctrl_t *pc, uint32_t reg_addr,
               uint32_t reg_data, uint32_t reg_mask)
{
    uint32_t  tmp, otmp;
    int ioerr;

    reg_data = reg_data & reg_mask;

    ioerr = _PHY_REG_READ(pc,reg_addr, &tmp);
    otmp = tmp;
    tmp &= ~(reg_mask);
    tmp |= reg_data;

    if (otmp != tmp) {
        ioerr += _PHY_REG_WRITE(pc, reg_addr, tmp);
    }
    return ioerr;
}

/*
 * Function:
 *      bcmi_hypercore_serdes_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_serdes_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1, serdesid0, xgxs_ctrl, mmd_sel, mode;
    int ioerr = 0;

    ioerr += phy_brcm_serdes_id(pc, &phyid0, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCM_SERDES_PHY_ID0 && phyid1 == BCM_SERDES_PHY_ID1) {
        /* Common PHY ID found - read specific SerDes ID */
        ioerr += _PHY_REG_READ(pc, SERDES_ID0, &serdesid0);
        if ((serdesid0 & 0x3f) == SERDES_ID0_XGXS_HYPERCORE) {
            /* Check for IndependentLaneOS5 mode */
            ioerr += _PHY_REG_READ(pc, XGXS_BLK0_XGXS_CTRL_REG, &xgxs_ctrl);
            mode = XGXS_CTRL_MODE_10G_GET(xgxs_ctrl);
            if (mode == MODE_10G_IND_LN || mode == MODE_10G_IND_LN_OS5) {
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
 *      bcmi_hypercore_serdes_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_serdes_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int ioerr = 0;
    uint32_t ctrl;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToPassthru:
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) |= PHY_F_PASSTHRU;
        /* Put the Serdes in passthru mode */
        ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_CTRL1_REG, &ctrl);
        ctrl &= ~SERDESDIGITAL_CONTROL1000X1_FIBER_MODE_1000X_MASK;
        ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL1_REG, ctrl);
        break;
    case PhyEvent_ChangeToFiber:
        PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_PASSTHRU;
        /* Put the Serdes in fiber mode */
        ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_CTRL1_REG, &ctrl);
        ctrl |= SERDESDIGITAL_CONTROL1000X1_FIBER_MODE_1000X_MASK;
        ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL1_REG, ctrl);
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
    _hypercore_serdes_stop(pc);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_hypercore_serdes_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_serdes_reset(phy_ctrl_t *pc)
{
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_hypercore_serdes_init
 * Purpose:     
 *      Initialize PHY driver.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_NONE
 */
static int
bcmi_hypercore_serdes_init(phy_ctrl_t *pc)
{
    int ioerr = 0;
    uint32_t xgxs_ctrl = MODE_10G_IND_LN_OS5;
    uint32_t vco_freq;
    int lane_num;
    int dxgxs = IS_DUAL_XGXS_PORT(pc);
    int addr;
    int rv, i;
    uint32_t mask16, data16;
 
    lane_num = _hypercore_serdes_lane(pc);

    /* Initialize resource shared by all 4 lanes
     * lane 0 should be always initialized first in the device 
     */
    if (lane_num == 0) {
        /* issue a soft reset first */
        ioerr += _hypercore_soft_reset(pc); 

        if (PHY_CTRL_FLAGS(pc) & PHY_F_R2_MODE) { 
            vco_freq = HC_VCO_FREQ_HD127;
        }
        else { 
            vco_freq = HC_VCO_FREQ_HD25;
        }

        xgxs_ctrl <<= XGXS_CTRL_MODE_10G_SHIFT;

        ioerr += _PHY_REG_MODIFY(pc, XGXS_BLK0_XGXS_CTRL_REG, xgxs_ctrl,
                                 XGXS_CTRL_START_SEQ |
                                 XGXS_CTRL_MODE_10G_MASK);

        /* broadcast to all lanes */
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, HC_AER_BCST_OFS_STRAP);

        /* configure VCO frequency */
        ioerr += _PHY_REG_WRITE(pc, DIGITAL_MISC1_REG, vco_freq);

        /* disable 10G parallel detect */
        ioerr += _PHY_REG_WRITE(pc, PAR_DET_10G_CTRL_REG, 0);

        /* reset AER broadcast */
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, 0);

	/* enable PLL sequencer */
        ioerr += _PHY_REG_MODIFY(pc, XGXS_BLK0_XGXS_CTRL_REG, XGXS_CTRL_START_SEQ,
 				XGXS_CTRL_START_SEQ);

        /* select recovery clock from lane0 for rxck0_10g */
         ioerr += _PHY_REG_MODIFY(pc, XGXS_BLK1_TEST_TX, 0,  
				TESTTX_RX_CK4X1MUXSEL_MASK); 
     }

    if ((PHY_CTRL_FLAGS(pc) & PHY_F_2LANE_MODE) && !(PHY_CTRL_FLAGS(pc) & PHY_F_R2_MODE)) {

        /* clear next lane default dxgxs configuration */
	addr = (lane_num+1) | (MII_C45_DEV_DTE_XS << AERBLK_AER_MMD_DEVICETYPE_SHIFT);
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, addr);

        ioerr += _PHY_REG_MODIFY(pc, DIGITAL_MISC1_REG, 0, 0x1f);
        ioerr += _PHY_REG_MODIFY(pc, DIGITAL_MISC3_REG, 0, 0x80);

    	/* disable the next lane */
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, 0);

    	mask16 = (1 << (lane_num + 1));    /* rx lane */
        mask16 |= (mask16 << 4); /* add tx lane */
        mask16 |= 0x800;         /* add force bit */
        data16 = mask16;

        ioerr += _PHY_REG_MODIFY(pc, XGXS_BLK1_LANE_CTRL3_REG, data16, mask16);
     }

    if (dxgxs) {
        addr = lane_num | (MII_C45_DEV_DTE_XS << AERBLK_AER_MMD_DEVICETYPE_SHIFT);
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, addr);
    }

    /* reset the SerDes */
    ioerr += _PHY_REG_WRITE(pc, COMBO_IEEE0_MII_CTRL, MII_CTRL_RESET);
    for (i = 0; i < 10000; i++) {
        rv = _PHY_REG_READ(pc, COMBO_IEEE0_MII_CTRL, &data16);
        if ((data16 & MII_CTRL_RESET) == 0)
            break;
    }
    if ((data16 & MII_CTRL_RESET) != 0) {
        CDK_WARN(("Combo SerDes reset failed: p=%d\n",
                         pc->port));
    }
     
     /* Enable output clock to be present when the core is commanded into
     * power down state.
     */
    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK1_LANE_TEST_REG, LANE_TEST_PWRDWN_CLKS_EN);

    data16 = D1000X_CTRL2_DISABLE_FALSE_LINK |
             D1000X_CTRL2_FILTER_FORCE_LINK;
    mask16 = data16 | D1000X_CTRL2_PAR_DET_EN;   
    ioerr += _PHY_REG_MODIFY(pc, DIGITAL_1000X_CTRL2_REG, data16, mask16);

    /* Initialialize autoneg and fullduplex */
    data16 = MII_CTRL_FD | MII_CTRL_SS_1000 | MII_CTRL_AE | MII_CTRL_RAN;
    ioerr += _PHY_REG_WRITE(pc, COMBO_IEEE0_MII_CTRL, data16);

    data16 = MII_CTRL_FD | MII_CTRL_SS_1000 | MII_CTRL_AE | MII_CTRL_RAN;
     
   /* Configuring operating mode */
    data16 = D1000X_CTRL1_DIS_PLL_PWRDWN | 
             D1000X_CTRL1_FIBER_MODE;
    mask16 = D1000X_CTRL1_AUTO_DET_ENABLE |
             D1000X_CTRL1_FIBER_MODE |
             D1000X_CTRL1_DIS_PLL_PWRDWN;
    ioerr += _PHY_REG_MODIFY(pc, DIGITAL_1000X_CTRL1_REG, data16, mask16); 

    /* config the 64B/66B for 20g dxgxs, won't affect other speeds and AN  */ 
    ioerr += _PHY_REG_WRITE(pc, BRCM_RX66_SCW0_REG, 0xE070);
    ioerr += _PHY_REG_WRITE(pc, BRCM_RX66_SCW1_REG, 0xC0D0);
    ioerr += _PHY_REG_WRITE(pc, BRCM_RX66_SCW2_REG, 0xA0B0);
    ioerr += _PHY_REG_WRITE(pc, BRCM_RX66_SCW3_REG, 0x8090);
    ioerr += _PHY_REG_WRITE(pc, BRCM_RX66_SCW0_MASK_REG, 0xF0F0);
    ioerr += _PHY_REG_WRITE(pc, BRCM_RX66_SCW1_MASK_REG, 0xF0F0);
    ioerr += _PHY_REG_WRITE(pc, BRCM_RX66_SCW2_MASK_REG, 0xF0F0);
    ioerr += _PHY_REG_WRITE(pc, BRCM_RX66_SCW3_MASK_REG, 0xF0F0);

    /* for custom dual-xgxs mode, autoneg is not supported. Set default
     * speed to 10G
     */
    if ((PHY_CTRL_FLAGS(pc) & PHY_F_2LANE_MODE) && (PHY_CTRL_FLAGS(pc) & PHY_F_R2_MODE)) {
        ioerr += _PHY_REG_MODIFY(pc, COMBO_IEEE0_MII_CTRL, 0, MII_CTRL_AE);

        /* force R2 speed */
        ioerr += _PHY_REG_MODIFY(pc, DIGITAL_MISC1_REG, 0x1, 0x1f);

        /* set the other force speed control bit in misc3 */
        ioerr += _PHY_REG_MODIFY(pc, DIGITAL_MISC3_REG,
                DIGITAL4_MISC3_FORCE_SPEED_B5_MASK,
                DIGITAL4_MISC3_FORCE_SPEED_B5_MASK);
    }
    else {
        ioerr += _PHY_REG_MODIFY(pc, COMBO_IEEE0_MII_ADV , 0x00a0, 0x00a0);
        ioerr += _PHY_REG_MODIFY(pc, COMBO_IEEE0_MII_CTRL, MII_CTRL_AE, 
				MII_CTRL_AE);
        ioerr += _PHY_REG_MODIFY(pc, DIGITAL_MISC1_REG, 0, 0x1f);
        ioerr += _PHY_REG_MODIFY(pc, DIGITAL_MISC3_REG, 0,
                            	DIGITAL4_MISC3_FORCE_SPEED_B5_MASK);
    }

    /* restore back AER register */
    if (dxgxs) {
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, 0);
    }

    /* Default mode is fiber */
    PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_hypercore_serdes_link_get
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
bcmi_hypercore_serdes_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    int ioerr = 0;
    int lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;
    int dxgxs = IS_DUAL_XGXS_PORT(pc);
    int addr;
    uint32_t mii_stat;
 
    if (dxgxs) {
        addr = lane_num | (MII_C45_DEV_DTE_XS << AERBLK_AER_MMD_DEVICETYPE_SHIFT);
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, addr);
    }

    ioerr += _PHY_REG_READ(pc, COMBO_IEEE0_MII_STATUS, &mii_stat);

    if (link) {
        *link = (mii_stat &  MII_STAT_LA) ? 1 : 0;
    }

    if (autoneg_done) {
        *autoneg_done = (mii_stat &  MII_STAT_AN_DONE) ? 1 : 0;
    }

    if (dxgxs) {
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, 0);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hypercore_serdes_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_serdes_duplex_set(phy_ctrl_t *pc, int duplex)
{
    return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
}

/*
 * Function:    
 *      bcmi_hypercore_serdes_duplex_get
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
bcmi_hypercore_serdes_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hypercore_serdes_speed_set
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
bcmi_hypercore_serdes_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    uint32_t       speed_val, mask, data;
    uint32_t       speed_mii;
    uint32_t       sgmii_status = 0;
    int ioerr = 0;
    int lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;
    int dxgxs = IS_DUAL_XGXS_PORT(pc);
    int tx_halfrate_bit;
    int addr;
    int rv;

    rv = PHY_SPEED_GET(pc, &speed_val);
    if (CDK_FAILURE(rv)) {
        return rv;
    }
    if (speed == speed_val) {
        return CDK_E_NONE;
    }

    speed_val = 0;
    speed_mii = 0;
    switch (speed) {
    case 0:         /* Do not change speed */
        return CDK_E_NONE;
    case 10:
        speed_mii = MII_CTRL_SS_10;
        break;
    case 100:
        speed_mii = MII_CTRL_SS_100;
        break;
    case 1000:
        speed_mii = MII_CTRL_SS_1000;
        break;
    case 2500:
        speed_val = 0x10;
        break;
    case 10000:  
        if (dxgxs) {  /* custom speed for now */
            if (PHY_CTRL_FLAGS(pc) & PHY_F_R2_MODE) {
                speed_val = 0x21; /* 10.5HiG dual-XGXS */
            } else {
                speed_val = 0x20; /* 10G ethernet dual-XGXS */
            }
        } else {
            speed_val = 0x13;
        }
        break;

    case 12000:  /* dxgxs */
        /* 12.773G       0x23
         */
        if (dxgxs) { /* custom speed for now */
            if (PHY_CTRL_FLAGS(pc) & PHY_F_R2_MODE) {
                speed_val = 0x23;
            } else {
                speed_val = 0x15;
            }
        } else {
            speed_val = 0x15;
        }
        break;
    case 13000:
	speed_val = 0x17;
        break; 	
    case 16000: /* speed_15750_hi_dxgxs */
        speed_val = 0x19;
        break;
    case 20000: /* 20G dxgxs, 20G dxgxs hig */
        speed_val = 0x1c; /* 20G ethernet dual-XGXS */
        break;
    case 21000:
        speed_val = 0x1d;
        break;
    case 25000:
       speed_val = 0x1e;
        break;
    default:
        return CDK_E_PARAM;
    }

    /* set to dual-lane broadcast addressing mode if dxgxs port */
    if (dxgxs) {
        addr = lane_num | (MII_C45_DEV_DTE_XS << AERBLK_AER_MMD_DEVICETYPE_SHIFT); 
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, addr);
    }

    /* Hold rxSeqStart */
    ioerr += _PHY_REG_MODIFY(pc, XGS_MIIM_REG(DSC2B0_DSC_MISC_CTRL0_BASE + (0x10 * lane_num)),
                             DSC2B0_DSC_MISC_CTRL0_RXSEQSTART_MASK,
                             DSC2B0_DSC_MISC_CTRL0_RXSEQSTART_MASK);

    /* hold TX FIFO in reset */
    ioerr += _PHY_REG_MODIFY(pc, DIGITAL_1000X_CTRL3_REG,
                           SERDESDIGITAL_CONTROL1000X3_TX_FIFO_RST_MASK,
                           SERDESDIGITAL_CONTROL1000X3_TX_FIFO_RST_MASK);

    /* disable 100FX and 100FX auto-detect */
    ioerr += _PHY_REG_MODIFY(pc, FX100_CONTROL1_REG, 0,
                         FX100_CONTROL1_AUTODET_EN_MASK |
                         FX100_CONTROL1_ENABLE_MASK);

    /* disable 100FX idle detect */
    ioerr += _PHY_REG_MODIFY(pc, FX100_CONTROL3_REG,
                             FX100_CONTROL3_CORRELATOR_DISABLE_MASK,
                             FX100_CONTROL3_CORRELATOR_DISABLE_MASK);

    data = speed_val & 0x1f;
    mask = MISC1_FORCE_SPEED_MASK;
    /* set the force speed in misc1 */
    ioerr += _PHY_REG_MODIFY(pc, DIGITAL_MISC1_REG, data, mask);

    /* set the other force speed control bit in misc3 */
    data = (speed_val & 0x20) ? DIGITAL4_MISC3_FORCE_SPEED_B5_MASK : 0;
    mask = DIGITAL4_MISC3_FORCE_SPEED_B5_MASK; 
    ioerr += _PHY_REG_MODIFY(pc, DIGITAL_MISC3_REG,data,mask);

    if (speed <= 1000) {
        ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_STATUS1_REG, &sgmii_status);
        sgmii_status &= SERDESDIGITAL_STATUS1000X1_SGMII_MODE_MASK;
        if (!sgmii_status && (speed == 100)) {

            /* fiber mode 100fx, enable */
            ioerr += _PHY_REG_MODIFY(pc, FX100_CONTROL1_REG,
                       FX100_CONTROL1_FAR_END_FAULT_EN_MASK |
                       FX100_CONTROL1_ENABLE_MASK,
                       FX100_CONTROL1_FAR_END_FAULT_EN_MASK |
                       FX100_CONTROL1_ENABLE_MASK);

            /* enable 100fx extended packet size */
            ioerr += _PHY_REG_MODIFY(pc, FX100_CONTROL2_REG,
                             FX100_CONTROL2_EXTEND_PKT_SIZE_MASK,
                             FX100_CONTROL2_EXTEND_PKT_SIZE_MASK);
        } else {
            ioerr += _PHY_REG_MODIFY(pc, COMBO_IEEE0_MII_CTRL,speed_mii,
                                     MII_CTRL_SS_MASK);
        }
    }

    speed_val = (speed >= 10000) ? 0 : XGXS_CTRL_TXCKO_DIV;
    ioerr += _PHY_REG_MODIFY(pc, XGXS_BLK0_XGXS_CTRL_REG, speed_val, 
 				XGXS_CTRL_TXCKO_DIV);  

    tx_halfrate_bit = (speed == 2500 || speed == 10000) ? 
                        TXA_CTRL1_HALFRATE_MASK : 0;
        /* set tx half rate bits after the link is established at 2.5G or 10G
         * in both force mode or autoneg mode.
         */
    ioerr += _PHY_REG_MODIFY(pc, TX0_ANA_TXA_CTRL1_REG, tx_halfrate_bit,
			TXA_CTRL1_HALFRATE_MASK);

    /* release rxSeqStart */
    ioerr += _PHY_REG_MODIFY(pc, XGS_MIIM_REG(DSC2B0_DSC_MISC_CTRL0_BASE + (0x10 * lane_num)),
                             0,
                             DSC2B0_DSC_MISC_CTRL0_RXSEQSTART_MASK);

    /* release TX FIFO reset */
    ioerr += _PHY_REG_MODIFY(pc, DIGITAL_1000X_CTRL3_REG,
                             0,
                             SERDESDIGITAL_CONTROL1000X3_TX_FIFO_RST_MASK);

    /* restore AER register */
    if (dxgxs) {
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, 0);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hypercore_serdes_speed_get
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
bcmi_hypercore_serdes_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    uint32_t stat1;
    uint32_t speed_val;
    int ioerr = 0;
    int lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;
    int dxgxs = IS_DUAL_XGXS_PORT(pc);
    int addr;
 
    if (dxgxs) {
        addr = lane_num | (MII_C45_DEV_DTE_XS << AERBLK_AER_MMD_DEVICETYPE_SHIFT);
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, addr);
    }

    if (PHY_CTRL_FLAGS(pc) & PHY_F_2LANE_MODE) {
	ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_STATUS1_REG, &stat1);
        stat1 = (stat1 >> 0x3)  & 3;
        switch (stat1) {
        case 2:
            *speed = 1000;
            break;
        case 3:
            *speed = 2500;
            break;
        case 0:
            *speed = 10;
            break;
        case 1:
            *speed = 100;
            break;
        default:
            *speed = 0;
        }
        /* check dxgxs speeds
         * There is no speed status for second dxgxs block. We'll simply
         * check what the speed is set. It should be OK since the dxgxs mode
         * does not support autoneg
         */
	if (PHY_CTRL_FLAGS(pc) & PHY_F_R2_MODE)	{
	    ioerr += _PHY_REG_READ(pc, DIGITAL_MISC3_REG, &speed_val);
            if (speed_val & DIGITAL4_MISC3_FORCE_SPEED_B5_MASK) {
		ioerr += _PHY_REG_READ(pc, DIGITAL_MISC1_REG, &speed_val);
                speed_val &= (MISC1_FORCE_SPEED_MASK & ~MISC1_FORCE_SPEED_SEL);
		if (speed_val == 3) {
		   *speed=12000;
		} else if (speed_val == 0 || speed_val == 1) {
		   *speed=10000;
               } 	
 	
	    }	
	}

    }

    if (dxgxs) {
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, 0);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hypercore_serdes_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */

static int
bcmi_hypercore_serdes_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int ioerr = 0;
    int lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;
    int dxgxs = IS_DUAL_XGXS_PORT(pc);
    int addr;
    uint32_t an_val, an_mask;
 
    if (dxgxs) {
        addr = lane_num | (MII_C45_DEV_DTE_XS << AERBLK_AER_MMD_DEVICETYPE_SHIFT);
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, addr);
    }

    an_mask = D1000X_CTRL1_AUTO_DET_ENABLE;
    an_val  = (autoneg) ? an_mask : 0;
    ioerr += _PHY_REG_MODIFY(pc, DIGITAL_1000X_CTRL1_REG, an_val, an_mask); 

    an_mask = MII_CTRL_AE | MII_CTRL_RAN;
    an_val  = (autoneg) ? an_mask : 0;
    ioerr += _PHY_REG_MODIFY(pc, COMBO_IEEE0_MII_CTRL, an_val, an_mask);

    /* Disable forced speed if atuoneg enabled */
    if (autoneg) {
        ioerr += _PHY_REG_MODIFY(pc, DIGITAL_MISC1_REG, 0,
                                 MISC1_FORCE_SPEED_MASK);
        ioerr += _PHY_REG_MODIFY(pc, DIGITAL_MISC3_REG, 0,
                                 DIGITAL4_MISC3_FORCE_SPEED_B5_MASK);
    }

    if (dxgxs) {
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, 0);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hypercore_serdes_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_serdes_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    int ioerr = 0;
    int lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;
    int dxgxs = IS_DUAL_XGXS_PORT(pc);
    int addr;
    uint32_t mii_ctrl;
 
    if (dxgxs) {
        addr = lane_num | (MII_C45_DEV_DTE_XS << AERBLK_AER_MMD_DEVICETYPE_SHIFT);
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, addr);
    }

    ioerr += _PHY_REG_READ(pc, COMBO_IEEE0_MII_CTRL, &mii_ctrl);
    if (autoneg) {
        *autoneg = (mii_ctrl & MII_CTRL_AE) ? 1 : 0;
    }

    if (dxgxs) {
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, 0);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hypercore_serdes_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_serdes_loopback_set(phy_ctrl_t *pc, int enable)
{
    int ioerr = 0;
    int lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;
    int dxgxs = IS_DUAL_XGXS_PORT(pc);
    int addr;
    uint32_t  lb_bit;
    uint32_t  lb_mask;
    uint32_t  reg;
    uint32_t  rx_flip;
    uint32_t  mask;

    lb_bit  = (enable) ? MII_CTRL_LE : 0;
    lb_mask = MII_CTRL_AE | MII_CTRL_RAN | MII_CTRL_LE;
    
    /* set to dual-lane broadcast addressing mode if dxgxs port */
    if (dxgxs) {
        addr = lane_num | (MII_C45_DEV_DTE_XS << AERBLK_AER_MMD_DEVICETYPE_SHIFT);
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, addr);

    	if (enable) {
            if (LANE_POLARITY_GET(pc) == 0) {
                /* Save the polarity setting and clear hardware */
                reg = RX0_ANARXCONTROLPCI + XGS_MIIM_REG(lane_num * 0x10);
                ioerr += _PHY_REG_READ(pc, reg, &rx_flip);
                mask = RX_POLARITY_FORCE_SM_MASK | RX_POLARITY_R_MASK;
                LANE_POLARITY_SET(pc, rx_flip & mask);
                ioerr += _PHY_REG_WRITE(pc, reg, rx_flip & ~mask);
            }
    	    ioerr += _PHY_REG_MODIFY(pc, COMBO_IEEE0_MII_CTRL, lb_bit, lb_mask);
    	}
    	else {
            if (LANE_POLARITY_GET(pc) != 0) {
                /* Restore the polarity setting to hardware */
                reg = RX0_ANARXCONTROLPCI + XGS_MIIM_REG(lane_num * 0x10);
                ioerr += _PHY_REG_READ(pc, reg, &rx_flip);
                mask = LANE_POLARITY_GET(pc);
                ioerr += _PHY_REG_WRITE(pc, reg, rx_flip | mask);
            }
            ioerr += _PHY_REG_MODIFY(pc, COMBO_IEEE0_MII_CTRL, 0, MII_CTRL_LE);
    	}

        ioerr += _PHY_REG_MODIFY(pc, DTE_IEEE0BLK_DTE_IEEECONTROL1,
                             lb_bit, MII_CTRL_LE);

        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, 0);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hypercore_serdes_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_serdes_loopback_get(phy_ctrl_t *pc, int *enable)
{
    int ioerr = 0;     
    uint32_t mii_ctrl;
    int lane_num = PHY_CTRL_INST(pc) & LANE_NUM_MASK;
    int dxgxs = IS_DUAL_XGXS_PORT(pc);
    int addr;

    if (dxgxs) {
        addr = lane_num | (MII_C45_DEV_DTE_XS << AERBLK_AER_MMD_DEVICETYPE_SHIFT);
        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, addr);

        /* Get loopback mode from SerDes registers */
        ioerr += _PHY_REG_READ(pc, COMBO_IEEE0_MII_CTRL, &mii_ctrl);
        *enable = (mii_ctrl & MII_CTRL_LE) ? 1 : 0;

        ioerr += _PHY_REG_WRITE(pc, AER_BLK_AER_REG, 0);
    } 
    else {
        ioerr += _PHY_REG_READ(pc, COMBO_IEEE0_MII_CTRL, &mii_ctrl);
        *enable = (mii_ctrl & MII_CTRL_LE) ? 1 : 0;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hypercore_serdes_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hypercore_serdes_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    int custom = PHY_CTRL_FLAGS(pc) & PHY_F_R2_MODE;

    if (custom) {
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
 *      bcmi_hypercore_serdes_config_set
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
bcmi_hypercore_serdes_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        PHY_CTRL_FLAGS(pc) |= PHY_F_PHY_DISABLE;
        if (val) {
            PHY_CTRL_FLAGS(pc) &= ~PHY_F_PHY_DISABLE;
        }
        return _hypercore_serdes_stop(pc);
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
#if PHY_CONFIG_INCLUDE_XAUI_RX_POLARITY_SET
    case PhyConfig_XauiRxPolInvert: {
        return _hypercore_rx_pol_set(pc, val);
    }
#endif
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcmi_hypercore_serdes_config_get
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
bcmi_hypercore_serdes_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = (PHY_CTRL_FLAGS(pc) & PHY_F_PHY_DISABLE) ? 0 : 1;
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        *val = PHY_IF_GMII;
        return CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/* Public PHY Driver Structure */
phy_driver_t bcmi_hypercore_serdes_drv = {
    "bcmi_hypercore_serdes", 
    "Internal Hypercore 2.5G/1.25G/10.5G/12.77G SerDes PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_hypercore_serdes_probe,        /* pd_probe */
    bcmi_hypercore_serdes_notify,       /* pd_notify */
    bcmi_hypercore_serdes_reset,        /* pd_reset */
    bcmi_hypercore_serdes_init,         /* pd_init */
    bcmi_hypercore_serdes_link_get,     /* pd_link_get */
    bcmi_hypercore_serdes_duplex_set,   /* pd_duplex_set */
    bcmi_hypercore_serdes_duplex_get,   /* pd_duplex_get */
    bcmi_hypercore_serdes_speed_set,    /* pd_speed_set */
    bcmi_hypercore_serdes_speed_get,    /* pd_speed_get */
    bcmi_hypercore_serdes_autoneg_set,  /* pd_autoneg_set */
    bcmi_hypercore_serdes_autoneg_get,  /* pd_autoneg_get */
    bcmi_hypercore_serdes_loopback_set, /* pd_loopback_set */
    bcmi_hypercore_serdes_loopback_get, /* pd_loopback_get */
    bcmi_hypercore_serdes_ability_get,  /* pd_ability_get */
    bcmi_hypercore_serdes_config_set,   /* pd_config_set */
    bcmi_hypercore_serdes_config_get,   /* pd_config_get */
    NULL,                               /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
