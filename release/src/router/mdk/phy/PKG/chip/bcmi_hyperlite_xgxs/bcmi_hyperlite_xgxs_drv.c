/*
 * $Id: bcmi_hyperlite_xgxs_drv.c,v 1.17 Broadcom SDK $
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
 * PHY driver for internal Hyperlite 21G XGXS PHY.
 *
 */

#include <phy/phy.h>
#include <phy/phy_xgs_iblk.h>
#include <phy/phy_brcm_serdes_id.h>
#include <phy/ge_phy.h>

#define BCM_SERDES_PHY_ID0              0x143
#define BCM_SERDES_PHY_ID1              0xbff0

#define PHY_ID1_REV_MASK                0x000f

#define SERDES_ID0_XGXS_HYPERLITE       0x03

#define _PHY_REG_READ(_pc, _r, _v)      phy_xgs_iblk_read(_pc, _r, _v)
#define _PHY_REG_WRITE(_pc, _r, _v)     phy_xgs_iblk_write(_pc, _r, _v)

#define PHY_AN_DONE_POLL_MAX            10000
#define TUNING_DONE_10MSEC              50      /* 500 msec */
#define VGA_DFE_SAMPLES                 50
#define VGA_SUM_SAMPLES                 10

/* Transform datasheet mapped address to MIIM address used by software API */
#define IBLK_DEVAD(_d) LSHIFT32((_d), PHY_REG_ACCESS_FLAGS_SHIFT)
#define XGS_MIIM_REG(_a) PHY_XGS_C45_TO_IBLK(_a)
#define PMA_MIIM_REG(_a) (XGS_MIIM_REG(_a) | IBLK_DEVAD(MII_C45_DEV_PMA_PMD))
#define DTE_MIIM_REG(_a) (XGS_MIIM_REG(_a) | IBLK_DEVAD(MII_C45_DEV_DTE_XS))

/* Lane offset applies to the transformed address */
#define LANE_OFFSET                     XGS_MIIM_REG(0x10)

/* IEEE PMA/PMD MII Control register */
#define PMA_CTRL_REG                    PMA_MIIM_REG(0x0000)
#define PMA_CTRL_SW_RST                 (1 << 15)
#define PMA_CTRL_SW_PD                  (1 << 13)
#define PMA_CTRL_PMD_LB                 (1 << 0)

/* IEEE DTE MII Control register */
#define DTE_CTRL_REG                    DTE_MIIM_REG(0x0000)
#define DTE_CTRL_SW_RST                 (1 << 15)
#define DTE_CTRL_LB                     (1 << 14)
#define DTE_CTRL_SW_PD                  (1 << 13)

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

/* XGXS BLOCK0 miscControl1 Register */
#define XGXS_BLK0_MISC_CTRL1_REG        XGS_MIIM_REG(0x800e)
#define MISC_CTRL1_PMD_EN               (1 << 9)
#define MISC_CTRL1_IEEE_AUTO            (1 << 1)
#define MISC_CTRL1_IEEE_XAUI            (1 << 0)

/* XGXS BLOCK1 laneTest Register */
#define XGXS_BLK1_LANE_TEST_REG        XGS_MIIM_REG(0x801a)
#define LANE_TEST_PWRDN_CLKS_EN        (1 << 8)

/* Tx LaneX/All TxAControl0 Register */
#define TX_LN0_TX_CTRL_REG              XGS_MIIM_REG(0x8061)
#define TX_ALL_TX_CTRL_REG              XGS_MIIM_REG(0x80a1)
#define TX_CTRL_TXPOL_FLIP              (1 << 5)

/* Tx Driver Register */
#define TX_ALL_TX_DRV_REG               XGS_MIIM_REG(0x80a7)
#define TX_DRV_PREEMP_GET(_r)           ((_r >> 12) & 0xf)
#define TX_DRV_PREEMP_SET(_r,_v)        _r = ((_r & ~(0xf << 12)) | (((_v) & 0xf) << 12))
#define TX_DRV_IDRV_GET(_r)             ((_r >> 8) & 0xf)
#define TX_DRV_IDRV_SET(_r,_v)          _r = ((_r & ~(0xf << 8)) | (((_v) & 0xf) << 8))
#define TX_DRV_PREIDRV_GET(_r)          ((_r >> 4) & 0xf)
#define TX_DRV_PREIDRV_SET(_r,_v)       _r = ((_r & ~(0xf << 4)) | (((_v) & 0xf) << 4))

/* Rx LaneX/All anaRxStatus Register */
#define RX_LN0_RX_STAT_REG              XGS_MIIM_REG(0x80b0)
#define RX_STAT_CX4_SIGDET              (1 << 15)

/* Rx LaneX/All anaRxControl Register */
#define RX_LN0_RX_CTRL_REG              XGS_MIIM_REG(0x80b1)

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

/* 10G Parallel Detect parDet10GControl Register */
#define PAR_DET_10G_CTRL_REG            XGS_MIIM_REG(0x8131)
#define PAR_DET_10G_EN                  (1 << 0)

/* 10G Parallel Detect xgxs20GStatus Register */
#define PAR_DET_20G_STAT_REG            XGS_MIIM_REG(0x813c)
#define XGXS_20G_STAT_SPEED_GET(_r)     ((_r >> 0) & 0x3f)
#define XGXS_20G_STAT_SPEED_SET(_r,_v)  _r = ((_r & ~(0x3f << 0)) | (((_v) & 0x3f) << 0))
#define STAT_20G_SPEED_20000            18
#define STAT_20G_SPEED_21000            19

/* DSC1 LaneX Analog Control 0 Register */
#define DSC2_LN0_ANA_CTRL0_REG          XGS_MIIM_REG(0x821a)
#define ANA_CTRL0_FORCE_ODD_CTRL        (1 << 15)

/* DSC1 LaneX DFE VGA Control 1 Register */
#define DSC2_LN0_DFE_VGA_CTRL1_REG      XGS_MIIM_REG(0x8215)
#define VGA_WRITE_VAL_SET(_r,_v)        _r = ((_r & ~(0x1f << 1)) | (((_v) & 0x1f) << 1))
#define DFE_VGA_CTRL1_VGA_WRITE_EN      (1 << 0)

/* DSC1 LaneX Analog Control 1 Register */
#define DSC2_LN0_ANA_CTRL1_REG          XGS_MIIM_REG(0x821b)
#define ANA_CTRL1_FORCE_EVN_CTRL        (1 << 15)

/* DSC2 LaneX/All State Machine Control 0 Register */
#define DSC2_LN0_SM_CTRL0_REG           XGS_MIIM_REG(0x8260)
#define DSC2_ALL_SM_CTRL0_REG           XGS_MIIM_REG(0x82a0)
#define SM_CTRL0_DEFAULT                0x821
#define SM_CTRL0_BYPASS_TX_POSTC_CAL    (1 << 14)
#define SM_CTRL0_BYPASS_BR_PF_CAL       (1 << 9)
#define SM_CTRL0_RESTART_TUNING         (1 << 1)
#define SM_CTRL0_TUNING_SM_EN           (1 << 0)

/* DSC2 LaneX/All State Machine Control 2 Register */
#define DSC2_LN0_SM_CTRL2_REG           XGS_MIIM_REG(0x8262)
#define DSC2_ALL_SM_CTRL2_REG           XGS_MIIM_REG(0x82a2)
#define SM_CTRL2_TRAIN_MODE_EN          (1 << 0)

/* DSC2 LaneX Misc. Control 0 Register */
#define DSC2_LN0_MISC_CTRL0_REG         XGS_MIIM_REG(0x826e)
#define MISC_CTRL0_RX_SEQ_START         (1 << 15)

/* DSC3 LaneX DFE/VGA Status 0 Register */
#define DSC3_LN0_DFE_VGA_STAT0_REG      XGS_MIIM_REG(0x82b5)
#define VGA_SUM_GET(_r)                 ((_r >> 5) & 0x1f)
#define DFE_TAP_BIN_GET(_r)             ((_r >> 0) & 0x1f)

/* DSC3 LaneX State Machine Status 0 Register */
#define DSC3_LN0_SM_STAT0_REG           XGS_MIIM_REG(0x82b7)
#define SM_STAT0_TUNING_DONE            (1 << 13)

/* DSC3 LaneX State Machine Status 1 Register */
#define DSC3_LN0_SM_STAT1_REG           XGS_MIIM_REG(0x82b8)
#define POSTC_METRIC_GET(_r)            ((_r >> 0) & 0x7ff)

/* SerDes Digital 1000XControl1 Register */
#define DIGITAL_1000X_CTRL1_REG         XGS_MIIM_REG(0x8300)
#define D1000X_CTRL1_DIS_PLL_PWRDN      (1 << 6)
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
#define MISC1_SPEED_20000               12
#define MISC1_SPEED_21000               13

/* IEEE-B0 MII Control Register */
#define B0_MII_CTRL_REG                 XGS_MIIM_REG(0xffe0)

/* IEEE-B0 MII Status Register */
#define B0_MII_STAT_REG                 XGS_MIIM_REG(0xffe1)

/* Low level debugging (off by default) */
#ifdef BCMI_HYPERLITE_XGXS_DEBUG_ENABLE
#define BCMI_HYPERLITE_XGXS_DBG(_pc, _str) \
    CDK_WARN(("bcm8073[%d.%d]: " _str "\n", \
               PHY_CTRL_UNIT(_pc), PHY_CTRL_PORT(_pc)));
#else
#define BCMI_HYPERLITE_XGXS_DBG(_pc, _str)
#endif

/***********************************************************************
 *
 * HELPER FUNCTIONS
 *
 ***********************************************************************/

#if PHY_CONFIG_INCLUDE_AUTO_TUNE

/*
 * Function:
 *      bcmi_hyperlite_xgxs_rx_tune_start
 * Purpose:
 *      Start Rx tuning on all lanes
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_xgxs_rx_tune_start(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int lane;
    uint32_t reg_addr;
    uint32_t misc_ctrl;

    for (lane = 0; lane < 4; lane++) {
        /* Start receive tuning by toggling rxSeqStart */
        reg_addr = DSC2_LN0_MISC_CTRL0_REG + lane * LANE_OFFSET;
        ioerr += _PHY_REG_READ(pc, reg_addr, &misc_ctrl);
        ioerr += _PHY_REG_WRITE(pc, reg_addr,
                                misc_ctrl | MISC_CTRL0_RX_SEQ_START);
        ioerr += _PHY_REG_WRITE(pc, reg_addr, misc_ctrl);
    }
    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_hyperlite_xgxs_rx_tune_status
 * Purpose:
 *      Get Rx tuning status
 * Parameters:
 *      pc - PHY control structure
 *      tune_ok - (OUT) non-zero indicates tuning ok
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_xgxs_rx_tune_status(phy_ctrl_t *pc, uint32_t *tune_ok)
{
    int ioerr = 0;
    int lane, cnt, early_rev;
    uint32_t reg_addr, reg_offset;
    uint32_t serdesid0, lane_ctrl, lane_stat, sm_stat, dfe_vga_stat;
    uint32_t dfe, postc_metric;

    /* Early revisions need special attention */
    ioerr += _PHY_REG_READ(pc, SERDES_ID0, &serdesid0);
    early_rev = ((serdesid0 & 0xc000) < 0x8000) ? 1 : 0;

    for (lane = 0; lane < 4; lane++) {
        /* For registers that have a copy for each lane */
        reg_offset = lane * LANE_OFFSET;

        /* Select Rx status type 0 */
        reg_addr = RX_LN0_RX_CTRL_REG + reg_offset;
        ioerr += _PHY_REG_READ(pc, reg_addr, &lane_ctrl);
        ioerr += _PHY_REG_WRITE(pc, reg_addr, lane_ctrl & ~0x7);

        /* Read signal detect status (twice to clear latched status) */
        reg_addr = RX_LN0_RX_STAT_REG + reg_offset;
        ioerr += _PHY_REG_READ(pc, reg_addr, &lane_stat);
        ioerr += _PHY_REG_READ(pc, reg_addr, &lane_stat);

        /* Make sure we have signal detect */
        if ((lane_stat & RX_STAT_CX4_SIGDET) == 0) {
            BCMI_HYPERLITE_XGXS_DBG(pc, "no signal");
            return CDK_E_FAIL;
        }

        /* Wait for tuning done signal */
        for (cnt = 0; cnt < TUNING_DONE_10MSEC; cnt++) {
            reg_addr = DSC3_LN0_SM_STAT0_REG + reg_offset;
            ioerr += _PHY_REG_READ(pc, reg_addr, &sm_stat);
            if (sm_stat & SM_STAT0_TUNING_DONE) {
                break;
            }
            PHY_SYS_USLEEP(10000);
        }

        if ((sm_stat & SM_STAT0_TUNING_DONE) == 0) {
            BCMI_HYPERLITE_XGXS_DBG(pc, "tuning done timeout");
            return CDK_E_TIMEOUT;
        }

        /* Collect DFE samples and calculate average */
        reg_addr = DSC3_LN0_DFE_VGA_STAT0_REG + reg_offset;
        dfe = 0;
        for (cnt = 0; cnt < VGA_DFE_SAMPLES; cnt++) {
            ioerr += _PHY_REG_READ(pc, reg_addr, &dfe_vga_stat);
            dfe += DFE_TAP_BIN_GET(dfe_vga_stat);
        }
        dfe = dfe / VGA_DFE_SAMPLES;

        /* Get port cursor metric from register */
        reg_addr = DSC3_LN0_SM_STAT1_REG + reg_offset;
        ioerr += _PHY_REG_READ(pc, reg_addr, &sm_stat);
        postc_metric = POSTC_METRIC_GET(sm_stat);

        /* Early revisions need special attention */
        if (early_rev) {
            if (dfe < 8) {
                postc_metric = 0x400; /* -1023 11 bit 2s complement number */
            } else if (dfe > 56) {
                postc_metric = 0x3ff; /* 1023 11 bit 2s complement number */
            }
        }

        /* Tune failed if portc_metric is positive with small DFE */
        if (postc_metric < 0x400 && dfe < 30) {
            *tune_ok = 0;
            break;
        }
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_hyperlite_xgxs_rx_fine_tune
 * Purpose:
 *      Get Rx tuning status
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_xgxs_rx_fine_tune(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int lane, cnt, early_rev;
    uint32_t reg_addr, reg_offset;
    uint32_t serdesid0, sm_ctrl, sm_stat, ana_ctrl, dfe_vga_stat, dfe_vga_ctrl;
    uint32_t vga_sum, br_pf_cal;

    /* Early revisions need special attention */
    ioerr += _PHY_REG_READ(pc, SERDES_ID0, &serdesid0);
    early_rev = ((serdesid0 & 0xc000) < 0x8000) ? 1 : 0;

    br_pf_cal = SM_CTRL0_BYPASS_BR_PF_CAL | SM_CTRL0_BYPASS_TX_POSTC_CAL;

    for (lane = 0; lane < 4; lane++) {
        /* For registers that have a copy for each lane */
        reg_offset = lane * LANE_OFFSET;

        if (early_rev) {
            /* Disable DSC tuning state machine */
            reg_addr = DSC2_LN0_SM_CTRL0_REG + reg_offset;
            ioerr += _PHY_REG_READ(pc, reg_addr, &sm_ctrl);
            sm_ctrl &= ~SM_CTRL0_TUNING_SM_EN;
            ioerr += _PHY_REG_WRITE(pc, reg_addr, sm_ctrl);
	
            /* Enable training mode in state machine */
            reg_addr = DSC2_LN0_SM_CTRL2_REG + reg_offset;
            ioerr += _PHY_REG_READ(pc, reg_addr, &sm_ctrl);
            sm_ctrl |= SM_CTRL2_TRAIN_MODE_EN;
            ioerr += _PHY_REG_WRITE(pc, reg_addr, sm_ctrl);

            /* Bypass BR peaking filter calibration */
            reg_addr = DSC2_LN0_SM_CTRL0_REG + reg_offset;
            br_pf_cal = SM_CTRL0_BYPASS_BR_PF_CAL;
            ioerr += _PHY_REG_READ(pc, reg_addr, &sm_ctrl);
            sm_ctrl |= br_pf_cal;
            ioerr += _PHY_REG_WRITE(pc, reg_addr, sm_ctrl);

            /* DSC Analog control 0 odd ctrl register setup */
            reg_addr = DSC2_LN0_ANA_CTRL0_REG + reg_offset;
            ana_ctrl = ANA_CTRL0_FORCE_ODD_CTRL;
            ioerr += _PHY_REG_WRITE(pc, reg_addr, ana_ctrl);

            /* DSC Analog control 0 even ctrl register setup */
            reg_addr = DSC2_LN0_ANA_CTRL1_REG + reg_offset;
            ana_ctrl = ANA_CTRL1_FORCE_EVN_CTRL;
            ioerr += _PHY_REG_WRITE(pc, reg_addr, ana_ctrl);

            /* Collect VGA samples and calculate average */
            reg_addr = DSC3_LN0_DFE_VGA_STAT0_REG + reg_offset;
            vga_sum = 0;
            for (cnt = 0; cnt < VGA_SUM_SAMPLES; cnt++) {
                ioerr += _PHY_REG_READ(pc, reg_addr, &dfe_vga_stat);
                vga_sum += VGA_SUM_GET(dfe_vga_stat);
            }
            vga_sum = vga_sum / VGA_SUM_SAMPLES;

            if (vga_sum > 31) {
                BCMI_HYPERLITE_XGXS_DBG(pc, "VGA sum out of range");
                return CDK_E_FAIL;
            }
	
            /* Write VGA sum average into vga_write_val */
            reg_addr = DSC2_LN0_DFE_VGA_CTRL1_REG + reg_offset;
            ioerr += _PHY_REG_READ(pc, reg_addr, &dfe_vga_ctrl);
            VGA_WRITE_VAL_SET(dfe_vga_ctrl, vga_sum);
            ioerr += _PHY_REG_WRITE(pc, reg_addr, dfe_vga_ctrl);

            /* Toggle vga_write_en to complete the VGA write */
            dfe_vga_ctrl |= DFE_VGA_CTRL1_VGA_WRITE_EN;
            ioerr += _PHY_REG_WRITE(pc, reg_addr, dfe_vga_ctrl);
            dfe_vga_ctrl &= ~DFE_VGA_CTRL1_VGA_WRITE_EN;
            ioerr += _PHY_REG_WRITE(pc, reg_addr, dfe_vga_ctrl);
        } else {
            /* Bypass BR peaking filter calibration */
            reg_addr = DSC2_LN0_SM_CTRL0_REG + reg_offset;
            ioerr += _PHY_REG_READ(pc, reg_addr, &sm_ctrl);
            sm_ctrl |= br_pf_cal;
            ioerr += _PHY_REG_WRITE(pc, reg_addr, sm_ctrl);
        }

        /* Enable DSC tuning state machine */
        reg_addr = DSC2_LN0_SM_CTRL0_REG + reg_offset;
        ioerr += _PHY_REG_READ(pc, reg_addr, &sm_ctrl);
        sm_ctrl |= SM_CTRL0_TUNING_SM_EN;
        ioerr += _PHY_REG_WRITE(pc, reg_addr, sm_ctrl);

        /* Restart tuning */
        sm_ctrl |= SM_CTRL0_RESTART_TUNING;
        ioerr += _PHY_REG_WRITE(pc, reg_addr, sm_ctrl);

        /* Wait for tuning done signal */
        for (cnt = 0; cnt < TUNING_DONE_10MSEC; cnt++) {
            reg_addr = DSC3_LN0_SM_STAT0_REG + reg_offset;
            ioerr += _PHY_REG_READ(pc, reg_addr, &sm_stat);
            if (sm_stat & SM_STAT0_TUNING_DONE) {
                break;
            }
            PHY_SYS_USLEEP(10000);
        }

        if ((sm_stat & SM_STAT0_TUNING_DONE) == 0) {
            BCMI_HYPERLITE_XGXS_DBG(pc, "fine tuning done timeout");
            return CDK_E_TIMEOUT;
        }

        /* Restore br_pf_calibration */
        reg_addr = DSC2_LN0_SM_CTRL0_REG + reg_offset;
        ioerr += _PHY_REG_READ(pc, reg_addr, &sm_ctrl);
        sm_ctrl &= ~br_pf_cal;
        ioerr += _PHY_REG_WRITE(pc, reg_addr, sm_ctrl);

        /* Disable training mode */
        reg_addr = DSC2_LN0_SM_CTRL2_REG + reg_offset;
        ioerr += _PHY_REG_READ(pc, reg_addr, &sm_ctrl);
        sm_ctrl &= ~SM_CTRL2_TRAIN_MODE_EN;
        ioerr += _PHY_REG_WRITE(pc, reg_addr, sm_ctrl);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

#endif

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
 *      bcmi_hyperlite_xgxs_probe
 * Purpose:     
 *      Probe for PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_xgxs_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1, serdesid0, xgxs_ctrl, mmd_sel;
    int ioerr = 0;

    ioerr += phy_brcm_serdes_id(pc, &phyid0, &phyid1);

    phyid1 &= ~PHY_ID1_REV_MASK;

    if (phyid0 == BCM_SERDES_PHY_ID0 && phyid1 == BCM_SERDES_PHY_ID1) {
        /* Common PHY ID found - read specific SerDes ID */
        ioerr += _PHY_REG_READ(pc, SERDES_ID0, &serdesid0);
        if ((serdesid0 & 0x3f) == SERDES_ID0_XGXS_HYPERLITE) {
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
 *      bcmi_hyperlite_xgxs_notify
 * Purpose:     
 *      Handle PHY notifications.
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_xgxs_notify(phy_ctrl_t *pc, phy_event_t event)
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
 *      bcmi_hyperlite_xgxs_reset
 * Purpose:     
 *      Reset PHY.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_xgxs_reset(phy_ctrl_t *pc)
{
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_hyperlite_xgxs_init
 * Purpose:     
 *      Initialize PHY driver.
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_NONE
 */
static int
bcmi_hyperlite_xgxs_init(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    int ioerr = 0;
    uint32_t d1000x_ctrl1, lane_test, xgxs_ctrl;

    PHY_CTRL_CHECK(pc);

    /* Never power down PLL (required for tx_wclk_o output) */
    ioerr += _PHY_REG_READ(pc, DIGITAL_1000X_CTRL1_REG, &d1000x_ctrl1);
    d1000x_ctrl1 |= D1000X_CTRL1_DIS_PLL_PWRDN;
    ioerr += _PHY_REG_WRITE(pc, DIGITAL_1000X_CTRL1_REG, d1000x_ctrl1);

    /* Enable clocks in powerdown mode */
    ioerr += _PHY_REG_READ(pc, XGXS_BLK1_LANE_TEST_REG, &lane_test);
    lane_test |= LANE_TEST_PWRDN_CLKS_EN;
    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK1_LANE_TEST_REG, lane_test);

    /* Stop and start sequencer */
    ioerr += _PHY_REG_READ(pc, XGXS_BLK0_XGXS_CTRL_REG, &xgxs_ctrl);
    xgxs_ctrl &= ~XGXS_CTRL_START_SEQ;
    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK0_XGXS_CTRL_REG, xgxs_ctrl);
    xgxs_ctrl |= XGXS_CTRL_START_SEQ;
    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK0_XGXS_CTRL_REG, xgxs_ctrl);

    /* Default mode is fiber */
    PHY_NOTIFY(pc, PhyEvent_ChangeToFiber);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcmi_hyperlite_xgxs_link_get
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
bcmi_hyperlite_xgxs_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
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
 *      bcmi_hyperlite_xgxs_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_xgxs_duplex_set(phy_ctrl_t *pc, int duplex)
{
    return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
}

/*
 * Function:    
 *      bcmi_hyperlite_xgxs_duplex_get
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
bcmi_hyperlite_xgxs_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hyperlite_xgxs_speed_set
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
bcmi_hyperlite_xgxs_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int ioerr = 0;
    int speed_val;
    uint32_t misc1, mii_ctrl;
    uint32_t xgxs_ctrl;

    switch (speed) {
    case 21000:
        speed_val = MISC1_SPEED_21000;
        break;
    case 20000:
        speed_val = MISC1_SPEED_20000;
        break;
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

    /* Configure clock divider */
    ioerr += _PHY_REG_READ(pc, XGXS_BLK0_XGXS_CTRL_REG, &xgxs_ctrl);
    xgxs_ctrl &= ~XGXS_CTRL_TXCKO_DIV;
    if (speed <= 10000) {
        xgxs_ctrl |= XGXS_CTRL_TXCKO_DIV;
    }
    ioerr += _PHY_REG_WRITE(pc, XGXS_BLK0_XGXS_CTRL_REG, xgxs_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hyperlite_xgxs_speed_get
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
bcmi_hyperlite_xgxs_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int ioerr = 0;
    int rv;
    int autoneg = 0, autoneg_done = 0;
    uint32_t xgxs20g_stat, xgxs_stat1;

    *speed = 0;

    rv = PHY_AUTONEG_GET(pc, &autoneg);

    if (CDK_SUCCESS(rv) && autoneg) {
        rv = PHY_LINK_GET(pc, NULL, &autoneg_done);
    }

    if (!autoneg || autoneg_done) {
        ioerr += _PHY_REG_READ(pc, PAR_DET_20G_STAT_REG, &xgxs20g_stat);
        switch (XGXS_20G_STAT_SPEED_GET(xgxs20g_stat)) {
        case STAT_20G_SPEED_21000:
            *speed = 21000;
            break;
        case STAT_20G_SPEED_20000:
            *speed = 20000;
            break;
        default:
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
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hyperlite_xgxs_autoneg_set
 * Purpose:     
 *      Enable or disabled auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */

static int
bcmi_hyperlite_xgxs_autoneg_set(phy_ctrl_t *pc, int autoneg)
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
 *      bcmi_hyperlite_xgxs_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation status (enabled/busy)
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_xgxs_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    int ioerr = 0;
    uint32_t mii_ctrl;

    ioerr += _PHY_REG_READ(pc, B0_MII_CTRL_REG, &mii_ctrl);
    *autoneg = (mii_ctrl & MII_CTRL_AE) ? 1 : 0;

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hyperlite_xgxs_loopback_set
 * Purpose:     
 *      Set PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_xgxs_loopback_set(phy_ctrl_t *pc, int enable)
{
    int ioerr = 0;
    uint32_t sm_ctrl, mii_ctrl;

    /* Required for loopback */
    ioerr += _PHY_REG_READ(pc, DSC2_ALL_SM_CTRL0_REG, &sm_ctrl);
    sm_ctrl = (enable) ? 0 : SM_CTRL0_DEFAULT;
    ioerr += _PHY_REG_WRITE(pc, DSC2_ALL_SM_CTRL0_REG, sm_ctrl);

    /* Set loopback mode for SerDes */
    ioerr += _PHY_REG_READ(pc, B0_MII_CTRL_REG, &mii_ctrl);
    mii_ctrl &= ~MII_CTRL_LE;
    if (enable) {
        mii_ctrl |= MII_CTRL_LE;
    }
    ioerr += _PHY_REG_WRITE(pc, B0_MII_CTRL_REG, mii_ctrl);

    /* Set loopback mode for XAUI */
    ioerr += _PHY_REG_READ(pc, PMA_CTRL_REG, &mii_ctrl);
    mii_ctrl &= ~PMA_CTRL_PMD_LB;
    if (enable) {
        mii_ctrl |= PMA_CTRL_PMD_LB;
    }
    ioerr += _PHY_REG_WRITE(pc, PMA_CTRL_REG, mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcmi_hyperlite_xgxs_loopback_get
 * Purpose:     
 *      Get the current PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_xgxs_loopback_get(phy_ctrl_t *pc, int *enable)
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
 *      bcmi_hyperlite_xgxs_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_xgxs_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    *abil = (PHY_ABIL_21GB | PHY_ABIL_16GB | PHY_ABIL_13GB | PHY_ABIL_10GB | 
             PHY_ABIL_PAUSE | PHY_ABIL_LOOPBACK | 
             PHY_ABIL_XAUI | PHY_ABIL_XGMII);
    
    return CDK_E_NONE;
}

/*
 * Function:
 *      bcmi_hyperlite_xgxs_config_set
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
bcmi_hyperlite_xgxs_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
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
        if (val > 0) {
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
        uint32_t reg_addr;
        uint32_t tx_ctrl;
        for (lane = 0; lane <= 3; lane++) {
            reg_addr = TX_LN0_TX_CTRL_REG + (lane * LANE_OFFSET);
            ioerr += _PHY_REG_READ(pc, reg_addr, &tx_ctrl);
            tx_ctrl &= ~TX_CTRL_TXPOL_FLIP;
            if (val & (1 << (lane * 4))) {
                tx_ctrl |= TX_CTRL_TXPOL_FLIP;
            }
            ioerr += _PHY_REG_WRITE(pc, reg_addr, tx_ctrl);
        }
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
#endif
    case PhyConfig_TxPreemp: {
        int ioerr = 0;
        uint32_t tx_drv;
        ioerr += _PHY_REG_READ(pc, TX_ALL_TX_DRV_REG, &tx_drv);
        TX_DRV_PREEMP_SET(tx_drv, val);
        ioerr += _PHY_REG_WRITE(pc, TX_ALL_TX_DRV_REG, tx_drv);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxIDrv: {
        int ioerr = 0;
        uint32_t tx_drv;
        ioerr += _PHY_REG_READ(pc, TX_ALL_TX_DRV_REG, &tx_drv);
        TX_DRV_IDRV_SET(tx_drv, val);
        ioerr += _PHY_REG_WRITE(pc, TX_ALL_TX_DRV_REG, tx_drv);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxPreIDrv: {
        int ioerr = 0;
        uint32_t tx_drv;
        ioerr += _PHY_REG_READ(pc, TX_ALL_TX_DRV_REG, &tx_drv);
        TX_DRV_PREIDRV_SET(tx_drv, val);
        ioerr += _PHY_REG_WRITE(pc, TX_ALL_TX_DRV_REG, tx_drv);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcmi_hyperlite_xgxs_config_get
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
bcmi_hyperlite_xgxs_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = 1;
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        *val = PHY_IF_XGMII;
        return CDK_E_NONE;
    case PhyConfig_Clause45Devs:
        if (PHY_CTRL_FLAGS(pc) & PHY_F_CLAUSE45) {
            *val = 0xa3;
            return CDK_E_NONE;
        }
        return CDK_E_UNAVAIL;
    case PhyConfig_TxPreemp: {
        int ioerr = 0;
        uint32_t tx_drv;
        ioerr += _PHY_REG_READ(pc, TX_ALL_TX_DRV_REG, &tx_drv);
        *val = TX_DRV_PREEMP_GET(tx_drv);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxIDrv: {
        int ioerr = 0;
        uint32_t tx_drv;
        ioerr += _PHY_REG_READ(pc, TX_ALL_TX_DRV_REG, &tx_drv);
        *val = TX_DRV_IDRV_GET(tx_drv);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    case PhyConfig_TxPreIDrv: {
        int ioerr = 0;
        uint32_t tx_drv;
        ioerr += _PHY_REG_READ(pc, TX_ALL_TX_DRV_REG, &tx_drv);
        *val = TX_DRV_PREIDRV_GET(tx_drv);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    }
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcmi_hyperlite_xgxs_status_get
 * Purpose:
 *      Get PHY status value.
 * Parameters:
 *      pc - PHY control structure
 *      st - Status parameter
 *      val - (OUT) Status value
 * Returns:
 *      CDK_E_xxx
 */
static int
bcmi_hyperlite_xgxs_status_get(phy_ctrl_t *pc, phy_status_t st, uint32_t *val)
{
    PHY_CTRL_CHECK(pc);

    switch (st) {
#if PHY_CONFIG_INCLUDE_AUTO_TUNE
    case PhyStatus_RxEqTuning: {
        int rv;
        rv = bcmi_hyperlite_xgxs_rx_tune_start(pc);
        if (CDK_SUCCESS(rv)) {
            rv = bcmi_hyperlite_xgxs_rx_tune_status(pc, val);
        }
        if (CDK_SUCCESS(rv)) {
            rv = bcmi_hyperlite_xgxs_rx_fine_tune(pc);
        }
        return rv;
    }
#endif
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/* Public PHY Driver Structure */
phy_driver_t bcmi_hyperlite_xgxs_drv = {
    "bcmi_hyperlite_xgxs", 
    "Internal Hyperlite 21G XGXS PHY Driver",  
    PHY_DRIVER_F_INTERNAL,
    bcmi_hyperlite_xgxs_probe,          /* pd_probe */
    bcmi_hyperlite_xgxs_notify,         /* pd_notify */
    bcmi_hyperlite_xgxs_reset,          /* pd_reset */
    bcmi_hyperlite_xgxs_init,           /* pd_init */
    bcmi_hyperlite_xgxs_link_get,       /* pd_link_get */
    bcmi_hyperlite_xgxs_duplex_set,     /* pd_duplex_set */
    bcmi_hyperlite_xgxs_duplex_get,     /* pd_duplex_get */
    bcmi_hyperlite_xgxs_speed_set,      /* pd_speed_set */
    bcmi_hyperlite_xgxs_speed_get,      /* pd_speed_get */
    bcmi_hyperlite_xgxs_autoneg_set,    /* pd_autoneg_set */
    bcmi_hyperlite_xgxs_autoneg_get,    /* pd_autoneg_get */
    bcmi_hyperlite_xgxs_loopback_set,   /* pd_loopback_set */
    bcmi_hyperlite_xgxs_loopback_get,   /* pd_loopback_get */
    bcmi_hyperlite_xgxs_ability_get,    /* pd_ability_get */
    bcmi_hyperlite_xgxs_config_set,     /* pd_config_set */
    bcmi_hyperlite_xgxs_config_get,     /* pd_config_get */
    bcmi_hyperlite_xgxs_status_get,     /* pd_status_get */
    NULL                                /* pd_cable_diag */
};
