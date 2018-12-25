#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56840_A0 == 1

/*
 * $Id: bcm56840_a0_bmd_reset.c,v 1.21.6.1 Broadcom SDK $
 * 
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
 */

#include <bmd/bmd.h>

#include <cdk/chip/bcm56840_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>
#include <cdk/arch/xgs_miim.h>

#include "bcm56840_a0_bmd.h"
#include "bcm56840_a0_internal.h"

#define RESET_SLEEP_USEC                100
#define PLL_LOCK_MSEC                   10
#define TXPLL_LOCK_MSEC                 100

#define MIIM_CL22_WRITE(_u, _addr, _reg, _val) \
    cdk_xgs_miim_write(_u, _addr, _reg, _val)
#define MIIM_CL22_READ(_u, _addr, _reg, _val) \
    cdk_xgs_miim_read(_u, _addr, _reg, _val)

#define MIIM_CL45_WRITE(_u, _addr, _dev, _reg, _val) \
    cdk_xgs_miim_write(_u, _addr, LSHIFT32(_dev, 16) | _reg, _val)
#define MIIM_CL45_READ(_u, _addr, _dev, _reg, _val) \
    cdk_xgs_miim_read(_u, _addr, LSHIFT32(_dev, 16) | _reg, _val)

/* Clause 45 devices */
#define C45_PMA         1
#define C45_AN          7

#if BMD_CONFIG_INCLUDE_PHY == 1
static uint32_t
_phy_addr_get(int port)
{
    uint32_t phy_addr = port + CDK_XGS_MIIM_IBUS(0);

    if (port > 48) {
        phy_addr = (port - 48) + CDK_XGS_MIIM_IBUS(2);
    } else if (port > 24) {
        phy_addr = (port - 24) + CDK_XGS_MIIM_IBUS(1);
    }

    return phy_addr;
}
#endif

int
bcm56840_a0_warpcore_phy_init(int unit, int port)
{
    int ioerr = 0;
#if BMD_CONFIG_INCLUDE_PHY == 1
    uint32_t phy_addr = _phy_addr_get(port);
    uint32_t mreg_val;
    uint32_t speed;
    int sub_port, mode_10g;

    /* Get lane index */
    sub_port = XLPORT_SUBPORT(port);

    if (sub_port != 0) {
        return 0;
    }

    speed = bcm56840_a0_port_speed_max(unit, port);

    /* Enable multi MMD mode to allow clause 45 access */
    ioerr += MIIM_CL22_WRITE(unit, phy_addr, 0x1f, 0x8000);
    ioerr += MIIM_CL22_READ(unit, phy_addr, 0x1d, &mreg_val);
    mreg_val |= 0x400f;
    mreg_val &= ~0x8000;
    ioerr += MIIM_CL22_WRITE(unit, phy_addr, 0x1d, mreg_val);

    /* Stop sequencer */
    ioerr += MIIM_CL45_READ(unit, phy_addr, C45_PMA, 0x8000, &mreg_val);
    mreg_val &= ~0x2000;
    ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x8000, mreg_val);

    /* Enable independent lane mode if max speed is 20G or below */
    if (speed <= 20000) {
        ioerr += MIIM_CL45_READ(unit, phy_addr, C45_PMA, 0x8000, &mreg_val);
        mreg_val &= ~(0xf << 8);
        mode_10g = 4;
        mreg_val |= (mode_10g << 8);
        ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x8000, mreg_val);
    }

    /* Enable broadcast */
    ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0xffde, 0x01ff);

    if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_GE) {
        /* Advertise 2.5G */
        ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x8329, 0x0001);
    } else if (speed <= 10000) {
        /* Do not advertise 1G */
        ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0xffe4, 0x0020);
        /* Do not advertise 10G CX4 */
        ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x8329, 0x0000);
        /* Advertise clause 72 capability */
        ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x832b, 0x0404);
        /* Advertise 10G KR and 1G KX */
        ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_AN, 0x0011, 0x00a0);
    } else if (speed <= 20000) {
        /* Do not advertise 1G */
        ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0xffe4, 0x0020);
        /* Do not advertise 10G CX4 */
        ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x8329, 0x0000);
        /* Advertise clause 72 capability */
        ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x832b, 0x0004);
        /* Do not advertise DXGXS speeds */
        ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x835d, 0x0400);
        /* Do not advertise >20G */
        ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_AN, 0x0011, 0x0000);
    } else {
        if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) {
            /* Do not advertise 1G */
            ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0xffe4, 0x0020);
            /* Advertise 10G (HiG/CX4), 12G, 13G, 15G, 16G and 20G */
            ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x8329, 0x07b8);
            /* Advertise clause 72, 21G, 25G, 31.5G and 40G */
            ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x832b, 0x03a4);
            /* Advertise 20G */
            ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x835d, 0x0401);
            /* Do not advertise 40G KR4/CR4 */
            ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_AN, 0x0011, 0x0000);
        } else {
            /* Do not advertise 1G */
            ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0xffe4, 0x0020);
            /* Advertise 10G CX4 */
            ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x8329, 0x0010);
            /* Advertise clause 72 capability */
            ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x832b, 0x0404);
            /* Advertise 40G KR4 and 10G KX4 */
            ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_AN, 0x0011, 0x0140);
        }
    }

    /* Disable 10G parallel detect */
    ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x8131, 0x0000);

    /* Set reference clock */
    ioerr += MIIM_CL45_READ(unit, phy_addr, C45_PMA, 0x8308, &mreg_val);
    mreg_val &= ~(0x7 << 13);
    if (CDK_CHIP_CONFIG(unit) & DCFG_LCPLL_156) {
        mreg_val |= (3 << 13);
    } else {
        /* Defaults to 161.25 MHz */
        mreg_val |= (5 << 13);
    }
    ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x8308, mreg_val);

    /* Disable broadcast */
    ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0xffde, 0x0000);

    /* Restart sequencer */
    ioerr += MIIM_CL45_READ(unit, phy_addr, C45_PMA, 0x8000, &mreg_val);
    mreg_val |= 0x2000;
    ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x8000, mreg_val);

#endif

    return ioerr;
}

int
bcm56840_a0_xport_reset(int unit, int port)
{
    int ioerr = 0;
    int msec;
    int idx;
    uint32_t dev_in_pkg;
    CMIC_XGXS_MDIO_CONFIGr_t xgxs_mdio_cfg;
    XLPORT_XGXS_CTRL_REGr_t xgxs_ctrl;
    XLPORT_XGXS_STATUS_GEN_REGr_t xgxs_stat;
    COMMAND_CONFIGr_t command_cfg;

    /* Zero-based xport index */
    idx = XLPORT_BLKIDX(port);

    /* Use indexed alias instead of CMIC_XGXS_MDIO_CONFIG_0r, etc. */
    ioerr += READ_CMIC_XGXS_MDIO_CONFIGr(unit, idx, &xgxs_mdio_cfg);
    dev_in_pkg = (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) ? 0x3 : 0x15;
    CMIC_XGXS_MDIO_CONFIGr_IEEE_DEVICES_IN_PKGf_SET(xgxs_mdio_cfg, dev_in_pkg);
    ioerr += WRITE_CMIC_XGXS_MDIO_CONFIGr(unit, idx, xgxs_mdio_cfg);

    /* Configure clock source */
    ioerr += READ_XLPORT_XGXS_CTRL_REGr(unit, &xgxs_ctrl, port);
    XLPORT_XGXS_CTRL_REGr_LCREF_ENf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_XLPORT_XGXS_CTRL_REGr(unit, xgxs_ctrl, port);

    /* Force XMAC into reset before initialization */
    XLPORT_XGXS_CTRL_REGr_IDDQf_SET(xgxs_ctrl, 1);
    XLPORT_XGXS_CTRL_REGr_PWRDWNf_SET(xgxs_ctrl, 1);
    XLPORT_XGXS_CTRL_REGr_PWRDWN_PLLf_SET(xgxs_ctrl, 1);
    XLPORT_XGXS_CTRL_REGr_RSTB_HWf_SET(xgxs_ctrl, 0);
    XLPORT_XGXS_CTRL_REGr_RSTB_PLLf_SET(xgxs_ctrl, 0);
    XLPORT_XGXS_CTRL_REGr_RSTB_MDIOREGSf_SET(xgxs_ctrl, 0);
    XLPORT_XGXS_CTRL_REGr_TXD1G_FIFO_RSTBf_SET(xgxs_ctrl, 0);
    XLPORT_XGXS_CTRL_REGr_TXD10G_FIFO_RSTBf_SET(xgxs_ctrl, 0);
    ioerr += WRITE_XLPORT_XGXS_CTRL_REGr(unit, xgxs_ctrl, port);

    /*
     * XGXS MAC initialization steps.
     *
     * A minimum delay is required between various initialization steps.
     * There is no maximum delay.  The values given are very conservative
     * including the timeout for TX PLL lock.
     */

    /* Powerup Unicore interface (digital and analog clocks) */
    ioerr += READ_XLPORT_XGXS_CTRL_REGr(unit, &xgxs_ctrl, port);
    XLPORT_XGXS_CTRL_REGr_IDDQf_SET(xgxs_ctrl, 0);
    XLPORT_XGXS_CTRL_REGr_PWRDWNf_SET(xgxs_ctrl, 0);
    XLPORT_XGXS_CTRL_REGr_PWRDWN_PLLf_SET(xgxs_ctrl, 0);
    ioerr += WRITE_XLPORT_XGXS_CTRL_REGr(unit, xgxs_ctrl, port);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /* Bring Warpcore out of reset */
    XLPORT_XGXS_CTRL_REGr_RSTB_HWf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_XLPORT_XGXS_CTRL_REGr(unit, xgxs_ctrl, port);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /* Bring MDIO registers out of reset */
    XLPORT_XGXS_CTRL_REGr_RSTB_MDIOREGSf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_XLPORT_XGXS_CTRL_REGr(unit, xgxs_ctrl, port);

    /* Activate all clocks */
    XLPORT_XGXS_CTRL_REGr_RSTB_PLLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_XLPORT_XGXS_CTRL_REGr(unit, xgxs_ctrl, port);

    /* Reset UniMac */
    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
    COMMAND_CONFIGr_SW_RESETf_SET(command_cfg, 1);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /* Bring UniMac out of reset (re-read register required) */
    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
    COMMAND_CONFIGr_SW_RESETf_SET(command_cfg, 0);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);

    /* Wait for TX PLL lock */
    for (msec = 0; msec < TXPLL_LOCK_MSEC; msec++) {
#if BMD_CONFIG_SIMULATION
        if (msec == 0) break;
#endif
        ioerr += READ_XLPORT_XGXS_STATUS_GEN_REGr(unit, &xgxs_stat, port);
        if (XLPORT_XGXS_STATUS_GEN_REGr_TXPLL_LOCKf_GET(xgxs_stat) != 0) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (msec >= TXPLL_LOCK_MSEC) {
        CDK_WARN(("bcm56840_a0_xport_reset[%d]: "
                  "TX PLL did not lock on port %d\n", unit, port));
    }

    /* Enable Tx FIFO */
    XLPORT_XGXS_CTRL_REGr_TXD1G_FIFO_RSTBf_SET(xgxs_ctrl, 0xf);
    XLPORT_XGXS_CTRL_REGr_TXD10G_FIFO_RSTBf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_XLPORT_XGXS_CTRL_REGr(unit, xgxs_ctrl, port);

    return ioerr;
}

static int
_lcpll_init(int unit)
{
    int ioerr = 0;
    int msec;
    CMIC_XGXS0_PLL_STATUSr_t pll0_status;
    CMIC_XGXS1_PLL_STATUSr_t pll1_status;
    CMIC_XGXS2_PLL_STATUSr_t pll2_status;
    CMIC_XGXS3_PLL_STATUSr_t pll3_status;

    /* Wait for LC PLL locks */
    for (msec = 0; msec < PLL_LOCK_MSEC; msec++) {
#if BMD_CONFIG_SIMULATION
        if (msec == 0) break;
#endif
        ioerr += READ_CMIC_XGXS0_PLL_STATUSr(unit, &pll0_status);
        ioerr += READ_CMIC_XGXS1_PLL_STATUSr(unit, &pll1_status);
        ioerr += READ_CMIC_XGXS2_PLL_STATUSr(unit, &pll2_status);
        ioerr += READ_CMIC_XGXS3_PLL_STATUSr(unit, &pll3_status);
        if (CMIC_XGXS0_PLL_STATUSr_CMIC_XGPLL_LOCKf_GET(pll0_status) == 1 &&
            CMIC_XGXS1_PLL_STATUSr_CMIC_XGPLL_LOCKf_GET(pll1_status) == 1 &&
            CMIC_XGXS2_PLL_STATUSr_CMIC_XGPLL_LOCKf_GET(pll2_status) == 1 &&
            CMIC_XGXS3_PLL_STATUSr_CMIC_XGPLL_LOCKf_GET(pll3_status) == 1) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (msec >= PLL_LOCK_MSEC) {
        CDK_WARN(("bcm56840_a0_bmd_reset[%d]: "
                  "LC PLL did not lock, status = "
                  "0x%08"PRIx32" 0x%08"PRIx32" 0x%08"PRIx32" 0x%08"PRIx32"\n",
                  unit,
                  CMIC_XGXS0_PLL_STATUSr_GET(pll0_status), 
                  CMIC_XGXS1_PLL_STATUSr_GET(pll1_status), 
                  CMIC_XGXS2_PLL_STATUSr_GET(pll2_status), 
                  CMIC_XGXS3_PLL_STATUSr_GET(pll3_status)));
    }

    return ioerr;
}

#ifndef _INIT_SVK_CLK
#define _INIT_SVK_CLK(_u) (0)
#endif

int
bcm56840_a0_bmd_reset(int unit)
{
    int ioerr = 0;
    int wait_usec = 10000;
    int port;
    cdk_pbmp_t pbmp;
    CMIC_CONFIGr_t cmic_config;
    CMIC_SOFT_RESET_REGr_t cmic_sreset;
    CMIC_SOFT_RESET_REG_2r_t cmic_sreset_2;
    CMIC_SBUS_RING_MAP_0r_t ring_map_0;
    CMIC_SBUS_RING_MAP_1r_t ring_map_1;
    CMIC_SBUS_RING_MAP_2r_t ring_map_2;
    CMIC_SBUS_RING_MAP_3r_t ring_map_3;
    CMIC_SBUS_TIMEOUTr_t sbus_to;

    BMD_CHECK_UNIT(unit);

    /* Initialize endian mode for correct reset access */
    ioerr += cdk_xgs_cmic_init(unit);

    /* Pull reset line */
    ioerr += READ_CMIC_CONFIGr(unit, &cmic_config);
    CMIC_CONFIGr_RESET_CPSf_SET(cmic_config, 1);
    ioerr += WRITE_CMIC_CONFIGr(unit, cmic_config);

    /* Wait for all tables to initialize */
    BMD_SYS_USLEEP(wait_usec);

    /* Re-initialize endian mode after reset */
    ioerr += cdk_xgs_cmic_init(unit);

    /* Reset all blocks */
    CMIC_SOFT_RESET_REGr_CLR(cmic_sreset);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);

    ioerr += _INIT_SVK_CLK(unit);

    if (CDK_CHIP_CONFIG(unit) & DCFG_LCPLL_156) {
        CMIC_XGXS0_PLL_CONTROL_1r_t xgxs0_pll_ctrl1;
        CMIC_XGXS0_PLL_CONTROL_2r_t xgxs0_pll_ctrl2;
        CMIC_XGXS0_PLL_CONTROL_3r_t xgxs0_pll_ctrl3;
        CMIC_XGXS0_PLL_CONTROL_4r_t xgxs0_pll_ctrl4;
        CMIC_XGXS1_PLL_CONTROL_1r_t xgxs1_pll_ctrl1;
        CMIC_XGXS1_PLL_CONTROL_2r_t xgxs1_pll_ctrl2;
        CMIC_XGXS1_PLL_CONTROL_3r_t xgxs1_pll_ctrl3;
        CMIC_XGXS1_PLL_CONTROL_4r_t xgxs1_pll_ctrl4;
        CMIC_XGXS2_PLL_CONTROL_1r_t xgxs2_pll_ctrl1;
        CMIC_XGXS2_PLL_CONTROL_2r_t xgxs2_pll_ctrl2;
        CMIC_XGXS2_PLL_CONTROL_3r_t xgxs2_pll_ctrl3;
        CMIC_XGXS2_PLL_CONTROL_4r_t xgxs2_pll_ctrl4;
        CMIC_XGXS3_PLL_CONTROL_1r_t xgxs3_pll_ctrl1;
        CMIC_XGXS3_PLL_CONTROL_2r_t xgxs3_pll_ctrl2;
        CMIC_XGXS3_PLL_CONTROL_3r_t xgxs3_pll_ctrl3;
        CMIC_XGXS3_PLL_CONTROL_4r_t xgxs3_pll_ctrl4;
        CMIC_MISC_CONTROLr_t misc_ctrl;

        CDK_VERB(("bcm56840_a0_bmd_reset[%d]: Configure LCPLL for 156.25 MHz\n",
                  unit));

        /* Configure XGXS0 LCPLL */
        ioerr += READ_CMIC_XGXS0_PLL_CONTROL_1r(unit, &xgxs0_pll_ctrl1);
        CMIC_XGXS0_PLL_CONTROL_1r_CH0_MDIVf_SET(xgxs0_pll_ctrl1, 20);
        CMIC_XGXS0_PLL_CONTROL_1r_CH3_MDIVf_SET(xgxs0_pll_ctrl1, 25);
        CMIC_XGXS0_PLL_CONTROL_1r_CH4_MDIVf_SET(xgxs0_pll_ctrl1, 125);
        CMIC_XGXS0_PLL_CONTROL_1r_CH5_MDIVf_SET(xgxs0_pll_ctrl1, 25);
        ioerr += WRITE_CMIC_XGXS0_PLL_CONTROL_1r(unit, xgxs0_pll_ctrl1);

        ioerr += READ_CMIC_XGXS0_PLL_CONTROL_3r(unit, &xgxs0_pll_ctrl3);
        CMIC_XGXS0_PLL_CONTROL_3r_NDIV_INTf_SET(xgxs0_pll_ctrl3, 140);
        ioerr += WRITE_CMIC_XGXS0_PLL_CONTROL_3r(unit, xgxs0_pll_ctrl3);

        ioerr += READ_CMIC_XGXS0_PLL_CONTROL_2r(unit, &xgxs0_pll_ctrl2);
        CMIC_XGXS0_PLL_CONTROL_2r_KAf_SET(xgxs0_pll_ctrl2, 4);
        CMIC_XGXS0_PLL_CONTROL_2r_KIf_SET(xgxs0_pll_ctrl2, 1);
        CMIC_XGXS0_PLL_CONTROL_2r_KPf_SET(xgxs0_pll_ctrl2, 9);
        CMIC_XGXS0_PLL_CONTROL_2r_PDIVf_SET(xgxs0_pll_ctrl2, 7);
        ioerr += WRITE_CMIC_XGXS0_PLL_CONTROL_2r(unit, xgxs0_pll_ctrl2);

        ioerr += READ_CMIC_XGXS0_PLL_CONTROL_4r(unit, &xgxs0_pll_ctrl4);
        CMIC_XGXS0_PLL_CONTROL_4r_CML_BYP_ENf_SET(xgxs0_pll_ctrl4, 1);
        CMIC_XGXS0_PLL_CONTROL_4r_TESTOUT_ENf_SET(xgxs0_pll_ctrl4, 0);
        CMIC_XGXS0_PLL_CONTROL_4r_CML_2ED_OUT_ENf_SET(xgxs0_pll_ctrl4, 0);
        CMIC_XGXS0_PLL_CONTROL_4r_TESTOUT2_ENf_SET(xgxs0_pll_ctrl4, 0);
        ioerr += WRITE_CMIC_XGXS0_PLL_CONTROL_4r(unit, xgxs0_pll_ctrl4);

        /* Configure XGXS1 LCPLL */
        ioerr += READ_CMIC_XGXS1_PLL_CONTROL_1r(unit, &xgxs1_pll_ctrl1);
        CMIC_XGXS1_PLL_CONTROL_1r_CH0_MDIVf_SET(xgxs1_pll_ctrl1, 20);
        CMIC_XGXS1_PLL_CONTROL_1r_CH3_MDIVf_SET(xgxs1_pll_ctrl1, 25);
        CMIC_XGXS1_PLL_CONTROL_1r_CH4_MDIVf_SET(xgxs1_pll_ctrl1, 125);
        CMIC_XGXS1_PLL_CONTROL_1r_CH5_MDIVf_SET(xgxs1_pll_ctrl1, 25);
        ioerr += WRITE_CMIC_XGXS1_PLL_CONTROL_1r(unit, xgxs1_pll_ctrl1);

        ioerr += READ_CMIC_XGXS1_PLL_CONTROL_3r(unit, &xgxs1_pll_ctrl3);
        CMIC_XGXS1_PLL_CONTROL_3r_NDIV_INTf_SET(xgxs1_pll_ctrl3, 140);
        ioerr += WRITE_CMIC_XGXS1_PLL_CONTROL_3r(unit, xgxs1_pll_ctrl3);

        ioerr += READ_CMIC_XGXS1_PLL_CONTROL_2r(unit, &xgxs1_pll_ctrl2);
        CMIC_XGXS1_PLL_CONTROL_2r_KAf_SET(xgxs1_pll_ctrl2, 4);
        CMIC_XGXS1_PLL_CONTROL_2r_KIf_SET(xgxs1_pll_ctrl2, 1);
        CMIC_XGXS1_PLL_CONTROL_2r_KPf_SET(xgxs1_pll_ctrl2, 9);
        CMIC_XGXS1_PLL_CONTROL_2r_PDIVf_SET(xgxs1_pll_ctrl2, 7);
        ioerr += WRITE_CMIC_XGXS1_PLL_CONTROL_2r(unit, xgxs1_pll_ctrl2);

        ioerr += READ_CMIC_XGXS1_PLL_CONTROL_4r(unit, &xgxs1_pll_ctrl4);
        CMIC_XGXS1_PLL_CONTROL_4r_CML_BYP_ENf_SET(xgxs1_pll_ctrl4, 1);
        CMIC_XGXS1_PLL_CONTROL_4r_TESTOUT_ENf_SET(xgxs1_pll_ctrl4, 0);
        CMIC_XGXS1_PLL_CONTROL_4r_CML_2ED_OUT_ENf_SET(xgxs1_pll_ctrl4, 0);
        CMIC_XGXS1_PLL_CONTROL_4r_TESTOUT2_ENf_SET(xgxs1_pll_ctrl4, 0);
        ioerr += WRITE_CMIC_XGXS1_PLL_CONTROL_4r(unit, xgxs1_pll_ctrl4);

        /* Configure XGXS2 LCPLL */
        ioerr += READ_CMIC_XGXS2_PLL_CONTROL_1r(unit, &xgxs2_pll_ctrl1);
        CMIC_XGXS2_PLL_CONTROL_1r_CH0_MDIVf_SET(xgxs2_pll_ctrl1, 20);
        CMIC_XGXS2_PLL_CONTROL_1r_CH3_MDIVf_SET(xgxs2_pll_ctrl1, 25);
        CMIC_XGXS2_PLL_CONTROL_1r_CH4_MDIVf_SET(xgxs2_pll_ctrl1, 125);
        CMIC_XGXS2_PLL_CONTROL_1r_CH5_MDIVf_SET(xgxs2_pll_ctrl1, 25);
        ioerr += WRITE_CMIC_XGXS2_PLL_CONTROL_1r(unit, xgxs2_pll_ctrl1);

        ioerr += READ_CMIC_XGXS2_PLL_CONTROL_3r(unit, &xgxs2_pll_ctrl3);
        CMIC_XGXS2_PLL_CONTROL_3r_NDIV_INTf_SET(xgxs2_pll_ctrl3, 140);
        ioerr += WRITE_CMIC_XGXS2_PLL_CONTROL_3r(unit, xgxs2_pll_ctrl3);

        ioerr += READ_CMIC_XGXS2_PLL_CONTROL_2r(unit, &xgxs2_pll_ctrl2);
        CMIC_XGXS2_PLL_CONTROL_2r_KAf_SET(xgxs2_pll_ctrl2, 4);
        CMIC_XGXS2_PLL_CONTROL_2r_KIf_SET(xgxs2_pll_ctrl2, 1);
        CMIC_XGXS2_PLL_CONTROL_2r_KPf_SET(xgxs2_pll_ctrl2, 9);
        CMIC_XGXS2_PLL_CONTROL_2r_PDIVf_SET(xgxs2_pll_ctrl2, 7);
        ioerr += WRITE_CMIC_XGXS2_PLL_CONTROL_2r(unit, xgxs2_pll_ctrl2);

        ioerr += READ_CMIC_XGXS2_PLL_CONTROL_4r(unit, &xgxs2_pll_ctrl4);
        CMIC_XGXS2_PLL_CONTROL_4r_CML_BYP_ENf_SET(xgxs2_pll_ctrl4, 1);
        CMIC_XGXS2_PLL_CONTROL_4r_TESTOUT_ENf_SET(xgxs2_pll_ctrl4, 0);
        CMIC_XGXS2_PLL_CONTROL_4r_CML_2ED_OUT_ENf_SET(xgxs2_pll_ctrl4, 0);
        CMIC_XGXS2_PLL_CONTROL_4r_TESTOUT2_ENf_SET(xgxs2_pll_ctrl4, 0);
        ioerr += WRITE_CMIC_XGXS2_PLL_CONTROL_4r(unit, xgxs2_pll_ctrl4);

        /* Configure XGXS3 LCPLL */
        ioerr += READ_CMIC_XGXS3_PLL_CONTROL_1r(unit, &xgxs3_pll_ctrl1);
        CMIC_XGXS3_PLL_CONTROL_1r_CH0_MDIVf_SET(xgxs3_pll_ctrl1, 20);
        CMIC_XGXS3_PLL_CONTROL_1r_CH3_MDIVf_SET(xgxs3_pll_ctrl1, 25);
        CMIC_XGXS3_PLL_CONTROL_1r_CH4_MDIVf_SET(xgxs3_pll_ctrl1, 125);
        CMIC_XGXS3_PLL_CONTROL_1r_CH5_MDIVf_SET(xgxs3_pll_ctrl1, 25);
        ioerr += WRITE_CMIC_XGXS3_PLL_CONTROL_1r(unit, xgxs3_pll_ctrl1);

        ioerr += READ_CMIC_XGXS3_PLL_CONTROL_3r(unit, &xgxs3_pll_ctrl3);
        CMIC_XGXS3_PLL_CONTROL_3r_NDIV_INTf_SET(xgxs3_pll_ctrl3, 140);
        ioerr += WRITE_CMIC_XGXS3_PLL_CONTROL_3r(unit, xgxs3_pll_ctrl3);

        ioerr += READ_CMIC_XGXS3_PLL_CONTROL_2r(unit, &xgxs3_pll_ctrl2);
        CMIC_XGXS3_PLL_CONTROL_2r_KAf_SET(xgxs3_pll_ctrl2, 4);
        CMIC_XGXS3_PLL_CONTROL_2r_KIf_SET(xgxs3_pll_ctrl2, 1);
        CMIC_XGXS3_PLL_CONTROL_2r_KPf_SET(xgxs3_pll_ctrl2, 9);
        CMIC_XGXS3_PLL_CONTROL_2r_PDIVf_SET(xgxs3_pll_ctrl2, 7);
        ioerr += WRITE_CMIC_XGXS3_PLL_CONTROL_2r(unit, xgxs3_pll_ctrl2);

        ioerr += READ_CMIC_XGXS3_PLL_CONTROL_4r(unit, &xgxs3_pll_ctrl4);
        CMIC_XGXS3_PLL_CONTROL_4r_CML_BYP_ENf_SET(xgxs3_pll_ctrl4, 1);
        CMIC_XGXS3_PLL_CONTROL_4r_TESTOUT_ENf_SET(xgxs3_pll_ctrl4, 0);
        CMIC_XGXS3_PLL_CONTROL_4r_CML_2ED_OUT_ENf_SET(xgxs3_pll_ctrl4, 0);
        CMIC_XGXS3_PLL_CONTROL_4r_TESTOUT2_ENf_SET(xgxs3_pll_ctrl4, 0);
        ioerr += WRITE_CMIC_XGXS3_PLL_CONTROL_4r(unit, xgxs3_pll_ctrl4);

        /* Enable software override */
        ioerr += READ_CMIC_MISC_CONTROLr(unit, &misc_ctrl);
        CMIC_MISC_CONTROLr_CMIC_TO_XG_PLL0_SW_OVWRf_SET(misc_ctrl, 1);
        CMIC_MISC_CONTROLr_CMIC_TO_XG_PLL1_SW_OVWRf_SET(misc_ctrl, 1);
        CMIC_MISC_CONTROLr_CMIC_TO_XG_PLL2_SW_OVWRf_SET(misc_ctrl, 1);
        CMIC_MISC_CONTROLr_CMIC_TO_XG_PLL3_SW_OVWRf_SET(misc_ctrl, 1);
        ioerr += WRITE_CMIC_MISC_CONTROLr(unit, misc_ctrl);
    }

    /* Bring PLL blocks out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL0_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL1_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL2_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL3_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(50);

    /* Initialize LC PLLs */
    ioerr += _lcpll_init(unit);

    /* De-assert LCPLL's post reset */
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL0_POST_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL1_POST_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL2_POST_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL3_POST_RST_Lf_SET(cmic_sreset, 1);
    BMD_SYS_USLEEP(50);

    /* Bring port blocks out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_PG0_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_PG1_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_PG2_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_PG3_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_TEMP_MON_PEAK_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(50);

    /* Clear hotswap reset */
    CMIC_SOFT_RESET_REG_2r_CLR(cmic_sreset_2);
    CMIC_SOFT_RESET_REG_2r_XQ0_HOTSWAP_RST_Lf_SET(cmic_sreset_2, 1);
    CMIC_SOFT_RESET_REG_2r_XQ1_HOTSWAP_RST_Lf_SET(cmic_sreset_2, 1);
    CMIC_SOFT_RESET_REG_2r_XQ2_HOTSWAP_RST_Lf_SET(cmic_sreset_2, 1);
    CMIC_SOFT_RESET_REG_2r_XQ3_HOTSWAP_RST_Lf_SET(cmic_sreset_2, 1);
    CMIC_SOFT_RESET_REG_2r_XQ4_HOTSWAP_RST_Lf_SET(cmic_sreset_2, 1);
    CMIC_SOFT_RESET_REG_2r_XQ5_HOTSWAP_RST_Lf_SET(cmic_sreset_2, 1);
    CMIC_SOFT_RESET_REG_2r_NS_RST_Lf_SET(cmic_sreset_2, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REG_2r(unit, cmic_sreset_2);

    /*
     * BCM56840 ring map
     *
     * map_0 includes blocks 0-7
     * map_1 includes blocks 8-15
     * map_2 includes blocks 16-23
     * map_3 includes blocks 24-31
     */
    CMIC_SBUS_RING_MAP_0r_SET(ring_map_0, 0x43052100);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_0r(unit, ring_map_0);
    CMIC_SBUS_RING_MAP_1r_SET(ring_map_1, 0x33333343);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_1r(unit, ring_map_1);
    CMIC_SBUS_RING_MAP_2r_SET(ring_map_2, 0x44444333);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_2r(unit, ring_map_2);
    CMIC_SBUS_RING_MAP_3r_SET(ring_map_3, 0x00034444);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_3r(unit, ring_map_3);

    CMIC_SBUS_TIMEOUTr_SET(sbus_to, 0x7d0);
    ioerr += WRITE_CMIC_SBUS_TIMEOUTr(unit, sbus_to);

    /* Bring IP, EP, and MMU blocks out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_EP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_IP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_MMU_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(wait_usec);

    /* Reset all XLPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XLPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        /* We only need to reset first port in each block */
        if (XLPORT_SUBPORT(port) == 0) {
            ioerr += bcm56840_a0_xport_reset(unit, port);
        }
        /* Initialize PHY for all ports */
        ioerr += bcm56840_a0_warpcore_phy_init(unit, port);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56840_A0 */
