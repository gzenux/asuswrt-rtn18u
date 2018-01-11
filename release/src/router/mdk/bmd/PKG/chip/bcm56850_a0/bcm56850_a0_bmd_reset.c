#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56850_A0 == 1

/*
 * $Id: bcm56850_a0_bmd_reset.c,v 1.3 Broadcom SDK $
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

#include <cdk/chip/bcm56850_a0_defs.h>
#include <cdk/arch/xgsm_chip.h>
#include <cdk/cdk_debug.h>
#include <cdk/arch/xgsm_miim.h>

#include "bcm56850_a0_bmd.h"
#include "bcm56850_a0_internal.h"

#define RESET_SLEEP_USEC                100
#define PLL_LOCK_MSEC                   10
#define TXPLL_LOCK_MSEC                 100

/* Transform datasheet mapped address to MIIM address used by software API */
#define MREG(_b) ((((_b) & 0xfff0) << 8) | 0x10 | ((_b) & 0xf))

#define MIIM_CL22_WRITE(_u, _addr, _reg, _val) \
    cdk_xgsm_miim_write(_u, _addr, _reg, _val)
#define MIIM_CL22_READ(_u, _addr, _reg, _val) \
    cdk_xgsm_miim_read(_u, _addr, _reg, _val)

#define MIIM_CL45_WRITE(_u, _addr, _dev, _reg, _val) \
    cdk_xgsm_miim_write(_u, _addr, LSHIFT32(_dev, 16) | _reg, _val)
#define MIIM_CL45_READ(_u, _addr, _dev, _reg, _val) \
    cdk_xgsm_miim_read(_u, _addr, LSHIFT32(_dev, 16) | _reg, _val)

/* Clause 45 devices */
#define C45_PMA         1
#define C45_AN          7

#if BMD_CONFIG_INCLUDE_PHY == 1
static uint32_t
_phy_addr_get(int port)
{
    if (port > 52) {
        return (port - 52) + CDK_XGSM_MIIM_IBUS(2);
    }
    if (port > 28) {
        return (port - 28) + CDK_XGSM_MIIM_IBUS(1);
    }
    return port + CDK_XGSM_MIIM_IBUS(0);
}
#endif

int
bcm56850_a0_warpcore_phy_init(int unit, int port)
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

    speed = bcm56850_a0_port_speed_max(unit, port);

    /* Enable multi MMD mode to allow clause 45 access */
    ioerr += MIIM_CL22_WRITE(unit, phy_addr, 0x1f, 0x8000);
    ioerr += MIIM_CL22_READ(unit, phy_addr, 0x1d, &mreg_val);
    mreg_val |= 0x400f;
    mreg_val &= ~0x8000;
    ioerr += MIIM_CL22_WRITE(unit, phy_addr, 0x1d, mreg_val);

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

    /* Disable broadcast */
    ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0xffde, 0x0000);

    /* Enable PLL state machine */
    ioerr += MIIM_CL45_WRITE(unit, phy_addr, C45_PMA, 0x8051, 0xd006);
#endif

    return ioerr;
}

int
bcm56850_a0_wait_for_tsc_lock(int unit, int port)
{
    int ioerr = 0;
    int msec;
    XLPORT_TSC_PLL_LOCK_STATUSr_t tsc_lock;

    /* Wait for TX PLL lock */
    for (msec = 0; msec < TXPLL_LOCK_MSEC; msec++) {
#if BMD_CONFIG_SIMULATION
        if (msec == 0) break;
#endif
        ioerr += READ_XLPORT_TSC_PLL_LOCK_STATUSr(unit, &tsc_lock, port);
        if (XLPORT_TSC_PLL_LOCK_STATUSr_CURRENTf_GET(tsc_lock) != 0) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (msec >= TXPLL_LOCK_MSEC) {
        CDK_WARN(("bcm56850_a0_xport_reset[%d]: "
                  "TX PLL did not lock on port %d\n", unit, port));
    }

    return ioerr;
}

int
bcm56850_a0_xport_reset(int unit, int port)
{
    int ioerr = 0;
    XLPORT_XGXS0_CTRL_REGr_t xgxs_ctrl;

    /* Configure clock source */
    ioerr += READ_XLPORT_XGXS0_CTRL_REGr(unit, &xgxs_ctrl, port);
    XLPORT_XGXS0_CTRL_REGr_REFIN_ENf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_XLPORT_XGXS0_CTRL_REGr(unit, xgxs_ctrl, port);

    /* Force XMAC into reset before initialization */
    XLPORT_XGXS0_CTRL_REGr_IDDQf_SET(xgxs_ctrl, 1);
    XLPORT_XGXS0_CTRL_REGr_PWRDWNf_SET(xgxs_ctrl, 1);
    XLPORT_XGXS0_CTRL_REGr_RSTB_HWf_SET(xgxs_ctrl, 0);
    XLPORT_XGXS0_CTRL_REGr_RSTB_PLLf_SET(xgxs_ctrl, 0);
    XLPORT_XGXS0_CTRL_REGr_TSCCLK_ENf_SET(xgxs_ctrl, 0);
    ioerr += WRITE_XLPORT_XGXS0_CTRL_REGr(unit, xgxs_ctrl, port);

    /*
     * XGXS MAC initialization steps.
     *
     * A minimum delay is required between various initialization steps.
     * There is no maximum delay.  The values given are very conservative
     * including the timeout for TX PLL lock.
     */

    /* Powerup Unicore interface (digital and analog clocks) */
    ioerr += READ_XLPORT_XGXS0_CTRL_REGr(unit, &xgxs_ctrl, port);
    XLPORT_XGXS0_CTRL_REGr_IDDQf_SET(xgxs_ctrl, 0);
    XLPORT_XGXS0_CTRL_REGr_PWRDWNf_SET(xgxs_ctrl, 0);
    ioerr += WRITE_XLPORT_XGXS0_CTRL_REGr(unit, xgxs_ctrl, port);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /* Bring Warpcore out of reset */
    XLPORT_XGXS0_CTRL_REGr_RSTB_HWf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_XLPORT_XGXS0_CTRL_REGr(unit, xgxs_ctrl, port);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /* Activate all clocks */
    XLPORT_XGXS0_CTRL_REGr_TSCCLK_ENf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_XLPORT_XGXS0_CTRL_REGr(unit, xgxs_ctrl, port);

    return ioerr;
}

static int
_wait_for_pll_lock(int unit)
{
    int ioerr = 0;
    int msec, idx, locks;
    TOP_XG_PLL_STATUSr_t pll_status[4];
    TOP_TS_PLL_STATUSr_t ts_pll_status;
    TOP_BS_PLL_STATUSr_t bs_pll_status;

    /* Wait for LC PLL locks */
    for (msec = 0; msec < PLL_LOCK_MSEC; msec++) {
#if BMD_CONFIG_SIMULATION
        if (msec == 0) break;
#endif
        locks = 0;
        for (idx = 0; idx < COUNTOF(pll_status); idx++) {
            ioerr += READ_TOP_XG_PLL_STATUSr(unit, idx, &pll_status[idx]);
            locks += TOP_XG_PLL_STATUSr_TOP_XGPLL_LOCKf_GET(pll_status[idx]);
        }
        if (locks == COUNTOF(pll_status)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (msec >= PLL_LOCK_MSEC) {
        CDK_WARN(("bcm56640_a0_bmd_reset[%d]: LC PLL did not lock, status = ",
                  unit));
        for (idx = 0; idx < COUNTOF(pll_status); idx++) {
            CDK_WARN(("0x%08"PRIx32" ",
                      TOP_XG_PLL_STATUSr_GET(pll_status[idx])));
        }
        CDK_WARN(("\n"));
    }

    /* Wait for timesync/broadsync PLL locks */
    for (msec = 0; msec < PLL_LOCK_MSEC; msec++) {
#if BMD_CONFIG_SIMULATION
        if (msec == 0) break;
#endif
        ioerr += READ_TOP_TS_PLL_STATUSr(unit, &ts_pll_status);
        ioerr += READ_TOP_BS_PLL_STATUSr(unit, &bs_pll_status);
        if (TOP_TS_PLL_STATUSr_PLL_LOCKf_GET(ts_pll_status) == 1 &&
            TOP_BS_PLL_STATUSr_PLL_LOCKf_GET(bs_pll_status) == 1) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (msec >= PLL_LOCK_MSEC) {
        CDK_WARN(("bcm56850_a0_bmd_reset[%d]: "
                  "TS/BS PLL did not lock, status = "
                  "0x%08"PRIx32" 0x%08"PRIx32"\n",
                  unit,
                  TOP_TS_PLL_STATUSr_GET(ts_pll_status), 
                  TOP_BS_PLL_STATUSr_GET(bs_pll_status)));
    }

    return ioerr;
}

int 
bcm56850_a0_bmd_reset(int unit)
{
    int ioerr = 0;
    int wait_usec = 10000;
    int port, idx;
    cdk_pbmp_t pbmp;
    CMIC_CPS_RESETr_t cps_reset;
    TOP_XG_PLL_CTRL_1r_t pll_ctrl_1;
    TOP_XG_PLL_CTRL_3r_t pll_ctrl_3;
    TOP_XG_PLL_CTRL_4r_t pll_ctrl_4;
    TOP_SOFT_RESET_REGr_t top_sreset;
    TOP_SOFT_RESET_REG_2r_t top_sreset_2;
    CMIC_SBUS_RING_MAPr_t sbus_ring_map;
    CMIC_SBUS_TIMEOUTr_t sbus_to;
    TOP_MISC_CONTROLr_t misc_ctrl;
    TOP_PVTMON_CTRL_1r_t pvtmon_ctrl;
    XLPORT_MAC_CONTROLr_t xmac_ctrl;
    CPORT_MAC_CONTROLr_t cmac_ctrl;
    uint32_t ring_map[] = { 0x33052100, 0x33776644, 0x33333333, 0x44444444,
                            0x66666644, 0x77776666, 0x00777777, 0x00000550 };

    BMD_CHECK_UNIT(unit);

    /* Initialize endian mode for correct reset access */
    ioerr += cdk_xgsm_cmic_init(unit);

    /* Pull reset line */
    ioerr += READ_CMIC_CPS_RESETr(unit, &cps_reset);
    CMIC_CPS_RESETr_CPS_RESETf_SET(cps_reset, 1);
    ioerr += WRITE_CMIC_CPS_RESETr(unit, cps_reset);

    /* Wait for all tables to initialize */
    BMD_SYS_USLEEP(wait_usec);

    /* Re-initialize endian mode after reset */
    ioerr += cdk_xgsm_cmic_init(unit);

    /*
     * SBUS ring and block number:
     * ring 0: IP(1)
     * ring 1: EP(2)
     * ring 2: MMU(3)
     * ring 3: PGW_CL0(6), CPORT0(14), XLPORT0(15)-XLPORT3(18)
     *         PGW_CL1(7), CPORT1(19), XLPORT4(20)-XLPORT7(23)
     * ring 4: PGW_CL2(8), CPORT2(24), XLPORT8(25)-XLPORT11(28)
     *         PGW_CL3(9), CPORT3(29), XLPORT12(30)-XLPORT15(33)
     * ring 5: OTPC(5), TOP(57), SER(58)
     * ring 6: PGW_CL4(10), CPORT4(34), XLPORT16(35)-XLPORT19(38)
     *         PGW_CL5(11), CPORT5(39), XLPORT20(40)-XLPORT23(43)
     * ring 7: PGW_CL6(12), CPORT6(44), XLPORT24(45)-XLPORT27(48)
     *         PGW_CL7(13), CPORT7(49), XLPORT28(50)-XLPORT31(53)
     */
    for (idx = 0; idx < COUNTOF(ring_map); idx++) {
        CMIC_SBUS_RING_MAPr_SET(sbus_ring_map, ring_map[idx]);
        ioerr += WRITE_CMIC_SBUS_RING_MAPr(unit, idx, sbus_ring_map);
    }

    CMIC_SBUS_TIMEOUTr_SET(sbus_to, 0x7d0);
    ioerr += WRITE_CMIC_SBUS_TIMEOUTr(unit, sbus_to);

    /* Reset all blocks */
    TOP_SOFT_RESET_REGr_CLR(top_sreset);
    ioerr += WRITE_TOP_SOFT_RESET_REGr(unit, top_sreset);

    /* Program LCPLL frequency */
    for (idx = 0; idx < 4; idx++) {
        ioerr += READ_TOP_XG_PLL_CTRL_1r(unit, idx, &pll_ctrl_1);
        TOP_XG_PLL_CTRL_1r_PDIVf_SET(pll_ctrl_1, 7);
        ioerr += WRITE_TOP_XG_PLL_CTRL_1r(unit, idx, pll_ctrl_1);
        ioerr += READ_TOP_XG_PLL_CTRL_3r(unit, idx, &pll_ctrl_3);
        TOP_XG_PLL_CTRL_3r_CML_BYP_ENf_SET(pll_ctrl_3, 1);
        ioerr += WRITE_TOP_XG_PLL_CTRL_3r(unit, idx, pll_ctrl_3);
        ioerr += READ_TOP_XG_PLL_CTRL_4r(unit, idx, &pll_ctrl_4);
        TOP_XG_PLL_CTRL_4r_NDIV_INTf_SET(pll_ctrl_4, 140);
        ioerr += WRITE_TOP_XG_PLL_CTRL_4r(unit, idx, pll_ctrl_4);
    }
    ioerr += READ_TOP_MISC_CONTROLr(unit, &misc_ctrl);
    TOP_MISC_CONTROLr_CMIC_TO_XG_PLL0_SW_OVWRf_SET(misc_ctrl, 1);
    TOP_MISC_CONTROLr_CMIC_TO_XG_PLL1_SW_OVWRf_SET(misc_ctrl, 1);
    TOP_MISC_CONTROLr_CMIC_TO_XG_PLL2_SW_OVWRf_SET(misc_ctrl, 1);
    TOP_MISC_CONTROLr_CMIC_TO_XG_PLL3_SW_OVWRf_SET(misc_ctrl, 1);
    ioerr += WRITE_TOP_MISC_CONTROLr(unit, misc_ctrl);

    /* Bring PLLs out of reset */
    ioerr += READ_TOP_SOFT_RESET_REG_2r(unit, &top_sreset_2);
    TOP_SOFT_RESET_REG_2r_TOP_XG_PLL0_RST_Lf_SET(top_sreset_2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_XG_PLL1_RST_Lf_SET(top_sreset_2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_XG_PLL2_RST_Lf_SET(top_sreset_2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_XG_PLL3_RST_Lf_SET(top_sreset_2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_TS_PLL_RST_Lf_SET(top_sreset_2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_BS_PLL_RST_Lf_SET(top_sreset_2, 1);
    ioerr += WRITE_TOP_SOFT_RESET_REG_2r(unit, top_sreset_2);
    BMD_SYS_USLEEP(50);

    /* Initialize LCPLLs */
    ioerr += _wait_for_pll_lock(unit);

    /* De-assert PLLs post reset */
    TOP_SOFT_RESET_REG_2r_TOP_XG_PLL0_POST_RST_Lf_SET(top_sreset_2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_XG_PLL1_POST_RST_Lf_SET(top_sreset_2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_XG_PLL2_POST_RST_Lf_SET(top_sreset_2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_XG_PLL3_POST_RST_Lf_SET(top_sreset_2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_TS_PLL_POST_RST_Lf_SET(top_sreset_2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_BS_PLL_POST_RST_Lf_SET(top_sreset_2, 1);
    ioerr += WRITE_TOP_SOFT_RESET_REG_2r(unit, top_sreset_2);
    BMD_SYS_USLEEP(50);

    /* Bring port blocks and timesync out of reset */
    TOP_SOFT_RESET_REGr_TOP_CLP0_RST_Lf_SET(top_sreset, 1);
    TOP_SOFT_RESET_REGr_TOP_CLP1_RST_Lf_SET(top_sreset, 1);
    TOP_SOFT_RESET_REGr_TOP_CLP2_RST_Lf_SET(top_sreset, 1);
    TOP_SOFT_RESET_REGr_TOP_CLP3_RST_Lf_SET(top_sreset, 1);
    TOP_SOFT_RESET_REGr_TOP_CLP4_RST_Lf_SET(top_sreset, 1);
    TOP_SOFT_RESET_REGr_TOP_CLP5_RST_Lf_SET(top_sreset, 1);
    TOP_SOFT_RESET_REGr_TOP_CLP6_RST_Lf_SET(top_sreset, 1);
    TOP_SOFT_RESET_REGr_TOP_CLP7_RST_Lf_SET(top_sreset, 1);
    TOP_SOFT_RESET_REGr_TOP_TS_RST_Lf_SET(top_sreset, 1);
    ioerr += WRITE_TOP_SOFT_RESET_REGr(unit, top_sreset);
    BMD_SYS_USLEEP(50);

    /* Bring IP, EP and MMU blocks out of reset */
    TOP_SOFT_RESET_REGr_TOP_EP_RST_Lf_SET(top_sreset, 1);
    TOP_SOFT_RESET_REGr_TOP_IP_RST_Lf_SET(top_sreset, 1);
    TOP_SOFT_RESET_REGr_TOP_MMU_RST_Lf_SET(top_sreset, 1);
    ioerr += WRITE_TOP_SOFT_RESET_REGr(unit, top_sreset);
    BMD_SYS_USLEEP(wait_usec);

    /* PVT monitor reset */
    ioerr += READ_TOP_PVTMON_CTRL_1r(unit, &pvtmon_ctrl);
    TOP_PVTMON_CTRL_1r_PVTMON_RESET_Nf_SET(pvtmon_ctrl, 1);
    ioerr += WRITE_TOP_PVTMON_CTRL_1r(unit, pvtmon_ctrl);
    TOP_PVTMON_CTRL_1r_PVTMON_RESET_Nf_SET(pvtmon_ctrl, 0);
    ioerr += WRITE_TOP_PVTMON_CTRL_1r(unit, pvtmon_ctrl);
    TOP_PVTMON_CTRL_1r_PVTMON_RESET_Nf_SET(pvtmon_ctrl, 1);
    ioerr += WRITE_TOP_PVTMON_CTRL_1r(unit, pvtmon_ctrl);

    /* Temperature monitor reset */
    TOP_SOFT_RESET_REG_2r_TOP_TEMP_MON_PEAK_RST_Lf_SET(top_sreset_2, 0);
    ioerr += WRITE_TOP_SOFT_RESET_REG_2r(unit, top_sreset_2);
    TOP_SOFT_RESET_REG_2r_TOP_TEMP_MON_PEAK_RST_Lf_SET(top_sreset_2, 1);
    ioerr += WRITE_TOP_SOFT_RESET_REG_2r(unit, top_sreset_2);
    BMD_SYS_USLEEP(50);

    /* Reset all XPORTs */
    CDK_XGSM_BLKTYPE_PBMP_GET(unit, BLKTYPE_XLPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        /* We only need to reset first port in each block */
        if (XLPORT_SUBPORT(port) == 0) {
            ioerr += bcm56850_a0_xport_reset(unit, port);
        }
        /* Initialize PHY for all ports */
        ioerr += bcm56850_a0_warpcore_phy_init(unit, port);
    }

    /* Bring XMACs out of reset */
    XLPORT_MAC_CONTROLr_SET(xmac_ctrl, 0);
    WRITE_XLPORT_MAC_CONTROLr(unit, xmac_ctrl, -1);

    /* Bring CMACs out of reset */
    CPORT_MAC_CONTROLr_SET(cmac_ctrl, 0);
    CDK_XGSM_BLKTYPE_PBMP_GET(unit, BLKTYPE_CPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        WRITE_CPORT_MAC_CONTROLr(unit, port, cmac_ctrl);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56850_A0 */

