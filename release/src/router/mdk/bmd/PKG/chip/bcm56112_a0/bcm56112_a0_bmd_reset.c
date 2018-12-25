#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56112_A0 == 1

/*
 * $Id: bcm56112_a0_bmd_reset.c,v 1.7 Broadcom SDK $
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

#include <cdk/chip/bcm56112_a0_defs.h>
#include <cdk/cdk_debug.h>

#include "bcm56112_a0_bmd.h"
#include "bcm56112_a0_internal.h"

#define RESET_SLEEP_USEC                100
#define PLL_LOCK_MSEC                   500

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1

#include <cdk/arch/xgs_miim.h>

int
bcm56112_a0_xport_reset(int unit, int port, int speed)
{
    int ioerr = 0;
    int idx;
    uint32_t dev_in_pkg;
    CMIC_XGXS_MDIO_CONFIGr_t xgxs_mdio_cfg;
    XPORT_CONFIGr_t xport_cfg;
    MAC_XGXS_CTRLr_t xgxs_ctrl;
    CMIC_XGXS_PLL_CONTROL_1r_t pll_ctrl1;
    int lcpll;
#if BMD_CONFIG_INCLUDE_PHY == 1
    int msec;
    int phy_addr = port | 0xc0;
    MAC_XGXS_STATr_t xgxs_stat;
#endif

    /* Zero-based xport index */
    idx = port - 24;

    /* Use indexed alias instead of CMIC_XGXS_MDIO_CONFIG_0r, etc. */
    ioerr += READ_CMIC_XGXS_MDIO_CONFIGr(unit, idx, &xgxs_mdio_cfg);
    dev_in_pkg = (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) ? 0x3 : 0x15;
    CMIC_XGXS_MDIO_CONFIGr_IEEE_DEVICES_IN_PKGf_SET(xgxs_mdio_cfg, dev_in_pkg);
    ioerr += WRITE_CMIC_XGXS_MDIO_CONFIGr(unit, idx, xgxs_mdio_cfg);

    /* Force BigMAC reset in case we were already enabled */
    XPORT_CONFIGr_CLR(xport_cfg);
    XPORT_CONFIGr_BIGMAC_RESETf_SET(xport_cfg, 1);
    ioerr += WRITE_XPORT_CONFIGr(unit, port, xport_cfg);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);
    XPORT_CONFIGr_BIGMAC_RESETf_SET(xport_cfg, 0);
    ioerr += WRITE_XPORT_CONFIGr(unit, port, xport_cfg);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /* Use internal TX PLL */
    ioerr += READ_MAC_XGXS_CTRLr(unit, port, &xgxs_ctrl);
    MAC_XGXS_CTRLr_LCREFENf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);

    /* Speed select on internal TX PLL */
    lcpll = (speed == 12000) ? 1 : 0;
    READ_CMIC_XGXS_PLL_CONTROL_1r(unit, &pll_ctrl1);
    switch (port) {
    case 24:
        CMIC_XGXS_PLL_CONTROL_1r_PLL_CONTROL_13f_SET(pll_ctrl1, lcpll);
        break;
    case 25:
        CMIC_XGXS_PLL_CONTROL_1r_PLL_CONTROL_12f_SET(pll_ctrl1, lcpll);
        break;
    case 26:
        CMIC_XGXS_PLL_CONTROL_1r_PLL_CONTROL_11f_SET(pll_ctrl1, lcpll);
        break;
    case 27:
        CMIC_XGXS_PLL_CONTROL_1r_PLL_CONTROL_10f_SET(pll_ctrl1, lcpll);
        break;
    default:
        return CDK_E_INTERNAL;
    }
    WRITE_CMIC_XGXS_PLL_CONTROL_1r(unit, pll_ctrl1);

    /*
     * XGXS MAC initialization steps.
     *
     * A minimum delay is required between various initialization steps.
     * There is no maximum delay.  The values given are very conservative
     * including the timeout for TX PLL lock.
     */

    /* Release reset (if asserted) to allow bigmac to initialize */
    ioerr += READ_MAC_XGXS_CTRLr(unit, port, &xgxs_ctrl);
    MAC_XGXS_CTRLr_IDDQf_SET(xgxs_ctrl, 0);
    MAC_XGXS_CTRLr_PWRDWNf_SET(xgxs_ctrl, 0);
    MAC_XGXS_CTRLr_HW_RSTLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /* PowerDown fusion-Core and PHY */
    MAC_XGXS_CTRLr_IDDQf_SET(xgxs_ctrl, 1);
    MAC_XGXS_CTRLr_PWRDWNf_SET(xgxs_ctrl, 1);
    MAC_XGXS_CTRLr_HW_RSTLf_SET(xgxs_ctrl, 0);
    MAC_XGXS_CTRLr_AFIFO_RSTf_SET(xgxs_ctrl, 1);
    MAC_XGXS_CTRLr_TXFIFO_RSTLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /*
     * Powerup FusionCore interface (analog and clocks).
     *
     * NOTE: Many MAC registers are not accessible until the FusionCore
     * achieves PLL lock.  An S-Channel timeout will occur before that.
     */
    MAC_XGXS_CTRLr_IDDQf_SET(xgxs_ctrl, 0);
    MAC_XGXS_CTRLr_PWRDWNf_SET(xgxs_ctrl, 0);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /* Bring FusionCore out of reset (AFIFO_RST stays 1) */
    MAC_XGXS_CTRLr_HW_RSTLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

#if BMD_CONFIG_INCLUDE_PHY == 1
    /* Disable PLL state machine */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x5011, 0x5006);

    /* Turn off slowdn_xor */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x5015, 0x0000);

    if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) {
        /* Disable LssQ */
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x0010, 0x292f);

        /* Enable DTE mdio reg mapping */
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x001e, 0x0000);
    } else {
        /* Enable PMA/PMD mdio reg mapping */
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x001e, 0x0200);

        /* TX pre-emphasis */
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0xa017, 0xaff0);
    }

    /* Enable PLL state machine */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x5011, 0xf01e);

    /* Wait for TX PLL lock */
    for (msec = 0; msec < PLL_LOCK_MSEC; msec++) {
        ioerr += READ_MAC_XGXS_STATr(unit, port, &xgxs_stat);
        if (MAC_XGXS_STATr_TXPLL_LOCKf_GET(xgxs_stat) != 0) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (msec >= PLL_LOCK_MSEC) {
        CDK_WARN(("bcm56112_a0_xport_reset[%d]: "
                  "TX PLL did not lock on port %d\n", unit, port));
    }
#endif

    return ioerr;
}

static int
bcm56112_a0_lcpll_init(int unit)
{
    int ioerr = 0;
    int msec;
    uint32_t raw_val;
    CMIC_XGXS_PLL_CONTROL_1r_t pll_ctrl1;
    CMIC_XGXS_PLL_CONTROL_2r_t pll_ctrl2;

    /* Reset PLL */
    ioerr += READ_CMIC_XGXS_PLL_CONTROL_1r(unit, &pll_ctrl1);
    CMIC_XGXS_PLL_CONTROL_1r_RESETf_SET(pll_ctrl1, 1);
    ioerr += WRITE_CMIC_XGXS_PLL_CONTROL_1r(unit, pll_ctrl1);
    BMD_SYS_USLEEP(50);
    CMIC_XGXS_PLL_CONTROL_1r_RESETf_SET(pll_ctrl1, 0);
    /* Set PLLFORCECAPPASS and PLLFORCECAPDONE to avoid PLL lock failure */
    raw_val = CMIC_XGXS_PLL_CONTROL_1r_GET(pll_ctrl1);
    CMIC_XGXS_PLL_CONTROL_1r_SET(pll_ctrl1, raw_val | 0xf0000000);
    ioerr += WRITE_CMIC_XGXS_PLL_CONTROL_1r(unit, pll_ctrl1);

    /* Wait for LC PLL locks */
    for (msec = 0; msec < PLL_LOCK_MSEC; msec++) {
        ioerr += READ_CMIC_XGXS_PLL_CONTROL_2r(unit, &pll_ctrl2);
#if BMD_CONFIG_SIMULATION
        if (msec == 0) break;
#endif
        /* Use PLL_SM_FREQ_PASS as CMIC_XG_PLL_LOCK is unreliable */
        if (CMIC_XGXS_PLL_CONTROL_2r_PLL_SM_FREQ_PASSf_GET(pll_ctrl2) == 1) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (msec >= PLL_LOCK_MSEC) {
        CDK_WARN(("bcm56112_a0_bmd_reset[%d]: "
                  "LC PLL did not lock, status = 0x%08"PRIx32"\n",
                  unit, CMIC_XGXS_PLL_CONTROL_2r_GET(pll_ctrl2)));
    }

    return ioerr;
}

#endif

int
bcm56112_a0_bmd_reset(int unit)
{
    int ioerr = 0;
    int wait_usec = 10000;
    CMIC_CONFIGr_t cmic_config;
    CMIC_SOFT_RESET_REGr_t cmic_sreset;
    CMIC_SBUS_RING_MAPr_t ring_map;
#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    int port;
    cdk_pbmp_t xport_pbmp;
#endif

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

    /* Bring PLL blocks out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_GX4_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_BSAFE_CLKGEN_RST_Lf_SET(cmic_sreset,1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(50);

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    /* Initialize LC PLL if we have active XE/HG ports */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XPORT, &xport_pbmp);
    CDK_PBMP_ITER(xport_pbmp, port) {
        ioerr += bcm56112_a0_lcpll_init(unit);
        break;
    }
#endif

    /* Bring remaining blocks out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_GXP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_BSAFE_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_IP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_EP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_MMU_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_GP_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(wait_usec);

    /*
     * BCM56304 ring map
     *
     * ring0 [00] : IPIPE[7] -> IPIPE_HI[8]
     * ring1 [01] : EPIPE[9] -> EPIPE_HI[10]
     * ring2 [10] : gport0[0] ->  gport1[1] -> xport0[2] ->
     *              xport1[3] ->  xport2[4] -> xport3[5] -> MMU[6]
     *              gport[12] ->  gport[13]
     * ring3 [11] : bsafe[11]
     *
     * 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1 0
     * 0000__1010__1101__0100__0010__1010__1010__1010
     */
    CMIC_SBUS_RING_MAPr_SET(ring_map, 0x0ad42aaa);
    ioerr += WRITE_CMIC_SBUS_RING_MAPr(unit, ring_map);

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    /* Reset XPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XPORT, &xport_pbmp);
    CDK_PBMP_ITER(xport_pbmp, port) {
        ioerr += bcm56112_a0_xport_reset(unit, port, 10000);
    }
#endif

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56112_A0 */
