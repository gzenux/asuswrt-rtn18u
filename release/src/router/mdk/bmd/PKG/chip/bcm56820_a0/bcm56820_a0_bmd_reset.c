#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56820_A0 == 1

/*
 * $Id: bcm56820_a0_bmd_reset.c,v 1.11 Broadcom SDK $
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

#include <cdk/chip/bcm56820_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>
#include <cdk/arch/xgs_miim.h>

#include "bcm56820_a0_bmd.h"
#include "bcm56820_a0_internal.h"

#define RESET_SLEEP_USEC                100
#define PLL_LOCK_MSEC                   500

/* Transform datasheet mapped address to MIIM address used by software API */
#define MREG(_b) ((((_b) & 0xfff0) << 8) | 0x10 | ((_b) & 0xf))

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1

static int
_unicore_phy_init(int unit, int port)
{
    int ioerr = 0;
#if BMD_CONFIG_INCLUDE_PHY == 1
    int phy_addr = port + CDK_XGS_MIIM_INTERNAL + CDK_XGS_MIIM_BUS_2;
    uint32_t mreg_val;

    /* Isolate external power-down input pins */
    ioerr += cdk_xgs_miim_iblk_read(unit, phy_addr, MREG(0x801a), &mreg_val);
    mreg_val |= (1 << 10);
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x801a), mreg_val);

    /* Disable PLL state machine */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8051), 0x5006);

    /* PLL VCO step time */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8052), 0x04ff);

    /* Turn off slowdn_xor */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8055), 0x0000);

    /* CDR bandwidth */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x80f6), 0x8300);

    /* Select ComboCore mode */
    ioerr += cdk_xgs_miim_iblk_read(unit, phy_addr, MREG(0x8000), &mreg_val);
    mreg_val &= ~(0xf << 8);
    mreg_val |= (0xc << 8);
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8000), mreg_val);

    /* Enable DTE mdio reg mapping */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x800e), 0x0001);

    if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) {
        /* Configure Tx to default value */
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x80a7), 0x0990);

        /* Advertise 10G, 12G, 13G and 16G HiG/CX4 by default */
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8329), 0x02b8);
    } else {
        /* Configure Tx for CX4 compliance */
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x80a7), 0x5ff0);

        /* Advertise 2.5G and 10G by default */
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8329), 0x0011);
    }

    /* Adjust 10G parallel detect link timer to 60ms */ 
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8133), 0x16e2); 

    /* Change 10G parallel detect lostlink timer */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8134), 0x4c4a);

    /* Configure 10G parallel detect */
    ioerr += cdk_xgs_miim_iblk_read(unit, phy_addr, MREG(0x8131), &mreg_val);
    mreg_val |= (1 << 0); /* Enable 10G parallel detect */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8131), mreg_val);

    /* Enable PLL state machine */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8051), 0xf01e);
#endif

    return ioerr;
}

static int
_hyperlite_phy_init(int unit, int port)
{
    int ioerr = 0;
#if BMD_CONFIG_INCLUDE_PHY == 1
    int speed_max;
    int phy_addr = port + CDK_XGS_MIIM_INTERNAL + CDK_XGS_MIIM_BUS_2;
    uint32_t mreg_val;

    speed_max = bcm56820_a0_port_speed_max(unit, port);

    /* Disable PLL state machine */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8051), 0x5006);

    /* PLL VCO step time */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8052), 0x04ff);

    /* Select ComboCore mode */
    ioerr += cdk_xgs_miim_iblk_read(unit, phy_addr, MREG(0x8000), &mreg_val);
    mreg_val &= ~(0xf << 8);
    mreg_val |= (0xc << 8);
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8000), mreg_val);

    /* Enable DTE mdio reg mapping */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x800e), 0x0001);

    if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) {
        /* Configure Tx to default value */
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x80a7), 0x0990);

        /* Advertise 10G, 12G, 13G and 16G HiG/CX4 by default */
        mreg_val = 0x02b8;
        if (speed_max >= 20000) {
            /* Also advertise 20G+ */
            mreg_val |= 0x0400;
        }
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8329), mreg_val);
        mreg_val = 0x0400;
        if (speed_max >= 21000) {
            /* Also advertise 21G */
            mreg_val |= 0x0200;
        }
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x832b), mreg_val);
    } else {
        /* Configure Tx for CX4 compliance */
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x80a7), 0x5ff0);

        /* Advertise 2.5G and 10G by default */
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8329), 0x0011);
    }

    /* Adjust 10G parallel detect link timer to 60ms */ 
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8133), 0x16e2); 

    /* Change 10G parallel detect lostlink timer */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8134), 0x4c4a);

    /* Configure 10G parallel detect */
    ioerr += cdk_xgs_miim_iblk_read(unit, phy_addr, MREG(0x8131), &mreg_val);
    mreg_val |= (1 << 0); /* Enable 10G parallel detect */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8131), mreg_val);

    /* Enable PLL state machine */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8051), 0xf01e);
#endif

    return ioerr;
}

int
bcm56820_a0_gxport_reset(int unit, int port)
{
    int ioerr = 0;
    int msec;
    int idx;
    uint32_t dev_in_pkg;
    CMIC_XGXS_MDIO_CONFIGr_t xgxs_mdio_cfg;
    XPORT_CONFIGr_t xport_cfg;
    MAC_XGXS_CTRLr_t xgxs_ctrl;
    MAC_XGXS_STATr_t xgxs_stat;

    /* Zero-based xport index */
    idx = port - 1;

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

    /* Configure clock source */
    ioerr += READ_MAC_XGXS_CTRLr(unit, port, &xgxs_ctrl);
    MAC_XGXS_CTRLr_LCREFENf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);

    /* Force BigMAC into reset before initialization */
    MAC_XGXS_CTRLr_IDDQf_SET(xgxs_ctrl, 1);
    MAC_XGXS_CTRLr_PWRDWNf_SET(xgxs_ctrl, 1);
    MAC_XGXS_CTRLr_AFIFO_RSTf_SET(xgxs_ctrl, 1);
    MAC_XGXS_CTRLr_HW_RSTLf_SET(xgxs_ctrl, 0);
    MAC_XGXS_CTRLr_RSTB_MDIOREGSf_SET(xgxs_ctrl, 0);
    MAC_XGXS_CTRLr_RSTB_PLLf_SET(xgxs_ctrl, 0);
    MAC_XGXS_CTRLr_BIGMACRSTLf_SET(xgxs_ctrl, 0);
    MAC_XGXS_CTRLr_TXFIFO_RSTLf_SET(xgxs_ctrl, 0);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);

    /*
     * XGXS MAC initialization steps.
     *
     * A minimum delay is required between various initialization steps.
     * There is no maximum delay.  The values given are very conservative
     * including the timeout for TX PLL lock.
     */

    /* Powerup Unicore interface (digital and analog clocks) */
    ioerr += READ_MAC_XGXS_CTRLr(unit, port, &xgxs_ctrl);
    MAC_XGXS_CTRLr_IDDQf_SET(xgxs_ctrl, 0);
    MAC_XGXS_CTRLr_PWRDWNf_SET(xgxs_ctrl, 0);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /* Bring Unicore out of reset (AFIFO_RST stays 1) */
    MAC_XGXS_CTRLr_HW_RSTLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);

    /* Bring MDIO registers out of reset */
    MAC_XGXS_CTRLr_RSTB_MDIOREGSf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);

    /* Activate all clocks */
    MAC_XGXS_CTRLr_RSTB_PLLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);

    /* Configure internal PHY */
    if (port >= 9 && port <= 16) {
        ioerr += _hyperlite_phy_init(unit, port);
    } else {
        ioerr += _unicore_phy_init(unit, port);
    }

    /* Wait for TX PLL lock */
    for (msec = 0; msec < PLL_LOCK_MSEC; msec++) {
#if BMD_CONFIG_SIMULATION
        if (msec == 0) break;
#endif
        ioerr += READ_MAC_XGXS_STATr(unit, port, &xgxs_stat);
        if (MAC_XGXS_STATr_TXPLL_LOCKf_GET(xgxs_stat) != 0) {
            break;
        }
        BMD_SYS_USLEEP(10000);
    }
    if (msec >= PLL_LOCK_MSEC) {
        CDK_WARN(("bcm56820_a0_gxport_reset[%d]: "
                  "TX PLL did not lock on port %d\n", unit, port));
    }

    /* Bring BigMac out of reset */
    MAC_XGXS_CTRLr_BIGMACRSTLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);

    /* Enable Tx FIFO */
    MAC_XGXS_CTRLr_TXFIFO_RSTLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);

    return ioerr;
}

#endif /* BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1 */

static int
bcm56820_a0_qgport_reset(int unit)
{
    int ioerr = 0;
    CMIC_XGXS_MDIO_CONFIGr_t xgxs_mdio_cfg;
    QGPORT_MAC_XGXS_CTRLr_t xgxs_ctrl;

    /* Use devad 0 for QGPORT */
    ioerr += READ_CMIC_XGXS_MDIO_CONFIGr(unit, 24, &xgxs_mdio_cfg);
    CMIC_XGXS_MDIO_CONFIGr_MD_DEVADf_SET(xgxs_mdio_cfg, 0);
    ioerr += WRITE_CMIC_XGXS_MDIO_CONFIGr(unit, 24, xgxs_mdio_cfg);

    /* Configure clock source */
    ioerr += READ_QGPORT_MAC_XGXS_CTRLr(unit, &xgxs_ctrl, -1);
    QGPORT_MAC_XGXS_CTRLr_LCREFENf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_QGPORT_MAC_XGXS_CTRLr(unit, xgxs_ctrl, -1);

    /* Force BigMAC into reset before initialization */
    QGPORT_MAC_XGXS_CTRLr_IDDQf_SET(xgxs_ctrl, 1);
    QGPORT_MAC_XGXS_CTRLr_PWRDWNf_SET(xgxs_ctrl, 1);
    QGPORT_MAC_XGXS_CTRLr_AFIFO_RSTf_SET(xgxs_ctrl, 1);
    QGPORT_MAC_XGXS_CTRLr_HW_RSTLf_SET(xgxs_ctrl, 0);
    QGPORT_MAC_XGXS_CTRLr_RSTB_MDIOREGSf_SET(xgxs_ctrl, 0);
    QGPORT_MAC_XGXS_CTRLr_RSTB_PLLf_SET(xgxs_ctrl, 0);
    QGPORT_MAC_XGXS_CTRLr_BIGMACRSTLf_SET(xgxs_ctrl, 0);
    QGPORT_MAC_XGXS_CTRLr_TXFIFO_RSTLf_SET(xgxs_ctrl, 0);
    ioerr += WRITE_QGPORT_MAC_XGXS_CTRLr(unit, xgxs_ctrl, -1);

    /*
     * XGXS MAC initialization steps.
     *
     * A minimum delay is required between various initialization steps.
     * There is no maximum delay.  The values given are very conservative
     * including the timeout for TX PLL lock.
     */

    /* Powerup Unicore interface (digital and analog clocks) */
    ioerr += READ_QGPORT_MAC_XGXS_CTRLr(unit, &xgxs_ctrl, -1);
    QGPORT_MAC_XGXS_CTRLr_IDDQf_SET(xgxs_ctrl, 0);
    QGPORT_MAC_XGXS_CTRLr_PWRDWNf_SET(xgxs_ctrl, 0);
    ioerr += WRITE_QGPORT_MAC_XGXS_CTRLr(unit, xgxs_ctrl, -1);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /* Bring Unicore out of reset (AFIFO_RST stays 1) */
    QGPORT_MAC_XGXS_CTRLr_HW_RSTLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_QGPORT_MAC_XGXS_CTRLr(unit, xgxs_ctrl, -1);

    /* Bring MDIO registers out of reset */
    QGPORT_MAC_XGXS_CTRLr_RSTB_MDIOREGSf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_QGPORT_MAC_XGXS_CTRLr(unit, xgxs_ctrl, -1);

    /* Activate all clocks */
    QGPORT_MAC_XGXS_CTRLr_RSTB_PLLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_QGPORT_MAC_XGXS_CTRLr(unit, xgxs_ctrl, -1);

    /* Bring BigMac out of reset */
    QGPORT_MAC_XGXS_CTRLr_BIGMACRSTLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_QGPORT_MAC_XGXS_CTRLr(unit, xgxs_ctrl, -1);

    /* Enable Tx FIFO */
    QGPORT_MAC_XGXS_CTRLr_TXFIFO_RSTLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_QGPORT_MAC_XGXS_CTRLr(unit, xgxs_ctrl, -1);

    return ioerr;
}

static int
bcm56820_a0_lcpll_init(int unit)
{
    int ioerr = 0;
    int msec;
    CMIC_XGXS0_PLL_STATUSr_t pll0_status;
    CMIC_XGXS1_PLL_STATUSr_t pll1_status;
    CMIC_XGXS2_PLL_STATUSr_t pll2_status;

    /* Wait for LC PLL locks */
    for (msec = 0; msec < PLL_LOCK_MSEC; msec++) {
#if BMD_CONFIG_SIMULATION
        if (msec == 0) break;
#endif
        ioerr += READ_CMIC_XGXS0_PLL_STATUSr(unit, &pll0_status);
        ioerr += READ_CMIC_XGXS1_PLL_STATUSr(unit, &pll1_status);
        ioerr += READ_CMIC_XGXS2_PLL_STATUSr(unit, &pll2_status);
        if (CMIC_XGXS0_PLL_STATUSr_CMIC_XGPLL_LOCKf_GET(pll0_status) == 1 &&
            CMIC_XGXS1_PLL_STATUSr_CMIC_XGPLL_LOCKf_GET(pll1_status) == 1 &&
            CMIC_XGXS2_PLL_STATUSr_CMIC_XGPLL_LOCKf_GET(pll2_status) == 1) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (msec >= PLL_LOCK_MSEC) {
        CDK_WARN(("bcm56820_a0_bmd_reset[%d]: "
                  "LC PLL did not lock, status = 0x%08"PRIx32" 0x%08"PRIx32" 0x%08"PRIx32"\n", 
                  unit,
                  CMIC_XGXS0_PLL_STATUSr_GET(pll0_status), 
                  CMIC_XGXS1_PLL_STATUSr_GET(pll1_status), 
                  CMIC_XGXS2_PLL_STATUSr_GET(pll2_status)));
    }

    return ioerr;
}

int
bcm56820_a0_bmd_reset(int unit)
{
    int ioerr = 0;
    int wait_usec = 10000;
#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    int port;
    cdk_pbmp_t pbmp;
#endif
    CMIC_CONFIGr_t cmic_config;
    CMIC_SOFT_RESET_REGr_t cmic_sreset;
    CMIC_CORE_PLL1_CTRL_STATUS_REGISTER_2r_t pll1_ctrl;
    CMIC_CORE_PLL2_CTRL_STATUS_REGISTER_2r_t pll2_ctrl;
    CMIC_CORE_PLL3_CTRL_STATUS_REGISTER_2r_t pll3_ctrl;
    CMIC_MISC_STATUSr_t misc_stat;
    CMIC_SBUS_RING_MAPr_t ring_map;
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

    /* Bring IP2 clock doubler out of reset */
    ioerr += READ_CMIC_CORE_PLL1_CTRL_STATUS_REGISTER_2r(unit, &pll1_ctrl);
    CMIC_CORE_PLL1_CTRL_STATUS_REGISTER_2r_ARESETf_SET(pll1_ctrl, 0);
    ioerr += WRITE_CMIC_CORE_PLL1_CTRL_STATUS_REGISTER_2r(unit, pll1_ctrl);
    BMD_SYS_USLEEP(wait_usec);
    CMIC_CORE_PLL1_CTRL_STATUS_REGISTER_2r_DRESETf_SET(pll1_ctrl, 0);
    ioerr += WRITE_CMIC_CORE_PLL1_CTRL_STATUS_REGISTER_2r(unit, pll1_ctrl);
    BMD_SYS_USLEEP(wait_usec);

    /* Bring MMU0 clock doubler out of reset */
    ioerr += READ_CMIC_CORE_PLL2_CTRL_STATUS_REGISTER_2r(unit, &pll2_ctrl);
    CMIC_CORE_PLL2_CTRL_STATUS_REGISTER_2r_ARESETf_SET(pll2_ctrl, 0);
    ioerr += WRITE_CMIC_CORE_PLL2_CTRL_STATUS_REGISTER_2r(unit, pll2_ctrl);
    BMD_SYS_USLEEP(wait_usec);
    CMIC_CORE_PLL2_CTRL_STATUS_REGISTER_2r_DRESETf_SET(pll2_ctrl, 0);
    ioerr += WRITE_CMIC_CORE_PLL2_CTRL_STATUS_REGISTER_2r(unit, pll2_ctrl);
    BMD_SYS_USLEEP(wait_usec);

    /* Bring MMU1 clock doubler out of reset */
    ioerr += READ_CMIC_CORE_PLL3_CTRL_STATUS_REGISTER_2r(unit, &pll3_ctrl);
    CMIC_CORE_PLL3_CTRL_STATUS_REGISTER_2r_ARESETf_SET(pll3_ctrl, 0);
    ioerr += WRITE_CMIC_CORE_PLL3_CTRL_STATUS_REGISTER_2r(unit, pll3_ctrl);
    BMD_SYS_USLEEP(wait_usec);
    CMIC_CORE_PLL3_CTRL_STATUS_REGISTER_2r_DRESETf_SET(pll3_ctrl, 0);
    ioerr += WRITE_CMIC_CORE_PLL3_CTRL_STATUS_REGISTER_2r(unit, pll3_ctrl);
    BMD_SYS_USLEEP(wait_usec);

    /* Check PLL lock status */
    ioerr += READ_CMIC_MISC_STATUSr(unit, &misc_stat);
#if BMD_CONFIG_SIMULATION == 0
    if (CMIC_MISC_STATUSr_CORE_PLL_IP2_LOCKf_GET(misc_stat) == 0) {
        CDK_WARN(("bcm56820_a0_gxport_reset[%d]: "
                  "IP2 clock doubler not locked\n", unit));
    }
    if (CMIC_MISC_STATUSr_CORE_PLL_MMU0_LOCKf_GET(misc_stat) == 0) {
        CDK_WARN(("bcm56820_a0_gxport_reset[%d]: "
                  "MMU0 clock doubler not locked\n", unit));
    }
    if (CMIC_MISC_STATUSr_CORE_PLL_MMU1_LOCKf_GET(misc_stat) == 0) {
        CDK_WARN(("bcm56820_a0_gxport_reset[%d]: "
                  "MMU1 clock doubler not locked\n", unit));
    }
#endif

    /* Bring PLL blocks out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL0_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL1_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_XG_PLL2_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(50);

    /* Initialize LC PLLs */
    ioerr += bcm56820_a0_lcpll_init(unit);

    /* Bring next set of blocks out of reset after PLLs */
    CMIC_SOFT_RESET_REGr_QGP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XGP0_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XGP1_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XGP2_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XGP3_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(wait_usec);

    /*
     * BCM56820 ring map
     *
     * ring0 [00] : IPIPE[1] -> EPIPE[4]
     * ring1 [01] : MMU[13]
     * ring2 [10] : [14]
     * ring3 [11] : gxport[0] -> qgport[2]
     *
     * 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1 0
     * XX10__01XX__XXXX__XXXX__XXXX__XX00__XX11__0011
     */
    CMIC_SBUS_RING_MAPr_SET(ring_map, 0x24000033);
    ioerr += WRITE_CMIC_SBUS_RING_MAPr(unit, ring_map);

    CMIC_SBUS_TIMEOUTr_SET(sbus_to, 0x7d0);
    ioerr += WRITE_CMIC_SBUS_TIMEOUTr(unit, sbus_to);

    /* Reset QGPORT */
    ioerr += bcm56820_a0_qgport_reset(unit);

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    /* Reset GXPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GXPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += bcm56820_a0_gxport_reset(unit, port);
    }
#endif

    /* Bring remaining blocks out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_EP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_IP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_MMU_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(wait_usec);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56820_A0 */
