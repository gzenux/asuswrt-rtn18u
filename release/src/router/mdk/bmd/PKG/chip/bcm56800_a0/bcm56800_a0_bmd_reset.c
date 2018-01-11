#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56800_A0 == 1

/*
 * $Id: bcm56800_a0_bmd_reset.c,v 1.10 Broadcom SDK $
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

#include <cdk/chip/bcm56800_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>
#include <cdk/arch/xgs_miim.h>

#include "bcm56800_a0_internal.h"
#include "bcm56800_a0_bmd.h"

#define RESET_SLEEP_USEC                100
#define PLL_LOCK_MSEC                   500

#if BMD_CONFIG_INCLUDE_PHY == 1
/*
 * For BCM56580 due to the hardware port remapping, we need to adjust  
 * the PHY addresses. The PHY addresses are remapped as follows:
 *
 * Original : 0 ... 13 14 15 16 17 18 19 
 * Remapped : 0 ... 13 16 17 18 19 14 15
 */
static int 
bcm56580_phy_addr_adjust(int port)
{
    if (port == 14 || port == 15) {
        return 4;
    } else if (port > 15) {
        return -2;
    }
    return 0;
}
#endif

int
bcm56800_a0_gxport_reset(int unit, int port)
{
    int ioerr = 0;
    uint32_t dev_in_pkg;
    CMIC_XGXS_MDIO_CONFIGr_t xgxs_mdio_cfg;
    XPORT_CONFIGr_t xport_cfg;
    MAC_XGXS_CTRLr_t xgxs_ctrl;
    GPORT_CONFIGr_t gport_cfg;
#if BMD_CONFIG_INCLUDE_PHY == 1
    int speed_max;
    int msec;
    int phy_addr = port | 0xc0;
    uint32_t mreg_val;
    MAC_XGXS_STATr_t xgxs_stat;

    if (CDK_XGS_FLAGS(unit) & BCM56800_A0_CHIP_FLAG_56580) {
        phy_addr += bcm56580_phy_addr_adjust(port);
    }

    speed_max = bcm56800_a0_port_speed_max(unit, port);
#endif

    /* Use indexed alias instead of CMIC_XGXS_MDIO_CONFIG_0r, etc. */
    ioerr += READ_CMIC_XGXS_MDIO_CONFIGr(unit, port, &xgxs_mdio_cfg);
    dev_in_pkg = (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) ? 0x3 : 0x15;
    CMIC_XGXS_MDIO_CONFIGr_IEEE_DEVICES_IN_PKGf_SET(xgxs_mdio_cfg, dev_in_pkg);
    ioerr += WRITE_CMIC_XGXS_MDIO_CONFIGr(unit, port, xgxs_mdio_cfg);

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
    ioerr += READ_MAC_XGXS_CTRLr(unit, port, &xgxs_ctrl);
    MAC_XGXS_CTRLr_IDDQf_SET(xgxs_ctrl, 1);
    MAC_XGXS_CTRLr_PWRDWNf_SET(xgxs_ctrl, 1);
    MAC_XGXS_CTRLr_AFIFO_RSTf_SET(xgxs_ctrl, 1);
    MAC_XGXS_CTRLr_HW_RSTLf_SET(xgxs_ctrl, 0);
    MAC_XGXS_CTRLr_RSTB_MDIOREGSf_SET(xgxs_ctrl, 0);
    MAC_XGXS_CTRLr_RSTB_PLLf_SET(xgxs_ctrl, 0);
    MAC_XGXS_CTRLr_BIGMACRSTLf_SET(xgxs_ctrl, 0);
    MAC_XGXS_CTRLr_TXFIFO_RSTLf_SET(xgxs_ctrl, 0);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);

    /* Force TriMAC into reset before initialization */
    ioerr += READ_GPORT_CONFIGr(unit, port, &gport_cfg);
    GPORT_CONFIGr_TRIMAC_RESETf_SET(gport_cfg, 1);
    ioerr += WRITE_GPORT_CONFIGr(unit, port, gport_cfg);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

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

    /* Bring TriMac out of reset */
    ioerr += READ_GPORT_CONFIGr(unit, port, &gport_cfg);
    GPORT_CONFIGr_TRIMAC_RESETf_SET(gport_cfg, 0);
    ioerr += WRITE_GPORT_CONFIGr(unit, port, gport_cfg);

#if BMD_CONFIG_INCLUDE_PHY == 1
    /* Isolate external power-down input pins */
    ioerr += cdk_xgs_miim_iblk_read(unit, phy_addr, 0x101a, &mreg_val);
    mreg_val |= (1 << 10);
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x101a, mreg_val);

    /* Disable PLL state machine */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x5011, 0x5006);

    /* PLL VCO step time */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x5012, 0x04ff);

    /* Turn off slowdn_xor */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x5015, 0x0000);

    /* CDR bandwidth */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0xf016, 0x8300);

    /* Select ComboCore mode */
    ioerr += cdk_xgs_miim_iblk_read(unit, phy_addr, 0x0010, &mreg_val);
    mreg_val &= ~(0xf << 8);
    mreg_val |= (0xc << 8);
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x0010, mreg_val);

    /* Enable DTE mdio reg mapping */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x001e, 0x0001);

    if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) {
        /* Configure Tx to default value */
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0xa017, 0x0990);

        /* Advertise 10G HiG/CX4 by default */
        mreg_val = 0x0018;
        if (speed_max == 13000) {
            /* Advertise 12G and 13G as well */
            mreg_val |= 0x00a0;
        }
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x32019, mreg_val);
    } else {
        /* Configure Tx for CX4 compliance */
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0xa017, 0x5ff0);

        /* Advertise 2.5G by default */
        mreg_val = 0x0001;
        if (speed_max >= 10000) {
            /* Advertise 10G as well */
            mreg_val |= 0x0010;
        }
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x32019, mreg_val);
    }

    /* Adjust 10G parallel detect link timer to 60ms */ 
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x34013, 0x16E2); 

    /* Change 10G parallel detect lostlink timer */
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x34014, 0x4c4a);

    /* Configure 10G parallel detect */
    ioerr += cdk_xgs_miim_iblk_read(unit, phy_addr, 0x34011, &mreg_val);
    mreg_val |= (1 << 0); /* Enable 10G parallel detect */
    if (speed_max == 10000) {
        mreg_val |= (5 << 0); /* Disable parallel detect for 12 Gbps */
        mreg_val |= (6 << 0); /* Disable parallel detect 12 Gbps TXD */
    }
    ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, 0x34011, mreg_val);

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
        CDK_WARN(("bcm56800_a0_gxport_reset[%d]: "
                  "TX PLL did not lock on port %d\n", unit, port));
    }
#endif

    /* Bring BigMac out of reset */
    MAC_XGXS_CTRLr_BIGMACRSTLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);

    /* Enable Tx FIFO */
    MAC_XGXS_CTRLr_TXFIFO_RSTLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_MAC_XGXS_CTRLr(unit, port, xgxs_ctrl);

    return ioerr;
}

static int
bcm56800_a0_lcpll_init(int unit)
{
    int ioerr = 0;
    int msec;
    union {
        CMIC_XGXS0_PLL_CONTROL_1r_t pll0;
        CMIC_XGXS1_PLL_CONTROL_1r_t pll1;
    } pll_ctrl1;
    CMIC_XGXS0_PLL_CONTROL_2r_t pll0_ctrl2;
    CMIC_XGXS1_PLL_CONTROL_2r_t pll1_ctrl2;

    /* Reinitialize LC PLLs (same values written to both registers) */
    ioerr += READ_CMIC_XGXS0_PLL_CONTROL_1r(unit, &pll_ctrl1.pll0);
    CMIC_XGXS0_PLL_CONTROL_1r_PLL_SEQSTARTf_SET(pll_ctrl1.pll0, 1);
    ioerr += WRITE_CMIC_XGXS0_PLL_CONTROL_1r(unit, pll_ctrl1.pll0);
    ioerr += WRITE_CMIC_XGXS1_PLL_CONTROL_1r(unit, pll_ctrl1.pll1);
    BMD_SYS_USLEEP(100);
    CMIC_XGXS0_PLL_CONTROL_1r_PLLFORCECAPDONE_ENf_SET(pll_ctrl1.pll0, 1);
    CMIC_XGXS0_PLL_CONTROL_1r_PLLFORCECAPDONEf_SET(pll_ctrl1.pll0, 1);
    CMIC_XGXS0_PLL_CONTROL_1r_PLLFORCECAPPASS_ENf_SET(pll_ctrl1.pll0, 1);
    CMIC_XGXS0_PLL_CONTROL_1r_PLLFORCECAPPASSf_SET(pll_ctrl1.pll0, 1);
    ioerr += WRITE_CMIC_XGXS0_PLL_CONTROL_1r(unit, pll_ctrl1.pll0);
    ioerr += WRITE_CMIC_XGXS1_PLL_CONTROL_1r(unit, pll_ctrl1.pll1);
    BMD_SYS_USLEEP(100);
    CMIC_XGXS0_PLL_CONTROL_1r_PLL_SEQSTARTf_SET(pll_ctrl1.pll0, 0);
    ioerr += WRITE_CMIC_XGXS0_PLL_CONTROL_1r(unit, pll_ctrl1.pll0);
    ioerr += WRITE_CMIC_XGXS1_PLL_CONTROL_1r(unit, pll_ctrl1.pll1);

    /* Wait for LC PLL locks */
    for (msec = 0; msec < PLL_LOCK_MSEC; msec++) {
        ioerr += READ_CMIC_XGXS0_PLL_CONTROL_2r(unit, &pll0_ctrl2);
        ioerr += READ_CMIC_XGXS1_PLL_CONTROL_2r(unit, &pll1_ctrl2);
#if BMD_CONFIG_SIMULATION
        if (msec == 0) break;
#endif
        if (CMIC_XGXS0_PLL_CONTROL_2r_CMIC_XGPLL_LOCKf_GET(pll0_ctrl2) == 1 &&
            CMIC_XGXS1_PLL_CONTROL_2r_CMIC_XGPLL_LOCKf_GET(pll1_ctrl2) == 1) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (msec >= PLL_LOCK_MSEC) {
        CDK_WARN(("bcm56800_a0_bmd_reset[%d]: "
                  "LC PLL did not lock, status = 0x%08"PRIx32" 0x%08"PRIx32"\n",
                  unit, CMIC_XGXS0_PLL_CONTROL_2r_GET(pll0_ctrl2), 
                  CMIC_XGXS1_PLL_CONTROL_2r_GET(pll1_ctrl2)));
    }

    return ioerr;
}

int
bcm56800_a0_bmd_reset(int unit)
{
    int ioerr = 0;
    int wait_usec = 10000;
    int port;
    cdk_pbmp_t pbmp;
    CMIC_CONFIGr_t cmic_config;
    CMIC_SOFT_RESET_REGr_t cmic_sreset;
    CMIC_SBUS_RING_MAPr_t ring_map;

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
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL0_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL1_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_BSAFE_CLKGEN_RST_Lf_SET(cmic_sreset,1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(1000);

    /* Bring GX4 block out of reset at least 1 msec after PLLs */
    CMIC_SOFT_RESET_REGr_CMIC_GX4_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);

    /* Initialize LC PLLs */
    ioerr += bcm56800_a0_lcpll_init(unit);

    /*
     * BCM56800 ring map
     *
     * ring0 [00] : ipipe[1] -> ipipe_x[2] -> ipipe_y[3] -> 
     *              epipe[4] -> epipe_x[5] -> epipe_y[6]
     * ring1 [01] : mmu[13]
     * ring2 [10] : bsafe[14]
     * ring3 [11] : gxport[0]
     *
     * 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0
     * 0010__0100__0000__0000__0000__0000__0000__0011
     */
    CMIC_SBUS_RING_MAPr_SET(ring_map, 0x24000003);
    ioerr += WRITE_CMIC_SBUS_RING_MAPr(unit, ring_map);

    /* Reset GXPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GXPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += bcm56800_a0_gxport_reset(unit, port);
    }

    /* Bring remaining blocks out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_BSAFE_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_IP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_EP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_MMU_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XP_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(wait_usec);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56800_A0 */
