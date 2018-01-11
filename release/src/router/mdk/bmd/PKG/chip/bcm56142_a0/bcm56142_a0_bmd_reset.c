/*
 * $Id: bcm56142_a0_bmd_reset.c,v 1.8 Broadcom SDK $
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
#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56142_A0 == 1

#include <bmd/bmd.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>
#include <cdk/arch/xgs_miim.h>
#include <cdk/chip/bcm56142_a0_defs.h>
#include "bcm56142_a0_bmd.h"
#include "bcm56142_a0_internal.h"

#define RESET_SLEEP_USEC                100
#define PLL_LOCK_MSEC                   500

/* Transform datasheet mapped address to MIIM address used by software API */
#define MREG(_b) ((((_b) & 0xfff0) << 8) | 0x10 | ((_b) & 0xf))

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1

static int
bcm56142_a0_hypercore_phy_init(int unit, int port)
{
    int ioerr = 0;
#if BMD_CONFIG_INCLUDE_PHY == 1
    int phy_addr = port - 1 + CDK_XGS_MIIM_INTERNAL;
    uint32_t mreg_val;

    if (port < 26) {
  	phy_addr = port - 1 + CDK_XGS_MIIM_INTERNAL;
    } else if (port < 28) {
	phy_addr = 25 + CDK_XGS_MIIM_INTERNAL;
    } else if (port < 30) {
	phy_addr = 26 + CDK_XGS_MIIM_INTERNAL;
    }

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

    /* set the independant lane mode */
    if(port > 27 && port <30 ){
        ioerr += cdk_xgs_miim_iblk_read(unit, phy_addr, MREG(0x8000), &mreg_val);
        mreg_val &= ~(0xf << 8);
        mreg_val |= (0x5 << 8);
        ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8000), mreg_val);
    }
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_HD25_HD127) {
        CMIC_MISC_STATUSr_t misc_stat;
        ioerr += READ_CMIC_MISC_STATUSr(unit, &misc_stat);
        if (CMIC_MISC_STATUSr_DUAL_XGXS_MODE_SELf_GET(misc_stat) == 0) {
            if ((port == 28) || (port == 29)) {
                BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_HG;
            }
            if ((port == 26) || (port == 27)) {
                BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_GE;
            }
        }
        if(port > 25 && port <30 ){
            ioerr += cdk_xgs_miim_iblk_read(unit, phy_addr, MREG(0x8000), &mreg_val);
            mreg_val &= ~(0xf << 8);
            mreg_val |= (0x5 << 8);
            ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8000), mreg_val);
        }
    }

    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_FE_ONLY) {
        if(port > 25 && port < 28){
           ioerr += cdk_xgs_miim_iblk_read(unit, phy_addr, MREG(0x8000), &mreg_val);
           mreg_val &= ~(0xf << 8);
           mreg_val |= (0x5 << 8);
           ioerr += cdk_xgs_miim_iblk_write(unit, phy_addr, MREG(0x8000), mreg_val);
        }
    }

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

#endif /* BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1 */

int 
bcm56142_a0_xport_reset(int unit, int port)
{
    int ioerr = 0;
    int msec;
    int idx;
    uint32_t dev_in_pkg;
    CMIC_XGXS_MDIO_CONFIGr_t xgxs_mdio_cfg;
    XPORT_CONFIGr_t xport_cfg;
    MAC_XGXS_CTRLr_t xgxs_ctrl;
    MAC_XGXS_STATr_t xgxs_stat;
    COMMAND_CONFIGr_t command_cfg;

    /* Zero-based xport index */
    if (port < 26) {
        return CDK_E_INTERNAL;
    } else if (port < 30) {
        idx = port - 26;
    } else {
        idx = (port - 30) / 4;
    }

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

    /* Reset UniMac */
    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
    COMMAND_CONFIGr_SW_RESETf_SET(command_cfg, 1);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /* Bring UniMac out of reset (re-read register required) */
    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
    COMMAND_CONFIGr_SW_RESETf_SET(command_cfg, 0);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
        ioerr += bcm56142_a0_hypercore_phy_init(unit, port);    
    }
    /* For 56146 variant, initialize hglite ports */   
    if ((BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_GE) && (port > 25)){
        ioerr += bcm56142_a0_hypercore_phy_init(unit, port);    
    }
#endif

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
        CDK_WARN(("bcm56142_a0_xport_reset[%d]: "
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

int
bcm56142_a0_bmd_reset(int unit)
{
    int ioerr = 0;
    int wait_usec = 10000;
    int idx;
    int port;
    cdk_pbmp_t pbmp;
    CMIC_CONFIGr_t cmic_config;
    CMIC_SOFT_RESET_REGr_t cmic_sreset;
    CMIC_SBUS_RING_MAP_0r_t ring_map_0;
    CMIC_SBUS_RING_MAP_1r_t ring_map_1;
    CMIC_SBUS_RING_MAP_2r_t ring_map_2;
    CMIC_SBUS_RING_MAP_3r_t ring_map_3;
    CMIC_SBUS_RING_MAP_4r_t ring_map_4;
    CMIC_SBUS_RING_MAP_5r_t ring_map_5;
    CMIC_SBUS_RING_MAP_6r_t ring_map_6;
    CMIC_SBUS_RING_MAP_7r_t ring_map_7;
    CMIC_SBUS_TIMEOUTr_t sbus_to;
    CMIC_XGXS_MDIO_CONFIGr_t xgxs_mdio_cfg;

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

    /* Bring PLL blocks out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_XG0_PLL_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(50);
    /* Bring SerDes cores out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_QSGMII2X_SERDES_0_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_QSGMII2X_SERDES_1_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_QSGMII2X_SERDES_2_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(50);

    /* Bring remaining blocks out of reset 1 msec after PLLs */
    CMIC_SOFT_RESET_REGr_CMIC_GP0_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_GP1_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_GP2_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XQP0_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XQP1_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XQP2_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_XQP3_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(wait_usec);

    CMIC_SOFT_RESET_REGr_XQ0_HOTSWAP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_XQ1_HOTSWAP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_XQ2_HOTSWAP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_XQ3_HOTSWAP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_NS_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_THERMAL_MON_RESETf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(wait_usec);

    CMIC_SOFT_RESET_REGr_THERMAL_MON_RESETf_SET(cmic_sreset, 0);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(wait_usec);
    /*
     * BCM56334 ring map
     *
     */
    CMIC_SBUS_RING_MAP_0r_SET(ring_map_0, 0x11122200);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_0r(unit, ring_map_0);
    CMIC_SBUS_RING_MAP_1r_SET(ring_map_1, 0x00330001);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_1r(unit, ring_map_1);
    CMIC_SBUS_RING_MAP_2r_SET(ring_map_2, 0x0);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_2r(unit, ring_map_2);
    CMIC_SBUS_RING_MAP_3r_SET(ring_map_3, 0x0);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_3r(unit, ring_map_3);
    CMIC_SBUS_RING_MAP_4r_SET(ring_map_4, 0x0);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_4r(unit, ring_map_4);
    CMIC_SBUS_RING_MAP_5r_SET(ring_map_5, 0x0);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_5r(unit, ring_map_5);
    CMIC_SBUS_RING_MAP_6r_SET(ring_map_6, 0x0);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_6r(unit, ring_map_6);
    CMIC_SBUS_RING_MAP_7r_SET(ring_map_7, 0x0);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_7r(unit, ring_map_7);

    CMIC_SBUS_TIMEOUTr_SET(sbus_to, 0x7d0);
    ioerr += WRITE_CMIC_SBUS_TIMEOUTr(unit, sbus_to);

    /* Bring IP, EP, and MMU blocks out of reset */
    ioerr += READ_CMIC_SOFT_RESET_REGr(unit, &cmic_sreset);
    CMIC_SOFT_RESET_REGr_CMIC_EP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_IP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_MMU_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(wait_usec);

    /* Use indexed alias instead of CMIC_XGXS_MDIO_CONFIG_0r, etc. */
    for (idx = 0; idx < 4; idx++) {
        ioerr += READ_CMIC_XGXS_MDIO_CONFIGr(unit, idx, &xgxs_mdio_cfg);
        CMIC_XGXS_MDIO_CONFIGr_IEEE_DEVICES_IN_PKGf_SET(xgxs_mdio_cfg, 0x3);
        CMIC_XGXS_MDIO_CONFIGr_MD_DEVADf_SET(xgxs_mdio_cfg, 5);
        ioerr += WRITE_CMIC_XGXS_MDIO_CONFIGr(unit, idx, xgxs_mdio_cfg);
    }

    /* Reset XQPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XQPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += bcm56142_a0_xport_reset(unit, port);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

#endif /* CDK_CONFIG_INCLUDE_BCM56142_A0 */
