#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56218_A0 == 1

/*
 * $Id: bcm56218_a0_bmd_port_mode_set.c,v 1.13 Broadcom SDK $
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
#include <bmd/bmd_device.h>

#include <bmdi/bmd_port_mode.h>

#include <cdk/chip/bcm56218_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56218_a0_bmd.h"

#define DRAIN_WAIT_MSEC                 500

int
bcm56218_a0_bmd_port_mode_set(int unit, int port, 
                              bmd_port_mode_t mode, uint32_t flags)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int mac_lb = (flags & BMD_PORT_MODE_F_MAC_LOOPBACK) ? 1 : 0;
    int phy_lb = (flags & BMD_PORT_MODE_F_PHY_LOOPBACK) ? 1 : 0;
    int duplex = 1;
    int speed = 1000;
    int sp_sel = 0;
    int hglite_port = 0;
    int cnt;
    uint32_t pbmp;
    EPC_LINK_BMAPr_t epc_link;
    EPC_LINK_BMAP_HIr_t epc_link_hi;
    GE_EGR_PKT_DROP_CTLr_t pkt_drop_ctl;
    COSLCCOUNTr_t lccount;
    FE_MAC1r_t fe_mac1;
    FE_MAC2r_t fe_mac2;
    FE_SUPPr_t fe_supp;
    GMACC0r_t gmacc0;
    GMACC1r_t gmacc1;
    GPORT_CONFIGr_t gport_cfg;
    GE_PORT_CONFIGr_t ge_port_config;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    if (port == 1 || port == 2) {
        hglite_port = 1;
    }

    switch (mode) {
    case bmdPortMode10hd:
    case bmdPortMode100hd:
    case bmdPortMode1000hd:
        duplex = 0;
        break;
    default:
        break;
    }
    switch (mode) {
    case bmdPortMode10fd:
    case bmdPortMode10hd:
        speed = 10;
        sp_sel = 2;
        break;
    case bmdPortMode100fd:
    case bmdPortMode100hd:
        speed = 100;
        sp_sel = 1;
        break;
    case bmdPortMode1000fd:
    case bmdPortMode1000hd:
        if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_FE) {
            return CDK_E_PARAM;
        }
        break;
    case bmdPortModeAuto:
        if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_FE) {
            /* Avoid configuring FE ports to 1000 Mbps */
            speed = 100;
            sp_sel = 1;
        } else if (hglite_port) {
            speed = 2500;
        }
        break;
    case bmdPortModeDisabled:
        break;
    case bmdPortMode2500fd:
        if (hglite_port) {
            speed = 2500;
            break;
        }
        /* Fall through */
    default:
        return CDK_E_PARAM;
    }

    if ((flags & BMD_PORT_MODE_F_INTERNAL) == 0) {

        /* Stop CPU and MMU from scheduling packets to the port */
        BMD_PORT_STATUS_CLR(unit, port, BMD_PST_LINK_UP);
        if (port >= 32) {
            ioerr += READ_EPC_LINK_BMAP_HIr(unit, &epc_link_hi);
            pbmp = EPC_LINK_BMAP_HIr_PORT_BITMAPf_GET(epc_link_hi);
            pbmp &= ~(1 << (port - 32));
            EPC_LINK_BMAP_HIr_PORT_BITMAPf_SET(epc_link_hi, pbmp);
            ioerr += WRITE_EPC_LINK_BMAP_HIr(unit, epc_link_hi);
        } else {
            ioerr += READ_EPC_LINK_BMAPr(unit, &epc_link);
            pbmp = EPC_LINK_BMAPr_PORT_BITMAPf_GET(epc_link);
            pbmp &= ~(1 << port);
            EPC_LINK_BMAPr_PORT_BITMAPf_SET(epc_link, pbmp);
            ioerr += WRITE_EPC_LINK_BMAPr(unit, epc_link);
        }

        /* Drain all packets from the TX pipeline */
        ioerr += READ_GE_EGR_PKT_DROP_CTLr(unit, port, &pkt_drop_ctl);
        GE_EGR_PKT_DROP_CTLr_FLUSHf_SET(pkt_drop_ctl, 1);
        ioerr += WRITE_GE_EGR_PKT_DROP_CTLr(unit, port, pkt_drop_ctl);
        cnt = DRAIN_WAIT_MSEC / 10;
        while (--cnt >= 0) {
            ioerr += READ_COSLCCOUNTr(unit, port, 0, &lccount);
            if (COSLCCOUNTr_GET(lccount) == 0) {
                break;
            }
            BMD_SYS_USLEEP(10000);
        }
        if (cnt < 0) {
            CDK_WARN(("bcm56218_a0_bmd_port_mode_set[%d]: "
                      "drain failed on port %d\n", unit, port));
        }
        GE_EGR_PKT_DROP_CTLr_FLUSHf_SET(pkt_drop_ctl, 0);
        ioerr += WRITE_GE_EGR_PKT_DROP_CTLr(unit, port, pkt_drop_ctl);
    }

    /* Update PHYs before MAC */
    if (CDK_SUCCESS(rv)) {
        rv = bmd_port_mode_to_phy(unit, port, mode, flags, speed, duplex);
    }

    /* Let PHYs know that we disable the MAC */
    if (CDK_SUCCESS(rv)) {
        rv = bmd_phy_notify_mac_enable(unit, port, 0);
    }

#if BMD_CONFIG_INCLUDE_HIGIG == 1
    if (hglite_port) {
        PORT_TABm_t port_tab;
        EGR_PORTr_t egr_port;
        ICONTROL_OPCODE_BITMAPr_t opcode_bmap;

        if (flags & BMD_PORT_MODE_F_HGLITE) {
            BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_HG;
        } else {
            BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_GE;
        }

        ioerr += READ_PORT_TABm(unit, port, &port_tab);
        ioerr += READ_EGR_PORTr(unit, port, &egr_port);
        if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) {
            PORT_TABm_HIGIG_PACKETf_SET(port_tab, 1); /* HiGig */
            EGR_PORTr_HIGIG_PACKETf_SET(egr_port, 1);
            ICONTROL_OPCODE_BITMAPr_SET(opcode_bmap, 0x1);
        } else {
            PORT_TABm_HIGIG_PACKETf_SET(port_tab, 0); /* IEEE */
            EGR_PORTr_HIGIG_PACKETf_SET(egr_port, 0);
            ICONTROL_OPCODE_BITMAPr_SET(opcode_bmap, 0x0);
        }
        ioerr += WRITE_PORT_TABm(unit, port, port_tab);
        ioerr += WRITE_EGR_PORTr(unit, port, egr_port);
        ioerr += WRITE_ICONTROL_OPCODE_BITMAPr(unit, port, opcode_bmap);
    }
#endif

    /* Disable MACs (Rx only) */
    ioerr += READ_GMACC1r(unit, port, &gmacc1);
    GMACC1r_RXEN0f_SET(gmacc1, 0);
    ioerr += WRITE_GMACC1r(unit, port, gmacc1);

    ioerr += READ_FE_MAC1r(unit, port, &fe_mac1);
    FE_MAC1r_RX_ENf_SET(fe_mac1, 0);
    ioerr += WRITE_FE_MAC1r(unit, port, fe_mac1);

    /* Enter soft-reset while changing mode */
    ioerr += READ_GMACC0r(unit, port, &gmacc0);
    GMACC0r_SRSTf_SET(gmacc0, 1);
    ioerr += WRITE_GMACC0r(unit, port, gmacc0);

    /* Set speed */
    ioerr += READ_FE_SUPPr(unit, port, &fe_supp);
    FE_SUPPr_SPEEDf_SET(fe_supp, sp_sel & 0x1);
    ioerr += WRITE_FE_SUPPr(unit, port, fe_supp);

    ioerr += READ_GE_PORT_CONFIGr(unit, port, &ge_port_config);
    GE_PORT_CONFIGr_SPEED_SELECTf_SET(ge_port_config, sp_sel);
    ioerr += WRITE_GE_PORT_CONFIGr(unit, port, ge_port_config);

    if (hglite_port) {
        int hgig2_en = 0;
        int pll_25g = (speed == 2500) ? 1 : 0;

#if BMD_CONFIG_INCLUDE_HIGIG == 1
        if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) {
            hgig2_en = 1;
        }
#endif
        /* Configure HGLite */
        ioerr += READ_GPORT_CONFIGr(unit, &gport_cfg, port);
        if (port == 1) {
            GPORT_CONFIGr_HGIG2_EN_S0f_SET(gport_cfg, hgig2_en);
            GPORT_CONFIGr_PLL_MODE_DEF_S0f_SET(gport_cfg, pll_25g);
        } else { /* port = 2 */
            GPORT_CONFIGr_HGIG2_EN_S1f_SET(gport_cfg, hgig2_en);
            GPORT_CONFIGr_PLL_MODE_DEF_S1f_SET(gport_cfg, pll_25g);
        }
        ioerr += WRITE_GPORT_CONFIGr(unit, gport_cfg, port);
    }

    /* Set duplex */
    ioerr += READ_FE_MAC2r(unit, port, &fe_mac2);
    FE_MAC2r_FULL_DUPf_SET(fe_mac2, duplex);
    FE_MAC2r_EXC_DEFf_SET(fe_mac2, 1);
    ioerr += WRITE_FE_MAC2r(unit, port, fe_mac2);

    ioerr += READ_GMACC1r(unit, port, &gmacc1);
    GMACC1r_FULLDf_SET(gmacc1, duplex);
    ioerr += WRITE_GMACC1r(unit, port, gmacc1);

    /* Set MAC loopback mode */
    ioerr += READ_GMACC0r(unit, port, &gmacc0);
    GMACC0r_L32Bf_SET(gmacc0, mac_lb);
    ioerr += WRITE_GMACC0r(unit, port, gmacc0);

    ioerr += READ_FE_MAC1r(unit, port, &fe_mac1);
    FE_MAC1r_LBACKf_SET(fe_mac1, mac_lb);
    ioerr += WRITE_FE_MAC1r(unit, port, fe_mac1);

    if (mode == bmdPortModeDisabled) {
        BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_LINK);
    } else {
        /* Leave soft- reset */
        ioerr += READ_GMACC0r(unit, port, &gmacc0);
        GMACC0r_SRSTf_SET(gmacc0, 0);
        ioerr += WRITE_GMACC0r(unit, port, gmacc0);

        /* Enable MAC */
        switch (speed) {
        case 10:
        case 100:
            ioerr += READ_FE_MAC1r(unit, port, &fe_mac1);
            FE_MAC1r_RX_ENf_SET(fe_mac1, 1);
            ioerr += WRITE_FE_MAC1r(unit, port, fe_mac1);
            break;
        case 1000:
        case 2500:
            ioerr += READ_GMACC1r(unit, port, &gmacc1);
            GMACC1r_RXEN0f_SET(gmacc1, 1);
            GMACC1r_TXEN0f_SET(gmacc1, 1);
            ioerr += WRITE_GMACC1r(unit, port, gmacc1);
            break;
        /* coverity[dead_error_begin] */
        default:
            break;
        }

        if (mac_lb || phy_lb) {
            BMD_PORT_STATUS_SET(unit, port, BMD_PST_LINK_UP | BMD_PST_FORCE_LINK);
        } else {
            BMD_PORT_STATUS_CLR(unit, port, BMD_PST_FORCE_LINK);
        }

        /* Let PHYs know that the MAC has been enabled */
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_notify_mac_enable(unit, port, 1);
        }
    }

    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56218_A0 */
