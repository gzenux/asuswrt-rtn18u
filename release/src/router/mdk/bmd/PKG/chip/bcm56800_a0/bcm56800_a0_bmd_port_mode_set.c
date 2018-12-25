#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56800_A0 == 1

/*
 * $Id: bcm56800_a0_bmd_port_mode_set.c,v 1.10 Broadcom SDK $
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

#include <cdk/chip/bcm56800_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56800_a0_bmd.h"
#include "bcm56800_a0_internal.h"

#define DRAIN_WAIT_MSEC                 500

/* Supported HiGig encapsulations */
#define HG_FLAGS        (BMD_PORT_MODE_F_HIGIG | BMD_PORT_MODE_F_HIGIG2)

int
bcm56800_a0_bmd_port_mode_set(int unit, int port, 
                              bmd_port_mode_t mode, uint32_t flags)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int mac_lb = (flags & BMD_PORT_MODE_F_MAC_LOOPBACK) ? 1 : 0;
    int phy_lb = (flags & BMD_PORT_MODE_F_PHY_LOOPBACK) ? 1 : 0;
    int duplex = 1;
    int speed = 1000;
    int sp_sel = 0;
    bmd_port_mode_t cur_mode;
    uint32_t cur_flags;
    int cnt;
    uint32_t pbmp;
    EPC_LINK_BMAPr_t epc_link;
    GE_EGR_PKT_DROP_CTLr_t ge_drop_ctl;
    XP_EGR_PKT_DROP_CTLr_t xp_drop_ctl;
    OP_PORT_TOTAL_COUNTr_t cell_cnt;
    MAC_CTRLr_t mac_ctrl;
    FE_MAC1r_t fe_mac1;
    FE_MAC2r_t fe_mac2;
    FE_SUPPr_t fe_supp;
    GMACC0r_t gmacc0;
    GMACC1r_t gmacc1;
    GPORT_CONFIGr_t gport_cfg;
    XPORT_CONFIGr_t xport_cfg;
    GE_PORT_CONFIGr_t ge_port_config;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
        switch (mode) {
        case bmdPortMode10000fd:
        case bmdPortModeAuto:
        case bmdPortModeDisabled:
            speed = 10000;
            break;
        case bmdPortMode12000fd:
            if (flags & HG_FLAGS) {
                speed = 12000;
            }
            break;
        case bmdPortMode13000fd:
            if (flags & HG_FLAGS) {
                speed = 13000;
            }
            break;
        default:
            break;
        }
    }
    /* If no XAUI mode was selected, check SerDes modes */
    if (speed == 1000) {
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
        case bmdPortMode2500fd:
            speed = 2500;
        case bmdPortMode1000fd:
        case bmdPortMode1000hd:
        case bmdPortModeAuto:
            break;
        case bmdPortModeDisabled:
            break;
        default:
            return CDK_E_PARAM;
        }
    }

    /* Check that speed is valid for this port */
    if (speed > bcm56800_a0_port_speed_max(unit, port)) {
        return CDK_E_PARAM;
    }

    /* Check port capability */
    if ((flags & HG_FLAGS) == 0 &&
        !bcm56800_a0_port_ethernet(unit, port)) {
        return CDK_E_PARAM;
    }

    if ((flags & BMD_PORT_MODE_F_INTERNAL) == 0) {

        /* Stop CPU and MMU from scheduling packets to the port */
        BMD_PORT_STATUS_CLR(unit, port, BMD_PST_LINK_UP);
        ioerr += READ_EPC_LINK_BMAPr(unit, &epc_link);
        pbmp = EPC_LINK_BMAPr_PORT_BITMAPf_GET(epc_link);
        EPC_LINK_BMAPr_PORT_BITMAPf_SET(epc_link, pbmp & ~(1 << port));
        ioerr += WRITE_EPC_LINK_BMAPr(unit, epc_link);

        /* Drain all packets from the Tx pipeline */
        GE_EGR_PKT_DROP_CTLr_SET(ge_drop_ctl, 1);
        ioerr += WRITE_GE_EGR_PKT_DROP_CTLr(unit, port, ge_drop_ctl);
        XP_EGR_PKT_DROP_CTLr_SET(xp_drop_ctl, 1);
        ioerr += WRITE_XP_EGR_PKT_DROP_CTLr(unit, port, xp_drop_ctl);
        cnt = DRAIN_WAIT_MSEC / 10;
        while (--cnt >= 0) {
            ioerr += READ_OP_PORT_TOTAL_COUNTr(unit, port, &cell_cnt);
            if (OP_PORT_TOTAL_COUNTr_GET(cell_cnt) == 0) {
                break;
            }
            BMD_SYS_USLEEP(10000);
        }
        if (cnt < 0) {
            CDK_WARN(("bcm56800_a0_bmd_port_mode_set[%d]: "
                      "drain failed on port %d\n", unit, port));
        }
        GE_EGR_PKT_DROP_CTLr_SET(ge_drop_ctl, 0);
        ioerr += WRITE_GE_EGR_PKT_DROP_CTLr(unit, port, ge_drop_ctl);
        XP_EGR_PKT_DROP_CTLr_SET(xp_drop_ctl, 0);
        ioerr += WRITE_XP_EGR_PKT_DROP_CTLr(unit, port, xp_drop_ctl);

        if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
            /*
             * If HiGig/Ethernet encapsulation changes, we need 
             * to reinitialize from scratch.
             */
            rv = bcm56800_a0_bmd_port_mode_get(unit, port, 
                                               &cur_mode, &cur_flags);
            if (CDK_SUCCESS(rv) && 
                ((flags ^ cur_flags) & HG_FLAGS)) {
                /* Change basic port mode */
                if (flags & HG_FLAGS) {
                    BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_HG;
                } else {
                    BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
                }
                /* Let PHYs know that we disable the MAC */
                rv = bmd_phy_notify_mac_enable(unit, port, 0);
                /* Reset and reinitialize port */
                if (CDK_SUCCESS(rv)) {
                    rv = bcm56800_a0_gxport_reset(unit, port);
                }
                if (CDK_SUCCESS(rv)) {
                    rv = bcm56800_a0_gxport_init(unit, port);
                }
            }
        }
    }

    /* Update PHYs before MAC */
    if (CDK_SUCCESS(rv)) {
        rv = bmd_port_mode_to_phy(unit, port, mode, flags, speed, duplex);
    }

    /* Let PHYs know that we disable the MAC */
    if (CDK_SUCCESS(rv)) {
        rv = bmd_phy_notify_mac_enable(unit, port, 0);
    }

    /* Disable MACs (Rx only) */
    ioerr += READ_MAC_CTRLr(unit, port, &mac_ctrl);
    MAC_CTRLr_RXENf_SET(mac_ctrl, 0);
    ioerr += WRITE_MAC_CTRLr(unit, port, mac_ctrl);

    ioerr += READ_GMACC1r(unit, port, &gmacc1);
    GMACC1r_RXEN0f_SET(gmacc1, 0);
    ioerr += WRITE_GMACC1r(unit, port, gmacc1);

    ioerr += READ_FE_MAC1r(unit, port, &fe_mac1);
    FE_MAC1r_RX_ENf_SET(fe_mac1, 0);
    ioerr += WRITE_FE_MAC1r(unit, port, fe_mac1);

    if (mode == bmdPortModeDisabled) {
        BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_LINK);
    } else {
#if BMD_CONFIG_INCLUDE_HIGIG == 1
        int hg, hg2;
        MAC_TXCTRLr_t txctrl;
        MAC_RXCTRLr_t rxctrl;
        PORT_TABm_t port_tab;
        EGR_PORTr_t egr_port;
        ICONTROL_OPCODE_BITMAPr_t opcode_bmap;

        /* Set encapsulation */
        hg = hg2 = 0;
        if (flags & HG_FLAGS) {
            hg = 1;
            if (flags & BMD_PORT_MODE_F_HIGIG2) {
                hg2 = 1;
            }
        }
        ioerr += READ_XPORT_CONFIGr(unit, port, &xport_cfg);
        ioerr += READ_MAC_TXCTRLr(unit, port, &txctrl);
        ioerr += READ_MAC_RXCTRLr(unit, port, &rxctrl);
        ioerr += READ_PORT_TABm(unit, port, &port_tab);
        ioerr += READ_EGR_PORTr(unit, port, &egr_port);
        /* Set IEEE vs HiGig */        
        XPORT_CONFIGr_HIGIG_MODEf_SET(xport_cfg, hg);
        MAC_TXCTRLr_HDRMODEf_SET(txctrl, hg);
        MAC_RXCTRLr_HDRMODEf_SET(rxctrl, hg);
        PORT_TABm_HIGIG_PACKETf_SET(port_tab, hg);
        EGR_PORTr_HIGIG_PACKETf_SET(egr_port, hg);
        ICONTROL_OPCODE_BITMAPr_SET(opcode_bmap, hg ? 0x100000 : 0);
        /* Set HiGig vs. HiGig2 */
        XPORT_CONFIGr_HIGIG2_MODEf_SET(xport_cfg, hg2);
        MAC_TXCTRLr_HIGIG2MODEf_SET(txctrl, hg2);
        MAC_RXCTRLr_HIGIG2MODEf_SET(rxctrl, hg2);
        PORT_TABm_HIGIG2f_SET(port_tab, hg2);
        EGR_PORTr_HIGIG2f_SET(egr_port, hg2);
        ioerr += WRITE_XPORT_CONFIGr(unit, port, xport_cfg);
        ioerr += WRITE_MAC_TXCTRLr(unit, port, txctrl);
        ioerr += WRITE_MAC_RXCTRLr(unit, port, rxctrl);
        ioerr += WRITE_PORT_TABm(unit, port, port_tab);
        ioerr += WRITE_EGR_PORTr(unit, port, egr_port);
        ioerr += WRITE_ICONTROL_OPCODE_BITMAPr(unit, port, opcode_bmap);
#endif

        /* Set port mode */
        ioerr += READ_GPORT_CONFIGr(unit, port, &gport_cfg);
        if (speed >= 10000) {
            GPORT_CONFIGr_GPORT_ENf_SET(gport_cfg, 0);
            XPORT_CONFIGr_XPORT_ENf_SET(xport_cfg, 1);
            /* Avoid having both GPORT and XPORT enabled simultaneously */
            ioerr += WRITE_GPORT_CONFIGr(unit, port, gport_cfg);
            ioerr += WRITE_XPORT_CONFIGr(unit, port, xport_cfg);
        } else {
            GPORT_CONFIGr_GPORT_ENf_SET(gport_cfg, 1);
            XPORT_CONFIGr_XPORT_ENf_SET(xport_cfg, 0);
            /* Avoid having both GPORT and XPORT enabled simultaneously */
            ioerr += WRITE_XPORT_CONFIGr(unit, port, xport_cfg);
            ioerr += WRITE_GPORT_CONFIGr(unit, port, gport_cfg);
        }

        /* Set MAC loopback mode */
        ioerr += READ_MAC_CTRLr(unit, port, &mac_ctrl);
        MAC_CTRLr_LCLLOOPf_SET(mac_ctrl, mac_lb);
        ioerr += WRITE_MAC_CTRLr(unit, port, mac_ctrl);

        ioerr += READ_GMACC0r(unit, port, &gmacc0);
        GMACC0r_L32Bf_SET(gmacc0, mac_lb);
        ioerr += WRITE_GMACC0r(unit, port, gmacc0);

        ioerr += READ_FE_MAC1r(unit, port, &fe_mac1);
        FE_MAC1r_LBACKf_SET(fe_mac1, mac_lb);
        ioerr += WRITE_FE_MAC1r(unit, port, fe_mac1);

        /* Configure and enable appropriate MAC */
        if (speed >= 10000) {
            ioerr += READ_MAC_CTRLr(unit, port, &mac_ctrl);
            MAC_CTRLr_RXENf_SET(mac_ctrl, 1);
            ioerr += WRITE_MAC_CTRLr(unit, port, mac_ctrl);
        } else {
            /* Set speed */
            ioerr += READ_FE_SUPPr(unit, port, &fe_supp);
            FE_SUPPr_SPEEDf_SET(fe_supp, sp_sel & 0x1);
            ioerr += WRITE_FE_SUPPr(unit, port, fe_supp);

            ioerr += READ_GE_PORT_CONFIGr(unit, port, &ge_port_config);
            GE_PORT_CONFIGr_SPEED_SELECTf_SET(ge_port_config, sp_sel);
            ioerr += WRITE_GE_PORT_CONFIGr(unit, port, ge_port_config);

            /* Set duplex */
            ioerr += READ_FE_MAC2r(unit, port, &fe_mac2);
            FE_MAC2r_FULL_DUPf_SET(fe_mac2, duplex);
            FE_MAC2r_EXC_DEFf_SET(fe_mac2, 1);
            ioerr += WRITE_FE_MAC2r(unit, port, fe_mac2);

            ioerr += READ_GMACC1r(unit, port, &gmacc1);
            GMACC1r_FULLDf_SET(gmacc1, duplex);
            ioerr += WRITE_GMACC1r(unit, port, gmacc1);

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
#endif /* CDK_CONFIG_INCLUDE_BCM56800_A0 */
