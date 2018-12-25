#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56514_A0 == 1

/*
 * $Id: bcm56514_a0_bmd_port_mode_set.c,v 1.10 Broadcom SDK $
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

#include <cdk/chip/bcm56514_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56514_a0_bmd.h"
#include "bcm56514_a0_internal.h"

#define DRAIN_WAIT_MSEC                 500

int
bcm56514_a0_bmd_port_mode_set(int unit, int port, 
                              bmd_port_mode_t mode, uint32_t flags)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int mac_lb = (flags & BMD_PORT_MODE_F_MAC_LOOPBACK) ? 1 : 0;
    int phy_lb = (flags & BMD_PORT_MODE_F_PHY_LOOPBACK) ? 1 : 0;
    int duplex = 1;
    int speed = 1000;
    int sp_sel = 0;
    int cnt;
    uint32_t pbmp;
    EPC_LINK_BMAPr_t epc_link;
    GE_EGR_PKT_DROP_CTLr_t ge_drop_ctl;
    COSLCCOUNTr_t lccount;
    FE_MAC1r_t fe_mac1;
    FE_MAC2r_t fe_mac2;
    FE_SUPPr_t fe_supp;
    GMACC0r_t gmacc0;
    GMACC1r_t gmacc1;
    GE_PORT_CONFIGr_t ge_port_config;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
        switch (mode) {
#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
        case bmdPortMode10000fd:
        case bmdPortModeAuto:
        case bmdPortModeDisabled:
            speed = 10000;
            break;
        case bmdPortMode12000fd:
            if (flags & BMD_PORT_MODE_F_HIGIG) {
                speed = 12000;
                break;
            }
            /* else fall through */
#endif
        default:
            return CDK_E_PARAM;
        }
    } else {
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
        case bmdPortModeAuto:
            break;
        case bmdPortModeDisabled:
            break;
        default:
            return CDK_E_PARAM;
        }
    }

    if ((flags & BMD_PORT_MODE_F_INTERNAL) == 0) {

        /* Stop CPU and MMU from scheduling packets to the port */
        BMD_PORT_STATUS_CLR(unit, port, BMD_PST_LINK_UP);
        ioerr += READ_EPC_LINK_BMAPr(unit, &epc_link);
        pbmp = EPC_LINK_BMAPr_PORT_BITMAPf_GET(epc_link);
        EPC_LINK_BMAPr_PORT_BITMAPf_SET(epc_link, pbmp & ~(1 << port));
        ioerr += WRITE_EPC_LINK_BMAPr(unit, epc_link);

        /* Drain all packets from the Tx pipeline (GE only) */
        if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_GE) {
            GE_EGR_PKT_DROP_CTLr_SET(ge_drop_ctl, 1);
            ioerr += WRITE_GE_EGR_PKT_DROP_CTLr(unit, port, ge_drop_ctl);
            cnt = DRAIN_WAIT_MSEC / 10;
            while (--cnt >= 0) {
                ioerr += READ_COSLCCOUNTr(unit, port, 0, &lccount);
                if (COSLCCOUNTr_GET(lccount) == 0) {
                    break;
                }
                BMD_SYS_USLEEP(10000);
            }
            if (cnt < 0) {
                CDK_WARN(("bcm56514_a0_bmd_port_mode_set[%d]: "
                          "drain failed on port %d\n", unit, port));
            }
            GE_EGR_PKT_DROP_CTLr_SET(ge_drop_ctl, 0);
            ioerr += WRITE_GE_EGR_PKT_DROP_CTLr(unit, port, ge_drop_ctl);
        }

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
        if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
            if (CDK_SUCCESS(rv)) {
                bmd_port_mode_t cur_mode;
                uint32_t cur_flags;

                /*
                 * If encapsulation or speed changes, we need 
                 * to reinitialize from scratch.
                 */
                rv = bcm56514_a0_bmd_port_mode_get(unit, port, 
                                                   &cur_mode, &cur_flags);
                if (CDK_SUCCESS(rv)) {
                    if (mode != cur_mode || 
                        ((flags ^ cur_flags) & BMD_PORT_MODE_F_HIGIG)) {
                        if (flags & BMD_PORT_MODE_F_HIGIG) {
                            BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_HG;
                        } else {
                            BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
                        }
                        rv = bcm56514_a0_xport_reset(unit, port, speed);
                        if (CDK_SUCCESS(rv)) {
                            rv = bcm56514_a0_xport_init(unit, port);
                        }
                    }
                }
            }
        }
#endif
    }

    /* Update PHYs before MAC */
    if (CDK_SUCCESS(rv)) {
        rv = bmd_port_mode_to_phy(unit, port, mode, flags, speed, duplex);
    }

    /* Let PHYs know that we disable the MAC */
    if (CDK_SUCCESS(rv)) {
        rv = bmd_phy_notify_mac_enable(unit, port, 0);
    }

    if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
        XPORT_CONFIGr_t xport_cfg;
        MAC_CTRLr_t mac_ctrl;
        MAC_TXCTRLr_t txctrl;
        MAC_RXCTRLr_t rxctrl;
        PORT_TABm_t port_tab;
        EGR_PORTr_t egr_port;
        ICONTROL_OPCODE_BITMAPr_t opcode_bmap;

        /* Set encapsulation */
        ioerr += READ_XPORT_CONFIGr(unit, port, &xport_cfg);
        ioerr += READ_MAC_TXCTRLr(unit, port, &txctrl);
        ioerr += READ_MAC_RXCTRLr(unit, port, &rxctrl);
        ioerr += READ_PORT_TABm(unit, port, &port_tab);
        ioerr += READ_EGR_PORTr(unit, port, &egr_port);
        if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) {
            XPORT_CONFIGr_HIGIG_MODEf_SET(xport_cfg, 1); /* HiGig */
            MAC_TXCTRLr_HDRMODEf_SET(txctrl, 1);
            MAC_RXCTRLr_HDRMODEf_SET(rxctrl, 1);
            PORT_TABm_HIGIG_PACKETf_SET(port_tab, 1);
            EGR_PORTr_HIGIG_PACKETf_SET(egr_port, 1);
            ICONTROL_OPCODE_BITMAPr_SET(opcode_bmap, 0x10);
        } else {
            XPORT_CONFIGr_HIGIG_MODEf_SET(xport_cfg, 0); /* IEEE */
            MAC_TXCTRLr_HDRMODEf_SET(txctrl, 0);
            MAC_RXCTRLr_HDRMODEf_SET(rxctrl, 0);
            PORT_TABm_HIGIG_PACKETf_SET(port_tab, 0);
            EGR_PORTr_HIGIG_PACKETf_SET(egr_port, 0);
            ICONTROL_OPCODE_BITMAPr_SET(opcode_bmap, 0x0);
        }
        ioerr += WRITE_XPORT_CONFIGr(unit, port, xport_cfg);
        ioerr += WRITE_MAC_TXCTRLr(unit, port, txctrl);
        ioerr += WRITE_MAC_RXCTRLr(unit, port, rxctrl);
        ioerr += WRITE_PORT_TABm(unit, port, port_tab);
        ioerr += WRITE_EGR_PORTr(unit, port, egr_port);
        ioerr += WRITE_ICONTROL_OPCODE_BITMAPr(unit, port, opcode_bmap);

        ioerr += READ_MAC_CTRLr(unit, port, &mac_ctrl);
        MAC_CTRLr_RXENf_SET(mac_ctrl, (mode == bmdPortModeDisabled) ? 0 : 1);
        MAC_CTRLr_LCLLOOPf_SET(mac_ctrl, mac_lb);
        ioerr += WRITE_MAC_CTRLr(unit, port, mac_ctrl);
#endif
    } else {
        /* Disable MACs (Rx only) */
        ioerr += READ_GMACC1r(unit, port, &gmacc1);
        GMACC1r_RXEN0f_SET(gmacc1, 0);
        ioerr += WRITE_GMACC1r(unit, port, gmacc1);

        ioerr += READ_FE_MAC1r(unit, port, &fe_mac1);
        FE_MAC1r_RX_ENf_SET(fe_mac1, 0);
        ioerr += WRITE_FE_MAC1r(unit, port, fe_mac1);

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

        /* Set MAC loopback mode */
        ioerr += READ_GMACC0r(unit, port, &gmacc0);
        GMACC0r_L32Bf_SET(gmacc0, mac_lb);
        ioerr += WRITE_GMACC0r(unit, port, gmacc0);

        ioerr += READ_FE_MAC1r(unit, port, &fe_mac1);
        FE_MAC1r_LBACKf_SET(fe_mac1, mac_lb);
        ioerr += WRITE_FE_MAC1r(unit, port, fe_mac1);
    }

    if (mode == bmdPortModeDisabled) {
        BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_LINK);
    } else {
        /* Enable MAC */
        switch (speed) {
        case 10:
        case 100:
            /* First, toggle reset bit to clear false carrier counter */
            ioerr += READ_GMACC0r(unit, port, &gmacc0);
            GMACC0r_SRSTf_SET(gmacc0, 1);
            ioerr += WRITE_GMACC0r(unit, port, gmacc0);
            GMACC0r_SRSTf_SET(gmacc0, 0);
            ioerr += WRITE_GMACC0r(unit, port, gmacc0);

            ioerr += READ_FE_MAC1r(unit, port, &fe_mac1);
            FE_MAC1r_RX_ENf_SET(fe_mac1, 1);
            ioerr += WRITE_FE_MAC1r(unit, port, fe_mac1);
            break;
        case 1000:
            ioerr += READ_GMACC1r(unit, port, &gmacc1);
            GMACC1r_RXEN0f_SET(gmacc1, 1);
            GMACC1r_TXEN0f_SET(gmacc1, 1);
            ioerr += WRITE_GMACC1r(unit, port, gmacc1);
            break;
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
#endif /* CDK_CONFIG_INCLUDE_BCM56514_A0 */
