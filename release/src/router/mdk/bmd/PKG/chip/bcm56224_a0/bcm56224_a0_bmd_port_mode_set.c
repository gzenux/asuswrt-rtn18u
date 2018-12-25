#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56224_A0 == 1

/*
 * $Id: bcm56224_a0_bmd_port_mode_set.c,v 1.11 Broadcom SDK $
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

#include <cdk/chip/bcm56224_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56224_a0_bmd.h"
#include "bcm56224_a0_internal.h"

#define DRAIN_WAIT_MSEC                 500

int
bcm56224_a0_bmd_port_mode_set(int unit, int port, 
                              bmd_port_mode_t mode, uint32_t flags)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int mac_lb = (flags & BMD_PORT_MODE_F_MAC_LOOPBACK) ? 1 : 0;
    int phy_lb = (flags & BMD_PORT_MODE_F_PHY_LOOPBACK) ? 1 : 0;
    int duplex = 1;
    int speed = 1000;
    int sp_sel = COMMAND_CONFIG_SPEED_1000;
    int hglite_port = 0;
    int cnt;
    uint32_t pbmp;
    EPC_LINK_BMAPr_t epc_link;
    FLUSH_CONTROLr_t flush_ctrl;
    COSLCCOUNTr_t lccount;
    COMMAND_CONFIGr_t command_config;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    if (port == 1 || port == 2 || port == 4 || port == 5) {
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
        sp_sel = COMMAND_CONFIG_SPEED_10;
        break;
    case bmdPortMode100fd:
    case bmdPortMode100hd:
        speed = 100;
        sp_sel = COMMAND_CONFIG_SPEED_100;
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
            sp_sel = COMMAND_CONFIG_SPEED_100;
        } else if (hglite_port) {
            speed = 2500;
            sp_sel = COMMAND_CONFIG_SPEED_2500;
        }
        break;
    case bmdPortModeDisabled:
        break;
    case bmdPortMode2500fd:
        if (hglite_port) {
            speed = 2500;
            sp_sel = COMMAND_CONFIG_SPEED_2500;
            break;
        }
        /* Fall through */
    default:
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
        ioerr += READ_FLUSH_CONTROLr(unit, port, &flush_ctrl);
        FLUSH_CONTROLr_FLUSHf_SET(flush_ctrl, 1);
        ioerr += WRITE_FLUSH_CONTROLr(unit, port, flush_ctrl);
        cnt = DRAIN_WAIT_MSEC / 10;
        while (--cnt >= 0) {
            ioerr += READ_COSLCCOUNTr(unit, port, 0, &lccount);
            if (COSLCCOUNTr_GET(lccount) == 0) {
                break;
            }
            BMD_SYS_USLEEP(10000);
        }
        if (cnt < 0) {
            CDK_WARN(("bcm56224_a0_bmd_port_mode_set[%d]: "
                      "drain failed on port %d\n", unit, port));
        }
        FLUSH_CONTROLr_FLUSHf_SET(flush_ctrl, 0);
        ioerr += WRITE_FLUSH_CONTROLr(unit, port, flush_ctrl);
    }

    /* Update PHYs before MAC */
    if (CDK_SUCCESS(rv)) {
        rv = bmd_port_mode_to_phy(unit, port, mode, flags, speed, duplex);
    }

    /* Let PHYs know that we disable the MAC */
    if (CDK_SUCCESS(rv)) {
        rv = bmd_phy_notify_mac_enable(unit, port, 0);
    }

    /* Reset the MAC */
    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_config);
    COMMAND_CONFIGr_SW_RESETf_SET(command_config, 1);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_config);

    /* Disable MACs (Rx only) */
    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_config);
    COMMAND_CONFIGr_RX_ENAf_SET(command_config, 0);

    /* Set speed */
    COMMAND_CONFIGr_ETH_SPEEDf_SET(command_config, sp_sel);

    /* Set duplex */
    COMMAND_CONFIGr_HD_ENAf_SET(command_config, !duplex);

    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_config);

#if BMD_CONFIG_INCLUDE_HIGIG == 1
    if (hglite_port) {
        PORT_TABm_t port_tab;
        EGR_PORTr_t egr_port;
        ICONTROL_OPCODE_BITMAPr_t opcode_bmap;
        GPORT_CONFIGr_t gport_cfg;
        int hgig2_en;

        if (flags & BMD_PORT_MODE_F_HGLITE) {
            BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_HG;
            hgig2_en = 1;
        } else {
            BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_GE;
            hgig2_en = 0;
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

        /* Configure HGLite */
        ioerr += READ_GPORT_CONFIGr(unit, &gport_cfg, -1);
        if (port == 1) {
            GPORT_CONFIGr_HGIG2_EN_S0f_SET(gport_cfg, hgig2_en);
        } else if (port == 2) {
            GPORT_CONFIGr_HGIG2_EN_S1f_SET(gport_cfg, hgig2_en);
        } else if (port == 4) {
            GPORT_CONFIGr_HGIG2_EN_S3f_SET(gport_cfg, hgig2_en);
        } else { /* port = 5 */
            GPORT_CONFIGr_HGIG2_EN_S4f_SET(gport_cfg, hgig2_en);
        }
        ioerr += WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);

    }
#endif

    /* Bring the MAC out of reset */
    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_config);
    COMMAND_CONFIGr_SW_RESETf_SET(command_config, 0);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_config);

    /* Set MAC loopback mode */
    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_config);
    COMMAND_CONFIGr_LOOP_ENAf_SET(command_config, mac_lb);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_config);

    if (mode == bmdPortModeDisabled) {
        BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_LINK);
    } else {
        /* Enable MAC */
        ioerr += READ_COMMAND_CONFIGr(unit, port, &command_config);
        COMMAND_CONFIGr_SW_RESETf_SET(command_config, 1);
        ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_config);

        ioerr += READ_COMMAND_CONFIGr(unit, port, &command_config);
        COMMAND_CONFIGr_RX_ENAf_SET(command_config, 1);
        ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_config);

        ioerr += READ_COMMAND_CONFIGr(unit, port, &command_config);
        COMMAND_CONFIGr_SW_RESETf_SET(command_config, 0);
        ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_config);

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
#endif /* CDK_CONFIG_INCLUDE_BCM56224_A0 */
