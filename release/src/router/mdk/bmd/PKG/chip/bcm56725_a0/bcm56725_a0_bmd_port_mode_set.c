#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56725_A0 == 1

/*
 * $Id: bcm56725_a0_bmd_port_mode_set.c,v 1.10 Broadcom SDK $
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

#include <cdk/chip/bcm56725_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56725_a0_bmd.h"
#include "bcm56725_a0_internal.h"

#define DRAIN_WAIT_MSEC                 500

/* Supported HiGig encapsulations */
#define HG_FLAGS        (BMD_PORT_MODE_F_HIGIG | BMD_PORT_MODE_F_HIGIG2)

int
bcm56725_a0_bmd_port_mode_set(int unit, int port, 
                              bmd_port_mode_t mode, uint32_t flags)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int mac_lb = (flags & BMD_PORT_MODE_F_MAC_LOOPBACK) ? 1 : 0;
    int phy_lb = (flags & BMD_PORT_MODE_F_PHY_LOOPBACK) ? 1 : 0;
    int duplex = 1;
    int speed = 1000;
    int hg2;
    int cnt;
    uint32_t pbmp;
    EPC_LINK_BMAPr_t epc_link;
    FLUSH_CONTROLr_t flush_ctrl;
    OP_PORT_TOTAL_COUNTr_t cell_cnt;
    MAC_CTRLr_t mac_ctrl;
    MAC_TXCTRLr_t txctrl;
    MAC_RXCTRLr_t rxctrl;
    PORT_TABm_t port_tab;
    EGR_PORTr_t egr_port;
    XPORT_CONFIGr_t xport_cfg;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    /* Higig mode only */
    if ((flags & HG_FLAGS) == 0) {
        return CDK_E_PARAM;
    }

    switch (mode) {
    case bmdPortMode10000fd:
    case bmdPortModeAuto:
    case bmdPortModeDisabled:
        speed = 10000;
        break;
    case bmdPortMode12000fd:
        speed = 12000;
        break;
    case bmdPortMode13000fd:
        speed = 13000;
        break;
    case bmdPortMode16000fd:
        speed = 16000;
        break;
    case bmdPortMode20000fd:
        speed = 20000;
        break;
    case bmdPortMode21000fd:
        speed = 21000;
        break;
    default:
        return CDK_E_PARAM;
    }

    if (speed > bcm56725_a0_port_speed_max(unit, port)) {
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
            ioerr += READ_OP_PORT_TOTAL_COUNTr(unit, port, &cell_cnt);
            if (OP_PORT_TOTAL_COUNTr_GET(cell_cnt) == 0) {
                break;
            }
            BMD_SYS_USLEEP(10000);
        }
        if (cnt < 0) {
            CDK_WARN(("bcm56725_a0_bmd_port_mode_set[%d]: "
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

    /* Disable MAC (Rx only) */
    ioerr += READ_MAC_CTRLr(unit, port, &mac_ctrl);
    MAC_CTRLr_RXENf_SET(mac_ctrl, 0);
    ioerr += WRITE_MAC_CTRLr(unit, port, mac_ctrl);

    if (mode == bmdPortModeDisabled) {
        BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_LINK);
    } else {
        /* Set HiGig vs. HiGig2 */
        hg2 = (flags & BMD_PORT_MODE_F_HIGIG2) ? 1 : 0;

        ioerr += READ_XPORT_CONFIGr(unit, port, &xport_cfg);
        ioerr += READ_MAC_TXCTRLr(unit, port, &txctrl);
        ioerr += READ_MAC_RXCTRLr(unit, port, &rxctrl);
        ioerr += READ_PORT_TABm(unit, port, &port_tab);
        ioerr += READ_EGR_PORTr(unit, port, &egr_port);
        XPORT_CONFIGr_HIGIG_MODEf_SET(xport_cfg, 1);
        XPORT_CONFIGr_HIGIG2_MODEf_SET(xport_cfg, hg2);
        MAC_TXCTRLr_HDRMODEf_SET(txctrl, 1);
        MAC_TXCTRLr_HIGIG2MODEf_SET(txctrl, hg2);
        MAC_RXCTRLr_HDRMODEf_SET(rxctrl, 1);
        MAC_RXCTRLr_HIGIG2MODEf_SET(rxctrl, hg2);
        PORT_TABm_HIGIG_PACKETf_SET(port_tab, 1);
        PORT_TABm_HIGIG2f_SET(port_tab, hg2);
        EGR_PORTr_HIGIG_PACKETf_SET(egr_port, 1);
        EGR_PORTr_HIGIG2f_SET(egr_port, hg2);
        ioerr += WRITE_XPORT_CONFIGr(unit, port, xport_cfg);
        ioerr += WRITE_MAC_TXCTRLr(unit, port, txctrl);
        ioerr += WRITE_MAC_RXCTRLr(unit, port, rxctrl);
        ioerr += WRITE_PORT_TABm(unit, port, port_tab);
        ioerr += WRITE_EGR_PORTr(unit, port, egr_port);

        ioerr += READ_MAC_CTRLr(unit, port, &mac_ctrl);

        /* Enable MAC */
        MAC_CTRLr_RXENf_SET(mac_ctrl, 1);

        /* Configyre loopback mode */
        MAC_CTRLr_LCLLOOPf_SET(mac_ctrl, mac_lb);
        ioerr += WRITE_MAC_CTRLr(unit, port, mac_ctrl);

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
#endif /* CDK_CONFIG_INCLUDE_BCM56725_A0 */
