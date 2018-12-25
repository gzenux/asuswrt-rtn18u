#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53324_A0 == 1

/*
 * $Id: bcm53324_a0_bmd_port_mode_set.c,v 1.7 Broadcom SDK $
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

#include <cdk/chip/bcm53324_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm53324_a0_bmd.h"
#include "bcm53324_a0_internal.h"

#define DRAIN_WAIT_MSEC                 500

int
bcm53324_a0_bmd_port_mode_set(int unit, int port, 
                              bmd_port_mode_t mode, uint32_t flags)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int mac_lb = (flags & BMD_PORT_MODE_F_MAC_LOOPBACK) ? 1 : 0;
    int phy_lb = (flags & BMD_PORT_MODE_F_PHY_LOOPBACK) ? 1 : 0;
    int duplex = 1;
    int speed = 1000;
    int sp_sel = COMMAND_CONFIG_SPEED_1000;
    int cnt;
    uint32_t pbmp;
    EPC_LINK_BMAPr_t epc_link;
    FLUSH_CONTROLr_t flush_ctrl;
    COSLCCOUNTr_t lccount;
    COMMAND_CONFIGr_t command_config;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

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
    case bmdPortModeAuto:
        break;
    case bmdPortModeDisabled:
        break;
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
            CDK_WARN(("bcm53324_a0_bmd_port_mode_set[%d]: "
                      "drain failed on port %d\n", unit, port));
        }
        FLUSH_CONTROLr_FLUSHf_SET(flush_ctrl, 0);
        ioerr += WRITE_FLUSH_CONTROLr(unit, port, flush_ctrl);
    }

    /* MAC loopback has no clock, so we also set PHY loopback */
    if (mac_lb) {
        flags |= BMD_PORT_MODE_F_PHY_LOOPBACK;
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
        UMAC_EEE_CTRLr_t umac_eee_ctrl;
            
        /* Configure EEE */
        ioerr += READ_UMAC_EEE_CTRLr(unit, port, &umac_eee_ctrl);            
        UMAC_EEE_CTRLr_EEE_ENf_SET(umac_eee_ctrl, 0);
        ioerr += WRITE_UMAC_EEE_CTRLr(unit, port, umac_eee_ctrl);                            

        if (flags & BMD_PORT_MODE_F_EEE) {
            /* Enable IEEE 802.3az EEE */
            UMAC_EEE_CTRLr_EEE_ENf_SET(umac_eee_ctrl, 1);
            ioerr += WRITE_UMAC_EEE_CTRLr(unit, port, umac_eee_ctrl);                            
        }

        /* Enable MAC TX / RX */
        ioerr += READ_COMMAND_CONFIGr(unit, port, &command_config);
        COMMAND_CONFIGr_SW_RESETf_SET(command_config, 1);
        ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_config);

        ioerr += READ_COMMAND_CONFIGr(unit, port, &command_config);
        COMMAND_CONFIGr_RX_ENAf_SET(command_config, 1);
        COMMAND_CONFIGr_TX_ENAf_SET(command_config, 1);
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
#endif /* CDK_CONFIG_INCLUDE_BCM53324_A0 */
