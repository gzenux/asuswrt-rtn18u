#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56440_A0 == 1

/*
 * $Id: bcm56440_a0_bmd_port_mode_set.c,v 1.14 Broadcom SDK $
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

#include <cdk/chip/bcm56440_a0_defs.h>
#include <cdk/arch/xgsm_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56440_a0_bmd.h"
#include "bcm56440_a0_internal.h"

#define DRAIN_WAIT_MSEC                 500

/* Supported HiGig encapsulations */
#define HG_FLAGS  (BMD_PORT_MODE_F_HIGIG | BMD_PORT_MODE_F_HIGIG2 | BMD_PORT_MODE_F_HGLITE)


uint32_t
bcm56440_a0_port_speed_max(int unit, int port)
{
    /* Use per-port config if available */
    if (CDK_NUM_PORT_CONFIGS(unit) != 0) {
        return CDK_PORT_CONFIG_SPEED_MAX(unit, port);
    }
    /* Default port speeds for fixed configurations */
    if (port >= 1 && port <= 24) {
        return 1000;
    }
    if (port >= 25 && port <= 28) {
        return 13000;
    }
    if (port >= 29 && port <= 34) {
        return 2500;
    }

    if (port == 35) { /* loopback port*/
        return 2500;
    }
    return 1000;
}

int
bcm56440_a0_bmd_port_mode_set(int unit, int port, 
                              bmd_port_mode_t mode, uint32_t flags)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int mac_lb = (flags & BMD_PORT_MODE_F_MAC_LOOPBACK) ? 1 : 0;
    int phy_lb = (flags & BMD_PORT_MODE_F_PHY_LOOPBACK) ? 1 : 0;
    int duplex = 1;
    uint32_t speed = 1000;
    int sp_sel = COMMAND_CONFIG_SPEED_1000;
    int pref_intf = 0;
    int lport;
    int hglite_port = 0;
    int quad_port_25g = 0;
    int quad_port_ge = 0;
    uint32_t pbm, clr_mask;
    int xmac_speed_mode;
    uint32_t speed_max;
    COMMAND_CONFIGr_t command_cfg;
    EPC_LINK_BMAPm_t epc_link;
    FLUSH_CONTROLr_t flush_ctrl;
    TOP_SWITCH_FEATURE_ENABLE_2r_t feature_enable;
    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    if ((port == 1) && (mac_lb || phy_lb)) {
        /* Check if CES enabled. if so, skip port 1 */ 
        ioerr += READ_TOP_SWITCH_FEATURE_ENABLE_2r(unit, &feature_enable);
        if (TOP_SWITCH_FEATURE_ENABLE_2r_BOND_CES_ENABLEf_GET(feature_enable)) {
            return CDK_E_PARAM;  
        }
    }
    if (port >= 25 && port <= 26) {
        if ((CDK_XGSM_FLAGS(unit) & CHIP_FLAG_HGL25) &&
            (!(CDK_XGSM_FLAGS(unit) & CHIP_FLAG_HG13))) {
            hglite_port = 1;
        }
    }
    if (port >= 27 && port <= 34) {
        if (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_HGL25) {
            hglite_port = 1;
        }
        if (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_EIGHTX25G_MODE) {
            quad_port_25g = 1;
        }  
        if (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX6_MODE) {
            quad_port_ge = 1;
            if ((port == 30) || (port == 31)) {
                quad_port_ge = 0;
            } 
        }
    }
    xmac_speed_mode = COMMAND_CONFIG_SPEED_10000;
    speed_max = bcm56440_a0_port_speed_max(unit, port);

    if (BMD_PORT_PROPERTIES(unit, port) & ((BMD_PORT_HG) | (BMD_PORT_XE))) {
        switch (mode) {
        case bmdPortModeAuto:
        case bmdPortModeDisabled:
            if ((hglite_port) || (quad_port_25g)) {
                speed = 2500;
                sp_sel = COMMAND_CONFIG_SPEED_2500;
                xmac_speed_mode = COMMAND_CONFIG_SPEED_2500;
                BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
            } else if (quad_port_ge == 1) { 
                speed = 1000;
                sp_sel = COMMAND_CONFIG_SPEED_1000;
                xmac_speed_mode = COMMAND_CONFIG_SPEED_1000;
                BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
            } else if (flags & HG_FLAGS) {
                speed = speed_max;
                BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_HG;
            }
            break;
        case bmdPortMode2500fd:
            if (hglite_port) {
                if ((flags & BMD_PORT_MODE_F_HIGIG) ||
                   (flags & BMD_PORT_MODE_F_HIGIG2)) {
                    return CDK_E_PARAM;
                }
                speed = 2500;
                sp_sel = COMMAND_CONFIG_SPEED_2500;
                xmac_speed_mode = COMMAND_CONFIG_SPEED_2500;
                if (quad_port_ge == 1) { 
                    speed = 1000;
                    sp_sel = COMMAND_CONFIG_SPEED_1000;
                    xmac_speed_mode = COMMAND_CONFIG_SPEED_1000;
                }
                BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
            }
            break;
        case bmdPortMode10000fd:
            if ((hglite_port == 1) || (quad_port_ge == 1) || 
                                      (quad_port_25g == 1)) {
                break;
            } 
            speed = 10000;
            BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
            xmac_speed_mode = COMMAND_CONFIG_SPEED_10000;
            break;
#if BMD_CONFIG_INCLUDE_HIGIG == 1
        case bmdPortMode12000fd:
            if ((hglite_port == 1) || (quad_port_ge == 1) || 
                                      (quad_port_25g == 1)) {
                break;
            } else if (flags & HG_FLAGS) {
                speed = 12000;
                BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_HG;
            }
            break;
        case bmdPortMode13000fd:
            if ((hglite_port == 1) || (quad_port_ge == 1) || 
                                      (quad_port_25g == 1)) {
                break;
            } else if (flags & HG_FLAGS) {
                speed = 13000;
                BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_HG;
            }
            break;
#endif
        default:
            break;
        }
    }
    /* If no XAUI mode was selected, check SerDes modes */
    if (speed == 1000) {
        if ((flags & HG_FLAGS) && (hglite_port == 0)) {
            return CDK_E_PARAM;
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
            if (hglite_port == 1) {
                return CDK_E_PARAM;
            } 
            if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_FE) {
                return CDK_E_PARAM;
            }
            speed = 10;
            sp_sel = COMMAND_CONFIG_SPEED_10;
            if (BMD_PORT_PROPERTIES(unit, port) & ((BMD_PORT_HG) | (BMD_PORT_XE))) {
                BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
                xmac_speed_mode = COMMAND_CONFIG_SPEED_10;
            }
            break;
        case bmdPortMode100fd:
            if (hglite_port == 1) {
                return CDK_E_PARAM;
            } 
            speed = 100;
            sp_sel = COMMAND_CONFIG_SPEED_100;
            if (BMD_PORT_PROPERTIES(unit, port) & ((BMD_PORT_HG) | (BMD_PORT_XE))) {
                BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
                xmac_speed_mode = COMMAND_CONFIG_SPEED_100;
            }
            break;
        case bmdPortMode1000fd:
            speed = 1000;
            if (BMD_PORT_PROPERTIES(unit, port) & ((BMD_PORT_HG) | (BMD_PORT_XE))) {
                BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
                xmac_speed_mode = COMMAND_CONFIG_SPEED_1000;
            }
            if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_FE) {
                return CDK_E_PARAM;
            }
            if ((hglite_port == 1) && 
                  ((flags & BMD_PORT_MODE_F_HIGIG) ||
                   (flags & BMD_PORT_MODE_F_HIGIG2))) {
                return CDK_E_PARAM;
            }
            break;
        case bmdPortMode2500fd:
            speed = 2500;
            sp_sel = COMMAND_CONFIG_SPEED_2500;
            if (BMD_PORT_PROPERTIES(unit, port) & ((BMD_PORT_HG) | (BMD_PORT_XE))) {
                BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
                xmac_speed_mode = COMMAND_CONFIG_SPEED_2500;
            }
            if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_FE) {
                return CDK_E_PARAM;
            }
            if ((hglite_port == 1) && 
                  ((flags & BMD_PORT_MODE_F_HIGIG) ||
                   (flags & BMD_PORT_MODE_F_HIGIG2))) {
                return CDK_E_PARAM;
            }
            if (quad_port_ge == 1) { 
                return CDK_E_PARAM;
            }   
            break;
        case bmdPortModeAuto:
            if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_FE) {
                speed = 100;
                sp_sel = COMMAND_CONFIG_SPEED_100;
            }
            break;
        case bmdPortModeDisabled:
            break;
        default:
            return CDK_E_PARAM;
        }
    }

    if (speed > speed_max) {
        return CDK_E_PARAM;
    }

    if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_GE) {
        if (speed > 1000) {
            return CDK_E_PARAM;
        }
    } else if (flags & HG_FLAGS) {
        if ((speed <= 10000) && ((hglite_port == 0) && 
               (quad_port_ge == 0) && (quad_port_25g == 0))) {  
            return CDK_E_PARAM;
        }
    }

    lport = P2L(unit, port);

    if ((flags & BMD_PORT_MODE_F_INTERNAL) == 0) {

        /* Set preferred line interface */
        bmd_phy_line_interface_set(unit, port, pref_intf);

        /* Stop CPU and MMU from scheduling packets to the port */
        BMD_PORT_STATUS_CLR(unit, port, BMD_PST_LINK_UP);
        ioerr += READ_EPC_LINK_BMAPm(unit, 0, &epc_link);
        clr_mask = LSHIFT32(1, lport & 0x1f);
        pbm = EPC_LINK_BMAPm_PORT_BITMAP_W0f_GET(epc_link);
        pbm &= ~clr_mask;
        EPC_LINK_BMAPm_PORT_BITMAP_W0f_SET(epc_link, pbm);
        ioerr += WRITE_EPC_LINK_BMAPm(unit, 0, epc_link);

        /* Drain all packets from the Tx pipeline */
        if (!(BMD_PORT_PROPERTIES(unit, port) & ((BMD_PORT_HG) | (BMD_PORT_XE)))) {
           ioerr += READ_FLUSH_CONTROLr(unit, port, &flush_ctrl);
           FLUSH_CONTROLr_FLUSHf_SET(flush_ctrl, 1);
           ioerr += WRITE_FLUSH_CONTROLr(unit, port, flush_ctrl);
           FLUSH_CONTROLr_FLUSHf_SET(flush_ctrl, 0);
           ioerr += WRITE_FLUSH_CONTROLr(unit, port, flush_ctrl);
        }
#if BMD_CONFIG_INCLUDE_HIGIG == 1
        if (BMD_PORT_PROPERTIES(unit, port) & ((BMD_PORT_HG) | (BMD_PORT_XE))) {
            bmd_port_mode_t cur_mode;
            uint32_t cur_flags;

            /*
             * If HiGig/Ethernet encapsulation changes, we need 
             * to reinitialize the warpcore.
             */
            rv = bcm56440_a0_bmd_port_mode_get(unit, port, 
                                               &cur_mode, &cur_flags);
            if (CDK_SUCCESS(rv) && 
                ((flags ^ cur_flags) & HG_FLAGS)) {
                if (flags & HG_FLAGS) {
                    BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_HG;
                    if (hglite_port == 1) {
                        BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
                    }
                } else {
                    BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
                }
                rv = bcm56440_a0_xport_reset(unit, port);
                if (CDK_SUCCESS(rv)) {
                    rv = bcm56440_a0_xport_init(unit, port);
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

    /* Reset the MAC */
    if (!(BMD_PORT_PROPERTIES(unit, port) & ((BMD_PORT_HG) | (BMD_PORT_XE)))) {
        ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
        COMMAND_CONFIGr_SW_RESETf_SET(command_cfg, 1);
        ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);
    }
    /* Disable MACs (Rx only) */
    if (BMD_PORT_PROPERTIES(unit, port) & ((BMD_PORT_HG) | (BMD_PORT_XE))) {
        XMAC_CTRLr_t mac_ctrl;

        ioerr += READ_XMAC_CTRLr(unit, port, &mac_ctrl);
        XMAC_CTRLr_RX_ENf_SET(mac_ctrl, 0);
        XMAC_CTRLr_SOFT_RESETf_SET(mac_ctrl, 0);
        ioerr += WRITE_XMAC_CTRLr(unit, port, mac_ctrl);
    }
    if (!(BMD_PORT_PROPERTIES(unit, port) & ((BMD_PORT_HG) | (BMD_PORT_XE)))) {
        ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
        COMMAND_CONFIGr_RX_ENAf_SET(command_cfg, 0);
        ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);
    }

    if (mode == bmdPortModeDisabled) {
        BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_LINK);
    } else {
        if (BMD_PORT_PROPERTIES(unit, port) & ((BMD_PORT_HG) | (BMD_PORT_XE))) {
            int hg, hg2;
            XMAC_CTRLr_t xmac_ctrl;
            XMAC_MODEr_t xmac_mode;
            XPORT_MODE_REGr_t xlport_mode;
            PORT_TABm_t port_tab;
            EGR_PORTm_t egr_port;
            EGR_ING_PORTm_t egr_ing_port;
            XPORT_CONFIGr_t xlport_cfg;
            ICONTROL_OPCODE_BITMAPm_t opcode_bmap;
            EGR_VLAN_CONTROL_3r_t vctrl3;
            XMAC_EEE_CTRLr_t xmac_eee_ctrl;
            GPORT_RSV_MASKr_t gport_rsv_mask;
            XPORT_PORT_ENABLEr_t   xport_enable;
            XMAC_RX_CTRLr_t xmac_rx_ctrl;
            XMAC_TX_CTRLr_t xmac_tx_ctrl;

            /* Update XLPORT mode according to speed */
            ioerr += READ_XPORT_MODE_REGr(unit, &xlport_mode, port);
            if (speed < 10000) {
               XPORT_MODE_REGr_PHY_PORT_MODEf_SET(xlport_mode, 0x2);
               XPORT_MODE_REGr_PORT_GMII_MII_ENABLEf_SET(xlport_mode, 1); 
            } else {
               XPORT_MODE_REGr_PHY_PORT_MODEf_SET(xlport_mode, 0x0);
               XPORT_MODE_REGr_PORT_GMII_MII_ENABLEf_SET(xlport_mode, 0); 
            }  
            WRITE_XPORT_MODE_REGr(unit, xlport_mode, port);
            /* Fixup packet purge filtering */
            if (hglite_port == 1) {
                GPORT_RSV_MASKr_SET(gport_rsv_mask, 0x58);
            } else {
                GPORT_RSV_MASKr_SET(gport_rsv_mask, 0x78);
            }
            WRITE_GPORT_RSV_MASKr(unit, gport_rsv_mask, -1);

            READ_XPORT_PORT_ENABLEr(unit, &xport_enable, port);
            XPORT_PORT_ENABLEr_PORT0f_SET(xport_enable, 1);

            /* Set encapsulation */
            hg = hg2 = 0;
#if BMD_CONFIG_INCLUDE_HIGIG == 1
            if (flags & HG_FLAGS) {
                hg = 1;
                if ((flags & BMD_PORT_MODE_F_HIGIG2) || (flags & BMD_PORT_MODE_F_HGLITE)) {
                    hg2 = 1;
                }
            }
#endif
            ioerr += READ_XMAC_MODEr(unit, port, &xmac_mode);
            ioerr += READ_PORT_TABm(unit, port, &port_tab);
            ioerr += READ_EGR_PORTm(unit, port, &egr_port);
            ioerr += READ_EGR_ING_PORTm(unit, port, &egr_ing_port);
            ioerr += READ_XPORT_CONFIGr(unit, port, &xlport_cfg);
            /* MAC header mode */
            XMAC_MODEr_SPEED_MODEf_SET(xmac_mode, xmac_speed_mode);
            if (speed < 10000) {
                XMAC_MODEr_HDR_MODEf_SET(xmac_mode, 0);
                if ((flags & BMD_PORT_MODE_F_HGLITE) && (hglite_port == 1)) {
                    XMAC_MODEr_HDR_MODEf_SET(xmac_mode, 2);
                }
            } else {
                XMAC_MODEr_HDR_MODEf_SET(xmac_mode, hg2 ? 2 : hg);
            }
            /* Set IEEE vs HiGig */        
            PORT_TABm_PORT_TYPEf_SET(port_tab, hg);
            EGR_PORTm_PORT_TYPEf_SET(egr_port, hg);
            EGR_ING_PORTm_PORT_TYPEf_SET(egr_ing_port, hg);
            XPORT_CONFIGr_HIGIG_MODEf_SET(xlport_cfg, hg);
            ICONTROL_OPCODE_BITMAPm_SET(opcode_bmap, 0, hg ? 0x1 : 0x0);
            ICONTROL_OPCODE_BITMAPm_SET(opcode_bmap, 1, 0x0);
            /* Set HiGig vs. HiGig2 */
            PORT_TABm_HIGIG2f_SET(port_tab, hg2);
            EGR_PORTm_HIGIG2f_SET(egr_port, hg2);
            EGR_ING_PORTm_HIGIG2f_SET(egr_ing_port, hg2);
            XPORT_CONFIGr_HIGIG2_MODEf_SET(xlport_cfg, hg2);
            ioerr += WRITE_XMAC_MODEr(unit, port, xmac_mode);
            ioerr += WRITE_PORT_TABm(unit, port, port_tab);
            ioerr += WRITE_EGR_PORTm(unit, port, egr_port);
            ioerr += WRITE_EGR_ING_PORTm(unit, port, egr_ing_port);
            ioerr += WRITE_XPORT_CONFIGr(unit, port, xlport_cfg);
            ioerr += WRITE_ICONTROL_OPCODE_BITMAPm(unit, port, opcode_bmap);

            /* HiGig ports require special egress tag action */
            ioerr += READ_EGR_VLAN_CONTROL_3r(unit, port, &vctrl3);
            EGR_VLAN_CONTROL_3r_TAG_ACTION_PROFILE_PTRf_SET(vctrl3, hg ? 1 : 0);
            ioerr += WRITE_EGR_VLAN_CONTROL_3r(unit, port, vctrl3);

            /* Disable Strip CRC */
            ioerr += READ_XMAC_RX_CTRLr(unit, port, &xmac_rx_ctrl);
            XMAC_RX_CTRLr_STRIP_CRCf_SET(xmac_rx_ctrl, 0);
            ioerr += WRITE_XMAC_RX_CTRLr(unit, port, xmac_rx_ctrl);
            ioerr += READ_XMAC_TX_CTRLr(unit, port, &xmac_tx_ctrl);
            XMAC_TX_CTRLr_CRC_MODEf_SET(xmac_tx_ctrl, 0x2);
            ioerr += WRITE_XMAC_TX_CTRLr(unit, port, xmac_tx_ctrl);

            /* Configure 10G MAC */
            ioerr += READ_XMAC_CTRLr(unit, port, &xmac_ctrl);
            XMAC_CTRLr_LINE_LOCAL_LPBKf_SET(xmac_ctrl, mac_lb);
            XMAC_CTRLr_XLGMII_ALIGN_ENBf_SET(xmac_ctrl, (speed >= 30000) ? 1 : 0);
            if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_GE | BMD_PORT_FE)) {
                XMAC_CTRLr_XGMII_IPG_CHECK_DISABLEf_SET(xmac_ctrl, 1);
            } else {
                XMAC_CTRLr_XGMII_IPG_CHECK_DISABLEf_SET(xmac_ctrl, 0);
                XMAC_CTRLr_LOCAL_LPBK_LEAK_ENBf_SET(xmac_ctrl, 1);
            }
            XMAC_CTRLr_RX_ENf_SET(xmac_ctrl, 1);
            XMAC_CTRLr_TX_ENf_SET(xmac_ctrl, 1);
            ioerr += WRITE_XMAC_CTRLr(unit, port, xmac_ctrl);
            
            /* Configure EEE */
            ioerr += READ_XMAC_EEE_CTRLr(unit, port, &xmac_eee_ctrl);            
            XMAC_EEE_CTRLr_EEE_ENf_SET(xmac_eee_ctrl, 0);
            ioerr += WRITE_XMAC_EEE_CTRLr(unit, port, xmac_eee_ctrl);                            
            if (flags & BMD_PORT_MODE_F_EEE) {
                /* Enable IEEE 802.3az EEE */
                XMAC_EEE_CTRLr_EEE_ENf_SET(xmac_eee_ctrl, 1);
                ioerr += WRITE_XMAC_EEE_CTRLr(unit, port, xmac_eee_ctrl);                            
            }
        }
        if ((speed < 10000) &&  (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_GE | BMD_PORT_FE))) {
            /* Set speed and duplex */
            ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
            COMMAND_CONFIGr_ETH_SPEEDf_SET(command_cfg, sp_sel);
            COMMAND_CONFIGr_HD_ENAf_SET(command_cfg, !duplex);
            ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);

            /* Set MAC loopback mode */
            ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
            COMMAND_CONFIGr_LOOP_ENAf_SET(command_cfg, mac_lb);
            ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);

            /* Enable MAC */
            ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
            COMMAND_CONFIGr_RX_ENAf_SET(command_cfg, 1);
            COMMAND_CONFIGr_TX_ENAf_SET(command_cfg, 1);
            COMMAND_CONFIGr_CRC_FWDf_SET(command_cfg, 1);
            COMMAND_CONFIGr_PAD_ENf_SET(command_cfg, 1);
            ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);

            /* Bring the MAC out of reset */
            ioerr += READ_COMMAND_CONFIGr(unit, port, &command_cfg);
            COMMAND_CONFIGr_SW_RESETf_SET(command_cfg, 0);
            ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_cfg);
        }

        if (mac_lb || phy_lb) {
            BMD_PORT_STATUS_SET(unit, port, BMD_PST_LINK_UP | BMD_PST_FORCE_LINK);
            ioerr += READ_EPC_LINK_BMAPm(unit, 0, &epc_link);
            epc_link.epc_link_bmap[0]|= LSHIFT32(1, lport & 0x1f);
            ioerr += WRITE_EPC_LINK_BMAPm(unit, 0, epc_link);
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
#endif /* CDK_CONFIG_INCLUDE_BCM56440_A0 */
