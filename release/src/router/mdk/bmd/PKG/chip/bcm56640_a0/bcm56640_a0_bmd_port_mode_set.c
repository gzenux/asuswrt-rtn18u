#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56640_A0 == 1

/*
 * $Id: bcm56640_a0_bmd_port_mode_set.c,v 1.7 Broadcom SDK $
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

#include <cdk/chip/bcm56640_a0_defs.h>
#include <cdk/arch/xgsm_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56640_a0_bmd.h"
#include "bcm56640_a0_internal.h"

#define DRAIN_WAIT_MSEC                 500

/* Supported HiGig encapsulations */
#define HG_FLAGS        (BMD_PORT_MODE_F_HIGIG | BMD_PORT_MODE_F_HIGIG2)

int 
bcm56640_a0_bmd_port_mode_set(int unit, int port, 
                              bmd_port_mode_t mode, uint32_t flags)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int mac_lb = (flags & BMD_PORT_MODE_F_MAC_LOOPBACK) ? 1 : 0;
    int phy_lb = (flags & BMD_PORT_MODE_F_PHY_LOOPBACK) ? 1 : 0;
    int duplex = 1;
    uint32_t speed = 1000;
    int sp_sel = XMAC_MODE_SPEED_1000;
    int pref_intf = 0;
    int cnt;
    int lport;
    uint32_t pbm, clr_mask;
    uint32_t speed_max;
    EPC_LINK_BMAPm_t epc_link;
    PORT_TXFIFO_PKT_DROP_CTLr_t flush_ctrl;
    PORT_TXFIFO_CELL_CNTr_t cell_cnt;
    XMAC_CTRLr_t xmac_ctrl;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    if (BMD_PORT_PROPERTIES(unit, port) == BMD_PORT_FLEX &&
        mode == bmdPortModeDisabled) {
        /* Unused flex port - just return success */
        return CDK_E_NONE;
    }

    speed_max = bcm56640_a0_port_speed_max(unit, port);

    if (flags & HG_FLAGS) {
        if (speed_max <= 10000) {
            /* HiGig not supported on single lane ports */
            return CDK_E_PARAM;
        }
        pref_intf = BMD_PHY_IF_HIGIG;
    }

    if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
        switch (mode) {
        case bmdPortModeAuto:
        case bmdPortModeDisabled:
            speed = speed_max;
            break;
        case bmdPortMode10000fd:
        case bmdPortMode10000XFI:
        case bmdPortMode10000KR:
            speed = 10000;
            break;
        case bmdPortMode10000SFI:
            speed = 10000;
            pref_intf = BMD_PHY_IF_SFI;
            break;
        case bmdPortMode20000fd:
            speed = 20000;
            break;
        case bmdPortMode40000fd:
            speed = 40000;
            break;
        case bmdPortMode40000KR:
            speed = 40000;
            pref_intf = BMD_PHY_IF_KR;
            break;
        case bmdPortMode40000CR:
            speed = 40000;
            pref_intf = BMD_PHY_IF_CR;
            break;
        case bmdPortMode100000CR:
            speed = 100000;
            pref_intf = BMD_PHY_IF_CR;
            break;
#if BMD_CONFIG_INCLUDE_HIGIG == 1
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
        case bmdPortMode15000fd:
            if (flags & HG_FLAGS) {
                speed = 15000;
            }
            break;
        case bmdPortMode16000fd:
            if (flags & HG_FLAGS) {
                speed = 16000;
            }
            break;
        case bmdPortMode21000fd:
            if (flags & HG_FLAGS) {
                speed = 21000;
            }
            break;
        case bmdPortMode25000fd:
            if (flags & HG_FLAGS) {
                speed = 25000;
            }
            break;
        case bmdPortMode30000fd:
            if (flags & HG_FLAGS) {
                speed = 30000;
            }
            break;
        case bmdPortMode42000fd:
            speed = 42000;
            break;
        case bmdPortMode127000fd:
            speed = 127000;
            break;
#endif
        default:
            break;
        }
    }

    /* If no XAUI mode was selected, check SerDes modes */
    if (speed == 1000) {
        if (speed_max > 10000) {
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
        case bmdPortMode10hd:
            if (port == 37 && !mac_lb) {
                /* Does not work with external copper PHY */
                return CDK_E_PARAM;
            }
            speed = 10;
            sp_sel = XMAC_MODE_SPEED_10;
            break;
        case bmdPortMode100fd:
        case bmdPortMode100hd:
            speed = 100;
            sp_sel = XMAC_MODE_SPEED_100;
            break;
        case bmdPortMode2500fd:
            speed = 2500;
            sp_sel = XMAC_MODE_SPEED_2500;
        case bmdPortMode1000fd:
        case bmdPortMode1000hd:
        case bmdPortModeAuto:
            break;
        case bmdPortModeDisabled:
            break;
        default:
            return CDK_E_PARAM;
        }
    } else {
        sp_sel = XMAC_MODE_SPEED_10000;
    }

    if (speed > speed_max) {
        return CDK_E_PARAM;
    }

    if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_GE) {
        if (speed > 1000) {
            return CDK_E_PARAM;
        }
    } else {
        if (speed < 1000) {
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
        if (lport >= 32) {
            pbm = EPC_LINK_BMAPm_PORT_BITMAP_W1f_GET(epc_link);
            pbm &= ~clr_mask;
            EPC_LINK_BMAPm_PORT_BITMAP_W1f_SET(epc_link, pbm);
        } else {
            pbm = EPC_LINK_BMAPm_PORT_BITMAP_W0f_GET(epc_link);
            pbm &= ~clr_mask;
            EPC_LINK_BMAPm_PORT_BITMAP_W0f_SET(epc_link, pbm);
        }
        ioerr += WRITE_EPC_LINK_BMAPm(unit, 0, epc_link);

        /* Drain all packets from the Tx pipeline */
        ioerr += READ_PORT_TXFIFO_PKT_DROP_CTLr(unit, port, &flush_ctrl);
        PORT_TXFIFO_PKT_DROP_CTLr_DROP_ENf_SET(flush_ctrl, 1);
        ioerr += WRITE_PORT_TXFIFO_PKT_DROP_CTLr(unit, port, flush_ctrl);
        cnt = DRAIN_WAIT_MSEC / 10;
        while (--cnt >= 0) {
            ioerr += READ_PORT_TXFIFO_CELL_CNTr(unit, port, &cell_cnt);
            if (PORT_TXFIFO_CELL_CNTr_GET(cell_cnt) == 0) {
                break;
            }
            BMD_SYS_USLEEP(10000);
        }
        if (cnt < 0) {
            CDK_WARN(("bcm56640_a0_bmd_port_mode_set[%d]: "
                      "drain failed on port %d\n", unit, port));
        }
        PORT_TXFIFO_PKT_DROP_CTLr_DROP_ENf_SET(flush_ctrl, 0);
        ioerr += WRITE_PORT_TXFIFO_PKT_DROP_CTLr(unit, port, flush_ctrl);

#if BMD_CONFIG_INCLUDE_HIGIG == 1
        if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
            bmd_port_mode_t cur_mode;
            uint32_t cur_flags;

            /*
             * If HiGig/Ethernet encapsulation changes, we need 
             * to reinitialize the warpcore.
             */
            rv = bcm56640_a0_bmd_port_mode_get(unit, port, 
                                               &cur_mode, &cur_flags);
            if (CDK_SUCCESS(rv) && 
                ((flags ^ cur_flags) & HG_FLAGS)) {
                if (flags & HG_FLAGS) {
                    BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_HG;
                } else {
                    BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
                }
                rv = bcm56640_a0_warpcore_phy_init(unit, port);
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

    /* Disable MACs (Rx only) */
    ioerr += READ_XMAC_CTRLr(unit, port, &xmac_ctrl);
    XMAC_CTRLr_RX_ENf_SET(xmac_ctrl, 0);
    XMAC_CTRLr_SOFT_RESETf_SET(xmac_ctrl, 1);
    ioerr += WRITE_XMAC_CTRLr(unit, port, xmac_ctrl);

    if (mode == bmdPortModeDisabled) {
        BMD_PORT_STATUS_SET(unit, port, BMD_PST_FORCE_LINK);
    } else {
        int hg, hg2;
        int inst;
        int old_phy_mode, phy_mode;
        int xlgmii_align;
        XMAC_MODEr_t xmac_mode;
        PORT_MODE_REGr_t port_mode;
        PORT_TABm_t port_tab;
        EGR_PORTm_t egr_port;
        EGR_ING_PORTm_t egr_ing_port;
        PORT_CONFIGr_t port_cfg;
        ICONTROL_OPCODE_BITMAPm_t opcode_bmap;
        EGR_VLAN_CONTROL_3r_t vctrl3;
        XMAC_EEE_CTRLr_t xmac_eee_ctrl;

        /* Update PORT mode according to speed */
        phy_mode = PHY_MODE_QUAD;
        if (speed > 20000) {
            phy_mode = PHY_MODE_SINGLE;
        } else if (speed > 10000) {
            phy_mode = PHY_MODE_DUAL;
        }
        inst = bcm56640_a0_xport_inst(unit, port);
        ioerr += READ_PORT_MODE_REGr(unit, &port_mode, port);
        if (inst == 2) {
            old_phy_mode = PORT_MODE_REGr_XPORT2_PHY_PORT_MODEf_GET(port_mode);
            PORT_MODE_REGr_XPORT2_PHY_PORT_MODEf_SET(port_mode, phy_mode);
        } else if (inst == 1) {
            old_phy_mode = PORT_MODE_REGr_XPORT1_PHY_PORT_MODEf_GET(port_mode);
            PORT_MODE_REGr_XPORT1_PHY_PORT_MODEf_SET(port_mode, phy_mode);
        } else {
            old_phy_mode = PORT_MODE_REGr_XPORT0_PHY_PORT_MODEf_GET(port_mode);
            PORT_MODE_REGr_XPORT0_PHY_PORT_MODEf_SET(port_mode, phy_mode);
        }

        /* Force a MAC reset if MAC loopback on multi-lane port */
        if ((flags & BMD_PORT_MODE_F_INTERNAL) == 0) {
            if (mac_lb && speed > 10000) {
                old_phy_mode = -1;
            }
        }

        /* Reset and initialize MAC if core mode changed */
        if (phy_mode != old_phy_mode) {
            bcm56640_a0_xmac_reset_set(unit, port, 1);
            ioerr += WRITE_PORT_MODE_REGr(unit, port_mode, port);
            bcm56640_a0_xmac_reset_set(unit, port, 0);
            ioerr += bcm56640_a0_xport_init(unit, port);
            /* Reinitialize PORT neighbor if 2-lane mode */
            if (speed_max > 10000 && speed_max <= 20000) {
                int np = port + 2;
                if (XPORT_SUBPORT(port) == 2) {
                    np = port - 2;
                }
                /* Align PHY speed to new core mode */
                if (CDK_SUCCESS(rv)) {
                    rv = bcm56640_a0_xport_init(unit, np);
                }
                if (CDK_SUCCESS(rv)) {
                    rv = bmd_phy_speed_set(unit, np, speed);
                }
            }
        }

        /* Set encapsulation and alignment */
        hg = hg2 = 0;
        xlgmii_align = 0;
        if (speed >= 30000) {
            xlgmii_align = 1;
        }
#if BMD_CONFIG_INCLUDE_HIGIG == 1
        if (flags & HG_FLAGS) {
            hg = 1;
            xlgmii_align = 0;
            if (flags & BMD_PORT_MODE_F_HIGIG2) {
                hg2 = 1;
            }
        }
#endif
        ioerr += READ_XMAC_MODEr(unit, port, &xmac_mode);
        ioerr += READ_PORT_TABm(unit, lport, &port_tab);
        ioerr += READ_EGR_PORTm(unit, lport, &egr_port);
        ioerr += READ_EGR_ING_PORTm(unit, lport, &egr_ing_port);
        ioerr += READ_PORT_CONFIGr(unit, port, &port_cfg);
        /* MAC speed */
        XMAC_MODEr_SPEED_MODEf_SET(xmac_mode, sp_sel);
        /* MAC header mode */
        XMAC_MODEr_HDR_MODEf_SET(xmac_mode, hg2 ? 2 : hg);
        /* Set IEEE vs HiGig */        
        PORT_TABm_PORT_TYPEf_SET(port_tab, hg);
        EGR_PORTm_PORT_TYPEf_SET(egr_port, hg);
        EGR_ING_PORTm_PORT_TYPEf_SET(egr_ing_port, hg);
        PORT_CONFIGr_HIGIG_MODEf_SET(port_cfg, hg);
        ICONTROL_OPCODE_BITMAPm_SET(opcode_bmap, 0, hg ? 0x1 : 0x0);
        /* Set HiGig vs. HiGig2 */
        PORT_TABm_HIGIG2f_SET(port_tab, hg2);
        EGR_PORTm_HIGIG2f_SET(egr_port, hg2);
        EGR_ING_PORTm_HIGIG2f_SET(egr_ing_port, hg2);
        PORT_CONFIGr_HIGIG2_MODEf_SET(port_cfg, hg2);
        ioerr += WRITE_XMAC_MODEr(unit, port, xmac_mode);
        ioerr += WRITE_PORT_TABm(unit, lport, port_tab);
        ioerr += WRITE_EGR_PORTm(unit, lport, egr_port);
        ioerr += WRITE_EGR_ING_PORTm(unit, lport, egr_ing_port);
        ioerr += WRITE_PORT_CONFIGr(unit, port, port_cfg);
        ioerr += WRITE_ICONTROL_OPCODE_BITMAPm(unit, lport, opcode_bmap);

        /* HiGig ports require special egress tag action */
        ioerr += READ_EGR_VLAN_CONTROL_3r(unit, lport, &vctrl3);
        EGR_VLAN_CONTROL_3r_TAG_ACTION_PROFILE_PTRf_SET(vctrl3, hg ? 1 : 0);
        ioerr += WRITE_EGR_VLAN_CONTROL_3r(unit, lport, vctrl3);

        /* Configure 10G MAC */
        ioerr += READ_XMAC_CTRLr(unit, port, &xmac_ctrl);
        XMAC_CTRLr_LINE_LOCAL_LPBKf_SET(xmac_ctrl, mac_lb);
        XMAC_CTRLr_XLGMII_ALIGN_ENBf_SET(xmac_ctrl, xlgmii_align);
        XMAC_CTRLr_RX_ENf_SET(xmac_ctrl, 1);
        XMAC_CTRLr_SOFT_RESETf_SET(xmac_ctrl, 0);
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

        if (mac_lb || phy_lb) {
            BMD_PORT_STATUS_SET(unit, port, BMD_PST_LINK_UP | BMD_PST_FORCE_LINK);
        } else {
            BMD_PORT_STATUS_CLR(unit, port, BMD_PST_FORCE_LINK);
        }

        /* MAC loopback may require adjustment to PHY configuration */
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_notify_mac_loopback(unit, port, mac_lb);
        }

        /* Let PHYs know that the MAC has been enabled */
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_notify_mac_enable(unit, port, 1);
        }
    }

    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56640_A0 */

