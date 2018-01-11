#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56224_A0 == 1

/*
 * $Id: bcm56224_a0_bmd_init.c,v 1.11 Broadcom SDK $
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

#include <bmdi/arch/xgs_dma.h>

#include <cdk/chip/bcm56224_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56224_a0_bmd.h"
#include "bcm56224_a0_internal.h"

#define PIPE_RESET_TIMEOUT_MSEC         5

static int
_port_init(int unit, int port)
{
    int ioerr = 0;
    EGR_ENABLEr_t egr_enable;
    EGR_PORTr_t egr_port;
    ING_EN_EFILTER_BITMAPr_t ing_en_efilter_bitmap;
    ING_OUTER_TPIDr_t ing_outer_tpid;
    EGR_VLAN_CONTROL_1r_t egr_vlan_control_1;
    PORT_TABm_t port_tab;
    uint32_t pbmp;

    /* Default port TPID */
    ioerr += READ_ING_OUTER_TPIDr(unit, 0, &ing_outer_tpid);
    ING_OUTER_TPIDr_TPIDf_SET(ing_outer_tpid, 0x8100);
    ioerr += WRITE_ING_OUTER_TPIDr(unit, 0, ing_outer_tpid);
    ioerr += READ_EGR_VLAN_CONTROL_1r(unit, port, &egr_vlan_control_1);
    EGR_VLAN_CONTROL_1r_OUTER_TPID_INDEXf_SET(egr_vlan_control_1, 0);
    EGR_VLAN_CONTROL_1r_OUTER_TPID_SELf_SET(egr_vlan_control_1, 0);
    ioerr += WRITE_EGR_VLAN_CONTROL_1r(unit, port, egr_vlan_control_1);

    /* Default port VLAN */
    PORT_TABm_CLR(port_tab);
    PORT_TABm_PORT_VIDf_SET(port_tab, 1);
    PORT_TABm_FILTER_ENABLEf_SET(port_tab, 1);
    PORT_TABm_OUTER_TPID_ENABLEf_SET(port_tab, 1);
    PORT_TABm_TRUST_INCOMING_VIDf_SET(port_tab, 1);
    ioerr += WRITE_PORT_TABm(unit, port, port_tab);

    /* Filter VLAN on egress enable */
    ioerr += READ_EGR_PORTr(unit, port, &egr_port);
    EGR_PORTr_EN_EFILTERf_SET(egr_port, 1);
    ioerr += WRITE_EGR_PORTr(unit, port, egr_port);

    /* Filter VLAN on egress bitmap */
    ioerr += READ_ING_EN_EFILTER_BITMAPr(unit, &ing_en_efilter_bitmap);
    pbmp = ING_EN_EFILTER_BITMAPr_BITMAPf_GET(ing_en_efilter_bitmap);
    pbmp |= (1 << port);
    ING_EN_EFILTER_BITMAPr_BITMAPf_SET(ing_en_efilter_bitmap, pbmp);
    ioerr += WRITE_ING_EN_EFILTER_BITMAPr(unit, ing_en_efilter_bitmap);

    /* Egress enable */
    ioerr += READ_EGR_ENABLEr(unit, port, &egr_enable);
    EGR_ENABLEr_PRT_ENABLEf_SET(egr_enable, 1);
    ioerr += WRITE_EGR_ENABLEr(unit, port, egr_enable);

    return ioerr;
}

static int
_gport_init(int unit, int port)
{
    int ioerr = 0;
    int sleep_time = 10;
    COMMAND_CONFIGr_t command_config;
    TX_IPG_LENGTHr_t tx_ipg;
    PAUSE_QUANTr_t pause_quant;

    /* Common port initialization */
    ioerr += _port_init(unit, port);

    /* Command config initialization with MAC held in reset */
    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_config);
    COMMAND_CONFIGr_SW_RESETf_SET(command_config, 1);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_config);
    BMD_SYS_USLEEP(sleep_time);

    /* Rely on default values, but turn off Rx and loopback to be safe */
    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_config);
    COMMAND_CONFIGr_ETH_SPEEDf_SET(command_config, COMMAND_CONFIG_SPEED_1000);
    if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_FE) {
        COMMAND_CONFIGr_ETH_SPEEDf_SET(command_config, COMMAND_CONFIG_SPEED_100);
    }
    COMMAND_CONFIGr_TX_ENAf_SET(command_config, 1);
    COMMAND_CONFIGr_RX_ENAf_SET(command_config, 0);
    COMMAND_CONFIGr_LOOP_ENAf_SET(command_config, 0);
    COMMAND_CONFIGr_LINE_LOOPBACKf_SET(command_config, 0);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_config);

    ioerr += READ_COMMAND_CONFIGr(unit, port, &command_config);
    COMMAND_CONFIGr_SW_RESETf_SET(command_config, 0);
    ioerr += WRITE_COMMAND_CONFIGr(unit, port, command_config);

    /* Write pause quant */
    ioerr += READ_PAUSE_QUANTr(unit, port, &pause_quant);
    PAUSE_QUANTr_STAD2f_SET(pause_quant, 0xffff);
    ioerr += WRITE_PAUSE_QUANTr(unit, port, pause_quant);

    /* Set Inter-Packet-Gap */
    ioerr += READ_TX_IPG_LENGTHr(unit, port, &tx_ipg);
    TX_IPG_LENGTHr_TX_IPG_LENGTHf_SET(tx_ipg, 12);
    ioerr += WRITE_TX_IPG_LENGTHr(unit, port, tx_ipg);

    return ioerr;
}


int
bcm56224_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    ING_HW_RESET_CONTROL_1r_t ing_rst_ctl_1;
    ING_HW_RESET_CONTROL_2r_t ing_rst_ctl_2;
    EGR_HW_RESET_CONTROL_0r_t egr_rst_ctl_0;
    EGR_HW_RESET_CONTROL_1r_t egr_rst_ctl_1;
    RDBGC0_SELECTr_t rdbgc0_select;
    VLAN_PROFILE_TABm_t vlan_profile_tab;
    GPORT_CONFIGr_t gport_cfg;
    GPORT_RSV_MASKr_t gport_rsv_mask;
    GPORT_STAT_UPDATE_MASKr_t stat_upd_mask;
    uint32_t rsv_mask;
    cdk_pbmp_t pbmp;
    int idx;
    int port;

    BMD_CHECK_UNIT(unit);

    /* Reset the IPIPE block */
    ING_HW_RESET_CONTROL_1r_CLR(ing_rst_ctl_1);
    ioerr += WRITE_ING_HW_RESET_CONTROL_1r(unit, ing_rst_ctl_1);
    ING_HW_RESET_CONTROL_2r_CLR(ing_rst_ctl_2);
    ING_HW_RESET_CONTROL_2r_RESET_ALLf_SET(ing_rst_ctl_2, 1);
    ING_HW_RESET_CONTROL_2r_VALIDf_SET(ing_rst_ctl_2, 1);
    ING_HW_RESET_CONTROL_2r_COUNTf_SET(ing_rst_ctl_2, 0x4000);
    ioerr += WRITE_ING_HW_RESET_CONTROL_2r(unit, ing_rst_ctl_2);

    /* Reset the EPIPE block */
    EGR_HW_RESET_CONTROL_0r_CLR(egr_rst_ctl_0);
    EGR_HW_RESET_CONTROL_1r_CLR(egr_rst_ctl_1);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_0r(unit, egr_rst_ctl_0);
    EGR_HW_RESET_CONTROL_1r_RESET_ALLf_SET(egr_rst_ctl_1, 1);
    EGR_HW_RESET_CONTROL_1r_VALIDf_SET(egr_rst_ctl_1, 1);
    EGR_HW_RESET_CONTROL_1r_COUNTf_SET(egr_rst_ctl_1, 0x4000);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_1r(unit, egr_rst_ctl_1);

    for (idx = 0; idx < PIPE_RESET_TIMEOUT_MSEC; idx++) {
        ioerr += READ_ING_HW_RESET_CONTROL_2r(unit, &ing_rst_ctl_2);
        if (ING_HW_RESET_CONTROL_2r_DONEf_GET(ing_rst_ctl_2)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (idx >= PIPE_RESET_TIMEOUT_MSEC) {
        CDK_WARN(("bcm56224_a0_bmd_init[%d]: IPIPE reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }
        
    for (; idx < PIPE_RESET_TIMEOUT_MSEC; idx++) {
        ioerr += READ_EGR_HW_RESET_CONTROL_1r(unit, &egr_rst_ctl_1);
        if (EGR_HW_RESET_CONTROL_1r_DONEf_GET(egr_rst_ctl_1)) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (idx >= PIPE_RESET_TIMEOUT_MSEC) {
        CDK_WARN(("bcm56224_a0_bmd_init[%d]: EPIPE reset timeout\n", unit));
        return ioerr ? CDK_E_IO : CDK_E_TIMEOUT;
    }

    /* Clear pipe reset registers */
    ING_HW_RESET_CONTROL_2r_CLR(ing_rst_ctl_2);
    ioerr += WRITE_ING_HW_RESET_CONTROL_2r(unit, ing_rst_ctl_2);
    EGR_HW_RESET_CONTROL_1r_CLR(egr_rst_ctl_1);
    ioerr += WRITE_EGR_HW_RESET_CONTROL_1r(unit, egr_rst_ctl_1);

    /* Configure discard counter */
    RDBGC0_SELECTr_CLR(rdbgc0_select);
    RDBGC0_SELECTr_BITMAPf_SET(rdbgc0_select, 0x0400ad11);
    ioerr += WRITE_RDBGC0_SELECTr(unit, rdbgc0_select);

    /* Set up default VLAN profile entry */
    ioerr += READ_VLAN_PROFILE_TABm(unit, 0, &vlan_profile_tab);
    VLAN_PROFILE_TABm_LEARN_DISABLEf_SET(vlan_profile_tab, 0);
    VLAN_PROFILE_TABm_L3_IPV6_PFMf_SET(vlan_profile_tab, 1);
    VLAN_PROFILE_TABm_L3_IPV4_PFMf_SET(vlan_profile_tab, 1);
    VLAN_PROFILE_TABm_L2_PFMf_SET(vlan_profile_tab, 1);
    VLAN_PROFILE_TABm_IPV4L3_ENABLEf_SET(vlan_profile_tab, 1);
    VLAN_PROFILE_TABm_IPV6L3_ENABLEf_SET(vlan_profile_tab, 1);
    VLAN_PROFILE_TABm_IPMCV4_ENABLEf_SET(vlan_profile_tab, 1);
    VLAN_PROFILE_TABm_IPMCV6_ENABLEf_SET(vlan_profile_tab, 1);
    VLAN_PROFILE_TABm_IPMCV4_L2_ENABLEf_SET(vlan_profile_tab, 1);
    VLAN_PROFILE_TABm_IPMCV6_L2_ENABLEf_SET(vlan_profile_tab, 1);
    ioerr += WRITE_VLAN_PROFILE_TABm(unit, 0, vlan_profile_tab);

    /* Enable GPORTs and clear counters */
    GPORT_CONFIGr_CLR(gport_cfg);
    GPORT_CONFIGr_GPORT_ENf_SET(gport_cfg, 1);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 1);
    ioerr += WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 0);
    ioerr += WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);

    /* Fixup packet purge filtering */
    rsv_mask = 0x70;
    GPORT_RSV_MASKr_SET(gport_rsv_mask, rsv_mask);
    ioerr += WRITE_GPORT_RSV_MASKr(unit, gport_rsv_mask, -1);
    GPORT_STAT_UPDATE_MASKr_SET(stat_upd_mask, rsv_mask);
    ioerr += WRITE_GPORT_STAT_UPDATE_MASKr(unit, stat_upd_mask, -1);

    /* Configure GPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _gport_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }

#if BMD_CONFIG_INCLUDE_DMA
    /* Common port initialization for CPU port */
    ioerr += _port_init(unit, CMIC_PORT);

    if (CDK_SUCCESS(rv)) {
        rv = bmd_xgs_dma_init(unit);
    }
#endif

    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56224_A0 */
