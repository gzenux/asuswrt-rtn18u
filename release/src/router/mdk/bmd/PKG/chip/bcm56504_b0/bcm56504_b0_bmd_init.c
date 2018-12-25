#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56504_B0 == 1

/*
 * $Id: bcm56504_b0_bmd_init.c,v 1.9 Broadcom SDK $
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

#include <cdk/chip/bcm56504_b0_defs.h>
#include <cdk/cdk_debug.h>

#include "bcm56504_b0_bmd.h"
#include "bcm56504_b0_internal.h"

#define PIPE_RESET_TIMEOUT_MSEC         5

#define JUMBO_MAXSZ                     0x3fe8

static int
_port_init(int unit, int port)
{
    int ioerr = 0;
    EGR_ENABLEr_t egr_enable;
    EGR_PORTr_t egr_port;
    PORT_TABm_t port_tab;

    /* Default port VLAN */
    PORT_TABm_CLR(port_tab);
    PORT_TABm_PORT_VIDf_SET(port_tab, 1);
    PORT_TABm_FILTER_ENABLEf_SET(port_tab, 1);
    PORT_TABm_OUTER_TPIDf_SET(port_tab, 0x8100);
    ioerr += WRITE_PORT_TABm(unit, port, port_tab);

    /* Filter VLAN on egress */
    ioerr += READ_EGR_PORTr(unit, port, &egr_port);
    EGR_PORTr_EN_EFILTERf_SET(egr_port, 1);
    ioerr += WRITE_EGR_PORTr(unit, port, egr_port);

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
    GPCSCr_t gpcsc;
    GMACC0r_t gmacc0;
    FE_IPGRr_t fe_ipgr;
    FE_IPGTr_t fe_ipgt;
    FE_MAXFr_t maxf;

    /* Common port initialization */
    ioerr += _port_init(unit, port);

    /* Select GMII */
    ioerr += READ_GMACC0r(unit, port, &gmacc0);
    GMACC0r_TMDSf_SET(gmacc0, 1);
    ioerr += WRITE_GMACC0r(unit, port, gmacc0);

    /* Run GMII at 125 MHz */
    ioerr += READ_GPCSCr(unit, port, &gpcsc);
    GPCSCr_RCSELf_SET(gpcsc, 1);
    ioerr += WRITE_GPCSCr(unit, port, gpcsc);

    /* Set minimum 10/100 Inter-Packet-Gap */
    ioerr += READ_FE_IPGRr(unit, port, &fe_ipgr);
    FE_IPGRr_IPGR1f_SET(fe_ipgr, 0x6);
    FE_IPGRr_IPGR2f_SET(fe_ipgr, 0xf);
    ioerr += WRITE_FE_IPGRr(unit, port, fe_ipgr);
    ioerr += READ_FE_IPGTr(unit, port, &fe_ipgt);
    FE_IPGTr_IPGTf_SET(fe_ipgt, 0x15);
    ioerr += WRITE_FE_IPGTr(unit, port, fe_ipgt);

    /* Adjust 10/100 max frame size */
    FE_MAXFr_CLR(maxf);
    FE_MAXFr_MAXFRf_SET(maxf, 0x5ef);
    ioerr += WRITE_FE_MAXFr(unit, port, maxf);

    return ioerr;
}

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1

int
bcm56504_b0_xport_init(int unit, int port)
{
    int ioerr = 0;
    XPORT_CONFIGr_t xport_cfg;
    MAC_CTRLr_t mac_ctrl;
    MAC_TXCTRLr_t txctrl;
    MAC_RXCTRLr_t rxctrl;
    MAC_TXMAXSZr_t txmaxsz;
    MAC_RXMAXSZr_t rxmaxsz;

    /* Common port initialization */
    ioerr += _port_init(unit, port);

    /* Enable xport */
    XPORT_CONFIGr_CLR(xport_cfg);
    XPORT_CONFIGr_XPORT_ENf_SET(xport_cfg, 1);
    ioerr += WRITE_XPORT_CONFIGr(unit, port, xport_cfg);

    /* Ensure that MAC (Rx) and loopback mode is disabled */
    MAC_CTRLr_CLR(mac_ctrl);
    MAC_CTRLr_TXENf_SET(mac_ctrl, 1);
    ioerr += WRITE_MAC_CTRLr(unit, port, mac_ctrl);

    /* Configure Tx (Inter-Packet-Gap, recompute CRC mode, IEEE header) */
    MAC_TXCTRLr_CLR(txctrl);
    MAC_TXCTRLr_AVGIPGf_SET(txctrl, 0xc);
    MAC_TXCTRLr_CRC_MODEf_SET(txctrl, 0x2);
    MAC_TXCTRLr_THROTDENOMf_SET(txctrl, 0x2);
    ioerr += WRITE_MAC_TXCTRLr(unit, port, txctrl);

    /* Configure Rx (strip CRC, strict preamble, IEEE header) */
    MAC_RXCTRLr_CLR(rxctrl);
    MAC_RXCTRLr_STRICTPRMBLf_SET(rxctrl, 1);
    ioerr += WRITE_MAC_RXCTRLr(unit, port, rxctrl);

    /* Set max Tx frame size */
    MAC_TXMAXSZr_CLR(txmaxsz);
    MAC_TXMAXSZr_SZf_SET(txmaxsz, JUMBO_MAXSZ);
    ioerr += WRITE_MAC_TXMAXSZr(unit, port, txmaxsz);

    /* Set max Rx frame size */
    MAC_RXMAXSZr_CLR(rxmaxsz);
    MAC_RXMAXSZr_SZf_SET(rxmaxsz, JUMBO_MAXSZ);
    ioerr += WRITE_MAC_RXMAXSZr(unit, port, rxmaxsz);

    return ioerr;
}

#endif

int
bcm56504_b0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    ING_HW_RESET_CONTROL_1r_t ing_rst_ctl_1;
    ING_HW_RESET_CONTROL_2r_t ing_rst_ctl_2;
    EGR_HW_RESET_CONTROL_0r_t egr_rst_ctl_0;
    EGR_HW_RESET_CONTROL_1r_t egr_rst_ctl_1;
    RDBGC0_SELECTr_t rdbgc0_select;
    GPORT_CONFIGr_t gport_cfg;
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
        CDK_WARN(("bcm56504_b0_bmd_init[%d]: IPIPE reset timeout\n", unit));
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
        CDK_WARN(("bcm56504_b0_bmd_init[%d]: EPIPE reset timeout\n", unit));
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

    /* Enable GPORTs and clear counters */
    ioerr += READ_GPORT_CONFIGr(unit, &gport_cfg, -1);
    GPORT_CONFIGr_GPORT_ENf_SET(gport_cfg, 1);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 1);
    ioerr += WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);
    GPORT_CONFIGr_CLR_CNTf_SET(gport_cfg, 0);
    ioerr += WRITE_GPORT_CONFIGr(unit, gport_cfg, -1);

    /* Configure GPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _gport_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    /* Configure XPORTs */
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += bcm56504_b0_xport_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }
#endif

#if BMD_CONFIG_INCLUDE_DMA
    /* Common port initialization for CPU port */
    ioerr += _port_init(unit, CMIC_PORT);

    if (CDK_SUCCESS(rv)) {
        rv = bmd_xgs_dma_init(unit);
    }
#endif

    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56504_B0 */
