#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56440_A0 == 1

/*
 * $Id: bcm56440_a0_bmd_reset.c,v 1.13 Broadcom SDK $
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

#include <cdk/chip/bcm56440_a0_defs.h>
#include <cdk/arch/xgsm_chip.h>
#include <cdk/cdk_debug.h>
#include <cdk/arch/xgsm_miim.h>

#include "bcm56440_a0_bmd.h"
#include "bcm56440_a0_internal.h"

#define RESET_SLEEP_USEC                100
#define PLL_LOCK_MSEC                   10

#ifndef _INIT_SVK_CLK
#define _INIT_SVK_CLK(_u) (0)
#endif

static int _lls_fill_tap_control(int unit, int number, int value[10]);
static int _lls_tap_seq_1(int unit, int seq1, int seq2);
static int _lls_tap_seq_2(int unit, int seq);
static int _lls_work_around(int unit);


static int
_lls_fill_tap_control(int unit, int number, int value[10])
{
    int i = 0;
    int ioerr = 0;
    TOP_TAP_CONTROLr_t top_tap_ctrl;
    for (i = 0; i < number; i++) {
        TOP_TAP_CONTROLr_SET(top_tap_ctrl, value[i]);
        ioerr += WRITE_TOP_TAP_CONTROLr(unit, top_tap_ctrl); 
    } 
    return ioerr;
}

static int
_lls_tap_seq_1(int unit, int seq1, int seq2)
{
    int i = 0;
    int ioerr = 0;
    TOP_TAP_CONTROLr_t tap_ctrl;
    
    TOP_TAP_CONTROLr_SET(tap_ctrl, 0xc);
    ioerr += WRITE_TOP_TAP_CONTROLr(unit, tap_ctrl); 
    for (i = 0; i < seq1; i++) {
        TOP_TAP_CONTROLr_SET(tap_ctrl, 0xd);
        ioerr += WRITE_TOP_TAP_CONTROLr(unit, tap_ctrl); 
        TOP_TAP_CONTROLr_SET(tap_ctrl, 0x9);
        ioerr += WRITE_TOP_TAP_CONTROLr(unit, tap_ctrl); 
    } 
    TOP_TAP_CONTROLr_SET(tap_ctrl, 0xd);
    ioerr += WRITE_TOP_TAP_CONTROLr(unit, tap_ctrl); 
    for (i = 0; i < seq2; i++) {
        TOP_TAP_CONTROLr_SET(tap_ctrl, 0xc);
        ioerr += WRITE_TOP_TAP_CONTROLr(unit, tap_ctrl); 
        TOP_TAP_CONTROLr_SET(tap_ctrl, 8);
        ioerr += WRITE_TOP_TAP_CONTROLr(unit, tap_ctrl); 
    }
    return ioerr; 
}

static int
_lls_tap_seq_2(int unit, int seq)
{
    int i = 0;
    int ioerr = 0;
    TOP_TAP_CONTROLr_t tap_ctrl;
    
    TOP_TAP_CONTROLr_SET(tap_ctrl, 0xe);
    ioerr += WRITE_TOP_TAP_CONTROLr(unit, tap_ctrl); 
    TOP_TAP_CONTROLr_SET(tap_ctrl, 0xa);
    ioerr += WRITE_TOP_TAP_CONTROLr(unit, tap_ctrl); 
    TOP_TAP_CONTROLr_SET(tap_ctrl, 0xe);
    ioerr += WRITE_TOP_TAP_CONTROLr(unit, tap_ctrl); 
    for (i = 0; i < seq; i++) {
        TOP_TAP_CONTROLr_SET(tap_ctrl, 0xc);
        ioerr += WRITE_TOP_TAP_CONTROLr(unit, tap_ctrl); 
        TOP_TAP_CONTROLr_SET(tap_ctrl, 0x8);
        ioerr += WRITE_TOP_TAP_CONTROLr(unit, tap_ctrl); 
    } 
    return ioerr; 
}

static int
_lls_work_around(int unit)
{
    static int value[10] = { 0 };
    int ioerr = 0;
    int j = 0;
    value[0] = 0;
    value[1] = 4;
    value[2] = 0xc;
    ioerr += _lls_fill_tap_control(unit, 1, value);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    ioerr += _lls_fill_tap_control(unit, 3, value);
    BMD_SYS_USLEEP(1);

    value[0] = 8;
    value[1] = 0xc;
    value[2] = 0xe;
    value[3] = 0xa;
    value[4] = 0xe;
    ioerr += _lls_fill_tap_control(unit, 5, value);
    BMD_SYS_USLEEP(1);

    value[0] = 0xa;
    value[1] = 0xe;
    value[2] = 0xc;
    value[3] = 0x8;
    value[4] = 0xc;
    value[5] = 0x8;
    value[6] = 0;
    value[7] = 4;
    value[8] = 0xc;
    ioerr += _lls_fill_tap_control(unit, 9, value);
    BMD_SYS_USLEEP(1);

    value[0] = 0x8;
    value[1] = 0xc;
    value[2] = 0xc;
    value[3] = 0xe;
    value[4] = 0xa;
    ioerr += _lls_fill_tap_control(unit, 5, value);
    ioerr += _lls_tap_seq_2(unit, 3);
    ioerr += _lls_tap_seq_1(unit, 1, 1);
    ioerr += _lls_tap_seq_1(unit, 6, 3);
    ioerr += _lls_tap_seq_1(unit, 8, 1);
    ioerr += _lls_tap_seq_1(unit, 9, 1);

    value[0] = 0xc;
    value[1] = 0xd;
    value[2] = 0xf;
    value[3] = 0xb;
    value[4] = 0xf;
    ioerr += _lls_fill_tap_control(unit, 5, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    ioerr += _lls_tap_seq_2(unit, 21);
    ioerr += _lls_tap_seq_1(unit, 1, 341);
    ioerr += _lls_tap_seq_1(unit, 2, 13);
    value[0] = 0xc;
    value[1] = 0xe;
    value[2] = 0xa;
    ioerr += _lls_fill_tap_control(unit, 3, value);
    ioerr += _lls_tap_seq_2(unit, 2);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    BMD_SYS_USLEEP(1);

    value[0] = 0xe;
    value[1] = 0xa;
    ioerr += _lls_fill_tap_control(unit, 2, value);
    ioerr += _lls_tap_seq_2(unit, 3);
    ioerr += _lls_tap_seq_1(unit, 1, 1);
    ioerr += _lls_tap_seq_1(unit, 6, 3);
    ioerr += _lls_tap_seq_1(unit, 8, 1);
    ioerr += _lls_tap_seq_1(unit, 9, 1);
    value[0] = 0xc;
    value[1] = 0xd;
    value[2] = 0xf;
    value[3] = 0xb;
    value[4] = 0xf;
    ioerr += _lls_fill_tap_control(unit, 5, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    ioerr += _lls_tap_seq_2(unit, 14);
    ioerr += _lls_tap_seq_1(unit, 2, 5);
    ioerr += _lls_tap_seq_1(unit, 1, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 338);
    ioerr += _lls_tap_seq_1(unit, 2, 13);
    value[0] = 0xc;
    value[1] = 0xe;
    value[2] = 0xa;
    ioerr += _lls_fill_tap_control(unit, 3, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 3, value);
    ioerr += _lls_tap_seq_2(unit, 3);
    ioerr += _lls_tap_seq_1(unit, 1, 1);
    ioerr += _lls_tap_seq_1(unit, 3, 1);
    ioerr += _lls_tap_seq_1(unit, 2, 1);
    ioerr += _lls_tap_seq_1(unit, 10, 1);
    ioerr += _lls_tap_seq_1(unit, 9, 1);
    value[0] = 0xc;
    value[1] = 0xd;
    value[2] = 0xf;
    value[3] = 0xb;
    value[4] = 0xf;
    ioerr += _lls_fill_tap_control(unit, 5, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    ioerr += _lls_tap_seq_2(unit, 4);
    ioerr += _lls_tap_seq_1(unit, 1, 703);
    ioerr += _lls_tap_seq_1(unit, 22, 1);
    for (j=0; j < 9; j++) {
        ioerr += _lls_tap_seq_1(unit, 32, 1);
    }
    ioerr += _lls_tap_seq_1(unit, 32, 17);
    ioerr += _lls_tap_seq_1(unit, 1, 3);
    ioerr += _lls_tap_seq_1(unit, 1, 3);
    ioerr += _lls_tap_seq_1(unit, 3, 7);
    ioerr += _lls_tap_seq_1(unit, 1, 10);
    ioerr += _lls_tap_seq_1(unit, 1, 5);
    ioerr += _lls_tap_seq_1(unit, 1, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 2);
    value[0] = 0xc;
    value[1] = 0xe;
    value[2] = 0xa;
    ioerr += _lls_fill_tap_control(unit, 3, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 3, value);
    ioerr += _lls_tap_seq_2(unit, 3);
    ioerr += _lls_tap_seq_1(unit, 1, 1);
    ioerr += _lls_tap_seq_1(unit, 6, 3);
    ioerr += _lls_tap_seq_1(unit, 8, 1);
    ioerr += _lls_tap_seq_1(unit, 9, 1);
    value[0] = 0xc;
    value[1] = 0xd;
    value[2] = 0xf;
    value[3] = 0xb;
    value[4] = 0xf;
    ioerr += _lls_fill_tap_control(unit, 5, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    ioerr += _lls_tap_seq_2(unit, 14);
    ioerr += _lls_tap_seq_1(unit, 2, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 338);
    ioerr += _lls_tap_seq_1(unit, 2, 13);
    value[0] = 0xc;
    value[1] = 0xe;
    value[2] = 0xa;
    ioerr += _lls_fill_tap_control(unit, 3, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 3, value);
    ioerr += _lls_tap_seq_2(unit, 3);
    ioerr += _lls_tap_seq_1(unit, 1, 1);
    ioerr += _lls_tap_seq_1(unit, 6, 3);
    ioerr += _lls_tap_seq_1(unit, 8, 1);
    ioerr += _lls_tap_seq_1(unit, 9, 1);
    value[0] = 0xc;
    value[1] = 0xd;
    value[2] = 0xf;
    value[3] = 0xb;
    value[4] = 0xf;
    ioerr += _lls_fill_tap_control(unit, 5, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    ioerr += _lls_tap_seq_2(unit, 5);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    BMD_SYS_USLEEP(4);

    value[0] = 0x8;
    ioerr += _lls_fill_tap_control(unit, 1, value);
    value[0] = 0xc;
    value[1] = 0x8;
    for (j=0; j < 9; j++) {
        ioerr += _lls_fill_tap_control(unit, 2, value);
    }
    ioerr += _lls_tap_seq_1(unit, 1, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 338);
    ioerr += _lls_tap_seq_1(unit, 2, 13);
    value[0] = 0xc;
    value[1] = 0xe;
    value[2] = 0xa;
    ioerr += _lls_fill_tap_control(unit, 3, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    ioerr += _lls_tap_seq_2(unit, 5);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    BMD_SYS_USLEEP(4);

    value[0] = 0x8;
    ioerr = _lls_fill_tap_control(unit, 1, value);
    value[0] = 0xc;
    value[1] = 0x8;
    for (j=0; j < 9; j++) {
        ioerr += _lls_fill_tap_control(unit, 2, value);
    }
    ioerr += _lls_tap_seq_1(unit, 2, 1);
    ioerr += _lls_tap_seq_1(unit, 1, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 338);
    ioerr += _lls_tap_seq_1(unit, 2, 13);
    value[0] = 0xc;
    value[1] = 0xe;
    value[2] = 0xa;
    ioerr += _lls_fill_tap_control(unit, 3, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    ioerr += _lls_tap_seq_2(unit, 15);
    ioerr += _lls_tap_seq_1(unit, 2, 1);
    ioerr += _lls_tap_seq_1(unit, 1, 1);
    ioerr += _lls_tap_seq_1(unit, 2, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 338);
    ioerr += _lls_tap_seq_1(unit, 2, 13);
    ioerr += _lls_fill_tap_control(unit, 3, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    ioerr += _lls_tap_seq_2(unit, 15);
    ioerr += _lls_tap_seq_1(unit, 2, 3);
    ioerr += _lls_tap_seq_1(unit, 2, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 338);
    ioerr += _lls_tap_seq_1(unit, 2, 13);
    ioerr += _lls_fill_tap_control(unit, 3, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    BMD_SYS_USLEEP(15);

    value[0] = 0x8;
    value[1] = 0xc;
    ioerr += _lls_fill_tap_control(unit, 2, value);
    BMD_SYS_USLEEP(1200);

    ioerr += _lls_fill_tap_control(unit, 2, value);
    value[0] = 0xe;
    value[1] = 0xa;
    ioerr += _lls_fill_tap_control(unit, 2, value);
    ioerr += _lls_tap_seq_2(unit, 3);
    ioerr += _lls_tap_seq_1(unit, 1, 3);
    ioerr += _lls_tap_seq_1(unit, 6, 3);
    ioerr += _lls_tap_seq_1(unit, 8, 1);
    ioerr += _lls_tap_seq_1(unit, 9, 1);
    value[0] = 0xc;
    value[1] = 0xd;
    value[2] = 0xf;
    value[3] = 0xb;
    value[4] = 0xf;
    ioerr += _lls_fill_tap_control(unit, 5, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    ioerr += _lls_tap_seq_2(unit, 15);
    ioerr += _lls_tap_seq_1(unit, 2, 1);
    ioerr += _lls_tap_seq_1(unit, 1, 1);
    ioerr += _lls_tap_seq_1(unit, 2, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 338);
    ioerr += _lls_tap_seq_1(unit, 2, 13);
    value[0] = 0xc;
    value[1] = 0xe;
    value[2] = 0xa;
    ioerr += _lls_fill_tap_control(unit, 3, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    ioerr += _lls_tap_seq_2(unit, 5);
    ioerr += _lls_fill_tap_control(unit, 1, value);
    BMD_SYS_USLEEP(4);

    value[0] = 0x8;
    ioerr = _lls_fill_tap_control(unit, 1, value);
    value[0] = 0xc;
    value[1] = 0x8;
    for (j=0; j < 9; j++) {
        ioerr += _lls_fill_tap_control(unit, 2, value);
    }
    ioerr += _lls_tap_seq_1(unit, 1, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 1);
    ioerr += _lls_tap_seq_1(unit, 2, 2);
    ioerr += _lls_tap_seq_1(unit, 1, 14);
    value[0] = 0xe;
    value[1] = 0xa;
    ioerr = _lls_fill_tap_control(unit, 2, value);
    ioerr += _lls_tap_seq_2(unit, 1);
    value[0] = 0xc;
    ioerr += _lls_fill_tap_control(unit, 1, value);
    value[0] = 0x0;
    for (j=0; j < 6; j++) {
        ioerr += _lls_fill_tap_control(unit, 1, value);
    }
    return ioerr;
}

static int
_lcpll_check(int unit)
{
    int ioerr = 0;
    int msec;
    TOP_XGXS0_PLL_STATUSr_t pll0_status;
    TOP_XGXS1_PLL_STATUSr_t pll1_status;

    /* Wait for LCPLL locks */
    for (msec = 0; msec < PLL_LOCK_MSEC; msec++) {
#if BMD_CONFIG_SIMULATION
        if (msec == 0) break;
#endif
        ioerr += READ_TOP_XGXS0_PLL_STATUSr(unit, &pll0_status);
        if (TOP_XGXS0_PLL_STATUSr_TOP_XGPLL0_LOCKf_GET(pll0_status)) {
            if (!(CDK_XGSM_FLAGS(unit) & CHIP_FLAG_NO_PLL1)) {
                ioerr += READ_TOP_XGXS1_PLL_STATUSr(unit, &pll1_status);
                if (TOP_XGXS1_PLL_STATUSr_TOP_XGPLL1_LOCKf_GET(pll1_status) == 1) {
                    break;
                }
            } else {
                break;
            }
        }
        BMD_SYS_USLEEP(1000);
    }
    if (msec >= PLL_LOCK_MSEC) {
        CDK_WARN(("bcm56440_a0_bmd_reset[%d]: "
                  "LC PLL did not lock, status = "
                  "0x%08"PRIx32" 0x%08"PRIx32"\n",
                  unit,
                  TOP_XGXS0_PLL_STATUSr_GET(pll0_status), 
                  TOP_XGXS1_PLL_STATUSr_GET(pll1_status)));
    }

    return ioerr;
}

int
bcm56440_a0_xport_reset(int unit, int port)
{
    int ioerr = 0;
    int idx;
    uint32_t dev_in_pkg;
    TOP_XGXS_MDIO_CONFIG_0r_t xgxs_mdio_cfg;
    TOP_XGXS_MDIO_CONFIG_1r_t xgxs_mdio_cfg1;
    TOP_XGXS_MDIO_CONFIG_2r_t xgxs_mdio_cfg2;
    TOP_XGXS_MDIO_CONFIG_3r_t xgxs_mdio_cfg3;
    XPORT_XGXS_CTRLr_t xgxs_ctrl;
    /* Zero-based xport index */
    if (port < 25) {
        idx = 4;
    } else if (port < 29) {
        idx = port - 25;
    } else {
        idx = 4;
    }

    dev_in_pkg = (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_HG) ? 0x3 : 0x15;
    /* Use indexed alias instead of CMIC_XGXS_MDIO_CONFIG_0r, etc. */
    if(0 == idx) {
        ioerr += READ_TOP_XGXS_MDIO_CONFIG_0r(unit, &xgxs_mdio_cfg);
        TOP_XGXS_MDIO_CONFIG_0r_IEEE_DEVICES_IN_PKGf_SET(xgxs_mdio_cfg, dev_in_pkg);
        ioerr += WRITE_TOP_XGXS_MDIO_CONFIG_0r(unit, xgxs_mdio_cfg);
    } else if(1 == idx) {
        ioerr += READ_TOP_XGXS_MDIO_CONFIG_1r(unit, &xgxs_mdio_cfg1);
        TOP_XGXS_MDIO_CONFIG_1r_IEEE_DEVICES_IN_PKGf_SET(xgxs_mdio_cfg1, dev_in_pkg);
        ioerr += WRITE_TOP_XGXS_MDIO_CONFIG_1r(unit, xgxs_mdio_cfg1);
    } else if(2 == idx) {
        ioerr += READ_TOP_XGXS_MDIO_CONFIG_2r(unit, &xgxs_mdio_cfg2);
        TOP_XGXS_MDIO_CONFIG_2r_IEEE_DEVICES_IN_PKGf_SET(xgxs_mdio_cfg2, dev_in_pkg);
        ioerr += WRITE_TOP_XGXS_MDIO_CONFIG_2r(unit, xgxs_mdio_cfg2);
    } else if(3 == idx) {
        ioerr += READ_TOP_XGXS_MDIO_CONFIG_3r(unit, &xgxs_mdio_cfg3);
        TOP_XGXS_MDIO_CONFIG_3r_IEEE_DEVICES_IN_PKGf_SET(xgxs_mdio_cfg3, dev_in_pkg);
        ioerr += WRITE_TOP_XGXS_MDIO_CONFIG_3r(unit, xgxs_mdio_cfg3);
    }
    /* Force XMAC into reset before initialization */
    ioerr += READ_XPORT_XGXS_CTRLr(unit, &xgxs_ctrl, port);
    XPORT_XGXS_CTRLr_IDDQf_SET(xgxs_ctrl, 1);
    XPORT_XGXS_CTRLr_PWRDWNf_SET(xgxs_ctrl, 1);
    XPORT_XGXS_CTRLr_HW_RSTLf_SET(xgxs_ctrl, 0);
    XPORT_XGXS_CTRLr_RSTB_PLLf_SET(xgxs_ctrl, 0);
    XPORT_XGXS_CTRLr_RSTB_MDIOREGSf_SET(xgxs_ctrl, 0);
    XPORT_XGXS_CTRLr_TXFIFO_RSTLf_SET(xgxs_ctrl, 0);
    ioerr += WRITE_XPORT_XGXS_CTRLr(unit, xgxs_ctrl, port);

    /*
     * XGXS MAC initialization steps.
     *
     * A minimum delay is required between various initialization steps.
     * There is no maximum delay.  The values given are very conservative
     * including the timeout for TX PLL lock.
     */

    /* Powerup Unicore interface (digital and analog clocks) */
    ioerr += READ_XPORT_XGXS_CTRLr(unit, &xgxs_ctrl, port);
    XPORT_XGXS_CTRLr_IDDQf_SET(xgxs_ctrl, 0);
    XPORT_XGXS_CTRLr_PWRDWNf_SET(xgxs_ctrl, 0);
    ioerr += WRITE_XPORT_XGXS_CTRLr(unit, xgxs_ctrl, port);

    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /* Bring Warpcore out of reset */
    ioerr += READ_XPORT_XGXS_CTRLr(unit, &xgxs_ctrl, port);
    XPORT_XGXS_CTRLr_HW_RSTLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_XPORT_XGXS_CTRLr(unit, xgxs_ctrl, port);
    BMD_SYS_USLEEP(RESET_SLEEP_USEC);

    /* Bring MDIO registers out of reset */
    ioerr += READ_XPORT_XGXS_CTRLr(unit, &xgxs_ctrl, port);
    XPORT_XGXS_CTRLr_RSTB_MDIOREGSf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_XPORT_XGXS_CTRLr(unit, xgxs_ctrl, port);

    /* Activate all clocks */
    ioerr += READ_XPORT_XGXS_CTRLr(unit, &xgxs_ctrl, port);
    XPORT_XGXS_CTRLr_RSTB_PLLf_SET(xgxs_ctrl, 1);
    ioerr += WRITE_XPORT_XGXS_CTRLr(unit, xgxs_ctrl, port);

    ioerr += READ_XPORT_XGXS_CTRLr(unit, &xgxs_ctrl, port);
    XPORT_XGXS_CTRLr_TXFIFO_RSTLf_SET(xgxs_ctrl, 0x1);
    ioerr += WRITE_XPORT_XGXS_CTRLr(unit, xgxs_ctrl, port);
    return ioerr;
}

int
bcm56440_a0_bmd_reset(int unit)
{
    int ioerr = 0;
    int wait_usec = 10000;
    int port;
    cdk_pbmp_t pbmp;
    CMIC_SBUS_TIMEOUTr_t sbus_to;
    CMIC_CPS_RESETr_t cmic_cps;
    CMIC_SBUS_RING_MAP_0_7r_t ring_map_0;
    CMIC_SBUS_RING_MAP_8_15r_t ring_map_1;
    CMIC_SBUS_RING_MAP_16_23r_t ring_map_2;
    CMIC_SBUS_RING_MAP_24_31r_t ring_map_3;
    TOP_MMU_PLL1_CTRL1r_t pll1_ctrl;
    TOP_MMU_PLL2_CTRL1r_t pll2_ctrl;
    TOP_MMU_PLL3_CTRL1r_t pll3_ctrl;
    TOP_MMU_PLL1_CTRL3r_t pll1_ctrl3;
    TOP_MMU_PLL2_CTRL3r_t pll2_ctrl3;
    TOP_MMU_PLL3_CTRL3r_t pll3_ctrl3;
    TOP_SOFT_RESET_REG_2r_t soft_reset2;
    TOP_SOFT_RESET_REGr_t soft_reset;
    XPORT_XGXS_NEWCTL_REGr_t xgxs_newctl;
    XPORT_XMAC_CONTROLr_t xmac_control;
    QUAD0_SERDES_CTRLr_t serdes_ctrl;
    QUAD1_SERDES_CTRLr_t serdes_ctrl1;
    BMD_CHECK_UNIT(unit);

    /* Initialize endian mode for correct reset access */
    ioerr += cdk_xgsm_cmic_init(unit);

    /* Pull reset line */
    ioerr += READ_CMIC_CPS_RESETr(unit, &cmic_cps);
    CMIC_CPS_RESETr_CPS_RESETf_SET(cmic_cps, 1);
    ioerr += WRITE_CMIC_CPS_RESETr(unit, cmic_cps);
    /* Wait for all tables to initialize */
    BMD_SYS_USLEEP(wait_usec);
    /* Re-initialize endian mode after reset */
    ioerr += cdk_xgsm_cmic_init(unit);

    ioerr += _INIT_SVK_CLK(unit);

    /* Re-initialize endian mode after reset */
    ioerr += cdk_xgsm_cmic_init(unit);

    CMIC_SBUS_RING_MAP_0_7r_SET(ring_map_0, 0x22034000);
    CMIC_SBUS_RING_MAP_8_15r_SET(ring_map_1, 0x55311112);
    CMIC_SBUS_RING_MAP_16_23r_SET(ring_map_2, 0x00000655);
    CMIC_SBUS_RING_MAP_24_31r_SET(ring_map_3, 0x00000000);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_0_7r(unit, ring_map_0);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_8_15r(unit, ring_map_1);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_16_23r(unit, ring_map_2);
    ioerr += WRITE_CMIC_SBUS_RING_MAP_24_31r(unit, ring_map_3);


    READ_TOP_MMU_PLL1_CTRL3r(unit, &pll1_ctrl3);
    READ_TOP_MMU_PLL2_CTRL3r(unit, &pll2_ctrl3);
    READ_TOP_MMU_PLL3_CTRL3r(unit, &pll3_ctrl3);

    if((CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX8_MODE) ||
       (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX16_MODE) || 
       (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_EIGHTX25G_MODE) || 
       (CDK_XGSM_FLAGS(unit) & CHIP_FLAG_GEX6_MODE)) {
        TOP_MMU_PLL1_CTRL3r_PLL_CTRL_PWM_RATEf_SET(pll1_ctrl3, 0);
        TOP_MMU_PLL2_CTRL3r_PLL_CTRL_PWM_RATEf_SET(pll2_ctrl3, 0);
        TOP_MMU_PLL3_CTRL3r_PLL_CTRL_PWM_RATEf_SET(pll3_ctrl3, 0);

    } else {
        READ_TOP_MMU_PLL1_CTRL1r(unit, &pll1_ctrl);
        READ_TOP_MMU_PLL2_CTRL1r(unit, &pll2_ctrl);
        READ_TOP_MMU_PLL3_CTRL1r(unit, &pll3_ctrl);

        TOP_MMU_PLL1_CTRL1r_KPf_SET(pll1_ctrl, 10);
        TOP_MMU_PLL2_CTRL1r_KPf_SET(pll2_ctrl, 10);
        TOP_MMU_PLL3_CTRL1r_KPf_SET(pll3_ctrl, 10);

        TOP_MMU_PLL1_CTRL3r_PLL_CTRL_VCO_DIV2f_SET(pll1_ctrl3, 1);
        TOP_MMU_PLL2_CTRL3r_PLL_CTRL_VCO_DIV2f_SET(pll2_ctrl3, 1);
        TOP_MMU_PLL3_CTRL3r_PLL_CTRL_VCO_DIV2f_SET(pll3_ctrl3, 1);

        ioerr += WRITE_TOP_MMU_PLL1_CTRL1r(unit, pll1_ctrl);
        ioerr += WRITE_TOP_MMU_PLL2_CTRL1r(unit, pll2_ctrl);
        ioerr += WRITE_TOP_MMU_PLL3_CTRL1r(unit, pll3_ctrl);
    }
    ioerr += WRITE_TOP_MMU_PLL1_CTRL3r(unit, pll1_ctrl3);
    ioerr += WRITE_TOP_MMU_PLL2_CTRL3r(unit, pll2_ctrl3);
    ioerr += WRITE_TOP_MMU_PLL3_CTRL3r(unit, pll3_ctrl3);

     /* Bring LCPLL out of reset */
    READ_TOP_SOFT_RESET_REG_2r(unit, &soft_reset2);
    TOP_SOFT_RESET_REG_2r_TOP_XG0_PLL_RST_Lf_SET(soft_reset2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_XG1_PLL_RST_Lf_SET(soft_reset2, 1);
    ioerr += WRITE_TOP_SOFT_RESET_REG_2r(unit, soft_reset2);

    /* Check LCPLL locks */
    ioerr += _lcpll_check(unit);

    /* De-assert LCPLL's post reset */
    READ_TOP_SOFT_RESET_REG_2r(unit, &soft_reset2);
    TOP_SOFT_RESET_REG_2r_TOP_XG0_PLL_POST_RST_Lf_SET(soft_reset2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_XG1_PLL_POST_RST_Lf_SET(soft_reset2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_TS_PLL_RST_Lf_SET(soft_reset2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_BS_PLL_RST_Lf_SET(soft_reset2, 1);
    ioerr += WRITE_TOP_SOFT_RESET_REG_2r(unit, soft_reset2);

    BMD_SYS_USLEEP(wait_usec);

    READ_TOP_SOFT_RESET_REG_2r(unit, &soft_reset2);
    TOP_SOFT_RESET_REG_2r_TOP_TS_PLL_POST_RST_Lf_SET(soft_reset2, 1);
    TOP_SOFT_RESET_REG_2r_TOP_BS_PLL_POST_RST_Lf_SET(soft_reset2, 1);
    ioerr += WRITE_TOP_SOFT_RESET_REG_2r(unit, soft_reset2);
    BMD_SYS_USLEEP(wait_usec); 

    /*
     * Bring port blocks out of reset
     */
    READ_TOP_SOFT_RESET_REGr(unit, &soft_reset);
    TOP_SOFT_RESET_REGr_TOP_MXQ0_RST_Lf_SET(soft_reset, 1);
    TOP_SOFT_RESET_REGr_TOP_MXQ1_RST_Lf_SET(soft_reset, 1);
    TOP_SOFT_RESET_REGr_TOP_MXQ2_RST_Lf_SET(soft_reset, 1);
    TOP_SOFT_RESET_REGr_TOP_MXQ3_RST_Lf_SET(soft_reset, 1);
    TOP_SOFT_RESET_REGr_TOP_GP0_RST_Lf_SET(soft_reset, 1);
    TOP_SOFT_RESET_REGr_TOP_GP1_RST_Lf_SET(soft_reset, 1);
    TOP_SOFT_RESET_REGr_TOP_GP2_RST_Lf_SET(soft_reset, 1);
    ioerr += WRITE_TOP_SOFT_RESET_REGr(unit, soft_reset);

    BMD_SYS_USLEEP(wait_usec); 

    /* Bring network sync out of reset */
    READ_TOP_SOFT_RESET_REGr(unit, &soft_reset);
    TOP_SOFT_RESET_REGr_TOP_MXQ0_HOTSWAP_RST_Lf_SET(soft_reset, 1);
    TOP_SOFT_RESET_REGr_TOP_MXQ1_HOTSWAP_RST_Lf_SET(soft_reset, 1);
    TOP_SOFT_RESET_REGr_TOP_MXQ2_HOTSWAP_RST_Lf_SET(soft_reset, 1);
    TOP_SOFT_RESET_REGr_TOP_MXQ3_HOTSWAP_RST_Lf_SET(soft_reset, 1);
    TOP_SOFT_RESET_REGr_TOP_NS_RST_Lf_SET (soft_reset, 1);
    ioerr += WRITE_TOP_SOFT_RESET_REGr(unit, soft_reset);

    BMD_SYS_USLEEP(wait_usec); 

    CMIC_SBUS_TIMEOUTr_SET(sbus_to, 0x7d0);
    WRITE_CMIC_SBUS_TIMEOUTr(unit, sbus_to);

    /* Bring IP, EP, and MMU blocks out of reset */
    READ_TOP_SOFT_RESET_REGr(unit, &soft_reset);
    TOP_SOFT_RESET_REGr_TOP_EP_RST_Lf_SET(soft_reset, 1);
    TOP_SOFT_RESET_REGr_TOP_IP_RST_Lf_SET(soft_reset, 1);
    TOP_SOFT_RESET_REGr_TOP_MMU_RST_Lf_SET(soft_reset, 1);
    ioerr += WRITE_TOP_SOFT_RESET_REGr(unit, soft_reset);

    BMD_SYS_USLEEP(wait_usec); 

    if(CDK_XGSM_FLAGS(unit) & CHIP_FLAG_LLS_WORKAROUND){
        ioerr += _lls_work_around(unit); 
    }

    CDK_XGSM_BLKTYPE_PBMP_GET(unit, BLKTYPE_MXQPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += bcm56440_a0_xport_reset(unit, port);
        /* Bring XMAC out of reset */
        READ_XPORT_XGXS_NEWCTL_REGr(unit, &xgxs_newctl, port);
        XPORT_XGXS_NEWCTL_REGr_TXD1G_FIFO_RSTBf_SET(xgxs_newctl, 0xf);
        ioerr += WRITE_XPORT_XGXS_NEWCTL_REGr(unit, xgxs_newctl, port);

        READ_XPORT_XMAC_CONTROLr(unit, &xmac_control, port);
        XPORT_XMAC_CONTROLr_XMAC_RESETf_SET(xmac_control, 1);
        ioerr += WRITE_XPORT_XMAC_CONTROLr(unit, xmac_control, port);
        BMD_SYS_USLEEP(wait_usec); 

        XPORT_XMAC_CONTROLr_XMAC_RESETf_SET(xmac_control, 0);
        ioerr += WRITE_XPORT_XMAC_CONTROLr(unit, xmac_control, port);
        BMD_SYS_USLEEP(wait_usec); 
    }
    CDK_XGSM_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        READ_QUAD0_SERDES_CTRLr(unit, &serdes_ctrl, port);
        READ_QUAD1_SERDES_CTRLr(unit, &serdes_ctrl1, port);
        QUAD0_SERDES_CTRLr_RSTB_PLLf_SET(serdes_ctrl, 1);
        QUAD1_SERDES_CTRLr_RSTB_PLLf_SET(serdes_ctrl1, 1);
        ioerr += WRITE_QUAD0_SERDES_CTRLr(unit, serdes_ctrl, port);
        ioerr += WRITE_QUAD1_SERDES_CTRLr(unit, serdes_ctrl1, port);
        BMD_SYS_USLEEP(wait_usec); 

        READ_QUAD0_SERDES_CTRLr(unit, &serdes_ctrl, port);
        READ_QUAD1_SERDES_CTRLr(unit, &serdes_ctrl1, port);
        QUAD0_SERDES_CTRLr_HW_RSTLf_SET(serdes_ctrl, 1);
        QUAD1_SERDES_CTRLr_HW_RSTLf_SET(serdes_ctrl1, 1);
        ioerr += WRITE_QUAD0_SERDES_CTRLr(unit, serdes_ctrl, port);
        ioerr += WRITE_QUAD1_SERDES_CTRLr(unit, serdes_ctrl1, port);
        BMD_SYS_USLEEP(wait_usec); 

        QUAD0_SERDES_CTRLr_TXFIFO_RSTLf_SET(serdes_ctrl, 0xf);
        QUAD1_SERDES_CTRLr_TXFIFO_RSTLf_SET(serdes_ctrl1, 0xf);
        QUAD0_SERDES_CTRLr_RSTB_PLLf_SET(serdes_ctrl, 1);
        QUAD1_SERDES_CTRLr_RSTB_PLLf_SET(serdes_ctrl1, 1);
        QUAD0_SERDES_CTRLr_RSTB_MDIOREGSf_SET(serdes_ctrl, 1);
        QUAD1_SERDES_CTRLr_RSTB_MDIOREGSf_SET(serdes_ctrl1, 1);
        ioerr += WRITE_QUAD0_SERDES_CTRLr(unit, serdes_ctrl, port);
        ioerr += WRITE_QUAD1_SERDES_CTRLr(unit, serdes_ctrl1, port);

    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56440_A0 */
