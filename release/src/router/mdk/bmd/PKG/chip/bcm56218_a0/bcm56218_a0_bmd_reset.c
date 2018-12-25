#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56218_A0 == 1

/*
 * $Id: bcm56218_a0_bmd_reset.c,v 1.5 Broadcom SDK $
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

#include <cdk/chip/bcm56218_a0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_debug.h>

#include "bcm56218_a0_bmd.h"

#define RESET_SLEEP_USEC                100
#define PLL_LOCK_MSEC                   500

static int
bcm56218_a0_lcpll_init(int unit)
{
    int ioerr = 0;
    int msec;
    uint32_t raw_val;
    CMIC_XGXS_PLL_CONTROL_1r_t pll_ctrl1;
    CMIC_XGXS_PLL_CONTROL_2r_t pll_ctrl2;

    /* Reset PLL */
    ioerr += READ_CMIC_XGXS_PLL_CONTROL_1r(unit, &pll_ctrl1);
    CMIC_XGXS_PLL_CONTROL_1r_RESETf_SET(pll_ctrl1, 1);
    ioerr += WRITE_CMIC_XGXS_PLL_CONTROL_1r(unit, pll_ctrl1);
    BMD_SYS_USLEEP(50);
    CMIC_XGXS_PLL_CONTROL_1r_RESETf_SET(pll_ctrl1, 0);
    /* Set PLLFORCECAPPASS and PLLFORCECAPDONE to avoid PLL lock failure */
    raw_val = CMIC_XGXS_PLL_CONTROL_1r_GET(pll_ctrl1);
    CMIC_XGXS_PLL_CONTROL_1r_SET(pll_ctrl1, raw_val | 0xf0000000);
    ioerr += WRITE_CMIC_XGXS_PLL_CONTROL_1r(unit, pll_ctrl1);

    /* Wait for LC PLL locks */
    for (msec = 0; msec < PLL_LOCK_MSEC; msec++) {
        ioerr += READ_CMIC_XGXS_PLL_CONTROL_2r(unit, &pll_ctrl2);
#if BMD_CONFIG_SIMULATION
        if (msec == 0) break;
#endif
        /* Use PLL_SM_FREQ_PASS as CMIC_XG_PLL_LOCK is unreliable */
        if (CMIC_XGXS_PLL_CONTROL_2r_PLL_SM_FREQ_PASSf_GET(pll_ctrl2) == 1) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (msec >= PLL_LOCK_MSEC) {
        CDK_WARN(("bcm56218_a0_bmd_reset[%d]: "
                  "LC PLL did not lock, status = 0x%08"PRIx32"\n",
                  unit, CMIC_XGXS_PLL_CONTROL_2r_GET(pll_ctrl2)));
    }

    return ioerr;
}

int
bcm56218_a0_bmd_reset(int unit)
{
    int ioerr = 0;
    int wait_usec = 10000;
    CMIC_CONFIGr_t cmic_config;
    CMIC_SOFT_RESET_REGr_t cmic_sreset;
    CMIC_SBUS_RING_MAPr_t ring_map;

    BMD_CHECK_UNIT(unit);

    /* Initialize endian mode for correct reset access */
    ioerr += cdk_xgs_cmic_init(unit);

    /* Pull reset line */
    ioerr += READ_CMIC_CONFIGr(unit, &cmic_config);
    CMIC_CONFIGr_RESET_CPSf_SET(cmic_config, 1);
    ioerr += WRITE_CMIC_CONFIGr(unit, cmic_config);

    /* Wait for all tables to initialize */
    BMD_SYS_USLEEP(wait_usec);

    /* Re-initialize endian mode after reset */
    ioerr += cdk_xgs_cmic_init(unit);

    /* Reset all blocks */
    CMIC_SOFT_RESET_REGr_CLR(cmic_sreset);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);

    /* Bring PLL blocks out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_XG_PLL_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_G2P51_RST_Lf_SET(cmic_sreset,1);
    CMIC_SOFT_RESET_REGr_CMIC_G2P50_RST_Lf_SET(cmic_sreset,1);
    CMIC_SOFT_RESET_REGr_CMIC_GX12_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_GX2_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(50);

    /* Initialize LC PLL */
    ioerr += bcm56218_a0_lcpll_init(unit);

    /* Bring remaining blocks out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_FP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_GP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_IP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_EP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_MMU_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(wait_usec);

    /*
     * BCM56218 ring map
     *
     * ring0 [00] : IPIPE[7] -> IPIPE_HI[8]
     * ring1 [01] : EPIPE[9] -> EPIPE_HI[10]
     * ring2 [10] : gsport0[1] -> gport0[2] ->
     *              gport1[3] ->  gport2[4] -> gport3[5] -> MMU[6]
     * ring3 [11] : bsafe[11]
     *
     * 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1 0
     * 0000__XXXX__1101__0100__0010__1010__1010__10XX
     */
    CMIC_SBUS_RING_MAPr_SET(ring_map, 0x0ad42aaa);
    ioerr += WRITE_CMIC_SBUS_RING_MAPr(unit, ring_map);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

#endif /* CDK_CONFIG_INCLUDE_BCM56218_A0 */
