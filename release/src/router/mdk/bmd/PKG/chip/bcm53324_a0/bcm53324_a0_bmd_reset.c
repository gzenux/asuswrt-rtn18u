#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53324_A0 == 1

/*
 * $Id: bcm53324_a0_bmd_reset.c,v 1.3 Broadcom SDK $
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

#include <cdk/chip/bcm53324_a0_defs.h>
#include <cdk/cdk_debug.h>

#include "bcm53324_a0_bmd.h"

#define RESET_SLEEP_USEC                100
#define PLL_LOCK_MSEC                   500

static int
bcm53324_a0_lcpll_check(int unit)
{
    int ioerr = 0;
    int msec;
    CMIC_XGXS_PLL_STATUSr_t pll_status;

    /* Wait for LC PLL locks */
    for (msec = 0; msec < PLL_LOCK_MSEC; msec++) {
        ioerr += READ_CMIC_XGXS_PLL_STATUSr(unit, &pll_status);
#if BMD_CONFIG_SIMULATION
        if (msec == 0) break;
#endif
        if (CMIC_XGXS_PLL_STATUSr_CMIC_XG_PLL_LOCKf_GET(pll_status) == 1) {
            break;
        }
        BMD_SYS_USLEEP(1000);
    }
    if (msec >= PLL_LOCK_MSEC) {
        CDK_WARN(("bcm53324_a0_bmd_reset[%d]: "
                  "LC PLL did not lock, status = 0x%08"PRIx32"\n",
                  unit, CMIC_XGXS_PLL_STATUSr_GET(pll_status)));
    }

    return ioerr;
}

int
bcm53324_a0_bmd_reset(int unit)
{
    int ioerr = 0;
    int wait_usec = 10000;
    CMIC_CONFIGr_t cmic_config;
    CMIC_SOFT_RESET_REGr_t cmic_sreset;
    CMIC_SBUS_RING_MAPr_t ring_map;
    CMIC_CHIP_MODE_CONTROLr_t chip_mode;
    CMIC_INTR_WAIT_CYCLESr_t wait_cycles;
    CMIC_QGPHY_QSGMII_CONTROLr_t qg_ctrl;

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
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);

    /* Check PLL lock */
    ioerr += bcm53324_a0_lcpll_check(unit);

    /* Bring QGMII and QGPHY out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_QSGMII2X0_RST_Lf_SET(cmic_sreset,1);
    CMIC_SOFT_RESET_REGr_CMIC_QSGMII2X1_RST_Lf_SET(cmic_sreset,1);
    CMIC_SOFT_RESET_REGr_CMIC_QGPHY0_RST_Lf_SET(cmic_sreset,1);
    CMIC_SOFT_RESET_REGr_CMIC_QGPHY1_RST_Lf_SET(cmic_sreset,1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(50);

    /* Bring remaining blocks out of reset */
    CMIC_SOFT_RESET_REGr_CMIC_GP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_IP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_EP_RST_Lf_SET(cmic_sreset, 1);
    CMIC_SOFT_RESET_REGr_CMIC_MMU_RST_Lf_SET(cmic_sreset, 1);
    ioerr += WRITE_CMIC_SOFT_RESET_REGr(unit, cmic_sreset);
    BMD_SYS_USLEEP(wait_usec);

    /*
     * BCM53324 ring map
     *
     * ring0 [00] : IPIPE[7] -> IPIPE_HI[8]
     * ring1 [01] : EPIPE[9] -> EPIPE_HI[10]
     * ring2 [10] : gport0[2] -> gport1[3] -> gport2[4] -> MMU[6]
     * ring3 [11] 
     *
     * 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1 0
     * 0000__XXXX__1101__0100__0010__1010__1010__10XX
     */
    CMIC_SBUS_RING_MAPr_SET(ring_map, 0x0ad42aaa);
    ioerr += WRITE_CMIC_SBUS_RING_MAPr(unit, ring_map);

    /* Select managed mode */
    READ_CMIC_CHIP_MODE_CONTROLr(unit, &chip_mode);  
    CMIC_CHIP_MODE_CONTROLr_UNMANAGED_MODEf_SET(chip_mode, 0);  
    WRITE_CMIC_CHIP_MODE_CONTROLr(unit, chip_mode);  

    /* Disable fatal error interrupt */
    CMIC_INTR_WAIT_CYCLESr_CLR(wait_cycles);
    WRITE_CMIC_INTR_WAIT_CYCLESr(unit, wait_cycles);

    /* Drive LEDs from CMIC */
    READ_CMIC_QGPHY_QSGMII_CONTROLr(unit, &qg_ctrl);
    CMIC_QGPHY_QSGMII_CONTROLr_SEL_LEDRAM_SERIAL_DATAf_SET(qg_ctrl, 1);
    WRITE_CMIC_QGPHY_QSGMII_CONTROLr(unit, qg_ctrl);

    /* Add delay to ensure that internal PHYs are probed correctly */
    BMD_SYS_USLEEP(100000);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}
#endif /* CDK_CONFIG_INCLUDE_BCM53324_A0 */
