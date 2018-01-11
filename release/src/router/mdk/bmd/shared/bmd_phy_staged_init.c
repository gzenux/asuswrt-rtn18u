/*
 * $Id: bmd_phy_staged_init.c,v 1.2 Broadcom SDK $
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
 *
 *
 * BMD Staged PHY Initialization
 * -----------------------------
 *
 * This module is designed to reduce PHY initialization time by
 * allowing PHY initialization to be done in separate stages, which
 * are completed for all PHYs before moving to the next init stage.
 * The two main advantages are:
 *
 *   1) Support for PHY firmware broadcast
 *   2) Reduce impact of wait loops
 *
 * The staged initialization is done via PhyConfig_InitStage, where
 * the current stage is supplied as a parameter.  Each PHY driver
 * determines how many init stages are required for a particular PHY.
 * When all stages are completed, the driver should return
 * CDK_E_UNAVAIL for any subsequent calls.
 *
 * For proper broadcast support the PHY driver must support
 * PhyConfig_BcastAddr, which returns the broadcast domain of the PHY
 * bus driver.  Based on this, the init stage control module will mark
 * one PHY in each domain as the master (PHY_F_BCAST_MSTR), and this
 * information can then be used by the PHY driver to determine what to
 * do at each init stage, for example:
 *
 *   Stage 1: Enter broadcast mode (all instances)
 *   Stage 2: Download firmware (master only via broadcast)
 *   Stage 3: Exit broadcast mode (all instances)
 *   Stage 4: Start firmware microcontroller
 *   Stage 5: Additional initialization as needed
 *
 * If the PHY loads firmware from an externa ROM, the staged init can
 * optimize the wait loops as shown in thew following example:
 *
 *   Stage 1: Initiate ROM load
 *   Stage 2: Wait for ROM load completion
 *   Stage 3: Start firmware microcontroller
 *   Stage 4: Wait for CRC calculation
 *   Stage 5: Additional initialization as needed
 *
 * The advantage is that all PHYs load firmware in parallel, so once
 * the first PHY has completed the download seqeunce, it is very
 * likely that all other PHYs are done as well.  Likewise, if CRC
 * calculation is done by the firmware, then this can be done in
 * parallel.
 *
 * If a PHY driver in the PHY chain does not support staged
 * inititialization, then the normal init function will be called.
 * Drivers that support staged init may still have their normal init
 * function called, if they are downstream from a driver that does not
 * support staged init.  In this case the driver should turn off
 * staged init (clear PHY_F_STAGED_INIT flag) and perform standard
 * initialization.
 *
 */

#include <bmd/bmd.h>
#include <bmd/bmd_phy_ctrl.h>
#include <bmd/bmd_phy.h>

#if BMD_CONFIG_INCLUDE_PHY == 1

#include <phy/phy.h>

typedef struct _bcast_sig_s {
    const char *drv_name;
    const char *bus_name;
    uint32_t addr;
} _bcast_sig_t;

#define MAX_BCAST_SIG   8
#define MAX_INIT_STAGE  8

#endif

int 
bmd_phy_staged_init(int unit, cdk_pbmp_t *pbmp)
{
    int rv = CDK_E_NONE;
#if BMD_CONFIG_INCLUDE_PHY == 1
    int port, idx, found;
    phy_ctrl_t *pc;
    uint32_t addr;
    _bcast_sig_t bcast_sig[MAX_BCAST_SIG];
    int num_sig, stage, done;

    num_sig = 0;
    CDK_PBMP_ITER(*pbmp, port) {
        pc = BMD_PORT_PHY_CTRL(unit, port);
        for (; pc != NULL; pc = pc->next) {
            /* Let driver know that staged init is being used */
            PHY_CTRL_FLAGS(pc) |= PHY_F_STAGED_INIT;
            /* Mark as broadcast slave by default */
            PHY_CTRL_FLAGS(pc) &= ~PHY_F_BCAST_MSTR;
            /* Get broadcast signature */
            rv = PHY_CONFIG_GET(pc, PhyConfig_BcastAddr, &addr, NULL);
            if (CDK_FAILURE(rv)) {
                continue;
            }
            if (pc->drv == NULL ||  pc->drv->drv_name == NULL) {
                continue;
            }
            if (pc->bus == NULL ||  pc->bus->drv_name == NULL) {
                continue;
            }
            /* Check if broadcast signature exists */
            found = 0;
            for (idx = 0; idx < num_sig; idx++) {
                if (bcast_sig[idx].drv_name == pc->drv->drv_name &&
                    bcast_sig[idx].bus_name == pc->bus->drv_name &&
                    bcast_sig[idx].addr == addr) {
                    found = 1;
                    break;
                }
            }
            if (found) {
                continue;
            }
            if (idx >= MAX_BCAST_SIG) {
                return CDK_E_FAIL;
            }
            /* Add new broadcast signature */
            bcast_sig[idx].drv_name = pc->drv->drv_name;
            bcast_sig[idx].bus_name = pc->bus->drv_name;
            bcast_sig[idx].addr = addr;
            CDK_VERB(("PHY init: new bcast sig: %s %s 0x%04"PRIx32"\n",
                      bcast_sig[idx].drv_name,
                      bcast_sig[idx].bus_name,
                      bcast_sig[idx].addr));
            num_sig++;
            /* Mark as master for this broadcast domain */
            PHY_CTRL_FLAGS(pc) |= PHY_F_BCAST_MSTR;
        }
    }

    /* Reset all PHYs */
    CDK_PBMP_ITER(*pbmp, port) {
        pc = BMD_PORT_PHY_CTRL(unit, port);
        if (pc == NULL) {
            continue;
        }
        rv = PHY_RESET(pc);
        if (CDK_FAILURE(rv)) {
            return rv;
        }
    }

    /* Perform reset callbacks */
    if (phy_reset_cb) {
        CDK_PBMP_ITER(*pbmp, port) {
            pc = BMD_PORT_PHY_CTRL(unit, port);
            if (pc == NULL) {
                continue;
            }
            rv = phy_reset_cb(pc);
            if (CDK_FAILURE(rv)) {
                return rv;
            }
        }
    }

    /* Repeat staged initialization until no more work */
    stage = 0;
    do {
        CDK_VERB(("PHY init: stage %d\n", stage));
        done = 1;
        CDK_PBMP_ITER(*pbmp, port) {
            CDK_VVERB(("PHY init: stage %d, port %d\n", stage, port));
            pc = BMD_PORT_PHY_CTRL(unit, port);
            for (; pc != NULL; pc = pc->next) {
                rv = PHY_CONFIG_SET(pc, PhyConfig_InitStage, stage, NULL);
                if (rv == CDK_E_UNAVAIL) {
                    /* Perform standard init if stage 0 is unsupported */
                    if (stage == 0) {
                        rv = PHY_INIT(pc);
                        if (CDK_FAILURE(rv)) {
                            return rv;
                        }
                        while (pc->next != NULL) {
                            pc = pc->next;
                        }
                    }
                    rv = CDK_E_NONE;
                    continue;
                }
                if (CDK_FAILURE(rv)) {
                    return rv;
                }
                done = 0;
            }
        }
        /* Add safety guard against loops */
        if (++stage > MAX_INIT_STAGE) {
            return CDK_E_INTERNAL;
        }
    } while (!done);

    /* Perform init callbacks */
    if (phy_init_cb) {
        CDK_PBMP_ITER(*pbmp, port) {
            pc = BMD_PORT_PHY_CTRL(unit, port);
            if (pc == NULL) {
                continue;
            }
            rv = phy_init_cb(pc);
            if (CDK_FAILURE(rv)) {
                return rv;
            }
        }
    }
#endif
    return rv;
}
