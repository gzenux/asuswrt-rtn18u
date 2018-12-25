#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56624_B0 == 1

/*
 * $Id: bcm56624_b0_bmd_attach.c,v 1.8 Broadcom SDK $
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
#include <bmd/bmd_phy_ctrl.h>

#include <cdk/chip/bcm56624_b0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_assert.h>

#include "bcm56624_b0_bmd.h"

#if BMD_CONFIG_INCLUDE_PHY == 1

#include <phy/phy_buslist.h>

static phy_bus_t *bcm56620_phy_bus[] = {
#ifdef PHY_BUS_BCM56624_MIIM_INT_INSTALLED
    &phy_bus_bcm56624_miim_int,
#endif
#ifdef PHY_BUS_BCM956620K24S_MIIM_EXT_INSTALLED
    &phy_bus_bcm956620k24s_miim_ext,
#endif
    NULL
};

static phy_bus_t *bcm56624_phy_bus[] = {
#ifdef PHY_BUS_BCM56624_MIIM_INT_INSTALLED
    &phy_bus_bcm56624_miim_int,
#endif
#ifdef PHY_BUS_BCM956624K49S_MIIM_EXT_INSTALLED
    &phy_bus_bcm956624k49s_miim_ext,
#endif
    NULL
};

static phy_bus_t *bcm56626_phy_bus[] = {
#ifdef PHY_BUS_BCM56624_MIIM_INT_INSTALLED
    &phy_bus_bcm56624_miim_int,
#endif
#ifdef PHY_BUS_BCM956626K25S_MIIM_EXT_INSTALLED
    &phy_bus_bcm956626k25s_miim_ext,
#endif
    NULL
};

static phy_bus_t *bcm56628_phy_bus[] = {
#ifdef PHY_BUS_BCM56624_MIIM_INT_INSTALLED
    &phy_bus_bcm56624_miim_int,
#endif
#ifdef PHY_BUS_BCM956628K8XS_MIIM_EXT_INSTALLED
    &phy_bus_bcm956628k8xs_miim_ext,
#endif
    NULL
};

static phy_bus_t *bcm56629_phy_bus[] = {
#ifdef PHY_BUS_BCM56624_MIIM_INT_INSTALLED
    &phy_bus_bcm56624_miim_int,
#endif
#ifdef PHY_BUS_BCM956629K24S_MIIM_EXT_INSTALLED
    &phy_bus_bcm956629k24s_miim_ext,
#endif
    NULL
};

#define PHY_BUS_SET(_u,_p,_b) bmd_phy_bus_set(_u,_p,_b)

#else

#define PHY_BUS_SET(_u,_p,_b)

#endif

int
bcm56624_b0_bmd_attach(int unit)
{
    int port;
    cdk_pbmp_t pbmp;
#if BMD_CONFIG_INCLUDE_PHY == 1
    phy_bus_t **phy_bus = bcm56624_phy_bus;
#endif

    if(!CDK_DEV_EXISTS(unit)) {
        return CDK_E_UNIT;
    }

#if BMD_CONFIG_INCLUDE_PHY == 1
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_NO_ESM) {
        phy_bus = bcm56620_phy_bus;
    }
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XG23_16G) {
        phy_bus = bcm56626_phy_bus;
        if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XG01_16G) {
            phy_bus = bcm56628_phy_bus;
            if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XG_MIXED) {
                phy_bus = bcm56629_phy_bus;
            }
        }
    }
#endif

    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_SPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        CDK_ASSERT(port < BMD_CONFIG_MAX_PORTS);
        BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_GE;
        PHY_BUS_SET(unit, port, phy_bus);
    }

    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XGPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        CDK_ASSERT(port < BMD_CONFIG_MAX_PORTS);
        BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_GE;
        PHY_BUS_SET(unit, port, phy_bus);
    }

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GXPORT, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        CDK_ASSERT(port < BMD_CONFIG_MAX_PORTS);
#if BMD_CONFIG_INCLUDE_HIGIG == 1
        BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_HG;
#else
        BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
#endif
        PHY_BUS_SET(unit, port, phy_bus);
    }
#endif

#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XG01_16G) {
        BMD_PORT_PROPERTIES(unit, 2) = BMD_PORT_XE;
        BMD_PORT_PROPERTIES(unit, 14) = BMD_PORT_XE;
        PHY_BUS_SET(unit, 2, phy_bus);
        PHY_BUS_SET(unit, 14, phy_bus);
    }
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XG23_16G) {
        BMD_PORT_PROPERTIES(unit, 26) = BMD_PORT_XE;
        BMD_PORT_PROPERTIES(unit, 27) = BMD_PORT_XE;
        PHY_BUS_SET(unit, 26, phy_bus);
        PHY_BUS_SET(unit, 27, phy_bus);
    }
#endif

    port = CMIC_PORT;
    CDK_ASSERT(port < BMD_CONFIG_MAX_PORTS);
    BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_CPU;

    BMD_DEV_FLAGS(unit) |= BMD_DEV_ATTACHED;

    return 0; 
}
#endif /* CDK_CONFIG_INCLUDE_BCM56624_B0 */
