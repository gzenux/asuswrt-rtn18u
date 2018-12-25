#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56634_B0 == 1

/*
 * $Id: bcm56634_b0_bmd_attach.c,v 1.2 Broadcom SDK $
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

#include <cdk/chip/bcm56634_b0_defs.h>
#include <cdk/arch/xgs_chip.h>
#include <cdk/cdk_assert.h>

#include "bcm56634_b0_bmd.h"

#if BMD_CONFIG_INCLUDE_PHY == 1

#include <phy/phy_buslist.h>

static phy_bus_t *bcm56526_phy_bus[] = {
#ifdef PHY_BUS_BCM56634_MIIM_INT_INSTALLED
    &phy_bus_bcm56634_miim_int,
#endif
#ifdef PHY_BUS_BCM956526K29S_MIIM_EXT_INSTALLED
    &phy_bus_bcm956526k29s_miim_ext,
#endif
    NULL
};

static phy_bus_t *bcm56521_phy_bus[] = {
#ifdef PHY_BUS_BCM56634_MIIM_INT_INSTALLED
    &phy_bus_bcm56634_miim_int,
#endif
#ifdef PHY_BUS_BCM956521K_MIIM_EXT_INSTALLED
    &phy_bus_bcm956521k_miim_ext,
#endif
    NULL
};

static phy_bus_t *bcm56630_phy_bus[] = {
#ifdef PHY_BUS_BCM56634_MIIM_INT_INSTALLED
    &phy_bus_bcm56634_miim_int,
#endif
#ifdef PHY_BUS_BCM956685K24TS_MIIM_EXT_INSTALLED
    &phy_bus_bcm956685k24ts_miim_ext,
#endif
    NULL
};

static phy_bus_t *bcm56634_phy_bus[] = {
#ifdef PHY_BUS_BCM56634_MIIM_INT_INSTALLED
    &phy_bus_bcm56634_miim_int,
#endif
#ifdef PHY_BUS_BCM956634K49S_MIIM_EXT_INSTALLED
    &phy_bus_bcm956634k49s_miim_ext,
#endif
    NULL
};

static phy_bus_t *bcm56636_phy_bus[] = {
#ifdef PHY_BUS_BCM56634_MIIM_INT_INSTALLED
    &phy_bus_bcm56634_miim_int,
#endif
#ifdef PHY_BUS_BCM956636K25S_MIIM_EXT_INSTALLED
    &phy_bus_bcm956636k25s_miim_ext,
#endif
    NULL
};

static phy_bus_t *bcm56638_phy_bus[] = {
#ifdef PHY_BUS_BCM56634_MIIM_INT_INSTALLED
    &phy_bus_bcm56634_miim_int,
#endif
#ifdef PHY_BUS_BCM956638K8XS_MIIM_EXT_INSTALLED
    &phy_bus_bcm956638k8xs_miim_ext,
#endif
    NULL
};

static phy_bus_t *bcm56639_phy_bus[] = {
#ifdef PHY_BUS_BCM56634_MIIM_INT_INSTALLED
    &phy_bus_bcm56634_miim_int,
#endif
#ifdef PHY_BUS_BCM956639K25S_MIIM_EXT_INSTALLED
    &phy_bus_bcm956639k25s_miim_ext,
#endif
    NULL
};

#define PHY_BUS_SET(_u,_p,_b) bmd_phy_bus_set(_u,_p,_b)

#else

#define PHY_BUS_SET(_u,_p,_b)

#endif

int
bcm56634_b0_bmd_attach(int unit)
{
    int port;
    uint32_t port_type_xe = 0;
    cdk_pbmp_t pbmp, pbmp_ge;
#if BMD_CONFIG_INCLUDE_PHY == 1
    phy_bus_t **phy_bus = bcm56634_phy_bus;
#endif

    if(!CDK_DEV_EXISTS(unit)) {
        return CDK_E_UNIT;
    }

    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_SPORT, &pbmp_ge);
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPORT, &pbmp);
    CDK_PBMP_OR(pbmp_ge, pbmp);
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_XQPORT, &pbmp);
    CDK_PBMP_OR(pbmp_ge, pbmp);

#if BMD_CONFIG_INCLUDE_PHY == 1
    CDK_XGS_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPORT, &pbmp);
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XQ0_XE) {
        phy_bus = bcm56639_phy_bus;
        if (CDK_PBMP_IS_NULL(pbmp)) {
            phy_bus = bcm56638_phy_bus;
        }
    } else if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XQ4_XE) {
        phy_bus = bcm56526_phy_bus;
    } else if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XQ3_XE) {
        phy_bus = bcm56636_phy_bus;
    } else if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_NO_ESM) {
        if (CDK_PBMP_MEMBER(pbmp_ge, 2)) {
            phy_bus = bcm56521_phy_bus;
        } else {
            phy_bus = bcm56630_phy_bus;
        }
    }
#endif

    CDK_PBMP_ITER(pbmp_ge, port) {
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
    port_type_xe = BMD_PORT_XE;
#endif

    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XQ0_XE) {
        BMD_PORT_PROPERTIES(unit, 30) = port_type_xe;
    }
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XQ2_XE) {
        BMD_PORT_PROPERTIES(unit, 38) = port_type_xe;
    }
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XQ3_XE) {
        BMD_PORT_PROPERTIES(unit, 42) = port_type_xe;
    }
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XQ4_XE) {
        BMD_PORT_PROPERTIES(unit, 46) = port_type_xe;
    }
    if (CDK_XGS_FLAGS(unit) & CHIP_FLAG_XQ5_XE) {
        BMD_PORT_PROPERTIES(unit, 50) = port_type_xe;
    }

    port = CMIC_PORT;
    CDK_ASSERT(port < BMD_CONFIG_MAX_PORTS);
    BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_CPU;

    BMD_DEV_FLAGS(unit) |= BMD_DEV_ATTACHED;

    return 0; 
}
#endif /* CDK_CONFIG_INCLUDE_BCM56634_B0 */
