#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56850_A0 == 1

/*
 * $Id: bcm56850_a0_bmd_attach.c,v 1.2 Broadcom SDK $
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

#include <cdk/chip/bcm56850_a0_defs.h>
#include <cdk/arch/xgsm_chip.h>
#include <cdk/cdk_debug.h>
#include <cdk/cdk_assert.h>

#include "bcm56850_a0_bmd.h"
#include "bcm56850_a0_internal.h"

#if BMD_CONFIG_INCLUDE_PHY == 1

#include <phy/phy_buslist.h>

static phy_bus_t *bcm56850_phy_bus[] = {
#ifdef PHY_BUS_BCM56850_MIIM_INT_INSTALLED
    &phy_bus_bcm56850_miim_int,
#endif
#ifdef PHY_BUS_BCM956850K_MIIM_EXT_INSTALLED
    &phy_bus_bcm956850k_miim_ext,
#endif
    NULL
};

#define PHY_BUS_SET(_u,_p,_b) bmd_phy_bus_set(_u,_p,_b)

#else

#define PHY_BUS_SET(_u,_p,_b)

#endif

/* Unicast queue base per unit/port */
static int _uc_q_base[BMD_CONFIG_MAX_UNITS][BMD_CONFIG_MAX_PORTS];

#if CDK_CONFIG_INCLUDE_PORT_MAP == 1

static struct _port_map_s {
    cdk_port_map_port_t map[BMD_CONFIG_MAX_PORTS];
} _port_map[BMD_CONFIG_MAX_UNITS];

static void
_init_port_map(int unit)
{
    cdk_pbmp_t pbmp;
    int lport, lport_max = 0;
    int port;

    CDK_MEMSET(&_port_map[unit], -1, sizeof(_port_map[unit]));

    _port_map[unit].map[0] = CMIC_PORT;

    bcm56850_a0_xlport_pbmp_get(unit, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        lport = P2L(unit, port);
        _port_map[unit].map[lport] = port;
        if (lport > lport_max) {
            lport_max = lport;
        }
    }

    CDK_PORT_MAP_SET(unit, _port_map[unit].map, lport_max + 1);
}

#endif

/*
 * The MMU port mappings must be derived from the individual
 * port configurations such as maximum speed and queueing
 * capabilities.
 */
static struct _mmu_port_map_s {
    cdk_port_map_port_t map[BMD_CONFIG_MAX_PORTS];
} _mmu_port_map[BMD_CONFIG_MAX_UNITS];

#define XLPS_PER_PGW            4
#define PGWS_PER_PIPE           4
#define PIPES_PER_DEV           2

#define PORTS_PER_XLP           4
#define PORTS_PER_PGW           (PORTS_PER_XLP * XLPS_PER_PGW)
#define PORTS_PER_PIPE          (PORTS_PER_PGW * PGWS_PER_PIPE) 

static void
_init_mmu_port_map(int unit)
{
    cdk_pbmp_t pbmp;
    int port_count[2];
    int idx, pipe, pgw, port, base_port, mmu_port;

    /* All configured physical ports */
    bcm56850_a0_xlport_pbmp_get(unit, &pbmp);

    /* Clear MMU port map */
    CDK_MEMSET(&_mmu_port_map[unit], -1, sizeof(_mmu_port_map[unit]));

    /* Count ports in each pipe */
    port_count[0] = port_count[1] = 0;
    CDK_PBMP_ITER(pbmp, port) {
        pipe = PORT_IN_Y_PIPE(port) ? 1 : 0;
        port_count[pipe]++;
    }
    /* Sanity check */
    for (pipe = 0; pipe < 2; pipe++) {
        if (port_count[pipe] > NUM_MMU_PORTS/2) {
            CDK_WARN(("bcm56850_a0_bmd_attach[%d]: MMU map error (%d %d)\n",
                      unit, pipe, port_count[pipe]));
        }
    }

    /* Assign MMU port */
    for (pipe = 0; pipe < PIPES_PER_DEV; pipe++) {
        mmu_port = pipe * PORTS_PER_PIPE;
        base_port = mmu_port + 1;
        /* First assign the lowest MMU port number for 100+G ports */
        for (pgw = 0; pgw < PGWS_PER_PIPE; pgw++) {
            port = base_port + (pgw * PORTS_PER_PGW) + ((pgw & 1) ? 20 : 0);
            if (bcm56850_a0_port_speed_max(unit, port) > 42000) {
                _mmu_port_map[unit].map[port] = mmu_port;
                mmu_port++;
            }
        }
        /* Then assign the next lowest MMU port number for 40+G ports */
        for (idx = 0; idx < PORTS_PER_PIPE; idx += 4) {
            port = base_port + idx;
            if (_mmu_port_map[unit].map[port] == -1 &&
                bcm56850_a0_port_speed_max(unit, port) > 20000) {
                _mmu_port_map[unit].map[port] = mmu_port;
                mmu_port++;
            }
        }
        /* Then assign the next lowest MMU port number for 20+G ports */
        for (idx = 0; idx < PORTS_PER_PIPE; idx += 2) {
            port = base_port + idx;
            if (_mmu_port_map[unit].map[port] == -1 &&
                bcm56850_a0_port_speed_max(unit, port) > 10000) {
                _mmu_port_map[unit].map[port] = mmu_port;
                mmu_port++;
            }
        }
        /* Finally assign MMU port number for all other ports */
        for (idx = 0; idx < PORTS_PER_PIPE; idx++) {
            port = base_port + idx;
            if (_mmu_port_map[unit].map[port] == -1 &&
                bcm56850_a0_port_speed_max(unit, port) > 0) {
                _mmu_port_map[unit].map[port] = mmu_port;
                mmu_port++;
            }
        }
    }
}

static int
_uc_q_num_config(int unit)
{
    cdk_pbmp_t mmu_pbmp;
    int port, num_uc_q;
    int base;

    /* Get front-panel ports */
    bcm56850_a0_xlport_pbmp_get(unit, &mmu_pbmp);

    base = 0;
    CDK_PBMP_ITER(mmu_pbmp, port) {
        num_uc_q = bcm56850_a0_mmu_port_uc_queues(unit, port);
        _uc_q_base[unit][port] = base;
        base += (num_uc_q + 3) & ~0x3;
    }
    return 0;
}

int
bcm56850_a0_xlport_pbmp_get(int unit, cdk_pbmp_t *pbmp)
{
    int port;

    CDK_XGSM_BLKTYPE_PBMP_GET(unit, BLKTYPE_XLPORT, pbmp);
    CDK_PBMP_ITER(*pbmp, port) {
        if (BMD_PORT_PROPERTIES(unit, port) == 0) {
            CDK_PBMP_PORT_REMOVE(*pbmp, port);
        }
    }
    return 0;
}

int
bcm56850_a0_p2l(int unit, int port, int inverse)
{
    cdk_pbmp_t pbmp;
    int pp, lp = 1;

    /* Fixed mappings */
    if (port == CMIC_PORT) {
        return CMIC_LPORT;
    }
    if (port == LB_PORT) {
        return LB_LPORT;
    }
    if (inverse && port == LB_LPORT) {
        return LB_PORT;
    }

    /* Use per-port config if available */
    if (CDK_NUM_PORT_CONFIGS(unit) != 0) {
        if (inverse) {
            for (pp = 0; pp < NUM_PHYS_PORTS; pp++) {
                if (port == CDK_PORT_CONFIG_SYS_PORT(unit, pp)) {
                    return pp;
                }
            }
            return -1;
        } else {
            return CDK_PORT_CONFIG_SYS_PORT(unit, port);
        }
    }

    /* By default logical ports are contiguous starting from 1 */
    bcm56850_a0_xlport_pbmp_get(unit, &pbmp);
    CDK_PBMP_ITER(pbmp, pp) {
        if (inverse) {
            if (port == lp) {
                return pp;
            }
        } else {
            if (port == pp) {
                return lp;
            }
        }
        lp++;
    }
    return -1;
}

int
bcm56850_a0_p2m(int unit, int port, int inverse)
{
    int pp;

    /* Fixed mappings */
    if (port == CMIC_PORT) {
        return CMIC_MPORT;
    }
    if (port == LB_PORT) {
        return LB_MPORT;
    }
    if (inverse && port == LB_MPORT) {
        return LB_PORT;
    }

    if (inverse) {
        for (pp = 0; pp < NUM_PHYS_PORTS; pp++) {
            if (port == _mmu_port_map[unit].map[pp]) {
                return pp;
            }
        }
        return -1;
    }
    return _mmu_port_map[unit].map[port];
}

uint32_t
bcm56850_a0_port_speed_max(int unit, int port)
{
    /* Use per-port config if available */
    if (CDK_NUM_PORT_CONFIGS(unit) != 0) {
        return CDK_PORT_CONFIG_SPEED_MAX(unit, port);
    }

    /* Default port speeds for fixed configurations */
    return 10000;
}

int
bcm56850_a0_mmu_port_mc_queues(int unit, int port)
{
    int mport = P2M(unit, port);

    if (mport < 0) {
        return 0;
    }
    if (mport == CMIC_MPORT) {
        return 48;
    }
    if (mport == LB_MPORT) {
        return 8;
    }
    return 10;
}

int
bcm56850_a0_mmu_port_uc_queues(int unit, int port)
{
    int mport = P2M(unit, port);

    if (mport < 0) {
        return 0;
    }
    if (mport == CMIC_MPORT || mport == LB_MPORT) {
        return 0;
    }
    return 10;
}

int
bcm56850_a0_mc_queue_num(int unit, int port, int cosq)
{
    int qnum, mport;

    mport = P2M(unit, port);
    if (mport >= NUM_MMU_PORTS || mport < 0) {
        CDK_WARN(("Unsupported MMU port %d\n", mport));
        return -1;
    }
    if (mport >= 64) {
        mport -= 64;
    }
    qnum = (port >= NUM_PHYS_PORTS/2) ? 568 : 0;
    qnum += (mport * 10);
    return qnum + cosq;
}

int
bcm56850_a0_uc_queue_num(int unit, int port, int cosq)
{
    if (port >= 0 && port < BMD_CONFIG_MAX_PORTS) {
        return _uc_q_base[unit][port] + cosq;
    }
    return -1;
}

int
bcm56850_a0_bmd_attach(int unit)
{
    int port;
    int port_mode;
    uint32_t speed_max;
    cdk_pbmp_t pbmp;
#if BMD_CONFIG_INCLUDE_PHY == 1
    phy_bus_t **phy_bus = bcm56850_phy_bus;
#endif

    if(!CDK_DEV_EXISTS(unit)) {
        return CDK_E_UNIT;
    }

    CDK_XGSM_BLKTYPE_PBMP_GET(unit, BLKTYPE_XLPORT, &pbmp);

    CDK_PBMP_ITER(pbmp, port) {
        CDK_ASSERT(port < BMD_CONFIG_MAX_PORTS);
        speed_max = bcm56850_a0_port_speed_max(unit, port);
        if (speed_max == 0) {
            continue;
        }
        BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_XE;
        port_mode = CDK_PORT_CONFIG_PORT_MODE(unit, port);
        if (port_mode == CDK_DCFG_PORT_MODE_HIGIG ||
            port_mode == CDK_DCFG_PORT_MODE_HIGIG2) {
            BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_HG;
        }
        PHY_BUS_SET(unit, port, phy_bus);
    }

    /* Initialize MMU port mappings */
    _init_mmu_port_map(unit);

#if CDK_CONFIG_INCLUDE_PORT_MAP == 1
    /* Match default API port map to configured logical ports */
    _init_port_map(unit);
#endif

    port = CMIC_PORT;
    CDK_ASSERT(port < BMD_CONFIG_MAX_PORTS);
    BMD_PORT_PROPERTIES(unit, port) = BMD_PORT_CPU;

    /* Initialize debug functions */
    BMD_PORT_SPEED_MAX(unit) = bcm56850_a0_port_speed_max;
    BMD_PORT_P2L(unit) = bcm56850_a0_p2l;
    BMD_PORT_P2M(unit) = bcm56850_a0_p2m;

    BMD_DEV_FLAGS(unit) |= BMD_DEV_ATTACHED;

    /* Configure unicast queues for linked list scheduler (LLS) */
    _uc_q_num_config(unit);

    return 0; 
}
#endif /* CDK_CONFIG_INCLUDE_BCM56850_A0 */
