/*
 * $Id: bmd_phy_probe_default.c,v 1.6 Broadcom SDK $
 *
 * $Copyright: Copyright 2009 Broadcom Corporation.
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
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$1,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 */

#include <bmd/bmd.h>
#include <bmd/bmd_device.h>
#include <bmd/bmd_phy_ctrl.h>

#include <cdk/cdk_string.h>

#if BMD_CONFIG_INCLUDE_PHY == 1

#include <phy/phy.h>

/* 
 * We do not want to rely on dynamic memory allocation,
 * so we allocate phy_ctrl blocks from a static pool.
 * The 'bus' member of the structure indicates whether
 * the block is free or in use.
 */
#define MAX_PHYS_PER_UNIT (BMD_CONFIG_MAX_PORTS * BMD_CONFIG_MAX_PHYS)
/* CONFIG_MDK_BCA_BEGIN */
#ifdef BCM_MDK_OS_DEP
phy_ctrl_t *_phy_ctrl_dev;
#else
phy_ctrl_t _phy_ctrl_dev[BMD_CONFIG_MAX_UNITS * MAX_PHYS_PER_UNIT];
#endif
/* CONFIG_MDK_BCA_END */


static phy_ctrl_t *
phy_ctrl_alloc(void)
{
    int idx;
    phy_ctrl_t *pc;

	/* CONFIG_MDK_BCA_BEGIN */
#ifdef BCM_MDK_OS_DEP
		for (idx = 0, pc = &_phy_ctrl_dev[0]; idx < (BMD_CONFIG_MAX_UNITS * MAX_PHYS_PER_UNIT); idx++, pc++) {
#else
		for (idx = 0, pc = &_phy_ctrl_dev[0]; idx < COUNTOF(_phy_ctrl_dev); idx++, pc++) {
#endif
	/* CONFIG_MDK_BCA_END */
        if (pc->bus == 0) {
            return pc;
        }
    }
    return NULL;
}

static void
phy_ctrl_free(phy_ctrl_t *pc)
{
    pc->bus = 0;
}

/*
 * Probe all PHY buses associated with BMD device
 */
int 
bmd_phy_probe_default(int unit, int port, phy_driver_t **phy_drv)
{
    phy_bus_t **bus;
    phy_driver_t **drv;
    phy_ctrl_t pc_probe;
    phy_ctrl_t *pc;
    int rv;

    /* Remove any existing PHYs on this port */
    while ((pc = bmd_phy_del(unit, port)) != 0) {
        phy_ctrl_free(pc);;
    }

    /* Bail if not PHY driver list is provided */
    if (phy_drv == NULL) {
        return CDK_E_NONE;
    }

    /* Check that we have PHY bus list */
    bus = BMD_PORT_PHY_BUS(unit, port);
    if (bus == NULL) {
        return CDK_E_CONFIG;
    }

    /* Loop over PHY buses for this port */
    while (*bus != NULL) {
        drv = phy_drv;
        /* Probe all PHY drivers on this bus */
        while (*drv != NULL) {
            /* Initialize PHY control used for probing */
            CDK_MEMSET(&pc_probe, 0, sizeof(pc_probe));
            pc_probe.unit = unit;
            pc_probe.port = port;
            pc_probe.bus = *bus;
            pc_probe.drv = *drv;

/* A compile error is generated here with the 4.6 compiler if 
   -Wno-error=address is not specified in the Makefile. See:
   http://archives.postgresql.org/pgsql-hackers/2011-10/msg01020.php
*/
            if (CDK_SUCCESS(PHY_PROBE(&pc_probe))) {
                /* Found known PHY on bus */
                pc = phy_ctrl_alloc();
                if (pc == NULL) {
                    return CDK_E_MEMORY;
                }
                /* Use macro instead of assignment to avoid calls to 'memcpy' */
                CDK_MEMCPY(pc, &pc_probe, sizeof(*pc));
                /* Install PHY */
                rv = bmd_phy_add(unit, port, pc);
                if (CDK_FAILURE(rv)) {
                    return rv;
                }
                /* Move to next bus */
                break;
            }
            drv++;
        }
        bus++;
    }
    return CDK_E_NONE;
}

#endif /* BMD_CONFIG_INCLUDE_PHY */
