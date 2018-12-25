/*
 * $Id: bmd_device.h,v 1.12 Broadcom SDK $
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

#ifndef __BMD_DEVICE_H__
#define __BMD_DEVICE_H__

#include <bmd_config.h>
#include <bmd/bmd_phy.h>

#include <cdk/cdk_chip.h>
#include <bmd/bmd_phy_ctrl.h>

/* Port properties */
#define BMD_PORT_FE             0x1
#define BMD_PORT_GE             0x2
#define BMD_PORT_XE             0x4
#define BMD_PORT_HG             0x8
#define BMD_PORT_CPU            0x10
#define BMD_PORT_ST             0x20
#define BMD_PORT_SCH            0x40
#define BMD_PORT_ASSP           0x80
#define BMD_PORT_FLEX           0x100

#define BMD_PORT_ENET           (BMD_PORT_FE | BMD_PORT_GE | BMD_PORT_XE)
#define BMD_PORT_ALL            (BMD_PORT_ENET | BMD_PORT_HG | BMD_PORT_FLEX)

/* Port status */
#define BMD_PST_DISABLED        0x1
#define BMD_PST_AN_DONE         0x2
#define BMD_PST_LINK_UP         0x4
#define BMD_PST_FORCE_LINK      0x8
#define BMD_PST_FORCE_UPDATE    0x80000000

typedef struct bmd_port_info_s {
    uint32_t properties;
    uint32_t status;
} bmd_port_info_t;

/* Device flags */
#define BMD_DEV_ATTACHED        0x1

/* Maps a port from one space to another (or back if inverse=1) */
typedef int (*bmd_port_map_func_t)(int unit, int port, int inverse);

/* Get a port configuration parameter */
typedef uint32_t (*bmd_port_param_get_func_t)(int unit, int port);

typedef struct bmd_dev_s {

    /* BMD device flags */
    uint32_t flags;

    /* BMD port information */
    bmd_port_info_t port_info[BMD_CONFIG_MAX_PORTS];

    /* Get maximum speed for port (for debug only) */
    bmd_port_param_get_func_t port_speed_max;

    /* Maps physical port to logical port (for debug only) */
    bmd_port_map_func_t port_p2l;

    /* Maps physical port to MMU port (for debug only) */
    bmd_port_map_func_t port_p2m;

} bmd_dev_t;

/* CONFIG_MDK_BCA_BEGIN */
#ifdef BCM_MDK_OS_DEP
#define SHARED_INFO_RESERVED 0x100
typedef struct shared_info_s {
    uint32_t shared_info_init_done; 
    cdk_dev_t *cdk_device;
	bmd_phy_info_t *bmd_phy_info;
	bmd_dev_t *bmd_dev;
	phy_ctrl_t *_phy_ctrl_dev;
} shared_info_t;
#define BMD_CONFIG_MDK_SHARED_SEG_ADDR 0x40000000

#define BMD_CONFIG_PHYCTRL_ELEMS (BMD_CONFIG_MAX_UNITS * BMD_CONFIG_MAX_PORTS * BMD_CONFIG_MAX_PHYS)

#define SHARED_MEMORY_TOTAL_SIZE (SHARED_INFO_RESERVED + \
     (sizeof(cdk_dev_t) * CDK_CONFIG_MAX_UNITS) + ALIGNMENT_SIZE + \
     (sizeof(bmd_phy_info_t) * BMD_CONFIG_MAX_UNITS) + ALIGNMENT_SIZE + \
     (sizeof(bmd_dev_t) * BMD_CONFIG_MAX_UNITS) + ALIGNMENT_SIZE + \
     (sizeof(phy_ctrl_t) * BMD_CONFIG_PHYCTRL_ELEMS) + ALIGNMENT_SIZE)
#endif
/* CONFIG_MDK_BCA_END */

#define BMD_DEV(_u) bmd_dev[_u]

#define BMD_DEV_FLAGS(_u) BMD_DEV(_u).flags
#define BMD_PORT_SPEED_MAX(_u) BMD_DEV(_u).port_speed_max
#define BMD_PORT_P2L(_u) BMD_DEV(_u).port_p2l
#define BMD_PORT_P2M(_u) BMD_DEV(_u).port_p2m
#define BMD_PORT_INFO(_u,_p) BMD_DEV(_u).port_info[_p]
#define BMD_PORT_PROPERTIES(_u,_p) BMD_PORT_INFO(_u,_p).properties
#define BMD_PORT_STATUS(_u,_p) BMD_PORT_INFO(_u,_p).status
#define BMD_PORT_STATUS_SET(_u,_p,_bits) BMD_PORT_STATUS(_u,_p) |= (_bits)
#define BMD_PORT_STATUS_CLR(_u,_p,_bits) BMD_PORT_STATUS(_u,_p) &= ~(_bits)

#define BMD_DEV_VALID(_u) (BMD_DEV(_u).flags & BMD_DEV_ATTACHED)
#define BMD_PORT_VALID(_u,_p) \
    (_p >= 0 && _p < BMD_CONFIG_MAX_PORTS && BMD_PORT_PROPERTIES(_u,_p) != 0)

#define BMD_PORT_ITER(_u,type,iter) \
    for ((iter) = 0; (iter) < BMD_CONFIG_MAX_PORTS; (iter++)) \
        if ((BMD_PORT_INFO(_u,iter).properties) & (type)) 

#define BMD_CHECK_UNIT(_u) \
    if (!BMD_DEV_VALID(_u)) return CDK_E_UNIT;

#define BMD_CHECK_PORT(_u,_p) \
    if (!BMD_PORT_VALID(_u,_p)) return CDK_E_PORT;

#define BMD_CHECK_VLAN(_u,_v) \
    if (_v <= 0 || _v > 4095) return CDK_E_PARAM;

#define BMD_CHECK_DSCP(_u,_v) \
    if (_v < 0 || _v > 63) return CDK_E_PARAM;

#define BMD_CHECK_PRIORITY(_u,_v) \
    if (_v < 0 || _v > 7) return CDK_E_PARAM;


/* CONFIG_MDK_BCA_BEGIN */
#ifdef BCM_MDK_OS_DEP
extern bmd_dev_t *bmd_dev;
#else
extern bmd_dev_t bmd_dev[BMD_CONFIG_MAX_UNITS];
#endif
/* CONFIG_MDK_BCA_END */

extern int
bmd_port_type_pbmp(int unit, uint32_t port_type, cdk_pbmp_t *pbmp);

#endif /* __BMD_DEVICE_H__ */
