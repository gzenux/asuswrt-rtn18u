/*
 * $Id: bmd_phy_ctrl.h,v 1.8 Broadcom SDK $
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

#ifndef __BMD_PHY_CTRL_H__
#define __BMD_PHY_CTRL_H__

#include <bmd_config.h>

#if BMD_CONFIG_INCLUDE_PHY == 1

#include <phy/phy.h>
#include <phy/phy_drvlist.h>

/* Allow backward comaptibility */
#define BMD_PHY_DRVLIST_INSTALLED

/* Callback used by bmd_phy_reset() */
extern int (*phy_reset_cb)(phy_ctrl_t *pc);

/* Callback used by bmd_phy_init() */
extern int (*phy_init_cb)(phy_ctrl_t *pc);

typedef struct bmd_phy_port_info_s {
    /* List of default PHY buses available for this port */
    phy_bus_t **phy_bus;
    /* Pointer to first (outermost) PHY */
    phy_ctrl_t *phy_ctrl;
} bmd_phy_port_info_t;

typedef struct bmd_phy_info_s {
    bmd_phy_port_info_t phy_port_info[BMD_CONFIG_MAX_PORTS];
} bmd_phy_info_t;

/* CONFIG_MDK_BCA_BEGIN */
#ifdef BCM_MDK_OS_DEP
extern bmd_phy_info_t *bmd_phy_info;
#else
extern bmd_phy_info_t bmd_phy_info[];
#endif
/* CONFIG_MDK_BCA_END */

/* Default list of PHY drivers based on PHY library configuration */
extern phy_driver_t *bmd_phy_drv_list[];

/* CONFIG_MDK_BCA_BEGIN */
#ifdef BCM_MDK_OS_DEP
extern phy_ctrl_t *_phy_ctrl_dev;
#else
extern phy_ctrl_t _phy_ctrl_dev[];
#endif
/* CONFIG_MDK_BCA_END */

typedef int (*bmd_phy_probe_func_t)(int, int, phy_driver_t **);

#define BMD_PHY_INFO(_u) bmd_phy_info[_u]

#define BMD_PHY_PORT_INFO(_u,_p) BMD_PHY_INFO(_u).phy_port_info[_p]

#define BMD_PORT_PHY_BUS(_u,_p) BMD_PHY_PORT_INFO(_u,_p).phy_bus
#define BMD_PORT_PHY_CTRL(_u,_p) BMD_PHY_PORT_INFO(_u,_p).phy_ctrl

/*
 * Configure PHY buses
 *
 * Note that the default buses are installed by bmd_attach().
 */
extern int
bmd_phy_bus_set(int unit, int port, phy_bus_t **bus_list);

/*
 * Utility function for PHY probing function
 */
extern int
bmd_phy_bus_get(int unit, int port, phy_bus_t ***bus_list);

extern int
bmd_phy_add(int unit, int port, phy_ctrl_t *pc);

extern phy_ctrl_t *
bmd_phy_del(int unit, int port);

/*
 * Install PHY probing function and drivers
 */
extern int 
bmd_phy_probe_init(bmd_phy_probe_func_t probe, phy_driver_t **drv_list);

/* 
 * Default PHY probing function.
 *
 * Note that this function is not referenced directly from the BMD,
 * but it can be installed using bmd_phy_probe_init().
 */
extern int 
bmd_phy_probe_default(int unit, int port, phy_driver_t **drv_list);

/*
 * Register PHY reset callback function.
 *
 * The callback function can be used for board specific configuration
 * like XAUI lane remapping and/or polarity flip.
 */
extern int 
bmd_phy_reset_cb_register(int (*reset_cb)(phy_ctrl_t *pc));

/*
 * Register PHY init callback function.
 *
 * The callback function can be used for board specific configuration
 * like LED modes, special MDIX setup and PHY-sepcific extensions.
 */
extern int 
bmd_phy_init_cb_register(int (*init_cb)(phy_ctrl_t *pc));

#endif /* BMD_CONFIG_INCLUDE_PHY */

#endif /* __BMD_PHY_CTRL_H__ */
