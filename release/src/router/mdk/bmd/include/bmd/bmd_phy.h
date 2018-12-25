/*
 * $Id: bmd_phy.h,v 1.21 Broadcom SDK $
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

#ifndef __BMD_PHY_H__
#define __BMD_PHY_H__

#include <bmd_config.h>
#include <cdk/cdk_chip.h>

/*
 * BMD PHY interface.
 *
 * These functions act as glue for the external PHY driver interface
 * in order to reduce impact in case the external PHY interface
 * changes.
 */

#define BMD_PHY_MODE_WAN        1
#define BMD_PHY_MODE_2LANE      2
#define BMD_PHY_MODE_SCRAMBLE   3
#define BMD_PHY_MODE_SERDES     4

#define BMD_PHY_M_EEE_OFF       0
#define BMD_PHY_M_EEE_802_3     1
#define BMD_PHY_M_EEE_AUTO      2

#define BMD_PHY_IF_DEFAULT      0
#define BMD_PHY_IF_NULL         1
#define BMD_PHY_IF_MII          2
#define BMD_PHY_IF_GMII         3
#define BMD_PHY_IF_SGMII        4
#define BMD_PHY_IF_TBI          5
#define BMD_PHY_IF_XGMII        6
#define BMD_PHY_IF_RGMII        7
#define BMD_PHY_IF_RVMII        8
#define BMD_PHY_IF_XAUI         9
#define BMD_PHY_IF_XLAUI        10
#define BMD_PHY_IF_XFI          11
#define BMD_PHY_IF_SFI          12
#define BMD_PHY_IF_KR           13
#define BMD_PHY_IF_CR           14
#define BMD_PHY_IF_FIBER        15
#define BMD_PHY_IF_HIGIG        16

extern int 
bmd_phy_probe(int unit, int port);

extern int 
bmd_phy_init(int unit, int port);

extern int 
bmd_phy_staged_init(int unit, cdk_pbmp_t *pbmp);

extern int 
bmd_phy_attach(int unit, int port);

extern int 
bmd_phy_detach(int unit, int port);

extern int 
bmd_phy_mode_set(int unit, int port, char *name, int mode, int enable);

extern int 
bmd_phy_notify_mac_enable(int unit, int port, int enable);

extern int 
bmd_phy_notify_mac_loopback(int unit, int port, int enable);

extern int 
bmd_phy_link_get(int unit, int port, int *link, int *an_done);

extern int 
bmd_phy_autoneg_set(int unit, int port, int an);

extern int 
bmd_phy_autoneg_get(int unit, int port, int *an);

extern int 
bmd_phy_speed_set(int unit, int port, uint32_t speed);

extern int 
bmd_phy_speed_get(int unit, int port, uint32_t *speed);

extern int 
bmd_phy_duplex_set(int unit, int port, int duplex);

extern int 
bmd_phy_duplex_get(int unit, int port, int *duplex);

extern int 
bmd_phy_loopback_set(int unit, int port, int enable);

extern int 
bmd_phy_loopback_get(int unit, int port, int *enable);

extern int 
bmd_phy_remote_loopback_set(int unit, int port, int enable);

extern int 
bmd_phy_remote_loopback_get(int unit, int port, int *enable);

/*  CONFIG_MDK_BCA_BEGIN */
extern int 
bmd_phy_reg_set(int unit, int port, int reg, int val);

extern int 
bmd_phy_reg_get(int unit, int port, int reg, int *val);

extern int
bmd_phy_admin_state_get(int unit, int port, int *val);

extern int 
bmd_phy_admin_state_set(int unit, int port, int val);

/*
 * Get Phy abilities.
 *
 * Can be used to set the port properties in bmd device structure
 */
int 
bmd_phy_ability_get(int unit, int port, unsigned int *ability);

#if 0
extern int
bmd_phy_autoneg_adv_get(int unit, int port, int *val);

extern int 
bmd_phy_autoneg_adv_set(int unit, int port, int val);
#endif
/*  CONFIG_MDK_BCA__END */

extern int 
bmd_phy_line_interface_set(int unit, int port, int intf);

extern int 
bmd_phy_line_interface_get(int unit, int port, int *intf);

extern int 
bmd_phy_eee_set(int unit, int port, int mode);

extern int 
bmd_phy_eee_get(int unit, int port, int *mode);

extern int 
bmd_phy_fw_helper_set(int unit, int port,
                      int (*fw_helper)(void *, uint32_t, uint32_t, void *));

extern int 
bmd_phy_fw_info_get(void *ctx, int *unit, int *port, const char **drv_name);

#endif /* __BMD_PHY_H__ */
