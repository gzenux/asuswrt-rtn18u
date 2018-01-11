/*
 * $Id: bmd_phy_ctrl.c,v 1.32 Broadcom SDK $
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
 * This API abstracts the PHY driver interface to the BMD
 * driver implementations, i.e. a change to the PHY driver 
 * interface should only require changes to this file.
 *
 * If no PHY support is compiled in or no PHYs are detected 
 * for a port, the API will report link up and an invalid
 * (negative) port speed. This behavior simplifies handling
 * of back-to-back MAC configurations as well as simulation
 * environments.
 *
 */

#include <bmd/bmd.h>
#include <bmd/bmd_phy_ctrl.h>
#include <bmd/bmd_phy.h>

#if BMD_CONFIG_INCLUDE_PHY == 1

#include <phy/phy.h>


/* CONFIG_MDK_BCA_BEGIN */
#ifdef BCM_MDK_OS_DEP
bmd_phy_info_t *bmd_phy_info = NULL;
#else
bmd_phy_info_t bmd_phy_info[BMD_CONFIG_MAX_UNITS];
#endif
/* CONFIG_MDK_BCA_END */

static bmd_phy_probe_func_t phy_probe_func;
static phy_driver_t **phy_drv_list;

int
bmd_phy_bus_set(int unit, int port, phy_bus_t **bus_list)
{
    BMD_PORT_PHY_BUS(unit, port) = bus_list;
    return CDK_E_NONE;
}

int
bmd_phy_bus_get(int unit, int port, phy_bus_t ***bus_list)
{
    *bus_list = BMD_PORT_PHY_BUS(unit, port);
    return CDK_E_NONE;
}

int
bmd_phy_add(int unit, int port, phy_ctrl_t *pc)
{
    pc->next = BMD_PORT_PHY_CTRL(unit, port);
    BMD_PORT_PHY_CTRL(unit, port) = pc;
    return CDK_E_NONE;
}

phy_ctrl_t *
bmd_phy_del(int unit, int port)
{
    phy_ctrl_t *pc;

    if ((pc = BMD_PORT_PHY_CTRL(unit, port)) != 0) {
        BMD_PORT_PHY_CTRL(unit, port) = pc->next;
    }
    return pc;
}

int 
bmd_phy_probe_init(bmd_phy_probe_func_t probe, phy_driver_t **drv_list)
{
    phy_probe_func = probe;
    phy_drv_list = drv_list;

    return CDK_E_NONE;
}
#endif

int 
bmd_phy_probe(int unit, int port)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    if (phy_probe_func) {
        return phy_probe_func(unit, port, phy_drv_list);
    }
#endif
    return CDK_E_NONE;
}

int 
bmd_phy_init(int unit, int port)
{
    int rv = CDK_E_NONE;

#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        rv = PHY_RESET(BMD_PORT_PHY_CTRL(unit, port));;
        if (CDK_SUCCESS(rv) && phy_reset_cb) {
            rv = phy_reset_cb(BMD_PORT_PHY_CTRL(unit, port));
        }
        if (CDK_SUCCESS(rv)) {
            rv = PHY_INIT(BMD_PORT_PHY_CTRL(unit, port));
        }
        if (CDK_SUCCESS(rv) && phy_init_cb) {
            rv = phy_init_cb(BMD_PORT_PHY_CTRL(unit, port));
        }
    }
#endif
    return rv;
}

int 
bmd_phy_attach(int unit, int port)
{
    int rv = bmd_phy_probe(unit, port);

#if BMD_CONFIG_INCLUDE_PHY == 1
    if (CDK_SUCCESS(rv)) {
        rv = bmd_phy_init(unit, port);
    }
#endif
    return rv;
}

int 
bmd_phy_detach(int unit, int port)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    if (phy_probe_func) {
        return phy_probe_func(unit, port, NULL);
    }
#endif
    return CDK_E_NONE;
}

int 
bmd_phy_mode_set(int unit, int port, char *name, int mode, int enable)
{
    int rv = CDK_E_NONE;

#if BMD_CONFIG_INCLUDE_PHY == 1
    phy_ctrl_t *pc = BMD_PORT_PHY_CTRL(unit, port);

    while (pc != NULL) {
        if (name && pc->drv && pc->drv->drv_name &&
            CDK_STRSTR(pc->drv->drv_name, name) == NULL) {
            pc = pc->next;
            continue;
        }
        switch (mode) {
        case BMD_PHY_MODE_WAN:
            rv = PHY_CONFIG_SET(pc, PhyConfig_Mode,
                                enable ? PHY_MODE_WAN : PHY_MODE_LAN, NULL);
            if (!enable && rv == CDK_E_UNAVAIL) {
                rv = CDK_E_NONE;
            }
            break;
        case BMD_PHY_MODE_2LANE:
            if (enable) {
                PHY_CTRL_FLAGS(pc) |= PHY_F_2LANE_MODE;
            } else {
                PHY_CTRL_FLAGS(pc) &= ~PHY_F_2LANE_MODE;
            }
            break;
        case BMD_PHY_MODE_SERDES:
            if (enable) {
                PHY_CTRL_FLAGS(pc) |= PHY_F_SERDES_MODE;
            } else {
                PHY_CTRL_FLAGS(pc) &= ~PHY_F_SERDES_MODE;
            }
            break;
        default:
            rv = CDK_E_PARAM;
            break;
        }
        break;
    }
#endif
    return rv;
}

int 
bmd_phy_notify_mac_enable(int unit, int port, int enable)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    phy_event_t event = (enable) ? PhyEvent_MacEnable : PhyEvent_MacDisable;
    phy_ctrl_t *pc = BMD_PORT_PHY_CTRL(unit, port);

    if (pc) {
        /* Get innermost PHY */
        while (pc->next) {
            pc = pc->next;
        }
        return PHY_NOTIFY(pc, event);
    }
#endif
    return CDK_E_NONE;
}

int 
bmd_phy_notify_mac_loopback(int unit, int port, int enable)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    phy_ctrl_t *pc = BMD_PORT_PHY_CTRL(unit, port);

    if (pc) {
        /* Get innermost PHY */
        while (pc->next) {
            pc = pc->next;
        }
        if (enable) {
            PHY_CTRL_FLAGS(pc) |= PHY_F_MAC_LOOPBACK;
        } else {
            PHY_CTRL_FLAGS(pc) &= ~PHY_F_MAC_LOOPBACK;
        }
    }
#endif
    return CDK_E_NONE;
}

int 
bmd_phy_link_get(int unit, int port, int *link, int *an_done)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        int rv, an;
        rv = PHY_AUTONEG_GET(BMD_PORT_PHY_CTRL(unit, port), &an);
        if (CDK_SUCCESS(rv)) {
            rv = PHY_LINK_GET(BMD_PORT_PHY_CTRL(unit, port), link, an_done);
            if (an && !an_done) {
                *link = 0;
            }
        }
        return rv;
    }
#endif
    *link = 1;
    *an_done = 1;
    return CDK_E_NONE;
}

int 
bmd_phy_autoneg_set(int unit, int port, int an)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        return PHY_AUTONEG_SET(BMD_PORT_PHY_CTRL(unit, port), an);
    }
#endif
    return CDK_E_NONE;
}

int 
bmd_phy_autoneg_get(int unit, int port, int *an)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        int rt = PHY_AUTONEG_GET(BMD_PORT_PHY_CTRL(unit, port), an);
        return rt;
    }
#endif
    *an = 0;
    return CDK_E_NONE;
}

int 
bmd_phy_speed_set(int unit, int port, uint32_t speed)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        return PHY_SPEED_SET(BMD_PORT_PHY_CTRL(unit, port), speed);
    }
#endif
    return CDK_E_NONE;
}

int 
bmd_phy_speed_get(int unit, int port, uint32_t *speed)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        return PHY_SPEED_GET(BMD_PORT_PHY_CTRL(unit, port), speed);
    }
#endif
    *speed = 0;
    return CDK_E_NONE;
}

int 
bmd_phy_duplex_set(int unit, int port, int duplex)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        return PHY_DUPLEX_SET(BMD_PORT_PHY_CTRL(unit, port), duplex);
    }
#endif
    return CDK_E_NONE;
}

int 
bmd_phy_duplex_get(int unit, int port, int *duplex)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        return PHY_DUPLEX_GET(BMD_PORT_PHY_CTRL(unit, port), duplex);
    }
#endif
    *duplex = 0;
    return CDK_E_NONE;
}

int 
bmd_phy_loopback_set(int unit, int port, int enable)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        return PHY_LOOPBACK_SET(BMD_PORT_PHY_CTRL(unit, port), enable);
    }
#endif
    return enable ? CDK_E_UNAVAIL : CDK_E_NONE;
}

int 
bmd_phy_loopback_get(int unit, int port, int *enable)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        return PHY_LOOPBACK_GET(BMD_PORT_PHY_CTRL(unit, port), enable);
    }
#endif
    *enable = 0;
    return CDK_E_NONE;
}

int 
bmd_phy_remote_loopback_set(int unit, int port, int enable)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    int rv;

    if (BMD_PORT_PHY_CTRL(unit, port)) {
        rv = PHY_CONFIG_SET(BMD_PORT_PHY_CTRL(unit, port), 
                            PhyConfig_RemoteLoopback, enable, NULL);
        if (rv == CDK_E_UNAVAIL && !enable) {
            rv = CDK_E_NONE;
        }
        return rv;
    }
#endif
    return enable ? CDK_E_UNAVAIL : CDK_E_NONE;
}

int 
bmd_phy_remote_loopback_get(int unit, int port, int *enable)
{
    uint32_t val = 0;

#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        int rv = PHY_CONFIG_GET(BMD_PORT_PHY_CTRL(unit, port), 
                                PhyConfig_RemoteLoopback, &val, NULL);
        if (CDK_FAILURE(rv) && rv != CDK_E_UNAVAIL) {
            return rv;
        }
    }
#endif
    *enable = (int)val;
    return CDK_E_NONE;
}

/* CONFIG_MDK_BCA_BEGIN */
int 
bmd_phy_ability_get(int unit, int port, unsigned int *ability)
{
    uint32_t val = 0;

#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        int rv = PHY_ABILITY_GET(BMD_PORT_PHY_CTRL(unit, port), &val);
        if (CDK_FAILURE(rv) && rv != CDK_E_UNAVAIL) {
            return rv;
        }
    }
#endif
    *ability = val;
    return CDK_E_NONE;
}

int 
bmd_phy_reg_get(int unit, int port, int reg, int *val)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        return PHY_BUS_READ(BMD_PORT_PHY_CTRL(unit, port), reg, (uint32_t *)val);
    }
#endif
    return CDK_E_NONE;
}

int 
bmd_phy_reg_set(int unit, int port, int reg, int val)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
	if (BMD_PORT_PHY_CTRL(unit, port)) {
		return PHY_BUS_WRITE(BMD_PORT_PHY_CTRL(unit, port), reg, val);
	}
#endif
	return CDK_E_NONE;
}

#define MII_AUX_MULT_PHY_REG 0x1E
#define MII_AUX_MULT_PHY_SUPER_ISOLATE 0x8
/* TBD: Change this phy specific function. For 6362/6328, use bit-3 of phy reg 0x1E to power down Phy */
int
bmd_phy_admin_state_get(int unit, int port, int *val)
{
//    int reg = MII_CTRL_REG, value;
    int reg = MII_AUX_MULT_PHY_REG, value;
    bmd_phy_reg_get(unit, port, reg, &value);
//    if (value & MII_CTRL_PD)
    if (value & MII_AUX_MULT_PHY_SUPER_ISOLATE)
        *val = 0;
    else
        *val = 1;
    return CDK_E_NONE;
}

/* TBD: Change this phy specific function. For 6362/6328, use bit-3 of phy reg 0x1E to power down Phy */
int 
bmd_phy_admin_state_set(int unit, int port, int val)
{
//    int reg = MII_CTRL_REG, value;
    int reg = MII_AUX_MULT_PHY_REG, value;
    bmd_phy_reg_get(unit, port, reg, &value);
    if (val)
        value &= ~MII_AUX_MULT_PHY_SUPER_ISOLATE;
    else
        value |= MII_AUX_MULT_PHY_SUPER_ISOLATE;
    bmd_phy_reg_set(unit, port, reg, value);
    return CDK_E_NONE;
}

#if 0
int
bmd_phy_autoneg_adv_get(int unit, int port, int *val)
{
    int reg = MII_ANA_REG, value;
	bmd_phy_reg_get(unit, port, reg, &value);
    reg = MII_GB_CTRL_REG;
	bmd_phy_reg_get(unit, port, reg, val);
	*val = (*val << 16) | (value & 0xFFFF);
}

int 
bmd_phy_autoneg_adv_set(int unit, int port, int val)
{
    int reg = MII_ANA_REG, value;
	bmd_phy_reg_get(unit, port, reg, &value);
    value &= ~(MII_ANA_FD_10 | MII_ANA_FD_100 | MII_ANA_HD_10 | MII_ANA_HD_100);
	value |= val & (MII_ANA_FD_10 | MII_ANA_FD_100 | MII_ANA_HD_10 | MII_ANA_HD_100);
	bmd_phy_reg_set(unit, port, reg, value);
    reg = MII_GB_CTRL_REG;
	bmd_phy_reg_get(unit, port, reg, &value);
    value &= ~(MII_GB_CTRL_ADV_1000FD | MII_GB_CTRL_ADV_1000HD);
	value |= ((val >> 16) &(MII_GB_CTRL_ADV_1000FD | MII_GB_CTRL_ADV_1000HD));
	bmd_phy_reg_set(unit, port, reg, value);
}
#endif

/* CONFIG_MDK_BCA_END */
int 
bmd_phy_line_interface_set(int unit, int port, int intf)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    int pref_intf;

    if (BMD_PORT_PHY_CTRL(unit, port)) {
        switch (intf) {
        case BMD_PHY_IF_XFI:
            pref_intf = PHY_IF_XFI;
            break;
        case BMD_PHY_IF_SFI:
            pref_intf = PHY_IF_SFI;
            break;
        case BMD_PHY_IF_KR:
            pref_intf = PHY_IF_KR;
            break;
        case BMD_PHY_IF_CR:
            pref_intf = PHY_IF_CR;
            break;
        case BMD_PHY_IF_HIGIG:
            pref_intf = PHY_IF_HIGIG;
            break;
        default:
            pref_intf = 0;
            break;
        }
        PHY_CTRL_LINE_INTF(BMD_PORT_PHY_CTRL(unit, port)) = pref_intf;
    }
#endif
    return CDK_E_NONE;
}

int 
bmd_phy_line_interface_get(int unit, int port, int *intf)
{
    *intf = 0;

#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        uint32_t val = 0;
        int rv = PHY_STATUS_GET(BMD_PORT_PHY_CTRL(unit, port), 
                                PhyStatus_LineInterface, &val);
        if (CDK_FAILURE(rv) && rv != CDK_E_UNAVAIL) {
            return rv;
        }
        switch (val) {
        case PHY_IF_XFI:
            *intf = BMD_PHY_IF_XFI;
            break;
        case PHY_IF_SFI:
            *intf = BMD_PHY_IF_SFI;
            break;
        case PHY_IF_KR:
            *intf = BMD_PHY_IF_KR;
            break;
        case PHY_IF_CR:
            *intf = BMD_PHY_IF_CR;
            break;
        case PHY_IF_HIGIG:
            *intf = BMD_PHY_IF_HIGIG;
            break;
        default:
            break;
        }
    }
#endif
    return CDK_E_NONE;
}

int 
bmd_phy_eee_set(int unit, int port, int mode)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        uint32_t eee_mode = PHY_EEE_NONE;
        int rv;
        if (mode == BMD_PHY_M_EEE_802_3) {
            eee_mode = PHY_EEE_802_3;
        } else if (mode == BMD_PHY_M_EEE_AUTO) {
            eee_mode = PHY_EEE_AUTO;
        }
        rv = PHY_CONFIG_SET(BMD_PORT_PHY_CTRL(unit, port),
                            PhyConfig_EEE, eee_mode, NULL);
        if (mode == BMD_PHY_M_EEE_OFF && rv == CDK_E_UNAVAIL) {
            rv = CDK_E_NONE;
        }
        return rv;
    }
#endif
    return CDK_E_NONE;
}

int 
bmd_phy_eee_get(int unit, int port, int *mode)
{
    *mode = BMD_PHY_M_EEE_OFF;

#if BMD_CONFIG_INCLUDE_PHY == 1
    if (BMD_PORT_PHY_CTRL(unit, port)) {
        uint32_t eee_mode;
        int rv = PHY_CONFIG_GET(BMD_PORT_PHY_CTRL(unit, port), 
                                PhyConfig_EEE, &eee_mode, NULL);
        if (CDK_FAILURE(rv) && rv != CDK_E_UNAVAIL) {
            return rv;
        }
        if (eee_mode == PHY_EEE_802_3) {
            *mode = BMD_PHY_M_EEE_802_3;
        } else if (eee_mode == PHY_EEE_AUTO) {
            *mode = BMD_PHY_M_EEE_AUTO;
        }
    }
#endif
    return CDK_E_NONE;
}

int 
bmd_phy_fw_helper_set(int unit, int port,
                      int (*fw_helper)(void *, uint32_t, uint32_t, void *))
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    phy_ctrl_t *pc = BMD_PORT_PHY_CTRL(unit, port);

    while (pc != NULL) {
        PHY_CTRL_FW_HELPER(pc) = fw_helper;
        pc = pc->next;
    }
#endif
    return CDK_E_NONE;
}

int 
bmd_phy_fw_info_get(void *ctx, int *unit, int *port, const char **drv_name)
{
#if BMD_CONFIG_INCLUDE_PHY == 1
    phy_ctrl_t *pc = (phy_ctrl_t *)ctx;

    if (unit) {
        *unit = PHY_CTRL_UNIT(pc);
    }
    if (port) {
        *port = PHY_CTRL_PORT(pc);
    }
    if (drv_name && pc->drv) {
        *drv_name = pc->drv->drv_name;
    }
#endif
    return CDK_E_NONE;
}
