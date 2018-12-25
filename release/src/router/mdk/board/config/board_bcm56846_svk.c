/*
 * $Id: board_bcm56846_svk.c,v 1.1 Broadcom SDK $
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
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$1,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 */

/*
 * This port configuration is intended for the Trident-based test
 * board equipped with BCM84834 and BCM84740 10G PHYs.
 */

#include <board/board_config.h>
#include <board/sdk56840.h>
#include <cdk/cdk_string.h>
#include <phy/phy_buslist.h>

#if defined(CDK_CONFIG_INCLUDE_BCM56840_B0) && CDK_CONFIG_INCLUDE_BCM56840_B0 == 1
#include <cdk/chip/bcm56840_b0_defs.h>
#define _CHIP_DYN_CONFIG        DCFG_LCPLL_156
#endif

static cdk_port_map_port_t _skip_ports[] = { -1 };

#ifndef _CHIP_DYN_CONFIG 
#define _CHIP_DYN_CONFIG        0
#endif

#define HG2 CDK_DCFG_PORT_MODE_HIGIG2

static cdk_port_config_t _port_configs[] = {
    /* speed flags mode  sys  app */
    {      0,    0,   0,  -1,  -1  },
    {  10000,    0,   0,   1,   9  },
    {  10000,    0,   0,   2,  10  },
    {  10000,    0,   0,   3,  11  },
    {  10000,    0,   0,   4,  12  },
    {  10000,    0,   0,   5,  13  },
    {  10000,    0,   0,   6,  14  },
    {  10000,    0,   0,   7,  15  },
    {  10000,    0,   0,   8,  16  },
    {  10000,    0,   0,   9,  17  },
    {  10000,    0,   0,  10,  18  },
    {  10000,    0,   0,  11,  19  },
    {  10000,    0,   0,  12,  20  },
    {  10000,    0,   0,  13,  21  },
    {  10000,    0,   0,  14,  22  },
    {  10000,    0,   0,  15,  23  },
    {  10000,    0,   0,  16,  24  },
    {  10000,    0,   0,  17,  25  },
    {  10000,    0,   0,  18,  26  },
    {  10000,    0,   0,  19,  27  },
    {  10000,    0,   0,  20,  28  },
    {  10000,    0,   0,  21,  29  },
    {  10000,    0,   0,  22,  30  },
    {  10000,    0,   0,  23,  31  },
    {  10000,    0,   0,  24,  32  },
    {  10000,    0,   0,  25,  33  },
    {  10000,    0,   0,  26,  34  },
    {  10000,    0,   0,  27,  35  },
    {  10000,    0,   0,  28,  36  },
    {  10000,    0,   0,  29,  37  },
    {  10000,    0,   0,  30,  38  },
    {  10000,    0,   0,  31,  39  },
    {  10000,    0,   0,  32,  40  },
    {  10000,    0,   0,  33,  41  },
    {  10000,    0,   0,  34,  42  },
    {  10000,    0,   0,  35,  43  },
    {  10000,    0,   0,  36,  44  },
    {  10000,    0,   0,  37,  45  },
    {  10000,    0,   0,  38,  46  },
    {  10000,    0,   0,  39,  47  },
    {  10000,    0,   0,  40,  48  },
    {  10000,    0,   0,  41,  49  },
    {  10000,    0,   0,  42,  50  },
    {  10000,    0,   0,  43,  51  },
    {  10000,    0,   0,  44,  52  },
    {  10000,    0,   0,  45,  57  },
    {  10000,    0,   0,  46,  58  },
    {  10000,    0,   0,  47,  59  },
    {  10000,    0,   0,  48,  60  },
    {  10000,    0,   0,  49,  61  },
    {  10000,    0,   0,  50,  62  },
    {  10000,    0,   0,  51,  63  },
    {  10000,    0,   0,  52,  64  },
    {  10000,    0,   0,  53,  65  },
    {  10000,    0,   0,  54,  66  },
    {  10000,    0,   0,  55,  67  },
    {  10000,    0,   0,  56,  68  },
};

#ifdef CDK_CONFIG_ARCH_XGS_INSTALLED

#include <cdk/cdk_device.h>
#include <cdk/arch/xgs_miim.h>

#include <phy/phy.h>

static uint32_t
_phy_addr(int port)
{
    if (port > 60) {
        return (port - 41) + CDK_XGS_MIIM_EBUS(2);
    }
    if (port > 56) {
        return (port - 44) + CDK_XGS_MIIM_EBUS(2);
    }
    if (port > 40) {
        return (port - 40) + CDK_XGS_MIIM_EBUS(2);
    }
    if (port > 24) {
        return (port - 24) + CDK_XGS_MIIM_EBUS(1);
    }
    return port - 8 + CDK_XGS_MIIM_EBUS(0);
}

static int 
_read(int unit, uint32_t addr, uint32_t reg, uint32_t *val)
{
    return cdk_xgs_miim_read(unit, addr, reg, val);
}

static int 
_write(int unit, uint32_t addr, uint32_t reg, uint32_t val)
{
    return cdk_xgs_miim_write(unit, addr, reg, val);
}

static int
_phy_inst(int port)
{
    return (port - 1) & 3;
}

phy_bus_t _phy_bus_miim_ext = {
    "bcm56846_svk",
    _phy_addr,
    _read,
    _write,
    _phy_inst
};

#endif /* CDK_CONFIG_ARCH_XGS_INSTALLED */

static phy_bus_t *_phy_bus[] = {
#ifdef CDK_CONFIG_ARCH_XGS_INSTALLED
#ifdef PHY_BUS_BCM56840_MIIM_INT_INSTALLED
    &phy_bus_bcm56840_miim_int,
#endif
    &_phy_bus_miim_ext,
#endif
    NULL
};

static int 
_phy_reset_cb(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    phy_ctrl_t *lpc = pc;
    uint32_t rx_map;

    while (lpc) {
        if (lpc->drv == NULL || lpc->drv->drv_name == NULL) {
            return CDK_E_INTERNAL;
        }
        if (CDK_STRSTR(lpc->drv->drv_name, "warpcore") != NULL) {
            /* Remap Rx lanes */
            if (PHY_CTRL_PHY_INST(pc) == 0) {
                if (PHY_CTRL_PORT(lpc) == 45) {
                    rx_map = 0x3210;
                } else {
                    rx_map = 0x1032;
                }
                rv = PHY_CONFIG_SET(lpc, PhyConfig_XauiRxLaneRemap,
                                    rx_map, NULL);
                PHY_VERB(lpc, ("Remap Rx lanes (0x%04"PRIx32")\n", rx_map));
            }
        }
        lpc = lpc->next;
    }

    return rv;
}

static int 
_phy_init_cb(phy_ctrl_t *pc)
{
    return CDK_E_NONE;
}

static board_chip_config_t _chip_config = {
    _skip_ports,
    _phy_bus,
    sdk56840_ledprog_info,
    _CHIP_DYN_CONFIG,
    COUNTOF(_port_configs),
    _port_configs
};

static board_chip_config_t *_chip_configs[] = {
    &_chip_config,
    NULL
};

board_config_t board_bcm56846_svk = {
    "bcm56846_svk",
    _chip_configs,
    &_phy_reset_cb,
    &_phy_init_cb,
};
