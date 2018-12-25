/*
 * $Id: board_bcm56850_10g.c,v 1.1 Broadcom SDK $
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

#include <board/board_config.h>
#include <cdk/cdk_string.h>
#include <phy/phy_buslist.h>

static cdk_port_map_port_t _skip_ports[] = { -1 };

#ifndef _CHIP_DYN_CONFIG 
#define _CHIP_DYN_CONFIG        0
#endif

#define HG2 CDK_DCFG_PORT_MODE_HIGIG2

static cdk_port_config_t _port_configs[] = {
    /* speed flags mode  sys  app */
    {      0,    0,   0,  -1,  -1  },
    {  10000,    0,   0,   1,   1  },
    {  10000,    0,   0,   2,   2  },
    {  10000,    0,   0,   3,   3  },
    {  10000,    0,   0,   4,   4  },
    {  10000,    0,   0,   5,   5  },
    {  10000,    0,   0,   6,   6  },
    {  10000,    0,   0,   7,   7  },
    {  10000,    0,   0,   8,   8  },
    {  10000,    0,   0,   9,   9  },
    {  10000,    0,   0,  10,  10  },
    {  10000,    0,   0,  11,  11  },
    {  10000,    0,   0,  12,  12  },
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
    {  10000,    0,   0,  37,  53  },
    {  10000,    0,   0,  38,  54  },
    {  10000,    0,   0,  39,  55  },
    {  10000,    0,   0,  40,  56  },
    {  10000,    0,   0,  41,  57  },
    {  10000,    0,   0,  42,  58  },
    {  10000,    0,   0,  43,  59  },
    {  10000,    0,   0,  44,  60  },
    {  10000,    0,   0,  45,  61  },
    {  10000,    0,   0,  46,  62  },
    {  10000,    0,   0,  47,  63  },
    {  10000,    0,   0,  48,  64  },
    {  10000,    0,   0,  49,  65  },
    {  10000,    0,   0,  50,  66  },
    {  10000,    0,   0,  51,  67  },
    {  10000,    0,   0,  52,  68  },
    {  10000,    0,   0,  53,  69  },
    {  10000,    0,   0,  54,  70  },
    {  10000,    0,   0,  55,  71  },
    {  10000,    0,   0,  56,  72  },
    {  10000,    0,   0,  57,  73  },
    {  10000,    0,   0,  58,  74  },
    {  10000,    0,   0,  59,  75  },
    {  10000,    0,   0,  60,  76  },
    {  10000,    0,   0,  61,  85  },
    {  10000,    0,   0,  62,  86  },
    {  10000,    0,   0,  63,  87  },
    {  10000,    0,   0,  64,  88  },
    {  10000,    0,   0,  65,  89  },
    {  10000,    0,   0,  66,  90  },
    {  10000,    0,   0,  67,  91  },
    {  10000,    0,   0,  68,  92  },
    {  10000,    0,   0,  69,  93  },
    {  10000,    0,   0,  70,  94  },
    {  10000,    0,   0,  71,  95  },
    {  10000,    0,   0,  72,  96  },
    {  10000,    0,   0,  73,  97  },
    {  10000,    0,   0,  74,  98  },
    {  10000,    0,   0,  75,  99  },
    {  10000,    0,   0,  76, 100  },
    {  10000,    0,   0,  77, 101  },
    {  10000,    0,   0,  78, 102  },
    {  10000,    0,   0,  79, 103  },
    {  10000,    0,   0,  80, 104  },
    {  10000,    0,   0,  81, 105  },
    {  10000,    0,   0,  82, 106  },
    {  10000,    0,   0,  83, 107  },
    {  10000,    0,   0,  84, 108  },
    {  10000,    0,   0,  85, 117  },
    {  10000,    0,   0,  86, 118  },
    {  10000,    0,   0,  87, 119  },
    {  10000,    0,   0,  88, 120  },
    {  10000,    0,   0,  89, 121  },
    {  10000,    0,   0,  90, 122  },
    {  10000,    0,   0,  91, 123  },
    {  10000,    0,   0,  92, 124  },
    {  10000,    0,   0,  93, 125  },
    {  10000,    0,   0,  94, 126  },
    {  10000,    0,   0,  95, 127  },
    {  10000,    0,   0,  96, 128  }
};
                               
#ifdef CDK_CONFIG_ARCH_XGSM_INSTALLED

#include <cdk/arch/xgsm_miim.h>

static uint32_t
_phy_addr(int port)
{
    if (port > 48) {
        return (port - 45) + CDK_XGSM_MIIM_EBUS(2);
    }
    if (port > 24) {
        return (port - 21) + CDK_XGSM_MIIM_EBUS(1);
    }
    return port + 3 + CDK_XGSM_MIIM_EBUS(0);
}

static int 
_read(int unit, uint32_t addr, uint32_t reg, uint32_t *val)
{
    return cdk_xgsm_miim_read(unit, addr, reg, val);
}

static int 
_write(int unit, uint32_t addr, uint32_t reg, uint32_t val)
{
    return cdk_xgsm_miim_write(unit, addr, reg, val);
}

static int
_phy_inst(int port)
{
    return (port - 1) & 3;
}

static phy_bus_t _phy_bus_miim_ext = {
    "bcm56850",
    _phy_addr,
    _read,
    _write,
    _phy_inst
};

#endif /* CDK_CONFIG_ARCH_XGSM_INSTALLED */

static phy_bus_t *_phy_bus[] = {
#ifdef CDK_CONFIG_ARCH_XGSM_INSTALLED
#ifdef PHY_BUS_BCM56850_MIIM_INT_INSTALLED
    &phy_bus_bcm56850_miim_int,
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
    uint32_t tx_pol, rx_map;

    while (lpc) {
        if (lpc->drv == NULL || lpc->drv->drv_name == NULL) {
            return CDK_E_INTERNAL;
        }
        if (CDK_STRSTR(lpc->drv->drv_name, "warpcore") != NULL) {
            /* Invert Tx polarity on all lanes */
            tx_pol = 0x1111;
            rv = PHY_CONFIG_SET(lpc, PhyConfig_XauiTxPolInvert,
                                tx_pol, NULL);
            PHY_VERB(lpc, ("Flip Tx pol (0x%04"PRIx32")\n", tx_pol));
            /* Remap Rx lanes */
            if (PHY_CTRL_PHY_INST(pc) == 0) {
                rx_map = 0x1032;
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
    NULL,
    _CHIP_DYN_CONFIG,
    COUNTOF(_port_configs),
    _port_configs
};

static board_chip_config_t *_chip_configs[] = {
    &_chip_config,
    NULL
};

board_config_t board_bcm56850_10g = {
    "bcm56850_10g",
    _chip_configs,
    &_phy_reset_cb,
    &_phy_init_cb,
};
