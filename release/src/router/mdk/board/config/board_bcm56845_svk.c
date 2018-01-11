/*
 * $Id: board_bcm56845_svk.c,v 1.1 Broadcom SDK $
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
 * This port configuration is intended for testing the Trident
 * Warpcore SerDes without any external PHYs connected.  The setup
 * matches a lab system with cables hooked up for testing 40G, 20G
 * (DXGXS/RXAUI) and 10G-KR.  Created for a BCM56845-based system, but
 * also works with the latest BCM56846-based system.
 */

#include <board/board_config.h>
#include <board/sdk56840.h>
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
    {  40000,    0,   0,   1,   5  },
    {  40000,    0,   0,   2,   9  },
    {  40000,    0,   0,   3,  13  },
    {  40000,    0,   0,   4,  17  },
    {  40000,    0, HG2,   5,  21  },
    {  40000,    0, HG2,   6,  25  },
    {  40000,    0, HG2,   7,  29  },
    {  40000,    0, HG2,   8,  33  },
    {  20000,    0, HG2,   9,  37  },
    {  20000,    0, HG2,  10,  39  },
    {  20000,    0, HG2,  11,  41  },
    {  20000,    0, HG2,  12,  43  },
    {  20000,    0, HG2,  13,  45  },
    {  20000,    0, HG2,  14,  47  },
    {  20000,    0, HG2,  15,  49  },
    {  20000,    0, HG2,  16,  51  },
    {  10000,    0,   0,  17,  57  },
    {  10000,    0,   0,  18,  58  },
    {  10000,    0,   0,  19,  59  },
    {  10000,    0,   0,  20,  60  },
    {  10000,    0,   0,  21,  61  },
    {  10000,    0,   0,  22,  62  },
    {  10000,    0,   0,  23,  63  },
    {  10000,    0,   0,  24,  64  },
    {  10000,    0,   0,  25,  65  },
    {  10000,    0,   0,  26,  66  },
    {  10000,    0,   0,  27,  67  },
    {  10000,    0,   0,  28,  68  },
    {  10000,    0,   0,  29,  69  },
    {  10000,    0,   0,  30,  70  },
    {  10000,    0,   0,  31,  71  },
    {  10000,    0,   0,  32,  72  }
};

static int 
_phy_reset_cb(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    phy_ctrl_t *lpc = pc;
    uint32_t tx_pol, rx_pol;

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
            /* Invert Rx polarity on all lanes */
            rx_pol = 0x1111;
            rv = PHY_CONFIG_SET(lpc, PhyConfig_XauiRxPolInvert,
                                rx_pol, NULL);
            PHY_VERB(lpc, ("Flip Rx pol (0x%04"PRIx32")\n", rx_pol));
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
    NULL,
    sdk56840_ledprog_info,
    _CHIP_DYN_CONFIG,
    COUNTOF(_port_configs),
    _port_configs
};

static board_chip_config_t *_chip_configs[] = {
    &_chip_config,
    NULL
};

board_config_t board_bcm56845_svk = {
    "bcm56845_svk",
    _chip_configs,
    &_phy_reset_cb,
    &_phy_init_cb,
};
