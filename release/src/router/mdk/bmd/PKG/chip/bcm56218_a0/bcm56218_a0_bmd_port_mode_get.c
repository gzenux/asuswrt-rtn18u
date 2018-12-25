#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56218_A0 == 1

/*
 * $Id: bcm56218_a0_bmd_port_mode_get.c,v 1.7 Broadcom SDK $
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

#include <bmdi/bmd_port_mode.h>

#include <cdk/chip/bcm56218_a0_defs.h>
#include <cdk/arch/xgs_chip.h>

#include "bcm56218_a0_bmd.h"

int
bcm56218_a0_bmd_port_mode_get(int unit, int port, 
                              bmd_port_mode_t *mode, uint32_t* flags)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    GMACC0r_t gmacc0;
    GMACC1r_t gmacc1;
    FE_MAC1r_t fe_mac1;
    GPORT_CONFIGr_t gport_cfg;
    GE_PORT_CONFIGr_t ge_port_config;
    PORT_TABm_t port_tab;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    *mode = bmdPortModeDisabled;
    *flags = 0;

    if (BMD_PORT_STATUS(unit, port) & BMD_PST_LINK_UP) {
        *flags |= BMD_PORT_MODE_F_LINK_UP;
    }

    ioerr += READ_PORT_TABm(unit, port, &port_tab);
    if (PORT_TABm_HIGIG_PACKETf_GET(port_tab)) {
        *flags |= BMD_PORT_MODE_F_HGLITE;
    }

    ioerr += READ_GMACC1r(unit, port, &gmacc1);
    ioerr += READ_FE_MAC1r(unit, port, &fe_mac1);
    if (GMACC1r_RXEN0f_GET(gmacc1) || FE_MAC1r_RX_ENf_GET(fe_mac1)) {
        ioerr += READ_GE_PORT_CONFIGr(unit, port, &ge_port_config);
        switch (GE_PORT_CONFIGr_SPEED_SELECTf_GET(ge_port_config)) {
        case 1:
            *mode = bmdPortMode100fd;
            break;
        case 2:
            *mode = bmdPortMode10fd;
            break;
        default:
            *mode = bmdPortMode1000fd;
            if (port == 1 || port == 2) {
                ioerr += READ_GPORT_CONFIGr(unit, &gport_cfg, port);
                if (port == 1) {
                    if (GPORT_CONFIGr_PLL_MODE_DEF_S0f_GET(gport_cfg)) {
                        *mode = bmdPortMode2500fd;
                    }
                } else { /* port = 2 */
                    if (GPORT_CONFIGr_PLL_MODE_DEF_S1f_GET(gport_cfg)) {
                        *mode = bmdPortMode2500fd;
                    }
                }
            }
            break;
        }
        ioerr += READ_GMACC0r(unit, port, &gmacc0);
        if (ioerr == 0 && GMACC0r_L32Bf_GET(gmacc0) == 1) {
            *flags |= BMD_PORT_MODE_F_MAC_LOOPBACK;
        } else {
            rv = bmd_port_mode_from_phy(unit, port, mode, flags);
        }
    }

    return ioerr ? CDK_E_IO : rv; 
}
#endif /* CDK_CONFIG_INCLUDE_BCM56218_A0 */
