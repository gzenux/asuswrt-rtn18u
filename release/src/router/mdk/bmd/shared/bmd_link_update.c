/*
 * $Id: bmd_link_update.c,v 1.10 Broadcom SDK $
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

#include <bmdi/bmd_link.h>

/* Track port status changes */
static uint32_t port_status[BMD_CONFIG_MAX_UNITS][BMD_CONFIG_MAX_PORTS];

/*
 * Function:
 *	bmd_link_update
 * Purpose:
 *	Update port status flags.
 * Parameters:
 *	unit - BMD device
 *	port - port number to update
 *	status_change - (OUT) non-zero if port status has changed
 * Returns:
 *      CDK_XXX
 * Notes:
 *      This is a helper function for the bmd_port_mode_update API.
 */
int
bmd_link_update(int unit, int port, int *status_change)
{
    int rv = CDK_E_NONE;
    int an, an_done, link;

    if ((BMD_PORT_STATUS(unit, port) & BMD_PST_FORCE_LINK) == 0) {
        rv = bmd_phy_link_get(unit, port, &link, &an_done);
        if (CDK_SUCCESS(rv)) {
            if (link) {
                BMD_PORT_STATUS_SET(unit, port, BMD_PST_LINK_UP);
                rv = bmd_phy_autoneg_get(unit, port, &an);
                if (CDK_SUCCESS(rv) && an && an_done) {
                    BMD_PORT_STATUS_SET(unit, port, BMD_PST_AN_DONE);
                }
            } else {
                BMD_PORT_STATUS_CLR(unit, port, 
                                    BMD_PST_LINK_UP | BMD_PST_AN_DONE);
            }
        }
    }

    *status_change = 0;
    if (port_status[unit][port] != BMD_PORT_STATUS(unit, port)) {
        BMD_PORT_STATUS_CLR(unit, port, BMD_PST_FORCE_UPDATE);
        port_status[unit][port] = BMD_PORT_STATUS(unit, port);
        *status_change = 1;
    }

    return rv;
}
