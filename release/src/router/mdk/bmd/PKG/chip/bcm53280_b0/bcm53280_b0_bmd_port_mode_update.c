#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53280_B0 == 1

/*
 * $Id: bcm53280_b0_bmd_port_mode_update.c,v 1.4 Broadcom SDK $
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

#include <cdk/chip/bcm53280_b0_defs.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_error.h>

#include "bcm53280_b0_bmd.h"

int
bcm53280_b0_bmd_port_mode_update(int unit, int port)
{
    int rv = CDK_E_NONE;
    int ioerr = 0;
    STS_OVERRIDE_Pr_t sts_override_p;
    STS_OVERRIDE_GPr_t sts_override_gp;
    int status_change;
    bmd_port_mode_t mode;
    uint32_t flags;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    rv = bmd_link_update(unit, port, &status_change);
    
    if (CDK_SUCCESS(rv) && status_change) {
        rv = bcm53280_b0_bmd_port_mode_get(unit, port, &mode, &flags);
        
        if (CDK_SUCCESS(rv)) {
            /* Set link down before changing port mode */
            if (BMD_PORT_PROPERTIES(unit, port) == BMD_PORT_GE) {
                ioerr += READ_STS_OVERRIDE_GPr(unit, port, &sts_override_gp);
                STS_OVERRIDE_GPr_LINK_STSf_SET(sts_override_gp, 0);
                ioerr += WRITE_STS_OVERRIDE_GPr(unit, port, sts_override_gp);
            } else {
                ioerr += READ_STS_OVERRIDE_Pr(unit, port, &sts_override_p);
                STS_OVERRIDE_Pr_LINK_STSf_SET(sts_override_p, 0);
                ioerr += WRITE_STS_OVERRIDE_Pr(unit, port, sts_override_p);
            }                 
            flags |= BMD_PORT_MODE_F_INTERNAL;
            rv = bcm53280_b0_bmd_port_mode_set(unit, port, mode, flags);

            /* Update link status */
            if (BMD_PORT_STATUS(unit, port) & BMD_PST_LINK_UP) {
                if (BMD_PORT_PROPERTIES(unit, port) == BMD_PORT_GE) {
                    ioerr += READ_STS_OVERRIDE_GPr(unit, port, &sts_override_gp);
                    STS_OVERRIDE_GPr_LINK_STSf_SET(sts_override_gp, 1);
                    ioerr += WRITE_STS_OVERRIDE_GPr(unit, port, sts_override_gp);
                } else {
                    ioerr += READ_STS_OVERRIDE_Pr(unit, port, &sts_override_p);
                    STS_OVERRIDE_Pr_LINK_STSf_SET(sts_override_p, 1);
                    ioerr += WRITE_STS_OVERRIDE_Pr(unit, port, sts_override_p);
                }            
            }
        }
    }

    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM53280_B0 */
