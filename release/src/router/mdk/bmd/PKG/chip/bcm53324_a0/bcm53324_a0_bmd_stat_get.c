#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53324_A0 == 1

/*
 * $Id: bcm53324_a0_bmd_stat_get.c,v 1.2 Broadcom SDK $
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

#include <cdk/cdk_device.h>
#include <cdk/cdk_error.h>
#include <cdk/chip/bcm53324_a0_defs.h>

#include "bcm53324_a0_bmd.h"

int
bcm53324_a0_bmd_stat_get(int unit, int port, bmd_stat_t stat, bmd_counter_t *counter)
{
    GTPKTr_t gtpkt;
    GTBYTr_t gtbyt;
    GTJBRr_t gtjbr;
    GTFCSr_t gtfcs;
    GTOVRr_t gtovr;
    GRPKTr_t grpkt;
    GRBYTr_t grbyt;
    GRJBRr_t grjbr;
    GRFCSr_t grfcs;
    GROVRr_t grovr;
    GRFLRr_t grflr;
    GRMTUEr_t grmtue;
    GRUNDr_t grund;
    GRFRGr_t grfrg;
    RRPKTr_t rrpkt;
    RDBGC0r_t rdbgc0;
    int ioerr = 0;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    CDK_MEMSET(counter, 0, sizeof(*counter));

    if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_GE | BMD_PORT_FE)) {
        switch (stat) {
        case bmdStatTxPackets:
            ioerr += READ_GTPKTr(unit, port, &gtpkt);
            counter->v[0] += GTPKTr_GET(gtpkt);
            break;
        case bmdStatTxBytes:
            ioerr += READ_GTBYTr(unit, port, &gtbyt);
            counter->v[0] += GTBYTr_GET(gtbyt);
            break;
        case bmdStatTxErrors:
            ioerr += READ_GTJBRr(unit, port, &gtjbr);
            counter->v[0] += GTJBRr_GET(gtjbr);
            ioerr += READ_GTFCSr(unit, port, &gtfcs);
            counter->v[0] += GTFCSr_GET(gtfcs);
            ioerr += READ_GTOVRr(unit, port, &gtovr);
            counter->v[0] += GTOVRr_GET(gtovr);
            break;
        case bmdStatRxPackets:
            ioerr += READ_GRPKTr(unit, port, &grpkt);
            counter->v[0] += GRPKTr_GET(grpkt);
            break;
        case bmdStatRxBytes:
            ioerr += READ_GRBYTr(unit, port, &grbyt);
            counter->v[0] += GRBYTr_GET(grbyt);
            break;
        case bmdStatRxErrors:
            ioerr += READ_GRJBRr(unit, port, &grjbr);
            counter->v[0] += GRJBRr_GET(grjbr);
            ioerr += READ_GRFCSr(unit, port, &grfcs);
            counter->v[0] += GRFCSr_GET(grfcs);
            ioerr += READ_GROVRr(unit, port, &grovr);
            counter->v[0] += GROVRr_GET(grovr);
            ioerr += READ_GRFLRr(unit, port, &grflr);
            counter->v[0] += GRFLRr_GET(grflr);
            ioerr += READ_GRMTUEr(unit, port, &grmtue);
            counter->v[0] += GRMTUEr_GET(grmtue);
            ioerr += READ_GRUNDr(unit, port, &grund);
            counter->v[0] += GRUNDr_GET(grund);
            ioerr += READ_GRFRGr(unit, port, &grfrg);
            counter->v[0] += GRFRGr_GET(grfrg);
            ioerr += READ_RRPKTr(unit, port, &rrpkt);
            counter->v[0] += RRPKTr_GET(rrpkt);
            break;
        case bmdStatRxDrops:
            ioerr += READ_RDBGC0r(unit, port, &rdbgc0);
            counter->v[0] += RDBGC0r_GET(rdbgc0);
            break;
        default:
            break;
        }
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

#endif /* CDK_CONFIG_INCLUDE_BCM53324_A0 */
