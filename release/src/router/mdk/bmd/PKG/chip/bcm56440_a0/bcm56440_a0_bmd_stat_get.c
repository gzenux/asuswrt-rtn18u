#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56440_A0 == 1

/*
 * $Id: bcm56440_a0_bmd_stat_get.c,v 1.3 Broadcom SDK $
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
#include <cdk/chip/bcm56440_a0_defs.h>

#include "bcm56440_a0_bmd.h"
#include "bcm56440_a0_internal.h"

int
bcm56440_a0_bmd_stat_get(int unit, int port, bmd_stat_t stat, bmd_counter_t *counter)
{
    int ioerr = 0;
    int lport;
    RRPKTr_t rrpkt;
    RDBGC0r_t rdbgc0;
    TPKTr_t tpkt;
    TBYTr_t tbyt;
    TFCSr_t tfcs;
    TFRGr_t tfrg;
    TOVRr_t tovr;
    TUFLr_t tufl;
    TERRr_t terr;
    RPKTr_t rpkt;
    RBYTr_t rbyt;
    RFCSr_t rfcs;
    RJBRr_t rjbr;
    ROVRr_t rovr;
    RFRGr_t rfrg;
    RERPKTr_t rerpkt;
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
    GRRPKTr_t grrpkt;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    CDK_MEMSET(counter, 0, sizeof(*counter));

    /* Only support lower 32-bits of counters */
    if (port != CMIC_PORT) {
        if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
            switch (stat) {
            case bmdStatTxPackets:
                ioerr += READ_TPKTr(unit, port, &tpkt);
                counter->v[0] += TPKTr_GET(tpkt, 0);
                break;
            case bmdStatTxBytes:
                ioerr += READ_TBYTr(unit, port, &tbyt);
                counter->v[0] += TBYTr_GET(tbyt, 0);
                break;
            case bmdStatTxErrors:
                ioerr += READ_TFRGr(unit, port, &tfrg);
                counter->v[0] += TFRGr_GET(tfrg, 0);
                ioerr += READ_TFCSr(unit, port, &tfcs);
                counter->v[0] += TFCSr_GET(tfcs, 0);
                ioerr += READ_TOVRr(unit, port, &tovr);
                counter->v[0] += TOVRr_GET(tovr, 0);
                ioerr += READ_TUFLr(unit, port, &tufl);
                counter->v[0] += TUFLr_GET(tufl, 0);
                ioerr += READ_TERRr(unit, port, &terr);
                counter->v[0] += TERRr_GET(terr, 0);
                break;
            case bmdStatRxPackets:
                ioerr += READ_RPKTr(unit, port, &rpkt);
                counter->v[0] += RPKTr_GET(rpkt, 0);
                break;
            case bmdStatRxBytes:
                ioerr += READ_RBYTr(unit, port, &rbyt);
                counter->v[0] += RBYTr_GET(rbyt, 0);
                break;
            case bmdStatRxErrors:
                ioerr += READ_RFCSr(unit, port, &rfcs);
                counter->v[0] += RFCSr_GET(rfcs, 0);
                ioerr += READ_RJBRr(unit, port, &rjbr);
                counter->v[0] += RJBRr_GET(rjbr, 0);
                ioerr += READ_ROVRr(unit, port, &rovr);
                counter->v[0] += ROVRr_GET(rovr, 0);
                ioerr += READ_RFRGr(unit, port, &rfrg);
                counter->v[0] += RFRGr_GET(rfrg, 0);
                ioerr += READ_RERPKTr(unit, port, &rerpkt);
                counter->v[0] += RERPKTr_GET(rerpkt, 0);
                ioerr += READ_RRPKTr(unit, port, &rrpkt);
                counter->v[0] += RRPKTr_GET(rrpkt, 0);
                break;
            default:
                break;
            }
        } else if (BMD_PORT_PROPERTIES(unit, port) & BMD_PORT_GE) {
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
                ioerr += READ_GRRPKTr(unit, port, &grrpkt);
                counter->v[0] += GRRPKTr_GET(grrpkt);
                break;
            case bmdStatRxDrops:
                ioerr += READ_RDBGC0r(unit, port, &rdbgc0);
                counter->v[0] += RDBGC0r_GET(rdbgc0);
                break;
            default:
                break;
            }
        }
    }
    
    lport = P2L(unit, port);

    /* Non-MAC counters */
    switch (stat) {
    case bmdStatRxDrops:
        ioerr += READ_RDBGC0r(unit, lport, &rdbgc0);
        counter->v[0] += RDBGC0r_GET(rdbgc0);
        break;
    default:
        break;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

#endif /* CDK_CONFIG_INCLUDE_BCM56440_A0 */
