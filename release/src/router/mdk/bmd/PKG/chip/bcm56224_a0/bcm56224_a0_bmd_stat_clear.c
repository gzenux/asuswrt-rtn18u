#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56224_A0 == 1

/*
 * $Id: bcm56224_a0_bmd_stat_clear.c,v 1.5 Broadcom SDK $
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
#include <cdk/chip/bcm56224_a0_defs.h>

#include "bcm56224_a0_bmd.h"

int
bcm56224_a0_bmd_stat_clear(int unit, int port, bmd_stat_t stat)
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

    if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_ENET)) {
        switch (stat) {
        case bmdStatTxPackets:
            GTPKTr_CLR(gtpkt);
            ioerr += WRITE_GTPKTr(unit, port, gtpkt);
            break;
        case bmdStatTxBytes:
            GTBYTr_CLR(gtbyt);
            ioerr += WRITE_GTBYTr(unit, port, gtbyt);
            break;
        case bmdStatTxErrors:
            GTJBRr_CLR(gtjbr);
            ioerr += WRITE_GTJBRr(unit, port, gtjbr);
            GTFCSr_CLR(gtfcs);
            ioerr += WRITE_GTFCSr(unit, port, gtfcs);
            GTOVRr_CLR(gtovr);
            ioerr += WRITE_GTOVRr(unit, port, gtovr);
            break;
        case bmdStatRxPackets:
            GRPKTr_CLR(grpkt);
            ioerr += WRITE_GRPKTr(unit, port, grpkt);
            break;
        case bmdStatRxBytes:
            GRBYTr_CLR(grbyt);
            ioerr += WRITE_GRBYTr(unit, port, grbyt);
            break;
        case bmdStatRxErrors:
            GRJBRr_CLR(grjbr);
            ioerr += WRITE_GRJBRr(unit, port, grjbr);
            GRFCSr_CLR(grfcs);
            ioerr += WRITE_GRFCSr(unit, port, grfcs);
            GROVRr_CLR(grovr);
            ioerr += WRITE_GROVRr(unit, port, grovr);
            GRFLRr_CLR(grflr);
            ioerr += WRITE_GRFLRr(unit, port, grflr);
            GRMTUEr_CLR(grmtue);
            ioerr += WRITE_GRMTUEr(unit, port, grmtue);
            GRUNDr_CLR(grund);
            ioerr += WRITE_GRUNDr(unit, port, grund);
            GRFRGr_CLR(grfrg);
            ioerr += WRITE_GRFRGr(unit, port, grfrg);
            RRPKTr_CLR(rrpkt);
            ioerr += WRITE_RRPKTr(unit, port, rrpkt);
            break;
        case bmdStatRxDrops:
            RDBGC0r_CLR(rdbgc0);
            ioerr += WRITE_RDBGC0r(unit, port, rdbgc0);
            break;
        default:
            break;
        }
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

#endif /* CDK_CONFIG_INCLUDE_BCM56224_A0 */
