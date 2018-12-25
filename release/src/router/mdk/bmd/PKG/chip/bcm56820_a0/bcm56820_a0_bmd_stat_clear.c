#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56820_A0 == 1

/*
 * $Id: bcm56820_a0_bmd_stat_clear.c,v 1.4 Broadcom SDK $
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
#include <cdk/chip/bcm56820_a0_defs.h>

#include "bcm56820_a0_bmd.h"

typedef union {
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
    ITPKTr_t itpkt;
    ITBYTr_t itbyt;
    ITFCSr_t itfcs;
    ITFRGr_t itfrg;
    ITOVRr_t itovr;
    ITUFLr_t itufl;
    ITERRr_t iterr;
    IRPKTr_t irpkt;
    IRBYTr_t irbyt;
    IRFCSr_t irfcs;
    IRJBRr_t irjbr;
    IROVRr_t irovr;
    IRMEGr_t irmeg;
    IRMEBr_t irmeb;
    IRFRGr_t irfrg;
    IRERPKTr_t irerpkt;
} bcm56820_a0_counter_t;

int
bcm56820_a0_bmd_stat_clear(int unit, int port, bmd_stat_t stat)
{
    int ioerr = 0;
    bcm56820_a0_counter_t ctr;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    CDK_MEMSET(&ctr, 0, sizeof(ctr));

    if (BMD_PORT_PROPERTIES(unit, port) & (BMD_PORT_HG | BMD_PORT_XE)) {
#if BMD_CONFIG_INCLUDE_HIGIG == 1 || BMD_CONFIG_INCLUDE_XE == 1
        switch (stat) {
        case bmdStatTxPackets:
            ioerr += WRITE_ITPKTr(unit, port, ctr.itpkt);
            break;
        case bmdStatTxBytes:
            ioerr += WRITE_ITBYTr(unit, port, ctr.itbyt);
            break;
        case bmdStatTxErrors:
            ioerr += WRITE_ITFRGr(unit, port, ctr.itfrg);
            ioerr += WRITE_ITFCSr(unit, port, ctr.itfcs);
            ioerr += WRITE_ITOVRr(unit, port, ctr.itovr);
            ioerr += WRITE_ITUFLr(unit, port, ctr.itufl);
            ioerr += WRITE_ITERRr(unit, port, ctr.iterr);
            break;
        case bmdStatRxPackets:
            ioerr += WRITE_IRPKTr(unit, port, ctr.irpkt);
            break;
        case bmdStatRxBytes:
            ioerr += WRITE_IRBYTr(unit, port, ctr.irbyt);
            break;
        case bmdStatRxErrors:
            ioerr += WRITE_IRFCSr(unit, port, ctr.irfcs);
            ioerr += WRITE_IRJBRr(unit, port, ctr.irjbr);
            ioerr += WRITE_IROVRr(unit, port, ctr.irovr);
            ioerr += WRITE_IRMEGr(unit, port, ctr.irmeg);
            ioerr += WRITE_IRMEBr(unit, port, ctr.irmeb);
            ioerr += WRITE_IRFRGr(unit, port, ctr.irfrg);
            ioerr += WRITE_IRERPKTr(unit, port, ctr.irerpkt);
            break;
        default:
            break;
        }
#endif
    }
    switch (stat) {
    case bmdStatTxPackets:
        ioerr += WRITE_GTPKTr(unit, port, ctr.gtpkt);
        break;
    case bmdStatTxBytes:
        ioerr += WRITE_GTBYTr(unit, port, ctr.gtbyt);
        break;
    case bmdStatTxErrors:
        ioerr += WRITE_GTJBRr(unit, port, ctr.gtjbr);
        ioerr += WRITE_GTFCSr(unit, port, ctr.gtfcs);
        ioerr += WRITE_GTOVRr(unit, port, ctr.gtovr);
        break;
    case bmdStatRxPackets:
        ioerr += WRITE_GRPKTr(unit, port, ctr.grpkt);
        break;
    case bmdStatRxBytes:
        ioerr += WRITE_GRBYTr(unit, port, ctr.grbyt);
        break;
    case bmdStatRxErrors:
        ioerr += WRITE_GRJBRr(unit, port, ctr.grjbr);
        ioerr += WRITE_GRFCSr(unit, port, ctr.grfcs);
        ioerr += WRITE_GROVRr(unit, port, ctr.grovr);
        ioerr += WRITE_GRFLRr(unit, port, ctr.grflr);
        ioerr += WRITE_GRMTUEr(unit, port, ctr.grmtue);
        ioerr += WRITE_GRUNDr(unit, port, ctr.grund);
        ioerr += WRITE_GRFRGr(unit, port, ctr.grfrg);
        ioerr += WRITE_RRPKTr(unit, port, ctr.rrpkt);
        break;
    case bmdStatRxDrops:
        ioerr += WRITE_RDBGC0r(unit, port, ctr.rdbgc0);
        break;
    default:
        break;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

#endif /* CDK_CONFIG_INCLUDE_BCM56820_A0 */
