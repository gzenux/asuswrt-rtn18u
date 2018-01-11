#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56640_A0 == 1

/*
 * $Id: bcm56640_a0_bmd_stat_clear.c,v 1.2 Broadcom SDK $
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
#include <cdk/chip/bcm56640_a0_defs.h>

#include "bcm56640_a0_bmd.h"
#include "bcm56640_a0_internal.h"

typedef union {
    TPKTr_t tpkt;
    TBYTr_t tbyt;
    TFCSr_t tfcs;
    TJBRr_t tjbr;
    TFRGr_t tfrg;
    TOVRr_t tovr;
    TUFLr_t tufl;
    TERRr_t terr;
    RPKTr_t rpkt;
    RBYTr_t rbyt;
    RFCSr_t rfcs;
    RJBRr_t rjbr;
    RFRGr_t rfrg;
    ROVRr_t rovr;
    RFLRr_t rflr;
    RUNDr_t rund;
    RMTUEr_t rmtue;
    RRPKTr_t rrpkt;
    RDBGC0r_t rdbgc0;
} bcm56640_a0_counter_t;

int
bcm56640_a0_bmd_stat_clear(int unit, int port, bmd_stat_t stat)
{
    int ioerr = 0;
    int lport;
    bcm56640_a0_counter_t ctr;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    CDK_MEMSET(&ctr, 0, sizeof(ctr));

    if (port != CMIC_PORT) {
        switch (stat) {
        case bmdStatTxPackets:
            ioerr += WRITE_TPKTr(unit, port, ctr.tpkt);
            break;
        case bmdStatTxBytes:
            ioerr += WRITE_TBYTr(unit, port, ctr.tbyt);
            break;
        case bmdStatTxErrors:
            ioerr += WRITE_TFCSr(unit, port, ctr.tfcs);
            ioerr += WRITE_TJBRr(unit, port, ctr.tjbr);
            ioerr += WRITE_TFRGr(unit, port, ctr.tfrg);
            ioerr += WRITE_TOVRr(unit, port, ctr.tovr);
            ioerr += WRITE_TUFLr(unit, port, ctr.tufl);
            ioerr += WRITE_TERRr(unit, port, ctr.terr);
            break;
        case bmdStatRxPackets:
            ioerr += WRITE_RPKTr(unit, port, ctr.rpkt);
            break;
        case bmdStatRxBytes:
            ioerr += WRITE_RBYTr(unit, port, ctr.rbyt);
            break;
        case bmdStatRxErrors:
            ioerr += WRITE_RFCSr(unit, port, ctr.rfcs);
            ioerr += WRITE_RJBRr(unit, port, ctr.rjbr);
            ioerr += WRITE_RFRGr(unit, port, ctr.rfrg);
            ioerr += WRITE_ROVRr(unit, port, ctr.rovr);
            ioerr += WRITE_RFLRr(unit, port, ctr.rflr);
            ioerr += WRITE_RUNDr(unit, port, ctr.rund);
            ioerr += WRITE_RMTUEr(unit, port, ctr.rmtue);
            ioerr += WRITE_RRPKTr(unit, port, ctr.rrpkt);
            break;
        default:
            break;
        } 
    }
    lport = P2L(unit, port);

    /* Non-MAC counters */
    switch (stat) {
    case bmdStatRxDrops:
        ioerr += WRITE_RDBGC0r(unit, lport, ctr.rdbgc0);
        break;
    default:
        break;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

#endif /* CDK_CONFIG_INCLUDE_BCM56640_A0 */
