#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53600_A0 == 1

/*
 * $Id: bcm53600_a0_bmd_stat_get.c,v 1.1 Broadcom SDK $
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
#include <cdk/chip/bcm53600_a0_defs.h>

#include "bcm53600_a0_bmd.h"

int
bcm53600_a0_bmd_stat_get(int unit, int port, bmd_stat_t stat, bmd_counter_t *counter)
{
    MIB_PORT_SELr_t mib_port_sel;
    
    TXUNICASTPKTSr_t txunicastpkts;
    TXMULTICASTPKTSr_t txmulticastpkts;
    TXBROADCASTPKTSr_t txbroadcastpkts;
    TXOCTETSr_t txoctets;
    TXEXCESSIVECOLLISIONr_t txexcessivecollision;
    RXUNICASTPKTSr_t rxunicastpkts;
    RXMULTICASTPKTSr_t rxmulticastpkts;
    RXBROADCASTPKTSr_t rxbroadcastpkt;
    RXOCTETSr_t rxoctets;
    RXJABBERPKTSr_t rxjabbers;
    RXFCSERRORSr_t rxfcserrors;
    RXOVERSIZEPKTSr_t rxoversizepkts;
    RXALIGNMENTERRORSr_t rxalignmenterrors;
    RXSYMBOLERRr_t rxsymblerr;
    RXUNDERSIZEPKTSr_t rxundersizepkts;
    RXFRAGMENTSr_t rxfragments;
    RXFWDDISCPKTSr_t rxdiscard;
    int ioerr = 0;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    CDK_MEMSET(counter, 0, sizeof(*counter));

    MIB_PORT_SELr_MIB_PORTf_SET(mib_port_sel, port);
    ioerr += WRITE_MIB_PORT_SELr(unit, mib_port_sel);
    switch (stat) {
    case bmdStatTxPackets:
        ioerr += READ_TXUNICASTPKTSr(unit, &txunicastpkts);
        counter->v[0] += TXUNICASTPKTSr_GET(txunicastpkts);
        ioerr += READ_TXMULTICASTPKTSr(unit, &txmulticastpkts);
        counter->v[0] += TXMULTICASTPKTSr_GET(txmulticastpkts);
        ioerr += READ_TXBROADCASTPKTSr(unit, &txbroadcastpkts);
        counter->v[0] += TXBROADCASTPKTSr_GET(txbroadcastpkts);
        break;
    case bmdStatTxBytes:
        ioerr += READ_TXOCTETSr(unit, &txoctets);
        counter->v[0] += TXOCTETSr_GET(txoctets, 0);
        break;
    case bmdStatTxErrors:
        ioerr += READ_TXEXCESSIVECOLLISIONr(unit, &txexcessivecollision);
        counter->v[0] += TXEXCESSIVECOLLISIONr_GET(txexcessivecollision);
        break;
    case bmdStatRxPackets:
        ioerr += READ_RXUNICASTPKTSr(unit, &rxunicastpkts);
        counter->v[0] += RXUNICASTPKTSr_GET(rxunicastpkts);
        ioerr += READ_RXMULTICASTPKTSr(unit, &rxmulticastpkts);
        counter->v[0] += RXMULTICASTPKTSr_GET(rxmulticastpkts);
        ioerr += READ_RXBROADCASTPKTSr(unit, &rxbroadcastpkt);
        counter->v[0] += RXBROADCASTPKTSr_GET(rxbroadcastpkt);
        break;
    case bmdStatRxBytes:
        ioerr += READ_RXOCTETSr(unit, &rxoctets);
        counter->v[0] += RXOCTETSr_GET(rxoctets, 0);
        break;
    case bmdStatRxErrors:
        ioerr += READ_RXJABBERPKTSr(unit, &rxjabbers);
        counter->v[0] += RXJABBERPKTSr_GET(rxjabbers);  
        ioerr += READ_RXFCSERRORSr(unit, &rxfcserrors);
        counter->v[0] += RXFCSERRORSr_GET(rxfcserrors);
        ioerr += READ_RXOVERSIZEPKTSr(unit, &rxoversizepkts);
        counter->v[0] += RXOVERSIZEPKTSr_GET(rxoversizepkts);
        ioerr += READ_RXALIGNMENTERRORSr(unit, &rxalignmenterrors);
        counter->v[0] += RXALIGNMENTERRORSr_GET(rxalignmenterrors);
        ioerr += READ_RXSYMBOLERRr(unit, &rxsymblerr);
        counter->v[0] += RXSYMBOLERRr_GET(rxsymblerr);
        ioerr += READ_RXUNDERSIZEPKTSr(unit, &rxundersizepkts);
        counter->v[0] += RXUNDERSIZEPKTSr_GET(rxundersizepkts);
        ioerr += READ_RXFRAGMENTSr(unit, &rxfragments);
        counter->v[0] += RXFRAGMENTSr_GET(rxfragments);
        break;
    case bmdStatRxDrops:
        ioerr += READ_RXFWDDISCPKTSr(unit, &rxdiscard);
        counter->v[0] += RXFWDDISCPKTSr_GET(rxdiscard);
        break;
    default:
        break;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

#endif /* CDK_CONFIG_INCLUDE_BCM53600_A0 */
