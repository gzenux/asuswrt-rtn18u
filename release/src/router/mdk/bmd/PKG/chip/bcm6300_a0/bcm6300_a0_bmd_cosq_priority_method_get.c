/*
 * $Id: $
 * 
 * $Copyright: Copyright 2010 Broadcom Corporation.
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
#include <cdk/chip/bcm6300_a0_defs.h>

#define PORTMAPALL 0x1FF

int 
bcm6300_a0_bmd_cosq_priority_method_get(
    int unit,
    bmd_cosq_qos_type_t *qos_method)
{
    int ioerr = 0, port_qos_en, qos_layer_sel, qos_portmap;
    QOS_GLOBAL_CTRLr_t ctrl;
    QOS_EN_TRAFFIC_PRI_REMAPr_t qos_traffic_type;
    QOS_1P_ENr_t qos_1p;
    QOS_EN_DIFFSERVr_t qos_diffserv;

    BMD_CHECK_UNIT(unit);
    
    ioerr += READ_QOS_EN_TRAFFIC_PRI_REMAPr(unit, &qos_traffic_type);
    qos_portmap = QOS_EN_TRAFFIC_PRI_REMAPr_EN_TRAFFIC_PRI_REMAPf_GET(qos_traffic_type);
    if (qos_portmap == PORTMAPALL) {
        *qos_method = bmdTrafficTypeQoS;
    } else {
        ioerr += READ_QOS_GLOBAL_CTRLr(unit, &ctrl);
        port_qos_en = QOS_GLOBAL_CTRLr_PORT_QOS_ENf_GET(ctrl);
        qos_layer_sel = QOS_GLOBAL_CTRLr_QOS_LAYER_SELf_GET(ctrl);
        if (port_qos_en) {
            if (qos_layer_sel != 3) {
                *qos_method = bmdPortQoS;
            } else {
                *qos_method = bmdComboHighestQoS;
            }
        } else {
            if (qos_layer_sel == 0) {
                ioerr += READ_QOS_1P_ENr(unit, &qos_1p);
                qos_portmap = QOS_1P_ENr_QOS_1P_ENf_GET(qos_1p);
                if (qos_portmap == PORTMAPALL) {
                    *qos_method = bmdPrio8021PQoS;
                } else {
                    *qos_method = bmdMacQoS;
                }
            } else if (qos_layer_sel == 1) {
                ioerr += READ_QOS_EN_DIFFSERVr(unit, &qos_diffserv);
                qos_portmap = QOS_EN_DIFFSERVr_QOS_EN_DIFFSERVf_GET(qos_diffserv);
                if (qos_portmap == PORTMAPALL) {
                    *qos_method = bmdDiffServQoS;
                } else {
                    *qos_method = bmdNoQoS;
                }
            } else if (qos_layer_sel == 2) {
                *qos_method = bmdComboQoS;
            } else {
                *qos_method = bmdComboHighestQoS;
            }        
        }
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

