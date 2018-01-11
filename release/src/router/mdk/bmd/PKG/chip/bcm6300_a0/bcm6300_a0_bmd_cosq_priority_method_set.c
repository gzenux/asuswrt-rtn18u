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
bcm6300_a0_bmd_cosq_priority_method_set(
    int unit, 
    bmd_cosq_qos_type_t qos_method)
{
    int ioerr = 0;
    QOS_GLOBAL_CTRLr_t ctrl;
    QOS_EN_TRAFFIC_PRI_REMAPr_t qos_traffic_type;
    QOS_1P_ENr_t qos_1p;
    QOS_EN_DIFFSERVr_t qos_diffserv;

    BMD_CHECK_UNIT(unit);

    ioerr += READ_QOS_EN_TRAFFIC_PRI_REMAPr(unit, &qos_traffic_type);
    if (qos_method == bmdTrafficTypeQoS) {
        QOS_EN_TRAFFIC_PRI_REMAPr_EN_TRAFFIC_PRI_REMAPf_SET(qos_traffic_type, PORTMAPALL);
        ioerr += WRITE_QOS_EN_TRAFFIC_PRI_REMAPr(unit, qos_traffic_type);
        return ioerr ? CDK_E_IO : CDK_E_NONE;
    } else {
        QOS_EN_TRAFFIC_PRI_REMAPr_EN_TRAFFIC_PRI_REMAPf_SET(qos_traffic_type, 0);
        ioerr += WRITE_QOS_EN_TRAFFIC_PRI_REMAPr(unit, qos_traffic_type);
    }

    ioerr += READ_QOS_GLOBAL_CTRLr(unit, &ctrl);
    ioerr += READ_QOS_1P_ENr(unit, &qos_1p);
    ioerr += READ_QOS_EN_DIFFSERVr(unit, &qos_diffserv);
    QOS_GLOBAL_CTRLr_PORT_QOS_ENf_SET(ctrl, 0);
    QOS_GLOBAL_CTRLr_QOS_LAYER_SELf_SET(ctrl, 0);
    if (qos_method == bmdPortQoS) {
        QOS_GLOBAL_CTRLr_PORT_QOS_ENf_SET(ctrl, 1);
    } else if (qos_method == bmdComboHighestQoS) {
        QOS_GLOBAL_CTRLr_PORT_QOS_ENf_SET(ctrl, 1);
        QOS_GLOBAL_CTRLr_QOS_LAYER_SELf_SET(ctrl, 3);
        QOS_EN_DIFFSERVr_QOS_EN_DIFFSERVf_SET(qos_diffserv, PORTMAPALL);
        QOS_1P_ENr_QOS_1P_ENf_SET(qos_1p, PORTMAPALL);
    } else if (qos_method == bmdPrio8021PQoS) {
        QOS_1P_ENr_QOS_1P_ENf_SET(qos_1p, PORTMAPALL);
    } else if (qos_method == bmdMacQoS) {
        QOS_1P_ENr_QOS_1P_ENf_SET(qos_1p, 0);
    } else if (qos_method == bmdDiffServQoS){
        QOS_GLOBAL_CTRLr_QOS_LAYER_SELf_SET(ctrl, 1);
        QOS_EN_DIFFSERVr_QOS_EN_DIFFSERVf_SET(qos_diffserv, PORTMAPALL);
    } else if (qos_method == bmdComboQoS) {
        QOS_GLOBAL_CTRLr_QOS_LAYER_SELf_SET(ctrl, 2);
        QOS_EN_DIFFSERVr_QOS_EN_DIFFSERVf_SET(qos_diffserv, PORTMAPALL);
        QOS_1P_ENr_QOS_1P_ENf_SET(qos_1p, PORTMAPALL);
    }
    ioerr += WRITE_QOS_GLOBAL_CTRLr(unit, ctrl);
    ioerr += WRITE_QOS_1P_ENr(unit, qos_1p);
    ioerr += WRITE_QOS_EN_DIFFSERVr(unit, qos_diffserv);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

