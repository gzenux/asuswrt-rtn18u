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

int 
bcm6300_a0_bmd_port_rate_ingress_get(
    int unit, 
    int port, 
    bmd_pkt_type_mask_t *pkt_type,
    uint32_t *kbits_sec, 
    uint32_t *kbits_burst)
{
    int ioerr = 0, temp = 0;
    PORT_IRC_CONr_t port_ctrl;
    COMM_IRC_CONr_t ctrl;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    /* Check ingress rate control
      *    - ING_RC_ENf should not be 0 in the runtime except the system been
      *       process without ingress rate setting or user manuel config
      *       register value. It will stop this port's storm control rate also.
      *    - set the REF_CNT to the MAX value means packets could
      *       be forwarded by no limit rate. (set to 0 will block all this
      *       port's traffic)
      */
    ioerr += READ_PORT_IRC_CONr(unit, port, &port_ctrl);
    temp = PORT_IRC_CONr_REF_CNT0f_GET(port_ctrl);
    if (temp == 254) {
        *kbits_sec = 0;
        *kbits_burst = 0;
    } else {
        temp = PORT_IRC_CONr_BUCKET_SIZE0f_GET(port_ctrl);
        switch (temp) {
            case 0:
                *kbits_burst = 16 * 8; /* 16KB */
                break;
            case 1:
                *kbits_burst = 20 * 8; /* 20KB */
                break;
            case 2:
                *kbits_burst = 28 * 8; /* 28KB */
                break;
            case 3:
                *kbits_burst = 40 * 8; /* 40KB */
                break;
            case 4:
                *kbits_burst = 76 * 8; /* 76KB */
                break;
            case 5:
                *kbits_burst = 140 * 8; /* 140KB */
                break;
            case 6:
                *kbits_burst = 268 * 8; /* 268KB */
                break;
            case 7:
                *kbits_burst = 500 * 8; /* 500KB */
                break;

            default:
                return CDK_E_INTERNAL;
        }

        temp = PORT_IRC_CONr_REF_CNT0f_GET(port_ctrl);
        if (temp <= 28) {
            *kbits_sec = temp * 64;
        } else if (temp <= 127) {
            *kbits_sec = (temp -27) * 1024;
        } else if (temp <=243) {
            *kbits_sec = (temp -115) * 1024 * 8;
        } else {
            return CDK_E_INTERNAL;
        }
    }

    ioerr += READ_COMM_IRC_CONr(unit, &ctrl);
    *pkt_type = COMM_IRC_CONr_PKT_MSK0f_GET(ctrl);
    if (COMM_IRC_CONr_EXT_PKT_MSK0f_GET(ctrl)) {
        *pkt_type |= bmdPktTypeSrcLookupFailure;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

