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
bcm6300_a0_bmd_port_rate_ingress_set(
    int unit, 
    int port, 
    bmd_pkt_type_mask_t pkt_type,
    uint32_t kbits_sec, 
    uint32_t kbits_burst)
{
    int ioerr = 0, burst_kbyte = 0, temp = 0;
    COMM_IRC_CONr_t ctrl;
    PORT_IRC_CONr_t port_ctrl;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    /* Enable XLEN_EN bit to include IPG for rate limiting */
    ioerr += READ_COMM_IRC_CONr(unit, &ctrl);
    COMM_IRC_CONr_XLEN_ENf_SET(ctrl, 1);
    ioerr += WRITE_COMM_IRC_CONr(unit, ctrl);

    /* Read the current Ingress Rate Config of the given port */
    ioerr += READ_PORT_IRC_CONr(unit, port, &port_ctrl);

    if (kbits_sec == 0) { /* Disable ingress rate control */
         /* Disable ingress rate control
          *    - ING_RC_ENf can't be set as 0, it will stop this port's storm
          *       control rate also.
          *    - to prevent the affecting on other ports' ingress rate cotrol,
          *       global ingress rate setting is not allowed been modified on
          *       trying to disable this port's ingress rate control also.
          *    - set the REF_CNT to the MAX value means packets could
          *       be forwarded by no limit rate. (set to 0 will block all this
          *       port's traffic)
          */
        PORT_IRC_CONr_REF_CNT0f_SET(port_ctrl, 254);
    } else {    /* Enable ingress rate control */
        /* Enable traffic types to be rate limited by bucket0 */
        COMM_IRC_CONr_PKT_MSK0f_SET(ctrl, pkt_type & 0x3F);
        if ((pkt_type == bmdPktTypeAll) || (pkt_type == bmdPktTypeSrcLookupFailure)) {
            /* Extended packet mask: SA lookup fail */
            COMM_IRC_CONr_EXT_PKT_MSK0f_SET(ctrl, 1);
        }
        ioerr += WRITE_COMM_IRC_CONr(unit, ctrl);

        burst_kbyte = kbits_burst / 8;
        if (kbits_burst > (500 * 8)) { /* 500 KB */
            return CDK_E_PARAM;
        }
        if (burst_kbyte <= 16) { /* 16KB */
            temp = 0;
        } else if (burst_kbyte <= 20) { /* 20KB */
            temp = 1;
        } else if (burst_kbyte <= 28) { /* 28KB */
            temp = 2;
        } else if (burst_kbyte <= 40) { /* 40KB */
            temp = 3;
        } else if (burst_kbyte <= 76) { /* 76KB */
            temp = 4;
        } else if (burst_kbyte <= 140){ /* 140KB */
            temp = 5;
        } else if (burst_kbyte <= 268){ /* 268KB */
            temp = 6;
        } else if (burst_kbyte <= 500){ /* 500KB */
            temp = 7;
        }
        PORT_IRC_CONr_BUCKET_SIZE0f_SET(port_ctrl, temp);

        /* refresh count  (fixed type)*/
        if (kbits_sec <= 1792) { /* 64KB ~ 1.792MB */
            temp = ((kbits_sec-1) / 64) +1;
        } else if (kbits_sec <= 102400){ /* 2MB ~ 100MB */
            temp = (kbits_sec /1024 ) + 27;
        } else if (kbits_sec <= 1024000){ /* 104MB ~ 1000MB */
            temp = (kbits_sec /8192) + 115;
        } else {
            temp = 255;
        }

        /* Setting ingress rate
                *    - here we defined ingress rate control will be disable if
                *       REF_CNT=255. (means no rate control)
                *    - this definition is for seperate different rate between
                *       "Ingress rate control" and "Strom rate control"
                *    - thus if the gave limit value trasfer REF_CNT is 255, we reasign
                *       REF_CNT to be 254
                */
        temp = (temp == 255) ? 254 : temp;
        PORT_IRC_CONr_REF_CNT0f_SET(port_ctrl, temp);

        /* enable ingress rate control */
        PORT_IRC_CONr_ING_RC_ENf_SET(port_ctrl, 1);
    }

    /* write register */
    ioerr += WRITE_PORT_IRC_CONr(unit, port, port_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

