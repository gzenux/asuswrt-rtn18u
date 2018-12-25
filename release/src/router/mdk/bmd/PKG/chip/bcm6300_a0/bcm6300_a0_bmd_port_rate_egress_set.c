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
bcm6300_a0_bmd_port_rate_egress_set(
    int unit, 
    int port, 
    bmd_pkt_type_mask_t pkt_type,
    uint32_t kbits_sec, 
    uint32_t kbits_burst)
{
    int ioerr = 0, burst_kbyte = 0, temp = 0;
    COMM_IRC_CONr_t ctrl;
    PORT_ERC_CONr_t port_ctrl;

    BMD_CHECK_UNIT(unit);
    BMD_CHECK_PORT(unit, port);

    /* Enable XLEN_EN bit to include IPG for rate limiting */
    ioerr += READ_COMM_IRC_CONr(unit, &ctrl);
    COMM_IRC_CONr_XLEN_ENf_SET(ctrl, 1);
    ioerr += WRITE_COMM_IRC_CONr(unit, ctrl);

    /* Read the current Egress Rate Config of the given port */
    ioerr += READ_PORT_ERC_CONr(unit, port, &port_ctrl);
    if (kbits_sec == 0) { /* Disable egress rate control */
        PORT_ERC_CONr_ENG_RC_ENf_SET(port_ctrl, 0);
    } else {    /* Enable egress rate control */
        /* burst size */
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
        } else if (burst_kbyte <= 140) { /* 140KB */
            temp = 5;
        } else if (burst_kbyte <= 268) { /* 268KB */
            temp = 6;
        } else if (burst_kbyte <= 500) { /* 500KB */
            temp = 7;
        }
        PORT_ERC_CONr_BUCKET_SIZEf_SET(port_ctrl, temp);

        /* refresh count  (fixed type)*/
        if (kbits_sec <= 1792) { /* 64KB ~ 1.792MB */
            temp = ((kbits_sec-1) / 64) +1;
        } else if (kbits_sec <= 102400){ /* 2MB ~ 100MB */
            temp = (kbits_sec /1024 ) + 27;
        } else { /* 104MB ~ 1000MB */
            temp = (kbits_sec /8192) + 115;
        }
        PORT_ERC_CONr_REF_CNTSf_SET(port_ctrl, temp);

        /* enable egress rate control */
        PORT_ERC_CONr_ENG_RC_ENf_SET(port_ctrl, 1);
    }
    ioerr += WRITE_PORT_ERC_CONr(unit, port, port_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

