/*
 * $Id: bmd_port_mode_from_speed_duplex.c,v 1.11 Broadcom SDK $
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

#include <bmdi/bmd_port_mode.h>

/*
 * Function:
 *	bmd_port_mode_from_speed_duplex
 * Purpose:
 *	Determine BMD port mode based on speed and duplex.
 * Parameters:
 *	speed - port speed setting
 *	duplex - port duplex setting
 *	mode - (OUT) BMD port mode
 * Returns:
 *      CDK_XXX
 * Notes:
 *      This is a helper function for the bmd_port_mode_get API.
 */
int
bmd_port_mode_from_speed_duplex(uint32_t speed, int duplex, bmd_port_mode_t *mode)
{
    switch (speed) {
    case 0:
        *mode = bmdPortModeAuto;
        break;
    case 10:
        *mode = duplex ? bmdPortMode10fd : bmdPortMode10hd;
        break;
    case 100:
        *mode = duplex ? bmdPortMode100fd : bmdPortMode100hd;
        break;
    case 1000:
        *mode = duplex ? bmdPortMode1000fd : bmdPortMode1000hd;
        break;
    case 2500:
        /* Full duplex only */
        *mode = bmdPortMode2500fd;
        break;
    case 10000:
        /* Full duplex only */
        *mode = bmdPortMode10000fd;
        break;
    case 12000:
        /* Full duplex only */
        *mode = bmdPortMode12000fd;
        break;
    case 13000:
        /* Full duplex only */
        *mode = bmdPortMode13000fd;
        break;
    case 16000:
        /* Full duplex only */
        *mode = bmdPortMode16000fd;
        break;
    case 20000:
        /* Full duplex only */
        *mode = bmdPortMode20000fd;
        break;
    case 21000:
        /* Full duplex only */
        *mode = bmdPortMode21000fd;
        break;
    case 25000:
        /* Full duplex only */
        *mode = bmdPortMode25000fd;
        break;
    case 40000:
        /* Full duplex only */
        *mode = bmdPortMode40000fd;
        break;
    case 42000:
        /* Full duplex only */
        *mode = bmdPortMode42000fd;
        break;
    case 100000:
        /* 100G CR10 only */
        *mode = bmdPortMode100000CR;
        break;
    case 127000:
        /* Full duplex only */
        *mode = bmdPortMode127000fd;
        break;
    default:
        return CDK_E_INTERNAL;
    }
    return CDK_E_NONE;
}
