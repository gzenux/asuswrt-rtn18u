/*
 * $Id: sdk56800.c,v 1.3 Broadcom SDK $
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
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$1,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 */

#include <board/sdk56800.h>

static unsigned char ledprog_sdk56800[] = {
    0xE0, 0x28, 0x60, 0xF2, 0x67, 0x1B, 0x06, 0xF2, 0x80, 0xD2, 0x14, 0x74, 0x01, 0x86, 0xF3, 0x12,
    0xF0, 0x85, 0x05, 0xD2, 0x05, 0x71, 0x19, 0x52, 0x00, 0x3A, 0x28, 0x32, 0x00, 0x97, 0x75, 0x27,
    0x12, 0xA8, 0xFE, 0xF2, 0x02, 0x0A, 0x50, 0x32, 0x01, 0x97, 0x75, 0x33, 0x12, 0xBC, 0xFE, 0xF2,
    0x02, 0x0A, 0x50, 0x12, 0xBC, 0xFE, 0xF2, 0x95, 0x75, 0x45, 0x85, 0x12, 0xA8, 0xFE, 0xF2, 0x95,
    0x75, 0x91, 0x85, 0x77, 0x57, 0x12, 0xA8, 0xFE, 0xF2, 0x95, 0x75, 0x4F, 0x85, 0x77, 0x8A, 0x16,
    0xF0, 0xDA, 0x02, 0x71, 0x8A, 0x77, 0x91, 0x06, 0xF2, 0x12, 0x94, 0xF8, 0x15, 0x02, 0x02, 0xC1,
    0x74, 0x6E, 0x02, 0x04, 0xC1, 0x74, 0x6E, 0x02, 0x08, 0xC1, 0x74, 0x6E, 0x77, 0x74, 0xC6, 0xF3,
    0x74, 0x91, 0x77, 0x8A, 0x06, 0xF2, 0x67, 0x7C, 0x75, 0x83, 0x77, 0x91, 0x12, 0x80, 0xF8, 0x15,
    0x1A, 0x00, 0x57, 0x32, 0x0E, 0x87, 0x32, 0x0E, 0x87, 0x57, 0x32, 0x0E, 0x87, 0x32, 0x0F, 0x87,
    0x57, 0x32, 0x0F, 0x87, 0x32, 0x0E, 0x87, 0x57
};

void *
sdk56800_ledprog_info(int *size)
{
    if (size) {
        *size = sizeof(ledprog_sdk56800);
    }
    return ledprog_sdk56800;
}
