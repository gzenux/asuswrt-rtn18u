/*
 * $Id: bmd_shell_parse_port_str.c,v 1.3 Broadcom SDK $
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
 *
 * Parse port string into port bitmap.
 */

#include "bmd_shell_util.h"

int bmd_shell_parse_port_str(int unit, const char *str, cdk_pbmp_t *pbmp)
{
    int rv = 0;
    int port = 0;
    int pstart = -1;
    int ptmp;
    char ch;
    const char *cptr = str;;

    if (CDK_STRCMP(str, "all") == 0) {
        bmd_port_type_pbmp(unit, BMD_PORT_ALL, pbmp);
        return rv;
    }
    CDK_PBMP_CLEAR(*pbmp);
    do {
        ch = *cptr++;
        if (ch >= '0' && ch <= '9') {
            port = (port * 10) + (ch - '0');
        } else {
            if (pstart >= 0) {
                while (pstart < port) {
                    ptmp = CDK_PORT_MAP_L2P(unit, pstart++);
                    if (ptmp >= 0) {
                        CDK_PBMP_ADD(*pbmp, ptmp);
                    }
                }
                pstart = -1;
            }
            if (ch == ',' || ch == 0) {
                ptmp = CDK_PORT_MAP_L2P(unit, port);
                if (ptmp >= 0) {
                    CDK_PBMP_ADD(*pbmp, ptmp);
                }
                port = 0;
            } else if (ch == '-') {
                pstart = port;
                port = 0;
            } else {
                rv = -1;
                break;
            }
        }
    } while (ch != 0);

    return rv;
}
