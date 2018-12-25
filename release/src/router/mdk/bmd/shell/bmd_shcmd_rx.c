/*
 * $Id: bmd_shcmd_rx.c,v 1.13 Broadcom SDK $
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
 * Chip packet transmit command
 */

#include <cdk/cdk_shell.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_string.h>
#include <cdk/cdk_stdlib.h>
#include <cdk/cdk_printf.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>

#include <bmd/bmd.h>
#include <bmd/bmd_dma.h>
#include <bmd/shell/shcmd_rx.h>

#include "bmd_shell_util.h"

#if BMD_CONFIG_INCLUDE_DMA == 1

static bmd_pkt_t test_pkt;

#endif

int 
bmd_shcmd_rx(int argc, char* argv[])
{
    int rv = CDK_E_NONE;
#if BMD_CONFIG_INCLUDE_DMA == 1
    bmd_pkt_t *pkt;
    int unit;
    int ax;
    int start = 0;
    int poll = 0;
    int stop = 0;
    int drain = 0;

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);

    pkt = &test_pkt;

    if (argc == 0) {
        poll = 1;
        start = 1;
    } else if (argc == 1) {
        if (CDK_STRCMP(argv[0], "start") == 0) {
            start = 1;
        } else if (CDK_STRCMP(argv[0], "poll") == 0) {
            poll = 1;
        } else if (CDK_STRCMP(argv[0], "stop") == 0) {
            stop = 1;
        } else if (CDK_STRCMP(argv[0], "drain") == 0) {
            drain = 1;
            poll = 1;
            start = 1;
        } else {
            return CDK_SHELL_CMD_BAD_ARG;
        }
    } else {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    do {
        if (poll) {
            rv = bmd_rx_poll(unit, &pkt);
            if (CDK_SUCCESS(rv)) {
                CDK_PRINTF("bmd_rx[%d]: port = %d, size = %d\n", 
                           unit, CDK_PORT_MAP_P2L(unit, pkt->port), pkt->size);
                CDK_DEBUG_HIGIG(("\tmh: src_mod: %d, src_port: %d, dst_mod: %d,"
                                 " dst_port: %d, pkt_type: %d\n",
                                 pkt->mh_src_mod, pkt->mh_src_port,
                                 pkt->mh_dst_mod, pkt->mh_dst_port,
                                 pkt->mh_pkt_type));

                BMD_DMA_CACHE_INVAL(pkt->data, pkt->size);
                for (ax = 0; ax < 128 && ax < pkt->size; ax++) {
                    if ((ax & 0xf) == 0) {
                        CDK_DEBUG_PACKET(("\t%04x:", ax));
                    }
                    CDK_DEBUG_PACKET(("%c%02x", (ax & 0xf) == 8 ? '-' : ' ', 
                                      pkt->data[ax]));
                    if ((ax & 0xf) == 0xf || ax == (pkt->size - 1)) {
                        CDK_DEBUG_PACKET(("\n"));
                    }
                }
                bmd_dma_free_coherent(unit, pkt->size, pkt->data, pkt->baddr);
            } else {
                start = 0;
                if (rv == CDK_E_TIMEOUT) {
                    rv = CDK_E_NONE;
                }
            }
        }
        if (start) {
            pkt->size = 1536;
            pkt->data = bmd_dma_alloc_coherent(unit, pkt->size, &pkt->baddr);
            CDK_ASSERT(pkt->data);
            CDK_MEMSET(pkt->data, 0, pkt->size);
            rv = bmd_rx_start(unit, pkt);
        }
    } while (drain && start && CDK_SUCCESS(rv));

    if (stop) {
        rv = bmd_rx_stop(unit);
    }
#else
    CDK_PRINTF("No DMA support.\n");
#endif

    return cdk_shell_error(rv);
}
