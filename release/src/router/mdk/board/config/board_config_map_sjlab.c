/*
 * $Id: board_config_map_sjlab.c,v 1.5 Broadcom SDK $
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

#include <board/board_config_maps.h>

extern board_config_t board_bcm56218_skip_18;
extern board_config_t board_bcm56445_nohg;
extern board_config_t board_bcm56504_skip_13;
extern board_config_t board_bcm56820_k24xg_r00;
extern board_config_t board_bcm56820_k24xg_r01;
extern board_config_t board_bcm56820_k24c;
extern board_config_t board_bcm56845_svk;
extern board_config_t board_bcm56845_ext;
extern board_config_t board_bcm56846_svk;
extern board_config_t board_bcm56644_a0;
extern board_config_t board_bcm56850_10g;
extern board_config_t board_bcm56850_40g;

board_config_map_t board_config_map_sjlab[] = {
    /* Board configurations required for regression testing */
    { "rack01_12",      &board_bcm56445_nohg },
    { "rack16_08",      &board_bcm56218_skip_18 },
    { "rack25_13",      &board_bcm56820_k24c },
    { "rack32_04",      &board_bcm56845_svk },
    { "rack33_08",      &board_bcm56845_ext },
    { "rack37_13",      &board_bcm56504_skip_13 },
    { "rack40_08",      &board_bcm56846_svk },
    { "rack41_04",      &board_bcm56644_a0 },
    /* Test configurations for dev boards */
    { "sc00",           &board_bcm56820_k24xg_r00 },
    { "sc01",           &board_bcm56820_k24xg_r01 },
    { "sc1g",           &board_bcm56820_k24c },
    { "td210g",         &board_bcm56850_10g },
    { "td240g",         &board_bcm56850_40g },
    /* Entries for disabling pre-assigned board configuration */
    { "none",           NULL },
    { "default",        NULL },
    { NULL, NULL }
};
