/*
 * $Id: bmd_custom_config.h MDK2.1.2 $
 * 
 * $Copyright: Copyright 2009 Broadcom Corporation.
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

/*
 * This config file defines custom compilation-time settings specific to the BMD.
 */

#ifndef __BMD_CUSTOM_CONFIG_H__
#define __BMD_CUSTOM_CONFIG_H__

#define BMD_CONFIG_INCLUDE_DMA                  0
#define BMD_CONFIG_INCLUDE_DMA_CACHE_CONTROL    0
#define BMD_CONFIG_DMA_MAX_POLLS                1
#define BMD_CONFIG_DEFAULT_VLAN                 1
#define BMD_CONFIG_INCLUDE_XE                   0
#define BMD_CONFIG_INCLUDE_HIGIG                0

#define BMD_CONFIG_OPTIMIZE_DISPATCH            1

#define BMD_CONFIG_SHELL_INCLUDE_BMD            1
#define BMD_CONFIG_SHELL_INCLUDE_RESET          1
#define BMD_CONFIG_SHELL_INCLUDE_INIT           1
#define BMD_CONFIG_SHELL_INCLUDE_TX             0
#define BMD_CONFIG_SHELL_INCLUDE_RX             0
#define BMD_CONFIG_SHELL_INCLUDE_VLAN           1
#define BMD_CONFIG_SHELL_INCLUDE_PORT_MODE      1
#define BMD_CONFIG_SHELL_INCLUDE_PORT_STP       1
#define BMD_CONFIG_SHELL_INCLUDE_PORT_VLAN      1
#define BMD_CONFIG_SHELL_INCLUDE_PORT_MAC       1
#define BMD_CONFIG_SHELL_INCLUDE_CPU_MAC        1
#define BMD_CONFIG_SHELL_INCLUDE_STAT           1
#define BMD_CONFIG_SHELL_INCLUDE_SWITCHING_INIT 1
#define BMD_CONFIG_SHELL_INCLUDE_PDL            0
#define BMD_CONFIG_SHELL_INCLUDE_PHY            1
#define BMD_CONFIG_SHELL_INCLUDE_QOS            1
#define BMD_CONFIG_SHELL_INCLUDE_MMAC           1
#define BMD_CONFIG_SHELL_INCLUDE_PORT           1
#define BMD_CONFIG_SHELL_INCLUDE_SWITCH         1
#define BMD_CONFIG_SHELL_INCLUDE_FC             1

#endif /* __BMD_CUSTOM_CONFIG_H__ */
