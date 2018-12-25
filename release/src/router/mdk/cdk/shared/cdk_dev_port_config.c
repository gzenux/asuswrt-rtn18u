/*
 * $Id: cdk_dev_port_config.c,v 1.2 Broadcom SDK $
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

#include <cdk_config.h>
#include <cdk/cdk_device.h>

#if CDK_CONFIG_INCLUDE_DYN_CONFIG == 1
static cdk_port_config_t *
_port_config_get(int unit, int port)
{
    int pcfg_id;

    pcfg_id = CDK_DEV(unit)->port_config_id[port];
    
    if (pcfg_id < CDK_DEV(unit)->num_port_configs) {
        return &CDK_DEV(unit)->port_configs[pcfg_id];
    }
    return NULL;
}
#endif

/*
 * Function:
 *	cdk_dev_port_speed_max_get
 * Purpose:
 *	Get maximum allowed speed for a given port.
 * Parameters:
 *      unit - unit number
 *      port - port number
 * Returns:
 *      Maximum port speed.
 */
uint32_t
cdk_dev_port_speed_max_get(int unit, int port)
{
#if CDK_CONFIG_INCLUDE_DYN_CONFIG == 1
    cdk_port_config_t *pcfg = _port_config_get(unit, port);

    if (pcfg != NULL) {
        return pcfg->speed_max;
    }
#endif
    return 0;
}

/*
 * Function:
 *	cdk_dev_port_flags_get
 * Purpose:
 *	Get default port flags for a given port.
 * Parameters:
 *      unit - unit number
 *      port - port number
 * Returns:
 *      Default port flags.
 */
uint32_t
cdk_dev_port_flags_get(int unit, int port)
{
#if CDK_CONFIG_INCLUDE_DYN_CONFIG == 1
    cdk_port_config_t *pcfg = _port_config_get(unit, port);

    if (pcfg != NULL) {
        return pcfg->port_flags;
    }
#endif
    return 0;
}

/*
 * Function:
 *	cdk_dev_port_mode_get
 * Purpose:
 *	Get default port mode for a given port.
 * Parameters:
 *      unit - unit number
 *      port - port number
 * Returns:
 *      Default port mode.
 */
int
cdk_dev_port_mode_get(int unit, int port)
{
#if CDK_CONFIG_INCLUDE_DYN_CONFIG == 1
    cdk_port_config_t *pcfg = _port_config_get(unit, port);

    if (pcfg != NULL) {
        return pcfg->port_mode;
    }
#endif
    return 0;
}

/*
 * Function:
 *	cdk_dev_sys_port_get
 * Purpose:
 *	Get system port mapping for a given (physical) port.
 * Parameters:
 *      unit - unit number
 *      port - port number
 * Returns:
 *      System port number.
 */
int
cdk_dev_sys_port_get(int unit, int port)
{
#if CDK_CONFIG_INCLUDE_DYN_CONFIG == 1
    cdk_port_config_t *pcfg = _port_config_get(unit, port);

    if (pcfg != NULL) {
        if (pcfg->sys_port >= 0) {
            return pcfg->sys_port;
        }
        return -1;
    }
#endif
    return port;
}
