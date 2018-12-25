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
#include "bcm53101_a0_bmd.h"
#include <cdk/cdk_device.h>
#include <cdk/cdk_error.h>

int 
bcm53101_a0_bmd_cosq_config_get(
    int unit, 
    int *numq)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_config_set(
    int unit, 
    int numq)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_dscp_priority_mapping_get(
    int unit, 
    int dscp, 
    int *priority)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_dscp_priority_mapping_set(
    int unit, 
    int dscp, 
    int priority)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_port_mapping_get(
    int unit, 
    int port, 
    int priority, 
    int *egressq)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_port_mapping_set(
    int unit, 
    int port, 
    int priority, 
    int egressq)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_priority_method_get(
    int unit, 
    bmd_cosq_qos_type_t *qos_method)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_priority_method_set(
    int unit, 
    bmd_cosq_qos_type_t qos_method)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_rxchannel_mapping_get(
    int unit, 
    int egressq, 
    int *channel)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_rxchannel_mapping_set(
    int unit, 
    int egressq, 
    int channel)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_sched_get(
    int unit, 
    bmd_cosq_sched_t *sched_type, 
    int *sp_endq)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_sched_set(
    int unit, 
    bmd_cosq_sched_t sched_type, 
    int sp_endq)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_txchannel_mapping_get(
    int unit, 
    int channel, 
    int *egressq)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_txchannel_mapping_set(
    int unit, 
    int channel, 
    int egressq)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_txq_selection_get(
    int unit, 
    bmd_cosq_txqsel_t *txq_sel_method)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_txq_selection_set(
    int unit, 
    bmd_cosq_txqsel_t txq_sel_method)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_wrr_weight_get(
    int unit, 
    int egressq, 
    int *weight)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_cosq_wrr_weight_set(
    int unit, 
    int egressq, 
    int weight)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_packet_padding_get(
    int unit, 
    int *pad_status, 
    int *length)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_packet_padding_set(
    int unit, 
    int pad_ctrl, 
    int length)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_jumbo_control_get(
    int unit, 
    int port, 
    int *value)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_jumbo_control_set(
    int unit, 
    int port, 
    int value)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_pause_capability_get(
    int unit, 
    int port, 
    bmd_pause_t *value)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_pause_capability_set(
    int unit, 
    int port, 
    bmd_pause_t value)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_pbvlanmap_get(
    int unit, 
    int port, 
    uint32_t *portmap)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_pbvlanmap_set(
    int unit, 
    int port, 
    uint32_t portmap)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_rate_egress_get(
    int unit, 
    int port, 
    bmd_pkt_type_mask_t *pkt_type,
    uint32_t *kbits_sec, 
    uint32_t *kbits_burst)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_rate_egress_set(
    int unit, 
    int port, 
    bmd_pkt_type_mask_t pkt_type,
    uint32_t kbits_sec, 
    uint32_t kbits_burst)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_rate_ingress_get(
    int unit, 
    int port, 
    bmd_pkt_type_mask_t *pkt_type,
    uint32_t *kbits_sec, 
    uint32_t *kbits_burst)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_rate_ingress_set(
    int unit, 
    int port, 
    bmd_pkt_type_mask_t pkt_type,
    uint32_t kbits_sec, 
    uint32_t kbits_burst)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_replace_egress_tag_get(
    int unit, 
    int port, 
    uint32_t *tag)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_replace_egress_tag_set(
    int unit, 
    int port, 
    uint32_t tag)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_tag_mangle_get(
    int unit, 
    int port, 
    bmd_tag_sel_t tag_sel, 
    int *value)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_tag_mangle_set(
    int unit, 
    int port, 
    bmd_tag_sel_t tag_sel, 
    int value)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_traffic_control_get(
    int unit, 
    int port, 
    bmd_traffic_ctrl_t *traffic_ctrl)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_traffic_control_set(
    int unit, 
    int port, 
    bmd_traffic_ctrl_t traffic_ctrl)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_vlan_priority_get(
    int unit, 
    int port, 
    int *priority)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_port_vlan_priority_set(
    int unit, 
    int port, 
    int priority)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_switch_control_get(
    int unit, 
    bmd_switch_control_t type, 
    int *value)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_switch_control_set(
    int unit, 
    bmd_switch_control_t type, 
    int value)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_switch_control_priority_get(
    int unit, 
    int priority, 
    bmd_switch_control_t type, 
    int *value)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_switch_control_priority_set(
    int unit, 
    int priority, 
    bmd_switch_control_t type, 
    int value)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_mcast_mac_addr_set(
    int unit, 
    int entry_id, 
    int vlan, 
    bmd_mac_addr_t *mac_addr, 
    int fwd_portmap, 
    int priority,
    int valid)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int 
bcm53101_a0_bmd_mcast_mac_addr_get(
    int unit, 
    int entry_id, 
    int *vlan, 
    bmd_mac_addr_t *mac_addr, 
    int *fwd_portmap, 
    int *priority, 
    int *used_bit, 
    int *valid_bit)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int bcm53101_a0_bmd_port_mac_addr_get(
    int unit, 
    int port, 
    int num_req_entries,
    bmd_arl_entry_t *arl_entry,
    int *num_entries)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

int bcm53101_a0_bmd_port_mac_addr_clear(
    int unit, 
    int port, 
    bmd_arl_entry_type_t type)
{
#ifdef UNFINISHED_DRIVER_CHECK
#error DRIVER UNFINISHED
#endif
    return CDK_E_UNAVAIL; 
}

