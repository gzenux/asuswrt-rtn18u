/*
 * @File: switchWrapper.h
 *
 * @Abstract: Wrapper function and definition for the switch driver
 *
 * @Notes:
 *
 * Copyright (c) 2014-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef __switchWrapper_H
#define __switchWrapper_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define SW_API_IGMP_ENTRY_MAX 32

typedef enum {
	FAL_ADDR_IPV4 = 0,
	FAL_ADDR_IPV6
} SW_IP_PROTOCOL;

typedef u_int32_t swIP4Addr;

typedef struct {
	u_int32_t ul[4];
} swIP6Addr;

typedef struct {
	u_int8_t uc[6];
} swMACAddr;

typedef enum {
	FAL_MAC_FRWRD = 0,
	FAL_MAC_DROP,
	FAL_MAC_CPY_TO_CPU,
	FAL_MAC_RDT_TO_CPU,
} SW_FORWARD_CMD;

typedef u_int32_t swBitsMap;

typedef struct {
	SW_IP_PROTOCOL proto;
	union {
		swIP4Addr ipv4;
		swIP6Addr ipv6;
	} u;
} swIPAddr;

typedef struct {
	struct ether_addr addr;
	u_int16_t vid;		//vlan id
	SW_FORWARD_CMD daCmd;
	SW_FORWARD_CMD saCmd;
	union {
		u_int32_t id;
		swBitsMap map;
	} port;
	MCS_BOOL enablePortMap;
	MCS_BOOL isMulticast;
	MCS_BOOL enableStatic;
	MCS_BOOL enableLeak;
	MCS_BOOL enableMirror;
	MCS_BOOL enableClone;
	MCS_BOOL crossPortState;
	MCS_BOOL enableDAPrio;
	u_int8_t daQueue;
	MCS_BOOL enableWhiteList;
} swFdbEntry;

typedef struct {
	swIPAddr src;
	swIPAddr group;
	swBitsMap portMap;
	u_int32_t vid;
} swIgmpForwardEntry;


#define    FAL_ACL_FIELD_IP_PROTO       11
#define    FAL_ACL_FIELD_ICMP_TYPE      17
#define    FAL_ACL_ACTION_REDPT         2
#define    FAL_ACL_UDF_MAX_LENGTH       16

typedef enum {
	FAL_ACL_RULE_MAC = 0,
	FAL_ACL_RULE_IP4,
	FAL_ACL_RULE_IP6,
	FAL_ACL_RULE_UDF,
	FAL_ACL_RULE_BUTT,
} SW_ACL_RULE_TYPE;

typedef enum {
	FAL_ACL_FIELD_MASK = 0,
	FAL_ACL_FIELD_RANGE,
	FAL_ACL_FIELD_LE,
	FAL_ACL_FIELD_GE,
	FAL_ACL_FIELD_NE,
	FAL_ACL_FIELD_OP_BUTT,
} SW_ACL_FIELD_OP;

typedef enum {
	FAL_ACL_UDF_TYPE_L2 = 0,
	FAL_ACL_UDF_TYPE_L3,
	FAL_ACL_UDF_TYPE_L4,
	FAL_ACL_UDF_TYPE_L2_SNAP,
	FAL_ACL_UDF_TYPE_L3_PLUS,
	FAL_ACL_UDF_TYPE_BUTT,
} SW_ACL_UDF_TYPE;

typedef enum {
	FAL_ACL_POLICY_ROUTE = 0,
	FAL_ACL_POLICY_SNAT,
	FAL_ACL_POLICY_DNAT,
	FAL_ACL_POLICY_RESERVE,
} SW_POLICY_FORWARD;

typedef enum {
	FAL_ACL_COMBINED_NONE = 0,
	FAL_ACL_COMBINED_START,
	FAL_ACL_COMBINED_CONTINUE,
	FAL_ACL_COMBINED_END,
} SW_COMBINED;

typedef u_int32_t swACLFieldMap[2];
typedef u_int32_t swACLActionMap;

#define FAL_FIELD_FLG_SET(flag, field) \
	(flag[(field) / 32]) |= (0x1UL << ((field) % 32))

typedef struct {
	SW_ACL_RULE_TYPE rule_type;
	swACLFieldMap field_flg;

	/* fields of mac rule */
	swMACAddr src_mac_val;
	swMACAddr src_mac_mask;
	swMACAddr dest_mac_val;
	swMACAddr dest_mac_mask;
	u_int16_t ethtype_val;
	u_int16_t ethtype_mask;
	u_int16_t vid_val;
	u_int16_t vid_mask;
	SW_ACL_FIELD_OP vid_op;
	u_int8_t tagged_val;
	u_int8_t tagged_mask;
	u_int8_t up_val;
	u_int8_t up_mask;
	u_int8_t cfi_val;
	u_int8_t cfi_mask;
	u_int16_t resv0;

	/* fields of enhanced mac rule */
	u_int8_t stagged_val;
	u_int8_t stagged_mask;
	u_int8_t ctagged_val;
	u_int8_t ctagged_mask;
	u_int16_t stag_vid_val;
	u_int16_t stag_vid_mask;
	SW_ACL_FIELD_OP stag_vid_op;
	u_int16_t ctag_vid_val;
	u_int16_t ctag_vid_mask;
	SW_ACL_FIELD_OP ctag_vid_op;
	u_int8_t stag_pri_val;
	u_int8_t stag_pri_mask;
	u_int8_t ctag_pri_val;
	u_int8_t ctag_pri_mask;
	u_int8_t stag_dei_val;
	u_int8_t stag_dei_mask;
	u_int8_t ctag_cfi_val;
	u_int8_t ctag_cfi_mask;

	/* fields of ip4 rule */
	swIP4Addr src_ip4_val;
	swIP4Addr src_ip4_mask;
	swIP4Addr dest_ip4_val;
	swIP4Addr dest_ip4_mask;

	/* fields of ip6 rule */
	u_int32_t ip6_lable_val;
	u_int32_t ip6_lable_mask;
	swIP6Addr src_ip6_val;
	swIP6Addr src_ip6_mask;
	swIP6Addr dest_ip6_val;
	swIP6Addr dest_ip6_mask;

	/* fields of ip rule */
	u_int8_t ip_proto_val;
	u_int8_t ip_proto_mask;
	u_int8_t ip_dscp_val;
	u_int8_t ip_dscp_mask;

	/* fields of layer four */
	u_int16_t src_l4port_val;
	u_int16_t src_l4port_mask;
	SW_ACL_FIELD_OP src_l4port_op;
	u_int16_t dest_l4port_val;
	u_int16_t dest_l4port_mask;
	SW_ACL_FIELD_OP dest_l4port_op;
	u_int8_t icmp_type_val;
	u_int8_t icmp_type_mask;
	u_int8_t icmp_code_val;
	u_int8_t icmp_code_mask;
	u_int8_t tcp_flag_val;
	u_int8_t tcp_flag_mask;
	u_int8_t ripv1_val;
	u_int8_t ripv1_mask;
	u_int8_t dhcpv4_val;
	u_int8_t dhcpv4_mask;
	u_int8_t dhcpv6_val;
	u_int8_t dhcpv6_mask;

	/* user defined fields */
	SW_ACL_UDF_TYPE udf_type;
	u_int8_t udf_offset;
	u_int8_t udf_len;
	u_int8_t udf_val[FAL_ACL_UDF_MAX_LENGTH];
	u_int8_t udf_mask[FAL_ACL_UDF_MAX_LENGTH];

	/* fields of action */
	swACLActionMap action_flg;
	swBitsMap ports;
	u_int32_t match_cnt;
	u_int16_t vid;
	u_int8_t up;
	u_int8_t queue;
	u_int16_t stag_vid;
	u_int8_t stag_pri;
	u_int8_t stag_dei;
	u_int16_t ctag_vid;
	u_int8_t ctag_pri;
	u_int8_t ctag_cfi;
	u_int16_t policer_ptr;
	u_int16_t arp_ptr;
	u_int16_t wcmp_ptr;
	u_int8_t dscp;
	u_int8_t rsv;
	SW_POLICY_FORWARD policy_fwd;
	SW_COMBINED combined;
} swACLRule;

int switchInitSnooping(void);
int switchSetGroupRule(swIgmpForwardEntry * entry);
int switchClearGroupRule(swIgmpForwardEntry *entry);
int switchAddFdb(struct ether_addr *mac, swBitsMap map);
int switchClearFdb(struct ether_addr *mac, swBitsMap map);
int switchUpdateForwardTbl(void *Table, int nSize);
#endif
