/*
 * @File: switchWrapper.c
 *
 * @Abstract: Wrapper functions to the switch driver
 *
 * @Notes:
 *
 * Copyright (c) 2014-2015, 2017 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/igmp.h>
#include <netinet/in.h>
#include <api/sw_ioctl.h>

#include <dbg.h>

#include "qassert.h"
#include "module.h"
#include "profile.h"
#include "mcnl.h"
#include "switchWrapper.h"	//switch header file

/*-----------Internal Definition -----------*/
#define SW_IOCTL_INTERFACE_NAME "/dev/switch_ssdk"

#define MC_IP4_FMT(ip4)		(ip4)[0], (ip4)[1], (ip4)[2], (ip4)[3]
#define MC_IP4_STR		"%d.%d.%d.%d"
#define MC_IP6_FMT(ip6)		ntohs((ip6)[0]), ntohs((ip6)[1]), ntohs((ip6)[2]), ntohs((ip6)[3]), ntohs((ip6)[4]), ntohs((ip6)[5]), ntohs((ip6)[6]), ntohs((ip6)[7])
#define MC_IP6_STR		"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#define MC_MAC_FMT(addr)	(addr)[0], (addr)[1], (addr)[2], (addr)[3], (addr)[4], (addr)[5]
#define MC_MAC_STR		"%02x:%02x:%02x:%02x:%02x:%02x"
#define MC_MAC_FMT(addr)	(addr)[0], (addr)[1], (addr)[2], (addr)[3], (addr)[4], (addr)[5]
#define MC_MAC_STR		"%02x:%02x:%02x:%02x:%02x:%02x"

typedef struct {
	u_int8_t index;		//Max is 32 for ACL Rule id
	swIgmpForwardEntry entry;	//Store the specified ACL rule infor
} swIgmpForwardItem;

typedef struct {
	u_int8_t cnt;
	swIgmpForwardItem igmpTable[SW_API_IGMP_ENTRY_MAX];
} swIgmpForwardTable;

static struct switchWrapper {
	u_int32_t isInit;	/* overall initialization done */
	int socketFd;
	swIgmpForwardTable keptTable;
	u_int32_t vid;
	u_int32_t rootPort;
	struct dbgModule *debugModule;	/* debug message context */
} switchWrapperState;

struct mcManagerIFtable {
	int32_t entryCnt;
	struct __mc_iftbl_entry entry[MC_DEF_GROUP_MAX];
};

static struct profileElement switchWrapperDefaulttable[] = {
	{"SwitchLanVid", "1"},
	{"SwitchCpuPort", "6"},
	{NULL, NULL},
};

typedef int (*FILLIPFUNC) (swIPAddr *addr, u_int32_t *newAddr);

#define switchWrapperDebug(level, ...) \
		 dbgf(switchWrapperState.debugModule,(level),__VA_ARGS__)


/*---------------------Internal Functions-----------------------*/
static void DUMPENTR(swIgmpForwardEntry *entry)
{
	u_int32_t tmp[4];
	u_int16_t *pTmp = NULL;
	int i;

	if (DBGDUMP > dbgModuleLevelGet(switchWrapperState.debugModule)) {
		return;
	}
	if (entry->group.proto == FAL_ADDR_IPV4) {
		tmp[0] = htonl(entry->group.u.ipv4);
		switchWrapperDebug(DBGDUMP, "group:" MC_IP4_STR, MC_IP4_FMT((u_int8_t *) tmp));
	} else {
		for (i = 0; i < 4; i++) {
			tmp[i] = htonl(entry->group.u.ipv6.ul[i]);
		}
		pTmp = (u_int16_t *) tmp;
		switchWrapperDebug(DBGDUMP, "group:" MC_IP6_STR, MC_IP6_FMT(pTmp));
	}
	if (entry->src.proto == FAL_ADDR_IPV4) {
		tmp[0] = htonl(entry->src.u.ipv4);
		switchWrapperDebug(DBGDUMP, "src:" MC_IP4_STR, MC_IP4_FMT((u_int8_t *) tmp));
	} else {
		for (i = 0; i < 4; i++) {
			tmp[i] = htonl(entry->src.u.ipv6.ul[i]);
		}
		pTmp = (u_int16_t *) tmp;
		switchWrapperDebug(DBGDUMP, "src:" MC_IP6_STR, MC_IP6_FMT(pTmp));
	}

	switchWrapperDebug(DBGDUMP, "PORTMAP:%08X", entry->portMap);

}

/*
This will send ioctl command to the switch.
We can improve this function by keep ioctl socket open always
*/
static int switchCommandExcute(u_int32_t devId, ...)
{
	int nValue[12] = { 0 };
	int nRtn = 0, idx;
	va_list vaArgs;
	int nrParam = 2;

	if (switchWrapperState.socketFd < 0) {
		switchWrapperDebug(DBGERR, "IOCTL interface is not opened");
		return -1;
	}
	nValue[0] = devId;
	nValue[1] = (int)&nRtn;

	va_start(vaArgs, devId);
	for (idx = 0; idx < nrParam; idx++) {
		nValue[idx + 2] = va_arg(vaArgs, u_int32_t);
	}
	va_end(vaArgs);
	nRtn = ioctl(switchWrapperState.socketFd, SIOCDEVPRIVATE, nValue);
	return nRtn;
}


static int switchCommandExcuteVar(u_int32_t devId, int nrParam, ...)
{
	int nValue[12] = { 0 };
	int nRtn = 0, idx;
	va_list vaArgs;

	if (switchWrapperState.socketFd < 0) {
		switchWrapperDebug(DBGERR, "IOCTL interface is not opened");
		return -1;
	}
	nValue[0] = devId;
	nValue[1] = (int)&nRtn;

	if (nrParam > sizeof(nValue)/sizeof(int) - 2)
		nrParam = sizeof(nValue)/sizeof(int) - 2;

	va_start(vaArgs, nrParam);
	for (idx = 0; idx < nrParam; idx++) {
		nValue[idx + 2] = va_arg(vaArgs, u_int32_t);
	}
	va_end(vaArgs);
	nRtn = ioctl(switchWrapperState.socketFd, SIOCDEVPRIVATE, nValue);
	return nRtn;
}

//Find the port number by the src mac address:
static u_int32_t switchFindPortmap(struct ether_addr *mac, u_int32_t vid)
{
	swFdbEntry entry;

	memset(&entry, 0, sizeof(swFdbEntry));
	switchWrapperDebug(DBGDEBUG, "Mac:" MC_MAC_STR, MC_MAC_FMT(mac->ether_addr_octet));
	memcpy(&entry.addr, mac, sizeof(struct ether_addr));
	entry.vid = vid;
	switchCommandExcute(SW_API_FDB_FIND, 0, &entry);
	switchWrapperDebug(DBGDEBUG, "PortId%d", entry.port.id);
	return entry.port.map;
}


static int switchFlushSnoopinfwdTable()
{
	int idx;

	switchWrapperDebug(DBGDUMP, "Flush the snooping table,cnt[%d]",
		switchWrapperState.keptTable.cnt);
	for (idx = 0; idx < switchWrapperState.keptTable.cnt; idx++) {
		DUMPENTR(&switchWrapperState.keptTable.igmpTable[idx].entry);
		switchClearGroupRule(&switchWrapperState.keptTable.igmpTable[idx].entry);

	}
	memset(&switchWrapperState.keptTable, 0, sizeof(switchWrapperState.keptTable));
	return 0;
}

static int switchFillIPv4(swIPAddr *addr, u_int32_t *newAddr)
{
	addr->proto = FAL_ADDR_IPV4;
	addr->u.ipv4 = ntohl(*newAddr);
	return 0;
}

static int switchFillIPv6(swIPAddr *addr, u_int32_t *newAddr)
{
	addr->proto = FAL_ADDR_IPV6;
	int i = 0;

	for (i = 0; i < 4; i++) {
		addr->u.ipv6.ul[i] = ntohl(newAddr[i]);
	}
	return 0;
}

/*Get the group Rules table*/
int switchQueryGroupRule(swIgmpForwardTable * entry)
{
	return switchCommandExcute(SW_API_IGMP_SG_ENTRY_QUERY, 0, entry);
}


/*
 * find the entry with same group and same source
 */
static int switchFindForwardEntry(swIgmpForwardTable * table, swIgmpForwardEntry * src)
{
	int idx;

	for (idx = 0; idx < table->cnt; idx++) {
		if (memcmp(&table->igmpTable[idx].entry, src, sizeof(swIPAddr) * 2) == 0)
			return idx;
	}
	return -1;
}

/*Add a wild entry, we need add the new port to the same group entry
  with/without specified src*/
static int switchAddWildentry(swIgmpForwardTable * table, const swIgmpForwardEntry * newEntry)
{
	int idx, sameGroup;
	swIgmpForwardEntry tmpEntry = *newEntry;

	memset(&tmpEntry.src.u, 0, sizeof(tmpEntry.src.u));
	/*Check where there already exist one entry with same group and wild source
	 *If it exist, we do nothing, because we have assigned the new wild entry's port
	 *map to the existing one.
	 */
	for (idx = 0; idx < table->cnt; idx++) {
		if (memcmp(&table->igmpTable[idx].entry, &tmpEntry, sizeof(swIPAddr) * 2) == 0) {
			break;
		}
	}
	if (idx < table->cnt && (table->igmpTable[idx].entry.portMap & newEntry->portMap))
		return 0;
	sameGroup = idx;

	/*We need add new port to the all exist entry with same group
	   with/without specified src */
	for (idx = 0; idx < table->cnt; idx++) {
		if (memcmp(&(table->igmpTable[idx].entry.group),
				&newEntry->group, sizeof(newEntry->group)) == 0) {
			table->igmpTable[idx].entry.portMap |= newEntry->portMap;
		}
	}

	if (sameGroup == table->cnt) {
		if (table->cnt < SW_API_IGMP_ENTRY_MAX) {
			switchWrapperDebug(DBGDUMP, "Add New Entry to the table:");
			memcpy(&table->igmpTable[table->cnt].entry, &tmpEntry, sizeof(tmpEntry));
			table->cnt++;
			DUMPENTR(&table->igmpTable[table->cnt - 1].entry);
		} else {
			switchWrapperDebug(DBGERR, "Out of the entry limitation of %d",
				SW_API_IGMP_ENTRY_MAX);
			return -1;
		}
	}
	return 0;
}

static int switchAddNewEntry(swIgmpForwardTable * table, const swIgmpForwardEntry * newEntry)
{
	int idx;
	swIgmpForwardEntry tmpEntry = *newEntry;

	memset(&tmpEntry.src.u, 0, sizeof(tmpEntry.src.u));

	/*Find the same group entry with wild src
	 *We need add the wild port map to its port map
	 */
	for (idx = 0; idx < table->cnt; idx++) {
		if (memcmp(&table->igmpTable[idx].entry, &tmpEntry, sizeof(swIPAddr) * 2) == 0) {

			switchWrapperDebug(DBGDUMP, "Find the wild group in the table");
			DUMPENTR(&table->igmpTable[idx].entry);
			break;
		}
	}
	if (table->cnt < SW_API_IGMP_ENTRY_MAX) {
		switchWrapperDebug(DBGDUMP, "Add New Entry to the table:");
		memcpy(&table->igmpTable[table->cnt].entry, newEntry, sizeof(swIgmpForwardEntry));
		table->cnt++;
		if (idx < (table->cnt - 1)) {	/*we find the same group with wild source */
			table->igmpTable[table->cnt - 1].entry.portMap |=
				table->igmpTable[idx].entry.portMap;
		}
		DUMPENTR(&table->igmpTable[table->cnt - 1].entry);
	} else {
		switchWrapperDebug(DBGERR, "Out of the entry limitation of %d",
			SW_API_IGMP_ENTRY_MAX);
		return -1;
	}
	return 0;
}

/*in the hardware, the group with src is in higher priority than the group with
  wild src in the ACL
  for a exclude entry:
	   we need use two ACL:
	  a group with the src is abandoned to its port
	  a group with wild src is allowed to its port
  for a wild src entry:
	  we need change all the entry with same group, allow it pass to its port.
  for a src entry:
	  add or change the entry with same group and src

 */
static int switchAddEntry(swIgmpForwardTable * table, swIgmpForwardEntry * newEntry, int isWild,
	int isExclude)
{
	int idx;

	for (idx = 0; idx < table->cnt; idx++) {
		if (memcmp(&table->igmpTable[idx].entry, newEntry, sizeof(swIPAddr) * 2) == 0) {
			break;
		}
	}
	/*Find the same group with same src ip */
	if (idx < table->cnt && !isExclude) {
		if (isWild) {
			/*the new  group with wild src,
			   We need add this port to the same group with/without specified src */
			return switchAddWildentry(table, newEntry);
		} else
			table->igmpTable[idx].entry.portMap |= newEntry->portMap;
	}

	/*There is no such entry with same group and src,we create */
	if (idx == table->cnt) {
		if (isWild) {
			return switchAddWildentry(table, newEntry);
		} else
		{		/*exclude add a new one too here,don't return at once */

			if (switchAddNewEntry(table, newEntry)) {
				return -1;
			}
		}
	}
	if (isExclude) {	/*for those exlude entry, it must not be a wild */
		switchAddWildentry(table, newEntry);
		/*Remove the its port from the port map of the entry newly created or existing
		   in the old list */
		table->igmpTable[idx].entry.portMap &= ~(newEntry->portMap);
	}
	return 0;
}

static int switchAddIgmpMldRules()
{
	swACLRule rule;

	/*Rules for IGMP packets */
	switchCommandExcuteVar(SW_API_ACL_LIST_CREAT, 3, 0, 10, 10);

	memset(&rule, 0, sizeof(swACLRule));
	rule.rule_type = FAL_ACL_RULE_IP4;
	rule.ip_proto_val = 0x02;
	rule.ip_proto_mask = 0xff;
	FAL_FIELD_FLG_SET(rule.field_flg, FAL_ACL_FIELD_IP_PROTO);
	rule.ports = 1 << switchWrapperState.rootPort;
	rule.action_flg = 0x1UL << FAL_ACL_ACTION_REDPT;
	switchCommandExcuteVar(SW_API_ACL_RULE_ADD, 5, 0, 10, 0, 1, (u_int32_t) (&rule));

	switchCommandExcuteVar(SW_API_ACL_LIST_BIND, 5, 0, 10, 0, 0, 1);
	switchCommandExcuteVar(SW_API_ACL_LIST_BIND, 5, 0, 10, 0, 0, 2);
	switchCommandExcuteVar(SW_API_ACL_LIST_BIND, 5, 0, 10, 0, 0, 3);
	switchCommandExcuteVar(SW_API_ACL_LIST_BIND, 5, 0, 10, 0, 0, 4);

	/*Rules for MLD packets */
	switchCommandExcuteVar(SW_API_ACL_LIST_CREAT, 3, 0, 20, 20);

	memset(&rule, 0, sizeof(swACLRule));
	rule.rule_type = FAL_ACL_RULE_IP6;
	rule.icmp_type_mask = 0xff;
	FAL_FIELD_FLG_SET(rule.field_flg, FAL_ACL_FIELD_ICMP_TYPE);
	rule.ports = 1 << switchWrapperState.rootPort;
	rule.action_flg = 0x1UL << FAL_ACL_ACTION_REDPT;

	rule.icmp_type_val = 130; /*Multicast Listener Query*/
	switchCommandExcuteVar(SW_API_ACL_RULE_ADD, 5, 0, 20, 0, 1, (u_int32_t)(&rule));
	rule.icmp_type_val = 131; /*Multicast Listener Report*/
	switchCommandExcuteVar(SW_API_ACL_RULE_ADD, 5, 0, 20, 1, 1, (u_int32_t)(&rule));
	rule.icmp_type_val = 132; /*Multicast Listener Done*/
	switchCommandExcuteVar(SW_API_ACL_RULE_ADD, 5, 0, 20, 2, 1, (u_int32_t)(&rule));
	rule.icmp_type_val = 143; /*Multicast Listener Report, Version 2*/
	switchCommandExcuteVar(SW_API_ACL_RULE_ADD, 5, 0, 20, 3, 1, (u_int32_t)(&rule));

	switchCommandExcuteVar(SW_API_ACL_LIST_BIND, 5, 0, 20, 0, 0, 1);
	switchCommandExcuteVar(SW_API_ACL_LIST_BIND, 5, 0, 20, 0, 0, 2);
	switchCommandExcuteVar(SW_API_ACL_LIST_BIND, 5, 0, 20, 0, 0, 3);
	switchCommandExcuteVar(SW_API_ACL_LIST_BIND, 5, 0, 20, 0, 0, 4);

	/*Ensure ACL engine working*/
	switchCommandExcuteVar(SW_API_ACL_STATUS_SET, 2, 0, 1);

	return 0;
}

/* ---------------------External Functions ------------------*/
/*switchInitSnooping
	Open IOCTL for the ACL operation,
	recover the igmp acl from switch driver
*/

int switchInitSnooping(void)
{
	if (switchWrapperState.isInit)
		return 0;
	switchWrapperState.isInit = 1;
	switchWrapperState.debugModule = dbgModuleFind("switchWrapper");
	/*Need get the vid from config */
	switchWrapperState.vid =
		atoi(profileGetOpts(mdModuleID_Interface, "SwitchLanVid",
			switchWrapperDefaulttable));
	switchWrapperState.rootPort =
		atoi(profileGetOpts(mdModuleID_Interface, "SwitchCpuPort",
			switchWrapperDefaulttable));
	switchWrapperDebug(DBGDUMP, "RootPort:%d", switchWrapperState.rootPort);
	switchWrapperDebug(DBGDUMP, "Enter %s", __func__);
	if ((switchWrapperState.socketFd = open(SW_IOCTL_INTERFACE_NAME, O_RDWR)) < 0) {
		switchWrapperDebug(DBGERR, "Can't Open Switch's IO");
		return -1;
	}

	/*All the packet in this port will pass to the CPU only */
	switchCommandExcute(SW_API_IGMP_RP_SET, 0, 1 << switchWrapperState.rootPort);
	/*The RP rule doesn't take effects when HW snooping is disabled,
	   so we need additional ACL rules to rediret IGMP/MLD to CPU ports */
	switchAddIgmpMldRules();

	//Sync the igmp entry from the hardware, not completed yet
	switchQueryGroupRule(&switchWrapperState.keptTable);
	switchWrapperDebug(DBGDUMP, "Leave %s", __func__);
	return 0;
}



//There are no flush ACL table function on the switch API
//We need keep the old TABLE, and compare with the new SNOOPING table
//for these disappearing group, we need call clear function to delete it
// for new group and kept group, we need call set function to add or modify them
int switchSetgroupRule(swIgmpForwardEntry * entry)
{
	return switchCommandExcute(SW_API_IGMP_SG_ENTRY_SET, 0, entry);
}

/*Clear the group Rules*/
int switchClearGroupRule(swIgmpForwardEntry * entry)
{
	return switchCommandExcute(SW_API_IGMP_SG_ENTRY_CLEAR, 0, entry);
}

/*
Add an item in the RESV FDB table, this is a limit of number 32,
because common fdb operation required vid information,there are
a lit difficult to get it
*/
int switchAddFdb(struct ether_addr *mac, swBitsMap map)
{
	swFdbEntry entry;

	memset(&entry, 0, sizeof(entry));
	entry.addr = *mac;
	entry.port.map = map;
	return switchCommandExcute(SW_API_FDB_RESV_ADD, 0, (u_int32_t) & entry);
}

/*
Clear an item in the RESV FDB table,
it will clear the ports included in the map
*/
int switchClearFdb(struct ether_addr *mac, swBitsMap map)
{
	swFdbEntry entry;

	memset(&entry, 0, sizeof(entry));
	entry.addr = *mac;
	entry.port.map = map;
	return switchCommandExcute(SW_API_FDB_RESV_DEL, 0, (u_int32_t) & entry);
}

/*switchUpdateForwardTbl:
 *	 The table is a group table collected by linux bridge
 *	  nSize: the size of the table in bytes
 */
int switchUpdateForwardTbl(void *table, int nSize)
{
	int idx, nodeidx, srcIdx;
	struct __mc_iftbl_entry *entry;
	struct __mc_iftbl_node *node;
	u_int32_t emptyIP[4];
	FILLIPFUNC fillIP;
	swIgmpForwardEntry tmpFwdEntry;
	swIgmpForwardTable newGroupTable;
	int keepArray[SW_API_IGMP_ENTRY_MAX] = { /*zero */  };
	struct mcManagerIFtable *fwdTable = table;

	switchWrapperDebug(DBGDUMP, "%s: Enter", __func__);
	if (!fwdTable || !nSize)
		return switchFlushSnoopinfwdTable();

	memset(&newGroupTable, 0, sizeof(newGroupTable));
	memset(emptyIP, 0, sizeof(emptyIP));

	for (idx = 0; idx < fwdTable->entryCnt; idx++) {
		memset(&tmpFwdEntry, 0, sizeof(tmpFwdEntry));
		entry = &(fwdTable->entry[idx]);
		if (entry->group.pro == htons(ETH_P_IP)) {
			fillIP = switchFillIPv4;
		} else {
			fillIP = switchFillIPv6;
		}
		fillIP(&tmpFwdEntry.group, (u_int32_t *) & (entry->group.u));
		tmpFwdEntry.vid = switchWrapperState.vid;
		/*In the switch, An ACL item include only one src and one group
		 *We need set one ACL for a src
		 */
		for (nodeidx = 0; nodeidx < entry->node_cnt; nodeidx++) {
			node = entry->nodes + nodeidx;
			tmpFwdEntry.portMap =
				switchFindPortmap((struct ether_addr *)node->mac,
				switchWrapperState.vid);
			/*When the it don't limit the src, it will allow all the src to the port */
			if (node->nsrcs == 0) {
				/*When delete ipv6, the source type must be ipv6 */
				switchWrapperDebug(DBGDUMP, "%s: Fill empty src", __func__);
				fillIP(&tmpFwdEntry.src, emptyIP);
				if (switchAddEntry(&newGroupTable, &tmpFwdEntry, 1, 0))
					break;	// When out of MAX entry, ignore the left entry
				DUMPENTR(&tmpFwdEntry);
				continue;
			}
			for (srcIdx = 0; srcIdx < node->nsrcs; srcIdx++) {
				switchWrapperDebug(DBGDUMP, "%s: Fill real src:%s",
					__func__,
					node->filter_mode ==
					IGMPV3_MODE_IS_EXCLUDE ? "exlude" : "include");
				if (memcmp(node->srcs + srcIdx * MC_DEF_IP6_SIZE, emptyIP,
						sizeof(emptyIP)) == 0) {
					switchWrapperDebug(DBGERR, "%s:Invalid source ", __func__);
					continue;
				}
				fillIP(&tmpFwdEntry.src,
					(u_int32_t *) (node->srcs + srcIdx * MC_DEF_IP6_SIZE));
				if (switchAddEntry(&newGroupTable, &tmpFwdEntry, 0,
						node->filter_mode == IGMPV3_MODE_IS_EXCLUDE))
					break;	// When out of MAX entry, ignore the left entry
				DUMPENTR(&tmpFwdEntry);
			}
		}
	}
	switchWrapperDebug(DBGDUMP, "Going to set newGroupTable.cnt:%d", newGroupTable.cnt);
	/*Set all the groups */
	for (idx = 0; idx < newGroupTable.cnt && idx < SW_API_IGMP_ENTRY_MAX; idx++) {
		srcIdx = switchFindForwardEntry(&switchWrapperState.keptTable,
			&newGroupTable.igmpTable[idx].entry);
		/*No Such entry in the list */
		if (srcIdx < 0 || srcIdx >= SW_API_IGMP_ENTRY_MAX)
			continue;

		/*We need clear it at first and the set new rule if its portMap is change */
		if (newGroupTable.igmpTable[idx].entry.portMap !=
			switchWrapperState.keptTable.igmpTable[srcIdx].entry.portMap) {
			switchWrapperDebug(DBGDUMP, "Clear the entry");
			/*Clear the old port map */
			DUMPENTR(&switchWrapperState.keptTable.igmpTable[srcIdx].entry);
			if (switchClearGroupRule(&switchWrapperState.keptTable.igmpTable[srcIdx].
					entry)) {
				switchWrapperDebug(DBGERR, "Clear ACL rule failed");
				return -1;
			}
		} else
			keepArray[idx] = 1;

		/*for No Change entry,do nothing here */
		/*we delete it from the kept record,
		 *if it is the last entry,we can delete it by subtracting the number of entry*/
		if (switchWrapperState.keptTable.cnt > srcIdx + 1) {
			memmove(switchWrapperState.keptTable.igmpTable + srcIdx,
				switchWrapperState.keptTable.igmpTable + srcIdx + 1,
				(switchWrapperState.keptTable.cnt - srcIdx -
					1) * sizeof(swIgmpForwardItem));
		}
		switchWrapperState.keptTable.cnt--;

	}

	switchWrapperDebug(DBGDEBUG, "Clear Non-exist entry");
	/*We need clear all the left igmpTable in the Kept table
	   since them is not required in the new table */
	for (idx = 0; idx < switchWrapperState.keptTable.cnt; idx++) {
		if (switchClearGroupRule(&switchWrapperState.keptTable.igmpTable[idx].entry)) {
			switchWrapperDebug(DBGERR, "Clear ACL rule failed");
			return -1;
		}
		DUMPENTR(&switchWrapperState.keptTable.igmpTable[idx].entry);
	}

	switchWrapperDebug(DBGDEBUG, "Set New entry:%d", newGroupTable.cnt);
	/*Because there are limitation of ACL entry, we clear the unused entry at first and
	 *set the new entry */
	for (idx = 0; idx < newGroupTable.cnt && idx < SW_API_IGMP_ENTRY_MAX; idx++) {
		if (keepArray[idx]) {
			switchWrapperDebug(DBGDUMP, "Skip the entry");
			DUMPENTR(&switchWrapperState.keptTable.igmpTable[idx].entry);
			continue;
		}
		if (switchSetgroupRule(&newGroupTable.igmpTable[idx].entry)) {
			switchWrapperDebug(DBGERR, "Set ACL rule failed");
			return -1;
		}
		DUMPENTR(&newGroupTable.igmpTable[idx].entry);
	}

	/*Put the new group as the Kept group table*/
	memcpy(&switchWrapperState.keptTable, &newGroupTable, sizeof(newGroupTable));

	switchWrapperDebug(DBGDUMP, "New switchWrapperState.keptTable.cnt:%d",
		switchWrapperState.keptTable.cnt);
	return 0;
}
