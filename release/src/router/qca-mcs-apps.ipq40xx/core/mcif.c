/*
 * @File: mcif.c
 *
 * @Abstract: multcast interface management module
 *
 * @Notes:
 *
 * Copyright (c) 2011, 2015, 2017 Qualcomm Atheros, Inc.
 * All rights reserved.
 *
 */

#include <string.h>
#include <stdlib.h>
#include <interface.h>
#include <split.h>
#include <dbg.h>
#include "mcif.h"
#include "module.h"
#include "profile.h"
#include "mcnl.h"
#include "wlanManager.h"

static struct {
	struct dbgModule *DebugModule;
	interface_t interfaceList[INTERFACE_MAX_INTERFACES];
	interface_t bridge;
	u_int32_t numInterfaces;
} interfaceS;

#define INTERFACE_GROUP_ID_NO_RELAY     0
#define INTERFACE_GROUP_ID_RELAY        1

/* Interface type stringification */
#define STR(_x)   #_x
#define XSTR(_x)  STR(_x)
#define INTERFACE_ENTRY( _x, _y ) XSTR( _x ),
static const char *interface_typeStrings[interfaceType_Reserved + 1] = {
	INTERFACE_LIST NULL	/* Last type */
};

#undef INTERFACE_ENTRY

static struct profileElement interfaceElementDefaultTable[] = {
	{NULL, NULL}
};

#define interfaceDebug(level, ...) \
        dbgf(interfaceS.DebugModule,(level),__VA_ARGS__)

static interfaceType_e interface_getType(const char *str, MCS_BOOL *nonQCA)
{
	u_int32_t i = 0;

	if (str[0] == '~') {
		str++;
		*nonQCA = MCS_TRUE;
	} else {
		*nonQCA = MCS_FALSE;
	}

	while (interface_typeStrings[i] != NULL) {
		if (strcmp(interface_typeStrings[i], str) == 0)
			return i;

		i++;
	}

	return interfaceType_Reserved;
}

const char *interface_getTypeString(interfaceType_e type)
{
	if (type >= interfaceType_Reserved) {
		return "UNKNOWN";
	}

	return interface_typeStrings[type];
}

void interface_init(void)
{
	u_int32_t i;
	const char *interfaceList;
	const char *ptr;

	/* Register for debug messages from this file */
	interfaceS.DebugModule = dbgModuleFind("mcif");

	/* Clear interface array */
	memset(interfaceS.interfaceList, 0, sizeof(interfaceS.interfaceList));
	memset(&interfaceS.bridge, 0, sizeof(interfaceS.bridge));

	for (i = 0; i < INTERFACE_MAX_INTERFACES; i++) {
		interfaceS.interfaceList[i].index = i;
		interfaceS.interfaceList[i].type = interfaceType_Reserved;
	}

	/* Initialize bridge from configuration file */
	ptr = profileGetOpts(mdModuleID_Interface, "BridgeName", interfaceElementDefaultTable);

	/*prt won't be null*/
	if (!ptr[0]) {
		interfaceDebug(DBGERR, "%s: Please specify the interface name of the bridge.",
			__func__);
		exit(1);
	}

	strlcpy(interfaceS.bridge.name, ptr, IFNAMSIZ);
	interfaceS.bridge.type = interfaceType_BRIDGE;
	interfaceS.bridge.index = INTERFACE_MAX_INTERFACES;	/* Pseudo-Index, used by clients */

	interfaceDebug(DBGDUMP, "%s: BridgeName = %s", __func__, interfaceS.bridge.name);

	interfaceList =
		profileGetOpts(mdModuleID_Interface, "ManagedInterfacesList",
		interfaceElementDefaultTable);

	interfaceDebug(DBGDUMP, "%s: ManagedInterfacesList = %s", __func__, interfaceList);

	char parsedInterfaceList[INTERFACE_MAX_INTERFACES][IFNAMSIZ + 8];

	if (strlen(interfaceList)) {
		interfaceS.numInterfaces =
			splitByToken(interfaceList, INTERFACE_MAX_INTERFACES, IFNAMSIZ + 8,
			(char *)parsedInterfaceList, ',');
	}

	if (interfaceS.numInterfaces == 0) {
		interfaceDebug(DBGERR, "%s: No interfaces specified!", __func__);
		exit(1);
	}

	/* Initialize interfaces from configuration file */
	for (i = 0; i < interfaceS.numInterfaces; i++) {
		char *semi;

		semi = strchr(parsedInterfaceList[i], ':');

		if (semi) {
			char *typeStr = semi + 1;
			interfaceType_e type;
			MCS_BOOL nonQCA;

			*semi = '\0';

			if ((type = interface_getType(typeStr, &nonQCA)) != interfaceType_Reserved) {
				/* Initialize an interface entry */
				strlcpy(interfaceS.interfaceList[i].name, parsedInterfaceList[i],
					IFNAMSIZ);
				interfaceS.interfaceList[i].type = type;
				interfaceS.interfaceList[i].systemIndex =
					if_nametoindex(interfaceS.interfaceList[i].name);

				if (nonQCA)
					interfaceS.interfaceList[i].flags |=
						INTERFACE_FLAGS_NON_QCA;

				if (type == interfaceType_WLAN) {
					if (wlanManager_getFreq(&interfaceS.interfaceList[i]) !=
						MCS_OK) {
						interfaceDebug(DBGERR,
							"%s: Unable to read Wi-Fi band!", __func__);
						if (nonQCA)
							interfaceS.interfaceList[i].type = interfaceType_WLAN;
						else
							exit(1);
					}
				} else if (type == interfaceType_ESWITCH) {
					interfaceS.interfaceList[i].type = interfaceType_ETHER;
					interfaceS.interfaceList[i].flags |=
						INTERFACE_FLAGS_ESWITCH;
				}

				if (interfaceSetIFFlag(interfaceS.interfaceList[i].name,
						IFF_ALLMULTI) < 0) {
					interfaceDebug(DBGERR,
						"%s: Failed to enable Multicast option for interface %s",
						__func__, interfaceS.interfaceList[i].name);
					exit(1);
				}
			} else {
				interfaceDebug(DBGERR,
					"%s: Invalid interface type specified devFile ManagedInterfacesList: %s",
					__func__, typeStr);
				exit(1);
			}
		} else {
			interfaceDebug(DBGERR,
				"%s: Invalid format devFile ManagedInterfacesList. Should be if:type,if:type,...",
				__func__);
			exit(1);
		}
	}

}

interface_t *interface_getInterfaceFromName(const char *name)
{
	u_int32_t i;

	for (i = 0; i < interfaceS.numInterfaces; i++) {
		if (strcmp(name, interfaceS.interfaceList[i].name) == 0) {
			return &interfaceS.interfaceList[i];
		}
	}

	return NULL;
}

interface_t *interface_getInterfaceFromSystemIndex(u_int32_t systemIndex)
{
	u_int32_t i;

	for (i = 0; i < interfaceS.numInterfaces; i++) {
		if (interfaceS.interfaceList[i].systemIndex == systemIndex) {
			return &interfaceS.interfaceList[i];
		}
	}

	/* Interface not found. Maybe indecies were updated */
	for (i = 0; i < interfaceS.numInterfaces; i++) {
		interfaceS.interfaceList[i].systemIndex =
			if_nametoindex(interfaceS.interfaceList[i].name);

		if (interfaceS.interfaceList[i].systemIndex == systemIndex) {
			return &interfaceS.interfaceList[i];
		}
	}

	return NULL;
}

u_int32_t interface_getNumInterfaces(void)
{
	return interfaceS.numInterfaces;
}

interface_t *interface_getFirst(void)
{
	return &interfaceS.interfaceList[0];
}

interface_t *interface_getNext(interface_t *prev)
{
	u_int32_t index;

	/* Check for last entry */
	if (prev->index >= interfaceS.numInterfaces - 1)
		return NULL;

	index = prev->index + 1;

	/* Check for type. Reserved means also end of list */
	if (interfaceS.interfaceList[index].type == interfaceType_Reserved)
		return NULL;

	return &interfaceS.interfaceList[index];
}

interface_t *interface_getBridge(void)
{
	return &interfaceS.bridge;
}

interface_t *interface_getInterfaceFromType(interfaceType_e type)
{
	u_int32_t i;

	/* Hai: todo: This function is a hack, to conform with previous implementation.
	 * Needs to be revised and/or removed.
	 */
	for (i = 0; i < interfaceS.numInterfaces; i++) {
		if (interfaceS.interfaceList[i].type == type) {
			return &interfaceS.interfaceList[i];
		}
	}

	/* Not found */
	return NULL;
}

#define IF_MAX_LINE_LENGTH    300
#define IF_STATS_DELIMITERS   "\n\t :"

static u_int64_t interface_getNextToken(char *saveptr, MCS_BOOL convert)
{
	char *token;
	u_int64_t value = 0;

	token = strtok_r(NULL, IF_STATS_DELIMITERS, &saveptr);

	if (convert && token) {
		/* Convert the ASCII value to a real number */
		value = strtoul(token, NULL, 10);
	}

	return value;
}

MCS_STATUS interface_getInterfaceStats(interface_t *iface, interfaceStats_t *stats)
{
	char buffer[IF_MAX_LINE_LENGTH];
	FILE *devFile;
	MCS_STATUS retval = MCS_NOK;
	char *saveptr;

	/* The /proc/net/dev file contains a list of all interfaces and their statistics.
	 * Here's a snapshot of the format we expect to read.
	 *
	 * The interfaceStats_t structure is a one to one matching to this format.
	 *
	 * Inter-|   Receive                                                |  Transmit
	 *  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
	 *     lo:    6121      73    0    0    0     0          0         0     6121      73    0    0    0     0       0          0
	 *   eth0: 1326887   13618    0    0    0     0          0      1219  1500147   13406    0    0    0     0       0          0
	 *
	 */
	if (!stats || !(devFile = fopen("/proc/net/dev", "r"))) {
		return MCS_NOK;
	}

	/* Skip the first two lines */
	fgets(buffer, IF_MAX_LINE_LENGTH, devFile);
	fgets(buffer, IF_MAX_LINE_LENGTH, devFile);

	/* Now read the statistics */
	while (fgets(buffer, IF_MAX_LINE_LENGTH, devFile)) {
		char *token;

		/* Tokenize the line */
		if (!(token = strtok_r(buffer, IF_STATS_DELIMITERS, &saveptr))) {
			break;
		}

		/* Skip this line if not our interface */
		if (strcmp(token, iface->name) != 0)
			continue;

		/* Read RX data */
		stats->rxBytes = interface_getNextToken(saveptr, MCS_TRUE);
		stats->rxPackets = interface_getNextToken(saveptr, MCS_TRUE);
		stats->rxErrors = (u_int32_t) interface_getNextToken(saveptr, MCS_TRUE);
		stats->rxDropped = (u_int32_t) interface_getNextToken(saveptr, MCS_TRUE);
		/* Don't care about fifo, frame, compressed */
		interface_getNextToken(saveptr, MCS_FALSE);
		interface_getNextToken(saveptr, MCS_FALSE);
		interface_getNextToken(saveptr, MCS_FALSE);
		stats->rxMulticast = (u_int32_t) interface_getNextToken(saveptr, MCS_TRUE);
		stats->rxUnicast = stats->rxPackets - stats->rxMulticast;

		/* Read TX data */
		stats->txBytes = interface_getNextToken(saveptr, MCS_TRUE);
		stats->txPackets = interface_getNextToken(saveptr, MCS_TRUE);
		stats->txErrors = (u_int32_t) interface_getNextToken(saveptr, MCS_TRUE);
		stats->txDropped = (u_int32_t) interface_getNextToken(saveptr, MCS_TRUE);
		stats->txUnicast = stats->txPackets;

		retval = MCS_OK;
	}

	fclose(devFile);
	return retval;
}

