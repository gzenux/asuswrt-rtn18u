/*
 * @File: mcfwdtblwlan5g.c
 *
 * @Abstract: WLAN5G Multicast forwarding database plugin
 *
 * @Notes:
 *
 * Copyright (c) 2014-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <dbg.h>

#include "wlanManager.h"
#include "qassert.h"
#include "mcif.h"

static struct mcWlan5gState_t {
	u_int32_t IsInit;	/* overall initialization done */
	struct dbgModule *DebugModule;	/* debug message context */
} mcWlan5gState;

#define mcWlan5gDebug(level, ...) \
                 dbgf(mcWlan5gState.DebugModule,(level),__VA_ARGS__)

/*========================================================================*/
/*============ Internal handling =========================================*/
/*========================================================================*/

int WLAN5G_InitForwardTablePlugin(interface_t *iface)
{
	if (mcWlan5gState.IsInit)
		return 0;

	if (!iface || iface->type != interfaceType_WLAN5G)
		return -1;

	mcWlan5gState.DebugModule = dbgModuleFind("mcWlan5g");
	mcWlan5gState.IsInit = 1;

	/* Finish processing for non-QCA interfaces */
	if (iface->flags & INTERFACE_FLAGS_NON_QCA)
		return 0;

	return 0;
}

int WLAN5G_UpdateForwardTable(interface_t *iface, void *table, u_int32_t size)
{
	int32_t NLSock;
	struct sockaddr_nl Kpeer;
	struct nlmsghdr *NLh;

	if (!mcWlan5gState.IsInit)
		return -1;

	if (!iface) {
		mcWlan5gDebug(DBGERR, "%s: error, iface is NULL!", __func__);
		return -1;
	}

	if (iface->type != interfaceType_WLAN5G)
		return -1;

	if (iface->flags & INTERFACE_FLAGS_NON_QCA)
		return 0;

	NLSock = wlanManager_GetSock();
	if (NLSock < 0) {
		mcWlan5gDebug(DBGERR, "%s: error, socket not initialized!", __func__);
		return -1;
	}

	NLh = malloc(NLMSG_LENGTH(size));
	if (!NLh) {
		mcWlan5gDebug(DBGERR, "%s: No memory!", __func__);
		return -1;
	}

	wlanManager_TriggerMsgWrap(NLh, &Kpeer, size);

	NLh->nlmsg_flags = iface->systemIndex;
	NLh->nlmsg_type = IEEE80211_ALD_MCTBL_UPDATE;
	if (table && size)
		memcpy(NLMSG_DATA(NLh), table, size);

	if (sendto(NLSock, NLh, NLh->nlmsg_len, 0, (struct sockaddr *)&Kpeer, sizeof Kpeer) < 0) {
		mcWlan5gDebug(DBGERR, "%s: Update WLAN Multicast forwarding table!", __func__);
		free(NLh);
		return -1;
	}

	free(NLh);

	mcWlan5gDebug(DBGDEBUG, "%s: Successfully updated WLAN5G Multicast forwarding table",
		__func__);
	return 0;
}

int WLAN5G_FlushForwardTable(interface_t *iface)
{
	return WLAN5G_UpdateForwardTable(iface, NULL, 0);
}
