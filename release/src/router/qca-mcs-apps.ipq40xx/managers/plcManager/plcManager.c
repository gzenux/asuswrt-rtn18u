/*
 * @File: plcManager.c
 *
 * @Abstract: PLC manager
 *
 * @Notes:
 *
 * Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

/* C and system library includes */
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include <dbg.h>
#include <bufrd.h>
#include <bufwr.h>
#include <evloop.h>

#include "module.h"
#include "profile.h"
#include "plcManager.h"
#include "service_message.h"
#include "internal.h"

#define plcManagerReadBufSize       1600
#define plcManagerGetDataInterval    2	/* 2s */
#define HYD_PLC_SOCKET_CLIENT       "/var/run/hybrid_socket_client"
#define PLC_SOCKET_SERVER           "/var/run/plc_socket_server"

struct plcManagerConfig_t {
	u_int32_t UpdateStatsInterval;
};

static struct plcManagerState_t {
	u_int32_t IsInit;	/* overall initialization done */
	int32_t PlcSock;	/* Socket Used for communication with PLC Host Daemon */
	struct bufrd ReadBuf;	/* for reading from */
	struct dbgModule *DebugModule;	/* debug message context */
	struct plcManagerConfig_t Config;	/* local configure parameters */

	struct evloopTimeout GetDataTimer;	/* evloop timer */
	u_int8_t LocalMAC[HD_ETH_ADDR_LEN];
	MCS_BOOL MACValid;
	u_int8_t LocalNID[plcManagerNIDLen];
	MCS_BOOL NIDValid;
} plcManagerS;

#define plcManagerDebug(level, ...) \
                 dbgf(plcManagerS.DebugModule,(level),__VA_ARGS__)
#define plcManagerTRACE() plcManagerDebug(DBGDEBUG, "ENTER %s", __func__)
static void plcManagerReadBufCB(void *Cookie /*unused */ );

/* Unregister read buffer callback.
 */
static void plcManagerReadbufUnRegister(void)
{
	/* Destroy the buffer and close the socket */
	bufrdDestroy(&plcManagerS.ReadBuf);
}

/* Create Unix socket to communicate with PLC Host Daemon
 */
static int32_t plcManagerCreatePlcSock(void)
{
	int32_t sock;

	struct sockaddr_un clientAddr = {
		AF_UNIX,
		HYD_PLC_SOCKET_CLIENT
	};

	plcManagerTRACE();
	unlink(clientAddr.sun_path);

	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		plcManagerDebug(DBGERR, "%s:Socket() failed. Err no=%d", __func__, errno);
		goto err;
	}

	if (bind(sock, (struct sockaddr *)(&clientAddr), sizeof(clientAddr)) == -1) {
		plcManagerDebug(DBGERR, "%s:Bind() failed. Err no=%d", __func__, errno);
		close(sock);
		goto err;
	}

	/* Set nonblock. */
	if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK)) {
		plcManagerDebug(DBGERR, "%s failed to set fd NONBLOCK", __func__);
		goto err;
	}

	return sock;
err:
	return -1;
}

/* Register read buffer callback.
 */
static void plcManagerReadbufRegister(void)
{
	plcManagerTRACE();
	plcManagerS.PlcSock = plcManagerCreatePlcSock();

	if (plcManagerS.PlcSock < 0) {
		plcManagerDebug(DBGERR, "%s: Create Unix socket failed", __func__);
		return;
	}

	/* Initialize input context */
	bufrdCreate(&plcManagerS.ReadBuf, "plcManager-rd",
		plcManagerS.PlcSock, plcManagerReadBufSize /* Read buf size */ ,
		plcManagerReadBufCB,	/* callback */
		NULL);
}


/*========================================================================*/

/*
 * Place holder function to be called when receive an Update on PLC Information.
 */
static void plcManagerOnPlcUpdate(void *Buf, u_int32_t BufLen)
{
	struct service_message *message = (struct service_message *)Buf;

	plcManagerTRACE();

	if (!Buf)
		return;

	switch (message->cmd) {
	case SM_GET_LOCAL_MAC_HYD_RSP:
		{
			int LocalMAC[HD_ETH_ADDR_LEN];

			plcManagerDebug(DBGDUMP, "%s: SM_GET_LOCAL_MAC_HYD_RSP: %s", __func__,
				message->data);

			if (sscanf((char *)message->data, "%02x:%02x:%02x:%02x:%02x:%02x",
					&LocalMAC[0], &LocalMAC[1], &LocalMAC[2], &LocalMAC[3],
					&LocalMAC[4], &LocalMAC[5]) == 6) {

				plcManagerS.LocalMAC[0] = LocalMAC[0];
				plcManagerS.LocalMAC[1] = LocalMAC[1];
				plcManagerS.LocalMAC[2] = LocalMAC[2];
				plcManagerS.LocalMAC[3] = LocalMAC[3];
				plcManagerS.LocalMAC[4] = LocalMAC[4];
				plcManagerS.LocalMAC[5] = LocalMAC[5];

				if (!((plcManagerS.LocalMAC[0] & 0x01) ||
						MACAddrEqual(PLC_STATIC_MAC, plcManagerS.LocalMAC)))
					plcManagerS.MACValid = MCS_TRUE;
			}
		}
		break;
	case SM_GET_PLC_NID_RSP:
		{
			int LocalNID[plcManagerNIDLen];
			u_int32_t i, change = 0;

			plcManagerDebug(DBGDUMP, "%s: SM_GET_PLC_NID_RSP: %s", __func__,
				message->data);

			if (sscanf((char *)message->data, "%02x%02x%02x%02x%02x%02x%02x",
					&LocalNID[0], &LocalNID[1], &LocalNID[2], &LocalNID[3],
					&LocalNID[4], &LocalNID[5], &LocalNID[6]) == 7) {

				for (i = 0; i < plcManagerNIDLen; i++) {
					if (plcManagerS.LocalNID[i] != (u_int8_t) LocalNID[i]) {
						change = 1;
					}

					plcManagerS.LocalNID[i] = LocalNID[i];
				}

				if (change || !plcManagerS.NIDValid) {
					mdCreateEvent(mdModuleID_Plc, mdEventPriority_Low,
						plcManagerEvent_NIDChange, NULL, 0);

					plcManagerDebug(DBGDUMP, "%s: Create event: NID Changed",
						__func__);
				}

				plcManagerS.NIDValid = MCS_TRUE;
			}
		}
		break;
	case SM_EVENT_PLC_DOWN:
	case SM_EVENT_PLC_UP:
		{
			u_int8_t Data = message->cmd;

			if (message->cmd == SM_EVENT_PLC_DOWN) {
				plcManagerS.NIDValid = MCS_FALSE;

				evloopTimeoutRegister(&plcManagerS.GetDataTimer,
					plcManagerGetDataInterval, 0);
			}

			mdCreateEvent(mdModuleID_Plc, mdEventPriority_Low,
				plcManagerEvent_Link, &Data, sizeof(Data));

			plcManagerDebug(DBGDUMP, "%s: Create event: %s",
				__func__, message->cmd == SM_EVENT_PLC_UP ? "PLC UP" : "PLC DOWN");
		}
		break;
	case SM_UPDATE_HIFI_TABLE_FAILURE:
	case SM_SET_IGMP_SNOOPING_FAILURE:
		{
			u_int8_t Data = message->cmd;
			u_int32_t Event = message->cmd == SM_UPDATE_HIFI_TABLE_FAILURE ?
				plcManagerEvent_MCTableFail : plcManagerEvent_MCSnoopFail;

			mdCreateEvent(mdModuleID_Plc, mdEventPriority_Low, Event, &Data,
				sizeof(Data));

			plcManagerDebug(DBGDUMP, "%s: Create event: %s",
				__func__,
				message->cmd ==
				SM_UPDATE_HIFI_TABLE_FAILURE ? "SET HIFI TABLE FAILED" :
				"SET SNOOPING FAILED");
		}
		break;

	default:
		mdCreateEvent(mdModuleID_Plc,
			mdEventPriority_Low, plcManagerEvent_UpdatedStats, Buf, BufLen);
	}
}

/* Read buffer callback.
 */
static void plcManagerReadBufCB(void *Cookie /*unused */ )
{
	struct bufrd *R = &plcManagerS.ReadBuf;
	u_int32_t NMax = bufrdNBytesGet(R);
	u_int8_t *Buf = bufrdBufGet(R);

	plcManagerTRACE();
	/* Error check. */
	if (bufrdErrorGet(R)) {
		plcManagerDebug(DBGINFO, "%s: Read error!", __func__);

		plcManagerReadbufUnRegister();
		plcManagerReadbufRegister();
		return;
	}

	if (!NMax)
		return;

	plcManagerOnPlcUpdate(Buf, NMax);

	bufrdConsume(R, NMax);
}

static void plcManagerGetDataTimerHandler(void *Cookie)
{
	struct service_message SM;

	struct sockaddr_un serverAddr = {
		AF_UNIX,
		PLC_SOCKET_SERVER
	};

	evloopTimeoutUnregister(&plcManagerS.GetDataTimer);

	if (plcManagerS.MACValid == MCS_TRUE && plcManagerS.NIDValid == MCS_TRUE)
		return;

	if (plcManagerS.MACValid != MCS_TRUE) {
		/* Send Get Local MAC Request */
		SM.cmd = SM_GET_LOCAL_MAC_HYD_REQ;
		SM.len = 1;

		if (sendto(plcManagerS.PlcSock, &SM, sizeof(SM), MSG_DONTWAIT,
				(const struct sockaddr *)(&serverAddr),
				(socklen_t) (sizeof(serverAddr))) < 0) {
			int err = errno;

			if ((err != ECONNREFUSED) && (err != ENOENT) && (err != EAGAIN))
				plcManagerDebug(DBGINFO, "%s:Sendto failed. Error=%d", __func__,
					errno);
		}
	}

	if (plcManagerS.NIDValid != MCS_TRUE) {
		/* Send Get Local NID Request */
		SM.cmd = SM_GET_PLC_NID_REQ;
		SM.len = 1;

		if (sendto(plcManagerS.PlcSock, &SM, sizeof(SM), MSG_DONTWAIT,
				(const struct sockaddr *)(&serverAddr),
				(socklen_t) (sizeof(serverAddr))) < 0) {
			int err = errno;

			if ((err != ECONNREFUSED) && (err != ENOENT) && (err != EAGAIN))
				plcManagerDebug(DBGINFO, "%s:Sendto failed. Error=%d", __func__,
					errno);
		}
	}

	evloopTimeoutRegister(&plcManagerS.GetDataTimer, plcManagerGetDataInterval, 0);
}

/*========================================================================*/
/*============ Init ======================================================*/
/*========================================================================*/

void plcManagerInit(void)
{
	interface_t *interface;

	if (plcManagerS.IsInit)
		return;

	memset(&plcManagerS, 0, sizeof plcManagerS);
	plcManagerS.IsInit = 1;
	plcManagerS.PlcSock = -1;

	plcManagerS.DebugModule = dbgModuleFind("plcManager");
	plcManagerDebug(DBGDEBUG, "ENTER plcManagerInit");

	/* Search for a PLC interface */
	interface = interface_getFirst();

	while (interface) {
		if ((interface->type == interfaceType_PLC) &&
			!(interface->flags & INTERFACE_FLAGS_NON_QCA)) {
			/* Found */
			break;
		}

		interface = interface_getNext(interface);
	}

	/* Register own event table to module core. */
	mdEventTableRegister(mdModuleID_Plc, plcManagerEvent_MaxNum);

	/* Check if no PLC interface is available,
	 * avoid allocating resources.
	 */
	if (!interface)
		return;

	/* Register readbuf to module core. */
	plcManagerReadbufRegister();

	/* creat evloop timer */
	evloopTimeoutCreate(&plcManagerS.GetDataTimer, "plcManagerGetDataTimer", plcManagerGetDataTimerHandler, NULL);	/* Cookie */

	/* register evloop timeout */
	evloopTimeoutRegister(&plcManagerS.GetDataTimer, 0, /* No delay */0);
}

/*========================================================================*/
/*============ Public API ================================================*/
/*========================================================================*/
/* Send Periodic Stats Request */
void plcManager_TriggerStats(void)
{
	struct service_message SM;

	struct sockaddr_un serverAddr = {
		AF_UNIX,
		PLC_SOCKET_SERVER
	};

	if (plcManagerS.PlcSock < 0)
		return;

	/* Send Medium Utilization Request */
	SM.cmd = SM_MEDIUM_UTIL_REQ;
	SM.len = 1;

	if (sendto(plcManagerS.PlcSock, &SM, sizeof(SM), MSG_DONTWAIT,
			(const struct sockaddr *)(&serverAddr),
			(socklen_t) (sizeof(serverAddr))) < 0) {
		int err = errno;

		if ((err != ECONNREFUSED) && (err != ENOENT) && (err != EAGAIN))
			plcManagerDebug(DBGINFO, "%s:Sendto failed. Error=%d", __func__, errno);
		return;
	}

	/* Send Medium Channel Capacity Request */
	SM.cmd = SM_CHANNEL_CAPACITY_REQ;
	SM.len = 1;

	if (sendto(plcManagerS.PlcSock, &SM, sizeof(SM), MSG_DONTWAIT,
			(const struct sockaddr *)(&serverAddr),
			(socklen_t) (sizeof(serverAddr))) < 0) {
		int err = errno;

		if ((err != ECONNREFUSED) && (err != ENOENT) && (err != EAGAIN))
			plcManagerDebug(DBGINFO, "%s:Sendto failed. Error=%d", __func__, errno);
		return;
	}
	return;
}

MCS_STATUS plcManager_GetLocalMAC(u_int8_t *MAC)
{
	if (plcManagerS.MACValid == MCS_TRUE) {
		MACAddrCopy(plcManagerS.LocalMAC, MAC);
		return MCS_OK;
	}

	return MCS_NOK;
}

MCS_STATUS plcManager_GetLocalNID(u_int8_t *NID)
{
	if (plcManagerS.NIDValid == MCS_TRUE) {
		memcpy(NID, plcManagerS.LocalNID, plcManagerNIDLen);
		return MCS_OK;
	}

	return MCS_NOK;
}

MCS_STATUS plcManagerUpdateForwardTable(interface_t *iface, void *table, u_int32_t size)
{
	char *Frame;
	struct service_message *SM;

	struct sockaddr_un serverAddr = {
		AF_UNIX,
		PLC_SOCKET_SERVER
	};
	int FrameLen = table ? (sizeof(*SM) - 1 + size) : sizeof(*SM);

	if (iface->flags & INTERFACE_FLAGS_NON_QCA)
		return MCS_OK;

	if (plcManagerS.PlcSock < 0)
		return MCS_NOK;

	if (FrameLen > SM_FRAME_LEN_MAX) {
		plcManagerDebug(DBGERR, "The size of message is too long, max length is 8184");
		return MCS_NOK;
	}

	if ((Frame = malloc(FrameLen)) == NULL) {
		plcManagerDebug(DBGERR, "No memory");
		return MCS_NOK;
	}
	SM = (struct service_message *)Frame;
	SM->cmd = SM_UPDATE_HIFI_TABLE;
	SM->len = (table && size) ? size : 0;
	if (size && table)
		memcpy(SM->data, table, size);

	if (sendto(plcManagerS.PlcSock, Frame, FrameLen, MSG_DONTWAIT,
			(const struct sockaddr *)(&serverAddr),
			(socklen_t) (sizeof(serverAddr))) < 0) {
		int err = errno;

		if ((err != ECONNREFUSED) && (err != ENOENT) && (err != EAGAIN))
			plcManagerDebug(DBGINFO, "%s:Sendto failed. Error=%d", __func__, err);
		free(Frame);
		return MCS_NOK;
	}
	free(Frame);

	return MCS_OK;
}

MCS_STATUS plcManagerFlushForwardTable(interface_t *iface)
{
	return plcManagerUpdateForwardTable(iface, NULL, 0);
}

MCS_STATUS plcManagerSetSnoopingDisable(void)
{
	char *Frame;
	struct service_message *SM;

	struct sockaddr_un serverAddr = {
		AF_UNIX,
		PLC_SOCKET_SERVER
	};
	int FrameLen = sizeof(*SM) + sizeof(int);

	if (plcManagerS.PlcSock < 0)
		return MCS_NOK;

	if ((Frame = malloc(FrameLen)) == NULL) {
		plcManagerDebug(DBGERR, "No memory");
		return MCS_NOK;
	}
	SM = (struct service_message *)Frame;
	SM->cmd = SM_SET_IGMP_SNOOPING;
	SM->len = sizeof(int);
	*((int *)SM->data) = 0;

	if (sendto(plcManagerS.PlcSock, Frame, FrameLen, MSG_DONTWAIT,
			(const struct sockaddr *)(&serverAddr),
			(socklen_t) (sizeof(serverAddr))) < 0) {
		int err = errno;

		if ((err != ECONNREFUSED) && (err != ENOENT) && (err != EAGAIN))
			plcManagerDebug(DBGINFO, "%s:Sendto failed. Error=%d", __func__, err);
		free(Frame);
		return MCS_NOK;
	}
	free(Frame);

	return MCS_OK;
}
