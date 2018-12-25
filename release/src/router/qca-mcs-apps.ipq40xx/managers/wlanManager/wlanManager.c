/*
 * @File: wlamManager.c
 *
 * @Abstract: WLAN manager
 *
 * @Notes:
 *
 * Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <asm/types.h>
#include <linux/socket.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <dbg.h>
#include <bufrd.h>
#include <bufwr.h>
#include <evloop.h>
#include <module.h>
#include "profile.h"
#include "internal.h"
#include "wlanManager.h"
#include "qassert.h"

#define wlanStatInfoSize       (sizeof(struct ald_stat_info))
#define wlanAssocInfoSize      (sizeof(struct ald_assoc_info))
#define wlanNLDataMaxSize      (wlanStatInfoSize > wlanAssocInfoSize ? wlanStatInfoSize : wlanAssocInfoSize)
#define wlanManagerReadBufSize (sizeof(struct nlmsghdr) + wlanNLDataMaxSize + 16)

static struct wlanManagerState_t {
	u_int32_t IsInit;	/* overall initialization done */
	int32_t NLSock;		/* netlink socket */
	struct bufrd ReadBuf;	/* for reading from */
	struct dbgModule *DebugModule;	/* debug message context */
	struct evloopTimeout CheckFreqTimeout;
} wlanManagerS;

#define wlanManagerDebug(level, ...) \
                 dbgf(wlanManagerS.DebugModule,(level),__VA_ARGS__)
#define wlanManagerTRACE() wlanManagerDebug(DBGDUMP, "ENTER %s", __func__)

static void wlanManagerReadBufCB(void *Cookie /*unused */ );
void wlanManagerMenuInit(void);
/*========================================================================*/
/*============ Internal handling =========================================*/
/*========================================================================*/

/*MHZ to IEEE channel, copied from WLAN driver*/
u_int8_t wlanManager_mhz2ieee(u_int32_t freq)
{
	if (freq == 2484)
		return 14;
	if (freq < 2484)
		return (freq - 2407) / 5;
	if (freq < 5000) {
		if (freq > 4940 && freq < 4990) {	/*public safty band */
			return ((freq * 10) + (((freq % 5) == 2) ? 5 : 0) - 49400) / 5;
		} else if (freq > 4900) {
			return (freq - 4000) / 5;
		} else {
			return 15 + ((freq - 2512) / 20);
		}
	}
	return (freq - 5000) / 5;
}


/* Create netlink socket
 */
static int32_t wlanManagerCreateNLSock(void)
{
	int32_t NLSock;
	struct sockaddr_nl Local;

	if ((NLSock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ALD)) < 0) {
		wlanManagerDebug(DBGERR, "%s: Create netlink socket failed", __func__);
		goto out;
	}

	/* Set nonblock. */
	if (fcntl(NLSock, F_SETFL, fcntl(NLSock, F_GETFL) | O_NONBLOCK)) {
		wlanManagerDebug(DBGERR, "%s fcntl() failed", __func__);
		goto err;
	}

	memset(&Local, 0, sizeof Local);
	Local.nl_family = AF_NETLINK;
	Local.nl_pid = getpid();	/* self pid */
	Local.nl_groups = 0;	/* not in mcast groups */

	if (bind(NLSock, (struct sockaddr *)&Local, sizeof Local) < 0) {
		wlanManagerDebug(DBGERR, "%s: Bind netlink socket failed", __func__);
		goto err;
	}

	return NLSock;
      err:
	close(NLSock);
      out:
	return -1;
}

/* Destroy netlink socket
 */
static void wlanManagerDetroyNLSock(void)
{
	close(wlanManagerS.NLSock);
}

void wlanManager_TriggerMsgWrap(struct nlmsghdr *NLh, struct sockaddr_nl *Kpeer, u_int32_t DataLen)
{
	if (!NLh || !Kpeer) {
		wlanManagerDebug(DBGERR, "%s: Invalid parameters", __func__);
		return;
	}

	memset(Kpeer, 0, sizeof *Kpeer);
	Kpeer->nl_family = AF_NETLINK;
	Kpeer->nl_pid = 0;	/* For Linux Kernel */
	Kpeer->nl_groups = 0;	/* unicast */

	NLh->nlmsg_len = NLMSG_SPACE(DataLen);
	NLh->nlmsg_flags = 0;
	NLh->nlmsg_type = 0;
	NLh->nlmsg_pid = getpid();
}


/* Register read buffer callback.
 */
static void wlanManagerReadbufRegister(void)
{
	u_int32_t RdBufSize = NLMSG_SPACE(wlanManagerReadBufSize);

	wlanManagerS.NLSock = wlanManagerCreateNLSock();

	if (wlanManagerS.NLSock < 0) {
		wlanManagerDebug(DBGERR, "%s: Failed to create Netlink socket", __func__);
		return;
	}

	/* Initialize input context */
	bufrdCreate(&wlanManagerS.ReadBuf, "wlanManager-rd", wlanManagerS.NLSock, RdBufSize,	/* Read buf size */
		wlanManagerReadBufCB,	/* callback */
		NULL);
}

/* Unregister read buffer callback.
 */
static void wlanManagerReadbufUnRegister(void)
{
	bufrdDestroy(&wlanManagerS.ReadBuf);
	wlanManagerDetroyNLSock();
}

/* Read buffer callback.
 */
static void wlanManagerReadBufCB(void *Cookie)
{
	struct bufrd *R = &wlanManagerS.ReadBuf;
	u_int32_t NMax = bufrdNBytesGet(R);

	wlanManagerTRACE();

	/* Error check. */
	if (bufrdErrorGet(R)) {
		wlanManagerDebug(DBGINFO, "%s: Read error!", __func__);

		wlanManagerReadbufUnRegister();
		wlanManagerReadbufRegister();
		return;
	}

	if (!NMax)
		return;

	bufrdConsume(R, NMax);
}


/*========================================================================*/
/*============ Init ======================================================*/
/*========================================================================*/
void wlanManagerListenInitCB(void)
{
}

void wlanManagerInit(void)
{
	interface_t *interface;
	MCS_BOOL readbufRegistered = MCS_FALSE;

	if (wlanManagerS.IsInit)
		return;

	memset(&wlanManagerS, 0, sizeof wlanManagerS);
	wlanManagerS.IsInit = 1;

	wlanManagerS.DebugModule = dbgModuleFind("wlanManager");
	wlanManagerDebug(DBGDEBUG, "ENTER wlanManagerInit");
	wlanManagerS.NLSock = -1;

	/* Register own event table to module core. */
	mdEventTableRegister(mdModuleID_Wlan, wlanManagerEvent_MaxNum);

	/* Register listen table init callback. */
	mdListenInitCBRegister(mdModuleID_Wlan, wlanManagerListenInitCB);

	/* Trigger the wlan driver start sending the association event. */
	interface = interface_getFirst();

	while (interface) {
		if ((interface->type == interfaceType_WLAN5G
				|| interface->type == interfaceType_WLAN2G)
			&& !(interface->flags & INTERFACE_FLAGS_NON_QCA)) {
			if (!readbufRegistered) {
				/* Register readbuf to module core. */
				wlanManagerReadbufRegister();

				readbufRegistered = MCS_TRUE;
			}

		}

		interface = interface_getNext(interface);
	}

	wlanManagerMenuInit();

}


/*===========================================================================*/
/*================= Optional Debug Menu======================================*/
/*===========================================================================*/
#ifdef MCS_DBG_MENU		/* entire debug menu section */
#include <cmd.h>

/* ------------------- freq = get freq used for IF -------------------------------- */
const char *wlanManagerMenuGetFreqHelp[] = {
	"freq -- Get frequency by IF name",
	"usage: freq xxx (xxx... is the wireless IF name, e.g. ath0)",
	"\tg: Given wireless interface name, get the frequency",
	NULL
};

void wlanManagerMenuGetFreqHandler(struct cmdContext *Context, const char *Cmd)
{
	const char *arg;
	interface_t *iface;

	/* Check IF Name is valid */
	arg = cmdWordFirst(Cmd);
	if (!arg || !cmdWordLen(arg)) {
		cmdf(Context, "Interface name missing\n");
		return;
	}

	iface = interface_getInterfaceFromName(arg);

	if (iface) {
		cmdf(Context, "%s uses %dG frequency.\n", arg,
			((iface->type == interfaceType_WLAN2G) ? 2 : 5));
	} else {
		cmdf(Context, "Interface name (%s) is not valid! \n", arg);
	}
}

/* ------------------- p = parameters -------------------------------- */
const char *wlanManagerMenuParametersHelp[] = {
	"p -- Parameters access command (set & display)",
	"usage:",
	"\tp: print all parameters",
	"\tp <parameter>: print specific parameter value",
	"\tp <parameter> <value>: set parameter to value",
	NULL
};

void wlanManagerMenuParametersHandler(struct cmdContext *Context, const char *Cmd)
{
	const char *arg;

	arg = cmdWordFirst(Cmd);
	if (!arg || !cmdWordLen(arg)) {	/* no arguments: print all parameters */
		return;
	}

	cmdf(Context, "Parameter not defined: %s\n", arg);
	return;
}

/* ------------ wlanManager menu (added to main menu) ----------*/

struct cmdMenuItem wlanManagerMenu[] = {
	CMD_MENU_STANDARD_STUFF(),
	{"freq", wlanManagerMenuGetFreqHandler, NULL, wlanManagerMenuGetFreqHelp},
	{"p", wlanManagerMenuParametersHandler, NULL, wlanManagerMenuParametersHelp},
	CMD_MENU_END()
};

const char *wlanManagerMenuHelp[] = {
	"wlan (wlanManager) -- WLAN Manager",
	NULL
};

const struct cmdMenuItem wlanManagerMenuItem = {
	"wlan",
	cmdMenu,
	wlanManagerMenu,
	wlanManagerMenuHelp
};

#endif /* MCS_DBG_MENU  -- entire section */

/*--- wlanManagerMenuInit -- add menu item for this module
*/
/*private*/ void wlanManagerMenuInit(void)
{
#ifdef MCS_DBG_MENU
	cmdMainMenuAdd(&wlanManagerMenuItem);
#endif
}



/*========================================================================*/
/*============ Public API ================================================*/
/*========================================================================*/

MCS_STATUS wlanManager_getName(interface_t *iface, char *name)
{
	int32_t Sock;
	struct iwreq Wrq;

	if (!iface || !name) {
		wlanManagerDebug(DBGERR, "%s: Invalid arguments", __func__);
		goto out;
	}

	if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		wlanManagerDebug(DBGERR, "%s: Create ioctl socket failed!", __func__);
		goto out;
	}

	if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
		wlanManagerDebug(DBGERR, "%s: fcntl() failed", __func__);
		goto err;
	}

	strlcpy(Wrq.ifr_name, iface->name, IFNAMSIZ);
	if (ioctl(Sock, SIOCGIWNAME, &Wrq) < 0) {
		wlanManagerDebug(DBGERR, "%s: ioctl() failed, ifName: %s.\n", __func__,
			iface->name);
		goto err;
	}

	strlcpy(name, Wrq.u.name, IFNAMSIZ);

	wlanManagerDebug(DBGDUMP, "%s: Interface %s, name: %s", __func__, iface->name, name);

	close(Sock);
	return MCS_OK;
err:
	close(Sock);
out:
	return MCS_NOK;
}

MCS_STATUS wlanManager_isAP(interface_t *iface, MCS_BOOL *result)
{
	int32_t Sock;
	struct iwreq Wrq;

	if (!iface || !result) {
		wlanManagerDebug(DBGERR, "%s: Invalid arguments", __func__);
		goto out;
	}

	if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		wlanManagerDebug(DBGERR, "%s: Create ioctl socket failed!", __func__);
		goto out;
	}

	if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
		wlanManagerDebug(DBGERR, "%s: fcntl() failed", __func__);
		goto err;
	}

	strlcpy(Wrq.ifr_name, iface->name, IFNAMSIZ);
	if (ioctl(Sock, SIOCGIWMODE, &Wrq) < 0) {
		wlanManagerDebug(DBGERR, "%s: ioctl() failed, ifName: %s.\n", __func__,
			iface->name);
		goto err;
	}

	*result = Wrq.u.mode == IW_MODE_MASTER ? MCS_TRUE : MCS_FALSE;

	close(Sock);
	return MCS_OK;
err:
	close(Sock);
out:
	return MCS_NOK;
}

MCS_STATUS wlanManager_getBSSID(interface_t *iface, struct ether_addr *BSSID)
{
	int32_t Sock;
	struct iwreq Wrq;

	if (!iface || !BSSID) {
		wlanManagerDebug(DBGERR, "%s: Invalid arguments", __func__);
		goto out;
	}

	if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		wlanManagerDebug(DBGERR, "%s: Create ioctl socket failed!", __func__);
		goto out;
	}

	if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
		wlanManagerDebug(DBGERR, "%s: fcntl() failed", __func__);
		goto err;
	}

	strlcpy(Wrq.ifr_name, iface->name, IFNAMSIZ);
	if (ioctl(Sock, SIOCGIWAP, &Wrq) < 0) {
		wlanManagerDebug(DBGERR, "%s: ioctl() failed, ifName: %s.\n", __func__,
			iface->name);
		goto err;
	}

	MACAddrCopy(&Wrq.u.ap_addr.sa_data, BSSID);

	wlanManagerDebug(DBGDUMP, "%s: Interface %s, BSSID: " MACAddrFmt(":"), __func__,
		iface->name, MACAddrData(BSSID->ether_addr_octet));

	close(Sock);
	return MCS_OK;
err:
	close(Sock);
out:
	return MCS_NOK;
}

MCS_STATUS wlanManager_getFreq(interface_t *iface)
{
	int32_t Sock;
	struct iwreq Wrq;

	if (!iface) {
		wlanManagerDebug(DBGERR, "%s: Invalid arguments", __func__);
		goto out;
	}

	if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		wlanManagerDebug(DBGERR, "%s: Create ioctl socket failed!", __func__);
		goto out;
	}

	if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
		wlanManagerDebug(DBGERR, "%s: fcntl() failed", __func__);
		goto err;
	}

	strlcpy(Wrq.ifr_name, iface->name, IFNAMSIZ);
	if (ioctl(Sock, SIOCGIWFREQ, &Wrq) < 0) {
		wlanManagerDebug(DBGERR, "%s: ioctl() failed, ifName: %s.\n", __func__,
			iface->name);
		goto err;
	}

	if (Wrq.u.freq.m / 100000000 >= 5)
		iface->type = interfaceType_WLAN5G;
	else
		iface->type = interfaceType_WLAN2G;

	wlanManagerDebug(DBGDUMP, "%s: Interface %s, frequency %uHz", __func__, iface->name,
		Wrq.u.freq.m);

	close(Sock);
	return MCS_OK;
err:
	close(Sock);
out:
	return MCS_NOK;
}

MCS_STATUS wlanManager_getChannelInfo(interface_t *iface, wlanManagerChanInfo_t *chaninfo)
{
	int32_t Sock;
	struct iwreq Wrq;
	u_int8_t channel;
	int iwparam;
	int chwidth, choffset;

	if (!iface) {
		wlanManagerDebug(DBGERR, "%s: Invalid arguments", __func__);
		goto out;
	}

	if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		wlanManagerDebug(DBGERR, "%s: Create ioctl socket failed!", __func__);
		goto out;
	}

	if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
		wlanManagerDebug(DBGERR, "%s: fcntl() failed", __func__);
		goto err;
	}

	strlcpy(Wrq.ifr_name, iface->name, IFNAMSIZ);
	if (ioctl(Sock, SIOCGIWFREQ, &Wrq) < 0) {
		wlanManagerDebug(DBGERR, "%s: ioctl() failed, ifName: %s.\n", __func__,
			iface->name);
		goto err;
	}

	channel = wlanManager_mhz2ieee(Wrq.u.freq.m / 100000);
	wlanManagerDebug(DBGDUMP, "%s: Interface %s, frequency %uHz channel %d", __func__,
		iface->name, Wrq.u.freq.m, channel);

	memset(&Wrq, 0, sizeof(struct iwreq));
	strlcpy(Wrq.ifr_name, iface->name, IFNAMSIZ);
	iwparam = IEEE80211_PARAM_CHWIDTH;
	memcpy(Wrq.u.name, &iwparam, sizeof(iwparam));
	if (ioctl(Sock, IEEE80211_IOCTL_GETPARAM, &Wrq) < 0) {
		wlanManagerDebug(DBGERR, "%s: ioctl() failed, ifName: %s.\n", __func__,
			iface->name);
		goto err;
	}
	memcpy(&chwidth, Wrq.u.name, sizeof(chwidth));
	wlanManagerDebug(DBGDUMP, "%s: Interface %s, channel width %d", __func__, iface->name,
		chwidth);

	memset(&Wrq, 0, sizeof(struct iwreq));
	strlcpy(Wrq.ifr_name, iface->name, IFNAMSIZ);
	iwparam = IEEE80211_PARAM_CHEXTOFFSET;
	memcpy(Wrq.u.name, &iwparam, sizeof(iwparam));
	if (ioctl(Sock, IEEE80211_IOCTL_GETPARAM, &Wrq) < 0) {
		wlanManagerDebug(DBGERR, "%s: ioctl() failed, ifName: %s.\n", __func__,
			iface->name);
		goto err;
	}
	memcpy(&choffset, Wrq.u.name, sizeof(choffset));
	wlanManagerDebug(DBGDUMP, "%s: Interface %s, channel offset %d", __func__, iface->name,
		choffset);

	switch (chwidth) {
	case 0:		//20MHz
		chaninfo->width = 0;
		chaninfo->ifreq1 = channel;
		chaninfo->ifreq2 = 0;
		break;

	case 1:		//40MHz
		chaninfo->width = 1;
		chaninfo->ifreq2 = 0;
		if (choffset == 1)
			chaninfo->ifreq1 = channel + 2;
		else if (choffset == -1)
			chaninfo->ifreq1 = channel - 2;
		else {
			wlanManagerDebug(DBGERR, "%s: Invalid channel offset for interface: %s",
				__func__, iface->name);
			goto err;
		}
		break;

	case 2:		//80MHz
		chaninfo->width = 2;
		chaninfo->ifreq2 = 0;
		if (choffset == 1)
			chaninfo->ifreq1 = channel + 4;
		else if (choffset == -1)
			chaninfo->ifreq1 = channel - 4;
		else {
			wlanManagerDebug(DBGERR, "%s: Invalid channel offset for interface: %s",
				__func__, iface->name);
			goto err;
		}
		break;

	default:
		wlanManagerDebug(DBGERR, "%s: Invalid channel width for interface: %s", __func__,
			iface->name);
		goto err;
	}

	close(Sock);
	return MCS_OK;
err:
	close(Sock);
out:
	return MCS_NOK;
}

MCS_STATUS wlanManager_getStats(interface_t *iface, wlanManagerStats_t *stats)
{
	int32_t Sock;
	struct iwreq Wrq;
	struct iw_statistics iwstats;

	if (!iface) {
		wlanManagerDebug(DBGERR, "%s: Invalid arguments", __func__);
		goto out;
	}

	if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		wlanManagerDebug(DBGERR, "%s: Create ioctl socket failed!", __func__);
		goto out;
	}

	if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
		wlanManagerDebug(DBGERR, "%s: fcntl() failed", __func__);
		goto err;
	}

	Wrq.u.data.pointer = &iwstats;

	strlcpy(Wrq.ifr_name, iface->name, IFNAMSIZ);
	if (ioctl(Sock, SIOCGIWSTATS, &Wrq) < 0) {
		wlanManagerDebug(DBGERR, "%s: ioctl() failed, ifName: %s.\n", __func__,
			iface->name);
		goto err;
	}

	stats->signal = iwstats.qual.level;
	stats->noise = iwstats.qual.noise;
	stats->quality = iwstats.qual.qual;
	wlanManagerDebug(DBGDUMP,
		"%s: Interface %s, signal level %ddBm, noise level %ddBm, link quality %d",
		__func__, iface->name, stats->signal, stats->noise, stats->quality);

	close(Sock);
	return MCS_OK;
err:
	close(Sock);
out:
	return MCS_NOK;
}

int wlanManager_GetSock(void)
{
	if (!wlanManagerS.IsInit)
		return -1;

	return wlanManagerS.NLSock;
}

