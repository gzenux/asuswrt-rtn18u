/*
 * @File: wlamManager.h
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

#ifndef wlanManager__h
#define wlanManager__h

#include <sys/types.h>
#include <net/if.h>
#include <net/ethernet.h>
#define _LINUX_IF_H		/* Avoid redefinition of stuff */
#include <linux/wireless.h>
#include <ieee80211_external.h>
#include <linux/netlink.h>
#include "mcif.h"
#include "internal.h"


/* events */
enum wlanManagerEvent_e {
	wlanManagerEvent_UpdatedStats = 0,
	wlanManagerEvent_Assoc,
	wlanManagerEvent_Disassoc,
	wlanManagerEvent_BufferFull,
	wlanManagerEvent_MaxNum
};

typedef struct {
	u_int32_t signal;
	u_int32_t noise;
	u_int32_t quality;

} wlanManagerStats_t;

typedef struct {
	u_int8_t width;		/*channel bandwidth, cbw20(0), cbw40(1), cbw80(2), cbw160(3), cbw80p80(4) */
	u_int8_t ifreq1;	/*center frequency index1, 0-200 */
	u_int8_t ifreq2;	/*certer frequency index2, 0-200 */
} wlanManagerChanInfo_t;


/* initialization */
void wlanManagerInit(void);

/* public API */
MCS_STATUS wlanManager_TriggerStats(interface_t *interface);
MCS_STATUS wlanManager_getFreq(interface_t *iface);
MCS_STATUS wlanManager_getBSSID(interface_t *iface, struct ether_addr *BSSID);
MCS_STATUS wlanManager_getName(interface_t *iface, char *name);
MCS_STATUS wlanManager_isAP(interface_t *iface, MCS_BOOL *result);
MCS_STATUS wlanManager_getStats(interface_t *iface, wlanManagerStats_t *stats);
u_int32_t wlanManager_getWlanCheckFreqInterval(void);
MCS_STATUS wlanManager_getStationInfo(interface_t *iface, struct ieee80211req_sta_info **info,
	u_int32_t *len);
MCS_STATUS wlanManagerUpdateForwardTable(interface_t *iface, void *table, u_int32_t size);
MCS_STATUS wlanManagerFlushForwardTable(interface_t *iface);
MCS_STATUS wlanManager_getChannelInfo(interface_t *iface, wlanManagerChanInfo_t *chaninfo);
int wlanManager_GetSock(void);
void wlanManager_TriggerMsgWrap(struct nlmsghdr *NLh, struct sockaddr_nl *Kpeer, u_int32_t DataLen);
MCS_STATUS wlanManagerAldStaEnable(interface_t *iface, struct ether_addr *ni_macaddr);
#endif


