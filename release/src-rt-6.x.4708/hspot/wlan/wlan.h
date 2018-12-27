/*
 * WLAN functions.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id:$
 */

#ifndef _WLAN_H_
#define _WLAN_H_

#include "typedefs.h"
#include "wlioctl.h"

typedef struct wlanStruct wlanT;

typedef enum {
	WLAN_PMF_MODE_DISABLED	= 0,
	WLAN_PMF_MODE_CAPABLE	= 1,
	WLAN_PMF_MODE_REQUIRED	= 2
} wlanPmfModeT;

/* initialize wlan */
int wlanInitialize(void);

/* deinitialize wlan */
int wlanDeinitialize(void);

/* create wlan instance */
wlanT *wlanCreate(void);

/* destroy wlan instance */
int wlanDestroy(wlanT *wlan);

/* get WLAN interface name */
char *wlanIfName(wlanT *wlan);

/* get WLAN ethernet address */
int wlanEtherAddr(wlanT *wlan, struct ether_addr *addr);

/* enable event msg */
int wlanEnableEventMsg(wlanT *wlan, int event);

/* disable event msg */
int wlanDisableEventMsg(wlanT *wlan, int event);

/* add vendor IEs */
int wlanAddVendorIe(wlanT *wlan, uint32 pktflag, int len, uchar *data);

/* delete vendor IEs */
int wlanDeleteVendorIe(wlanT *wlan, uint32 pktflag, int len, uchar *data);

/* delete all vendor IEs */
int wlanDeleteAllVendorIe(wlanT *wlan);

/* add/del IE */
int wlanIe(wlanT *wlan, uint8 id, uint8 len, uchar *data);

/* start escan */
int wlanStartEscan(wlanT *wlan, int isActive, int numProbes,
	int activeDwellTime, int passiveDwellTime);

/* stop scan engine (scan, escan, action frame, etc.) */
int wlanStopScan(wlanT *wlan);

/* disassociate */
int wlanDisassociate(wlanT *wlan);

/* PMF disassociate */
int wlanPmfDisassociate(wlanT *wlan);

/* send BSS transition query */
int wlanBssTransitionQuery(wlanT *wlan);

/* send BSS transition request - ESS disassociation imminent */
int wlanBssTransReqEssDisassocImminent(wlanT *wlan,
	uint16 disassocTimer, char *url);

/* send action frame */
int wlanActionFrame(wlanT *wlan, uint32 packetId,
	uint32 channel, int32 dwellTime,
	struct ether_addr *bssid, struct ether_addr *da,
	uint16 len, uint8 *data);

/* wlan association status */
int wlanAssociationStatus(wlanT *wlan, int *isAssociated,
	int biBufferSize, wl_bss_info_t *biBuffer);

/* send TDLS discovery request */
int wlanTdlsDiscoveryRequest(wlanT *wlan, struct ether_addr *ea);

/* send TDLS setup request */
int wlanTdlsSetupRequest(wlanT *wlan, struct ether_addr *ea);

/* drop gratuitous ARP */
int wlanDropGratuitousArp(wlanT *wlan, int enable);

/* WNM configuration enable */
int wlanWnm(wlanT *wlan, int mask);

/* WNM configuration get */
int wlanWnmGet(wlanT *wlan, int *mask);

/* PMF mode (0=disable, 1=capable, 2=required) */
int wlanPmf(wlanT *wlan, wlanPmfModeT mode);

/* set MAC mode and list */
int wlanMac(wlanT *wlan, int mode, int count, struct ether_addr *addr);

/* enable/disable interworking */
int wlanInterworking(wlanT *wlan, int enable);

/* enable/disable OSEN */
int wlanOsen(wlanT *wlan, int enable);

/* send frame */
int wlanSendFrame(wlanT *wlan, uint16 len, uint8 *data);

/* enable/disable BSS load */
int wlanBssLoad(wlanT *wlan, int enable);

/* configure static BSS load */
int wlanBssLoadStatic(wlanT *wlan, bool isStatic, uint16 staCount,
	uint8 utilization, uint16 aac);

/* subscribe for event notification callback */
int wlanSubscribeEvent(void *context, void (*fn)(void *context, uint32 eventType,
	wl_event_msg_t *wlEvent, uint8 *data, uint32 length));

/* unsubscribe for event notification callback */
int wlanUnsubscribeEvent(void (*fn)(void *context, uint32 eventType,
	wl_event_msg_t *wlEvent, uint8 *data, uint32 length));

#endif /* _WLAN_H_ */
