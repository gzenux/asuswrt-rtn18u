/*
 * @File: plcManager.h
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

#ifndef plcManager__h
#define plcManager__h

#include "internal.h"
#include "mcif.h"

/* events */
enum plcManagerEvent_e {
	plcManagerEvent_UpdatedStats = 0,
	plcManagerEvent_Link,
	plcManagerEvent_MCSnoopFail,
	plcManagerEvent_MCTableFail,
	plcManagerEvent_NIDChange,

	plcManagerEvent_MaxNum
};

/*
 * PLC device static MAC address
 */
#define PLC_STATIC_MAC "\x00\xB0\x52\x00\x00\x01"

/*
 * plcManagerNIDLen: Length of NID
 */
#define plcManagerNIDLen            7

/* initialization */
void plcManagerInit(void);

/* public API */
void plcManager_TriggerStats(void);
MCS_STATUS plcManager_GetLocalMAC(u_int8_t *MAC);
MCS_STATUS plcManager_GetLocalNID(u_int8_t *NID);
MCs_STATUS plcManagerUpdateForwardTable(interface_t *iface, void *table, u_int32_t size);
MCS_STATUS plcManagerFlushForwardTable(interface_t *iface);
MCS_STATUS plcManagerSetSnoopingDisable(void);

#endif


