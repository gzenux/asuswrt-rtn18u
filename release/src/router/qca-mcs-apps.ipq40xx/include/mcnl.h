/*
 *  Copyright (c) 2010 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Copyright (c) 2012, 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef mcnl__h
#define mcnl__h

#include <sys/types.h>
#include "mc_api.h"

typedef enum {
	MC_BRIDGE_MDB_TABLE,
	MC_BRIDGE_ACL_TABLE,
	MC_BRIDGE_ENCAP_TABLE,
	MC_BRIDGE_FLOOD_TABLE,
	MC_BRIDGE_TABLE_LAST
} bridgeTable_e;

typedef enum {
	MC_BRIDGE_ACTION_GET = 0,
	MC_BRIDGE_ACTION_SET
} bridgeTableAction_e;

/* Message size overhead */
#define MC_BRIDGE_MESSAGE_SIZE( x )		( NLMSG_LENGTH(0) + MC_MSG_HDRLEN + x )

/* Bridge table action */
int32_t bridgeTableAction(const char *BridgeName, bridgeTable_e TableType, int32_t *NumEntries,
	void *TableEntry, bridgeTableAction_e TableAction, int sync);

/* Get a table from the bridge */
#define bridgeGetTable( _BridgeName, _TableType, _NumEntries, _TableEntry ) \
    bridgeTableAction( _BridgeName, _TableType, _NumEntries, _TableEntry, MC_BRIDGE_ACTION_GET, 1)

/* Set a table in the bridge */
#define bridgeSetTable( _BridgeName, _TableType, _NumEntries, _TableEntry ) \
    bridgeTableAction( _BridgeName, _TableType, _NumEntries, _TableEntry, MC_BRIDGE_ACTION_SET, 1)

/* Get a table from the bridge */
#define bridgeGetTableAsyn(_BridgeName, _TableType, _NumEntries, _TableEntry ) \
    bridgeTableAction(_BridgeName, _TableType, _NumEntries, _TableEntry, MC_BRIDGE_ACTION_GET, 0)

/* Set a table in the bridge */
#define bridgeSetTableAsyn(_BridgeName, _TableType, _NumEntries, _TableEntry ) \
    bridgeTableAction(_BridgeName, _TableType, _NumEntries, _TableEntry, MC_BRIDGE_ACTION_SET, 0)

/* Allocate table buffer, use with the bridgeGetTable function */
void *bridgeAllocTableBuf(int32_t Size, const char *BridgeName);

/* Free table buffer */
void bridgeFreeTableBuf(void *Buf);

/*-F- bridgeSetBridgeMode --
 */
int32_t bridgeSetBridgeMode(const char *BridgeName, int32_t Mode);

/*-F- netlink_msg --
 */
int32_t netlink_msg(int32_t msg_type, u_int8_t *data, int32_t msgdatalen, int32_t netlink_key,
	int sync);

/* Init buffer; to be used by the bridge int32_terface only
 */
void bridgeInitBuf(void *Buf, size_t Size, const char *BridgeName);

/*-F- bridgeSetEventInfo --
 */
int32_t bridgeSetEventInfo(const char *BridgeName, u_int32_t Pid, u_int32_t Cmd,
	u_int32_t netlinkKey);

/*-F- bridgeSetSnoopingParam --
 */
int32_t bridgeSetSnoopingParam(const char *BridgeName, int Cmd, void *MCParam, u_int32_t ParamLen);

#endif //mcnl__h
