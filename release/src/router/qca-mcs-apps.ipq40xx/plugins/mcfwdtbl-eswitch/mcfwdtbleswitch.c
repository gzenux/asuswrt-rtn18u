/*
 * @File: mcfwdtbleswitch.c
 *
 * @Abstract: ESWITCH Multicast forwarding database plugin
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

#include "qassert.h"
#include "mcif.h"
#include "switchWrapper.h"
static struct mcEswitchState_t {
	u_int32_t IsInit;	/* overall initialization done */
	struct dbgModule *DebugModule;	/* debug message context */
} mcEswitchState;

#define mcEswitchDebug(level, ...) \
                 dbgf(mcEswitchState.DebugModule,(level),__VA_ARGS__)

/*========================================================================*/
/*============ Internal handling =========================================*/
/*========================================================================*/

int ESWITCH_InitForwardTablePlugin(interface_t *iface)
{
	if (mcEswitchState.IsInit)
		return 0;

	if (iface->type != interfaceType_ETHER || !(iface->flags & INTERFACE_FLAGS_ESWITCH))
		return -1;

	mcEswitchState.DebugModule = dbgModuleFind("mcEswitch");
	mcEswitchState.IsInit = 1;

	/* Finish processing for non-QCA interfaces */
	if (iface->flags & INTERFACE_FLAGS_NON_QCA)
		return 0;

	return switchInitSnooping();
}

int ESWITCH_UpdateForwardTable(interface_t *iface, void *table, u_int32_t size)
{
	if (!mcEswitchState.IsInit)
		return -1;

	mcEswitchDebug(DBGDUMP, "%s: Enter", __func__);
	if (!iface) {
		mcEswitchDebug(DBGERR, "%s: error, iface is NULL!", __func__);
		return -1;
	}

	if (iface->type != interfaceType_ETHER || !(iface->flags & INTERFACE_FLAGS_ESWITCH))
		return -1;

	if (iface->flags & INTERFACE_FLAGS_NON_QCA)
		return 0;

	if (!switchUpdateForwardTbl(table, size))
		mcEswitchDebug(DBGDUMP,
			"%s: Successfully updated ESWITCH Multicast forwarding table", __func__);
	else {
		mcEswitchDebug(DBGERR, "%s: Failed to update ESWICH multicast forwarding table",
			__func__);
		return -1;
	}
	return 0;
}

int ESWITCH_FlushForwardTable(interface_t *iface)
{
	return ESWITCH_UpdateForwardTable(iface, NULL, 0);
}
