/*
 * @File: dbgService.c
 *
 * @Abstract: Debug service
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <dbg.h>
#include <bufrd.h>
#include <bufwr.h>
#include <evloop.h>
#include <module.h>

#ifdef MCS_MODULE_WLAN
#include <wlanManager.h>
#endif
#ifdef MCS_MODULE_PLC
#include <plcManager.h>
#endif

#include "dbgService.h"

struct dbgServiceState {
	int IsInit;		/* overall initialization done */
	struct dbgModule *DebugModule;	/* debug message context */
} dbgServiceS;

#define dbgServiceDebug(level, ...) \
                 dbgf(dbgServiceS.DebugModule,(level),__VA_ARGS__)
#define dbgServiceTRACE() dbgServiceDebug(DBGDEBUG, "ENTER %s", __func__)

//void dbgServiceRead(void *Cookie/*unused*/);
/*========================================================================*/
/*============ Internal handling =========================================*/
/*========================================================================*/

/*===========================================================================*/
/*================= Optional Debug Menu======================================*/
/*===========================================================================*/
#ifdef MCS_DBG_MENU		/* entire debug menu section */
#include <cmd.h>

#define dbgServiceEventMaxNum   10

const struct dbgServiceMapping {
	int ModuleID;
	const char *ModuleName;
	const struct {
		int EventID;
		const char *EventName;
	} EventMap[dbgServiceEventMaxNum];
} dbgServiceMappingTable[] = {
	{
		.ModuleName = "main",
		.ModuleID = mdModuleID_Main,
		.EventMap = {
			{
				.EventName = NULL,
			},
		}
	},
#ifdef MCS_MODULE_PLC
	{
		.ModuleName = "plc",
		.ModuleID = mdModuleID_Plc,
		.EventMap = {
			{
				.EventName = "UpdatedStats",
				.EventID = plcManagerEvent_UpdatedStats,
			},
			{
				.EventName = NULL,
			},
		}
	},
#endif
	{
		.ModuleName = NULL,
	},
};

const char *dbgServiceMenuListEventHelp[] = {
	"l -- list all events",
	NULL
};

void dbgServiceMenuListEventHandler(struct cmdContext *Context, const char *Cmd)
{
	int IModule = 0;

	while (dbgServiceMappingTable[IModule].ModuleName) {
		int IEvent = 0;

		cmdf(Context, "Module %d: %s\n",
			dbgServiceMappingTable[IModule].ModuleID,
			dbgServiceMappingTable[IModule].ModuleName);

		while (dbgServiceMappingTable[IModule].EventMap[IEvent].EventName) {
			cmdf(Context, "\tEvent %d: %s\n",
				dbgServiceMappingTable[IModule].EventMap[IEvent].EventID,
				dbgServiceMappingTable[IModule].EventMap[IEvent].EventName);
			IEvent++;
		}

		cmdf(Context, "\n");

		IModule++;
	}
}

const char *dbgServiceMenuCreateEventHelp[] = {
	"c [-m ModuleID] [-e EventID] [-p Priority[high,low]] -- create event",
	NULL
};

void dbgServiceMenuCreateEventHandler(struct cmdContext *Context, const char *Cmd)
{
	char Buf[32];
	int ModuleID = 0xff, EventID = 0xff, Priority = 0xff;

	while (Cmd && *Cmd == '-') {
		if (cmdWordEq(Cmd, "-m")) {
			Cmd = cmdWordNext(Cmd);
			cmdWordCopy(Buf, Cmd, 32);
			ModuleID = atoi(Buf);
			Cmd = cmdWordNext(Cmd);
		} else if (cmdWordEq(Cmd, "-e")) {
			Cmd = cmdWordNext(Cmd);
			cmdWordCopy(Buf, Cmd, 32);
			EventID = atoi(Buf);
			Cmd = cmdWordNext(Cmd);
		} else if (cmdWordEq(Cmd, "-p")) {
			Cmd = cmdWordNext(Cmd);
			cmdWordCopy(Buf, Cmd, 32);
			if (!strcasecmp(Buf, "high")) {
				Priority = mdEventPriority_High;
			} else if (!strcasecmp(Buf, "low")) {
				Priority = mdEventPriority_Low;
			} else {
				cmdf(Context, "Invalid priority value: %s!\n", Buf);
				return;
			}

			Cmd = cmdWordNext(Cmd);
		} else {
			cmdWordCopy(Buf, Cmd, 32);
			cmdf(Context, "Not supported option:%s\n", Buf);
			return;
		}
	}

	if (ModuleID == 0xff || EventID == 0xff || Priority == 0xff) {
		cmdf(Context, "Illegal input!\n");
		return;
	}

	if (ModuleID >= mdModuleID_MaxNum) {
		cmdf(Context, "Invalid module id!\n");
		return;
	}

	if (mdCreateEvent(ModuleID, Priority, EventID, NULL, 0) < 0) {
		cmdf(Context, "Create event failed!\n");
	}

	return;
}

// Returns module ID corresponding to a module's name.

int dbgGetModuleIDGivenName(const char *InputModuleName) {
	int i;

	for (i = 0; i < (sizeof(dbgServiceMappingTable) / sizeof(dbgServiceMappingTable[0])); i++) {
		if (!strcmp(dbgServiceMappingTable[i].ModuleName, InputModuleName)) {
			return dbgServiceMappingTable[i].ModuleID;
		}
	}
	return -1;
}

// Returns numeric command ID corresponding to an ASCII name.

int dbgGetCommandIDGivenName(int ModuleID, const char *InputCommandName) {
	int i;

	for (i = 0; i < (sizeof(dbgServiceMappingTable) / sizeof(dbgServiceMappingTable[0])); i++) {
		if (dbgServiceMappingTable[i].ModuleID == ModuleID) {
			int j;

			for (j = 0; j < dbgServiceEventMaxNum; j++) {
				if (!strcmp(dbgServiceMappingTable[i].EventMap[j].EventName,
						InputCommandName)) {
					return dbgServiceMappingTable[i].EventMap[j].EventID;
				}
			}
			return -1;
		}
	}
	return -1;
}

/* ------------ dbgService menu (added to main menu) ----------*/

struct cmdMenuItem dbgServiceMenu[] = {
	CMD_MENU_STANDARD_STUFF(),
	{
			"l",	/* Command */
			dbgServiceMenuListEventHandler,	/* Callback */
			NULL,	/* Cookie */
			dbgServiceMenuListEventHelp	/* Help menu */
		},
	{
			"c",	/* Command */
			dbgServiceMenuCreateEventHandler,	/* Callback */
			NULL,	/* Cookie */
			dbgServiceMenuCreateEventHelp	/* Help menu */
		},
	/* you can add more menu items here */
	CMD_MENU_END()
};

const char *dbgServiceMenuHelp[] = {
	"dbgService -- debug service menu",
	NULL
};

const struct cmdMenuItem dbgServiceMenuItem = {
	"dbgService",
	cmdMenu,
	dbgServiceMenu,
	dbgServiceMenuHelp
};

#endif /* MCS_DBG_MENU  -- entire section */

/*--- dbgServiceMenuInit -- add menu item for this module
*/
/*private*/ void dbgServiceMenuInit(void)
{
#ifdef MCS_DBG_MENU
	cmdMainMenuAdd(&dbgServiceMenuItem);
#endif
}

/*========================================================================*/
/*============ Init ======================================================*/
/*========================================================================*/

void dbgServiceInit(void)
{
	if (dbgServiceS.IsInit)
		return;

	memset(&dbgServiceS, 0, sizeof dbgServiceS);
	dbgServiceS.IsInit = 1;

	dbgServiceS.DebugModule = dbgModuleFind("dbgService");
	dbgServiceDebug(DBGDEBUG, "ENTER dbgServiceInit");

	dbgServiceMenuInit();
}
