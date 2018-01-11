/*
 * @File: profile.c
 *
 * @Abstract: configuration/profile support
 *
 * @Notes:
 *
 * Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

#include <dbg.h>

#include "module.h"
#include "config.h"
#include "profile.h"
#include "qassert.h"

#define profileMissing ""

/*--- profileState -- global data for profile
 */
struct profileState {
	int IsInit;
	const char *File;
	struct dbgModule *DebugModule;
} profileS;

struct profileOpt {
	const char *Section;
	const char *Missing;
} profileOpts[mdModuleID_MaxNum] = {
	{"MAIN",   profileMissing},
#ifdef MCS_MODULE_WLAN
	{"WLAN",   profileMissing},
#endif
#ifdef MCS_MODULE_PLC
	{"PLC",   profileMissing},
#endif

#ifdef MCS_MODULE_DBG
	{"LOG",   profileMissing},
#endif
	{"INTERFACE",   profileMissing},
	{"PLUGIN",   profileMissing},
	{"MC",   profileMissing},
};

/*--- profileDebug -- print debug messages (see dbgf documentation)
 */
#define profileDebug(...) dbgf(profileS.DebugModule, __VA_ARGS__)

static const char *profileElementDefault(const char *Element, struct profileElement *DefaultTable)
{
	int Index = 0;

	if (!Element || !DefaultTable)
		return NULL;

	while (DefaultTable[Index].Element) {
		if (!strcmp(DefaultTable[Index].Element, Element))
			return DefaultTable[Index].Default;
		Index++;
	}

	return NULL;
}

/* DefaultTable is the default value which the module owns.
 * It can be set to NULL when there is no default table.
 */
const char *profileGetOpts(u_int32_t ModuleID,
	const char *Element, struct profileElement *DefaultTable)
{
	const char *Result = NULL;

	if (!__ASSERT(!(ModuleID >= mdModuleID_MaxNum
				|| !Element), "Invalid parameters: ModuleID %d, Element %p",
			ModuleID, Element))
		goto out;

	Result = configstring(profileS.File,
		profileOpts[ModuleID].Section, Element, profileOpts[ModuleID].Missing);

	if (!Result || !strlen(Result))
		Result = profileElementDefault(Element, DefaultTable);

out:
	return Result ? Result : profileMissing;
}

/*====================================================================*
 *          Init
 *--------------------------------------------------------------------*/
void profileInit(const char *File)
{
	if (profileS.IsInit)
		return;

	memset(&profileS, 0, sizeof profileS);
	profileS.IsInit = 1;
	profileS.File = File;

	profileS.DebugModule = dbgModuleFind("profile");
	profileDebug(DBGDEBUG, "%s: File %s", __func__, File);
}


