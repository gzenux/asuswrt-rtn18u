/*
 * Plugin manager - reference code
 *
 * Copyright (c) 2012-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include "internal.h"
#include "dbg.h"

/*
 * Debug macros
 */
#define pluginManagerDebug(level, ...) \
                 dbgf(pluginManagerS.DebugModule,(level),__VA_ARGS__)
#define pluginManagerTRACE() pluginManagerDebug(DBGDUMP, "ENTER %s", __func__)

typedef struct pluginManagerState_t {
	u_int32_t IsInit;	/* overall initialization done */
	struct dbgModule *DebugModule;	/* debug message context */

} pluginManagerState_t;

/*
 * pluginManagerS:
 * Plugin manager state variable
 */
static pluginManagerState_t pluginManagerS;

void pluginManagerInit(void)
{
	/* This function will be called every time the daemon starts.
	 * Add additional plugin init functions here.
	 *
	 * Do NOT modify the function's prototype!
	 */
	if (pluginManagerS.IsInit)
		return;

	pluginManagerS.IsInit = 1;
	pluginManagerS.DebugModule = dbgModuleFind("plugin");

	/* Setup default level */
	pluginManagerS.DebugModule->Level = DBGINFO;

	pluginManagerDebug(DBGINFO, "Initializing plugin manager");

	return;
}
