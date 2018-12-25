/*
 * @File: profile.c
 *
 * @Abstract: Load balancing daemon configuration/profile support
 *
 * @Notes:
 *
 * Copyright (c) 2011,2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

#include <dbg.h>

#include "module.h"
#include "config.h"
#include "profile.h"
#include "lbd_assert.h"

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
} profileOpts[] = {
    {"MAIN",        profileMissing},
#include "lb_profileSections.h"
};

/*--- profileDebug -- print debug messages (see dbgf documentation)
 */
#define profileDebug(...) dbgf(profileS.DebugModule, __VA_ARGS__)

const char *profileElementDefault(const char *Element,
        struct profileElement *DefaultTable)
{
    int Index = 0;

    if (!Element || !DefaultTable) return NULL;

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
        const char *Element,
        struct profileElement *DefaultTable)
{
    const char *Result = NULL;

    if (ModuleID >= mdModuleID_MaxNum || !Element){
        profileDebug(DBGERR, "%s: Invalid parameters: ModuleID %d, Element %p",__func__,ModuleID, Element);
        goto out;
    }
    Result = configstring(profileS.File,
            profileOpts[ModuleID].Section,
            Element,
            profileOpts[ModuleID].Missing);

    if (!Result || !strlen(Result)) {
        if (Result) { free((char *) Result); }
        Result = profileElementDefault(Element, DefaultTable);

        // Allocations from the defaults table need to be strdup'ed so that
        // all return values from this function need to be free'ed. Otherwise,
        // the caller would have no way to know whether free() should be
        // called or not.
        if (Result) { Result = strdup(Result); }
    }

out:
    return Result ? Result : strdup(profileMissing);
}

int profileGetOptsInt(u_int32_t ModuleID,
        const char *Element,
        struct profileElement *DefaultTable)
{
    int Result = -1;
    const char *ResultStr = profileGetOpts(ModuleID, Element, DefaultTable);
    if (ResultStr) {
        Result = atoi(ResultStr);
        free((char *) ResultStr);  // must cast away const-ness for free
    }

    return Result;
}

float profileGetOptsFloat(u_int32_t ModuleID,
        const char *Element,
        struct profileElement *DefaultTable)
{
    float Result = -1;
    const char *ResultStr = profileGetOpts(ModuleID, Element, DefaultTable);
    if (ResultStr) {
        Result = atof(ResultStr);
        free((char *) ResultStr);  // must cast away const-ness for free
    }

    return Result;
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


