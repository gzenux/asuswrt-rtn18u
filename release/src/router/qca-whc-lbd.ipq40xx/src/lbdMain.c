/*
 * @File: lbdMain.c
 *
 * @Abstract: Load balancing daemon main
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2011,2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include <dbg.h>
#include <evloop.h>
#include <module.h>
#include <profile.h>
#include <split.h>

#include <lb_common.h>
#include <lbd_types.h>

#include <diaglog.h>
#include <wlanif.h>
#include <steerexec.h>
#include <stadb.h>
#include <bandmon.h>
#include <stamon.h>
#include <estimator.h>
#include <steeralg.h>

#ifdef LBD_DBG_MENU
#include <csh.h>
#endif

#include "lbdMain.h"


/* Debugging options */
/*private*/ const struct dbgInitOptions lbdDbgInitOptions = {
    .ProgramName = "LBDR",
    .EnvName = "LBDR_DBG_LEVELS",
};

struct profileElement lbdElementDefaultTable[] = {
    {"LoadBalancingInterfaces",     "ath0"  },
    {NULL,                          NULL    }
};

/* State info for lbd main level */
/*private*/ struct {
    struct dbgModule *DebugModule;
    int DoDaemonize;    /* detach from parent */
    const char *ConfFile;
} lbdS;

#define lbdDebug(level, ...) \
        dbgf(lbdS.DebugModule,(level),__VA_ARGS__)

/**
 * @brief React to a signal to shut down the daemon by marking the event
 *        event loop as terminated.
 */
static void lbdShutdownSignalHandler(int signal) {
    evloopAbort();
}

static void lbdRun(void) {
    mdInit();
    evloopRunPrepare();

    while(!evloopIsAbort()) {
        evloopOnce();
    }
}

static void lbdUsage(void) {
    lbdDebug(DBGINFO, "Usage: lbd [-d] [-C conf-file]");
    lbdDebug(DBGINFO, "       -d: Do NOT fork into the background: run in debug mode.");
    lbdDebug(DBGINFO, "       -C: Specify configuration file.");

    exit(1);
}

static void lbdParseArgs(char **argv) {
    char *Arg;

    lbdS.DoDaemonize = 1;

    argv++;     /* skip program name */
    while ((Arg = *argv++) != NULL) {
        if (!strcmp(Arg, "-d")) {
            lbdS.DoDaemonize = 0;
        } else
        if (!strcmp(Arg, "-C")) { /* configuration file */
            Arg = *argv++;
            if (Arg == NULL)
                lbdUsage();

            if (!access(Arg, R_OK))
                lbdS.ConfFile = Arg;
            else
                lbdS.ConfFile = NULL;
        } else {
            lbdDebug(DBGERR, "INVALID ARG: %s", Arg);
            lbdUsage();
        }
    }
    return;
}

static LBD_STATUS lbdInit(void) {
    if (diaglog_init() != LBD_OK ||
        wlanif_init() != LBD_OK ||
        steerexec_init() != LBD_OK ||
        stadb_init() != LBD_OK ||
        bandmon_init() != LBD_OK ||
        estimator_init() != LBD_OK ||
        stamon_init() != LBD_OK ||
        steeralg_init() != LBD_OK) {
        return LBD_NOK;
    }

    return LBD_OK;
}

/**
 * @brief Perform a clean shutdown of the daemon, terminating all of
 *        underlying components.
 */
static void lbdFini(void) {
    // Any errors are ignored as there is not much we can do at this point.
    // We're about to pull the plug.
    steeralg_fini();
    stamon_fini();
    estimator_fini();
    bandmon_fini();
    stadb_fini();
    steerexec_fini();
    wlanif_fini();
    diaglog_fini();
}

void lbFatalShutdown(void) {
    lbdFini();
    exit(1);
}

/* The main function of lbd.
 * Usage: lbd [-d] [-C conf-file]
 * -d: Do NOT fork into the background: run in debug mode.
 * -C: Specify configuration file.
 */
int main(int argc, char **argv) {

	/* Make sure our debug options are set before any debugging! */
    dbgInit1(&lbdDbgInitOptions);

    /* Register for debug messages from this file */
    lbdS.DebugModule = dbgModuleFind("lbd");
    lbdS.DebugModule->Level = DBGDEBUG;

    lbdDebug(DBGDEBUG, "Entering main of lbd executive program");

    /* Now we can look at arguments */
    lbdParseArgs(argv);

    if (lbdS.DoDaemonize) {
        if (daemon(0,0)) {
            perror("daemon");
            exit(1);
        }
    }

    /* Make sure profile module initilized before other modules. */
    profileInit(lbdS.ConfFile);

    // Register signal handlers for an orderly shutdown.
    signal(SIGINT, lbdShutdownSignalHandler);
    signal(SIGTERM, lbdShutdownSignalHandler);

    if (lbdInit() != LBD_OK) {
        lbdDebug(DBGERR, "lbd init failed!");
        lbFatalShutdown();
    }

#ifdef LBD_DBG_MENU
    /* Add debugging shell capability */
    cshInit(LBD_DBG_PORT);
#endif

    /* must called after all initilization */
    mdDoListenInitCB();

    /* Main event loop waits for things to happen...
     * is the ONLY place we should EVER wait for anything to happen.
     */
    lbdDebug(DBGDEBUG, "Entering evloopRun");
    lbdRun();

    lbdFini();

    /* Probably won't get here... */
    lbdDebug(DBGDEBUG, "Leaving lbd executive program");

    return 0;
}
