/*
 * Copyright (c) 2010 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/* csh -- command shell
 * This uses a TCP interface (works with telnet) and the cmd menus.
 *
 * The following may connect to it:  
 *      telnet 127.0.0.1 9999
 * (or more conveniently, where supported):
 *      telnet localhost 9999
 * ... assuming port 9999 is being used.
 * 
 * Provided that cshInit() is called with Port==0, the following
 * environmental variables configure csh:
 * CSH_PORT -- set port to use (decimal) or 0 to disable
 * CSH_FIND_PORT -- "1" to cause searching for available port
 *      starting with CSH_PORT or defaulted (assuming not disabled).
 * CSH_MAX_SHELLS -- maximum no. of connections allowed (decimal)
 *
 *
 * BUGS:
 * -- assigning port numbers is a pain
 * -- after program termination, the port is not available for a while.
 * -- no security from outside intrusion, except as provided by a firewall
 *
 * TODO:
 * -- provide alternate socket file based method.
 */

/* We probably don't need all of these: */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <sys/time.h>

#include <evloop.h>
#include <dbg.h>
#include <cmd.h>

#ifndef CSH_PORT
#define CSH_PORT        9999    /* default which port to use */
#endif
#ifndef CSH_PORT_ENV_NAME
#define CSH_PORT_ENV_NAME "CSH_PORT"    /* to set other port in decimal */
#endif

#ifndef CSH_FIND_PORT
#define CSH_FIND_PORT 0         /* 1 to use other port until one works */
#endif
#ifndef CSH_FIND_PORT_ENV_NAME
#define CSH_FIND_PORT_ENV_NAME "CSH_FIND_PORT"
#endif

#ifndef CSH_MAX_SHELLS
#define CSH_MAX_SHELLS 5        /* default max shells */
#endif
#ifndef CSH_MAX_SHELLS_ENV_NAME
#define CSH_MAX_SHELLS_ENV_NAME "CSH_MAX_SHELLS" /* to set other limit, decimal */
#endif

/*
 * csh state data
 */
struct cshShellContext {
    struct cshShellContext *Next;       /* linked list of shells */
    struct cshShellContext **Prev;      /* linked list of shells */
    int Sd;         /* socket desciptor to read from */
    struct evloopReady Ready;
    struct cmdContext *CmdContext;      /* cmd parsing context */
    FILE *OutF; /* for writing output to */
    char InBuf[2048];     /* input buffer */
    int InBufCount;     /* how much in input buffer */
};
struct cshState {
    int IsInit;         /* overall initialization done */
    int IsInitServer;   /* server initialization is separate phase */
    struct dbgModule *DebugModule;   /* debug message context */
    int Port;           /* which port we listen to */
    int FindPort;       /* nonzero if try other ports if that doesn't work */
    int ListenSd;       /* socket descriptor to listen on */
    struct evloopReady Ready;
    struct evloopTimeout Timeout;
    struct cshShellContext *FirstShell; /* linked list */
    int NShells;        /* no. of shells in the linked list */
    int MaxShells;      /* max no. of shells we allow */
} cshS;

/*--- cshDebug -- debug printf
 */
#define cshDebug(level, ...) \
        dbgf(cshS.DebugModule,(level),__VA_ARGS__)

/*--- cshClose -- called when we should close down a shell.
 */
void cshClose(struct cshShellContext *ShellContext)
{
    cshDebug(DBGINFO, "Close shell session Sd=%d", ShellContext->Sd);
    evloopReadyUnregister(&ShellContext->Ready);
    cmdContextDestroy(ShellContext->CmdContext);
    ShellContext->CmdContext = NULL;
    fclose(ShellContext->OutF); /* this closes Sd also */
    ShellContext->OutF = NULL;
    ShellContext->Sd = -1;
    ShellContext->InBufCount = 0;
    /* unlink from list */
    if (ShellContext->Next)
        ShellContext->Next->Prev = ShellContext->Prev;
    *ShellContext->Prev = ShellContext->Next;
    ShellContext->Next = NULL;
    ShellContext->Prev = NULL;
    free(ShellContext);
	 cshS.NShells--;
}

/*--- cshRead -- called back when we can read commands from socket
 */
void cshRead(void *Cookie)
{
    char Buf[512];
    int NRead;
    struct cshShellContext *ShellContext = Cookie;
    struct cmdContext *CmdContext = ShellContext->CmdContext;
    int Sd = ShellContext->Sd;
    NRead = read(Sd, Buf, sizeof(Buf));
    if (NRead < 0) {
        cshDebug(DBGERR, "shell read error");
        cshClose(ShellContext);
        return;
    }
    if (NRead == 0) {
        cshDebug(DBGERR, "shell read eof");
        cshClose(ShellContext);
        return;
    }
    if (cmdInputAdd(
            CmdContext, 
            ShellContext->InBuf,
            &ShellContext->InBufCount,
            sizeof(ShellContext->InBuf),
            Buf,
            NRead)) {
        cshDebug(DBGERR, "cmd quit");
        cshClose(ShellContext);
        return;
    }
}

/*--- cshListen -- called back when we can accept new connection
 */
void cshListen(void *Cookie)
{
    struct sockaddr_in Addr = {};
    socklen_t AddrSize;
    int Sd = -1;
    struct cshShellContext *ShellContext = NULL;

    AddrSize = sizeof(Addr);
    Sd = accept(cshS.ListenSd, (struct sockaddr *)&Addr, &AddrSize);
    if (Sd < 0) {
        cshDebug(DBGERR, "accept errno %d", errno);
        return;
    }
    /* Make SURE we don't block.
     * It is easy to avoid blocking on read, but it can be easy
     * to block on a write particularly if there is a high volume
     * of messages.
     */
    (void) fcntl(Sd, F_SETFL, fcntl(Sd, F_GETFL) | O_NONBLOCK);

    if (cshS.NShells >= cshS.MaxShells) {
        const char *Msg = "TOO MANY SHELLS\n";
        cshDebug(DBGERR, "csh:too many shells already!");
        write(Sd, Msg, strlen(Msg));
        close(Sd);
        return;
    }

    ShellContext = malloc(sizeof(*ShellContext));
    if (!ShellContext) {
        cshDebug(DBGERR, "Malloc failure on shell open!");
        close(Sd);
        return;
    }
    memset(ShellContext, 0, sizeof(*ShellContext));

    evloopReadReadyCreate(&ShellContext->Ready, "csh-session", 
        Sd, cshRead, ShellContext);
    evloopReadyRegister(&ShellContext->Ready);

    if (cshS.FirstShell) {
        struct cshShellContext *Next = cshS.FirstShell;
        while (Next->Next) Next = Next->Next;
        Next->Next = ShellContext;
        ShellContext->Prev = &Next->Next;
    } else {
        cshS.FirstShell = ShellContext;
        ShellContext->Prev = &cshS.FirstShell;
    }

    cshS.NShells++;
	cshDebug(DBGERR, "New shell session (%d/%d) using sd %d", 
        cshS.NShells, cshS.MaxShells, Sd);


    cshDebug(DBGINFO, "New shell session (%d/%d) using sd %d", 
        cshS.NShells, cshS.MaxShells, Sd);

    /* Set up cmd (menu) context */
    ShellContext->Sd = Sd;
    ShellContext->OutF = fdopen(Sd, "w");
    ShellContext->CmdContext = cmdContextCreate(NULL);
    cmdContextOutFileSet(
        ShellContext->CmdContext,
        ShellContext->OutF);
    #if CMD_STDOUT_REDIRECT_FEATURE()
    cmdContextOutFdSet(ShellContext->CmdContext, Sd);
    #endif      //  CMD_STDOUT_REDIRECT_FEATURE()
    cmdf(ShellContext->CmdContext,
        "Use `h' and `help' for help messages\n");
    cmdf(ShellContext->CmdContext,
        "Use `dbg here' to see log messages; other dbg cmds for log level\n");
    cmdContextAutoPromptSet(ShellContext->CmdContext, 1);
    return;
}


/* cshInitServer -- set up shell server
 * Returns nonzero if error.
 */
int cshInitServer(void *unused)
{
    struct sockaddr_in Addr = {};

    if (cshS.IsInitServer)
        return 0;
    cshDebug(DBGDEBUG, "ENTER cshInitServer");

    /* Advertise as server */
    cshS.ListenSd = socket(PF_INET, SOCK_STREAM, 0);
    if (cshS.ListenSd < 0) {
        cshDebug(DBGERR, "cshInit: socket() errno %d", errno);
        goto TryLater;
    }
    Addr.sin_family = AF_INET;
    Addr.sin_port = htons(cshS.Port);
    // TODO: review for security issues
	// Can be accessed in localhost.
#ifndef DISABLE_DBG_PORT
    Addr.sin_addr.s_addr = INADDR_ANY;
#else 
    inet_aton("127.0.0.1", &Addr.sin_addr);
#endif
    int cflag = 1;
    if(setsockopt(cshS.ListenSd,SOL_SOCKET,SO_REUSEADDR,
                   (char *)&cflag,sizeof(cflag)) == -1)
    {
        cshDebug(DBGERR, "cshInit: setsockopt() errno %d", errno);
        goto TryLater;

    } 
    if (bind(cshS.ListenSd, (struct sockaddr *)&Addr, sizeof(Addr))) {
        cshDebug(DBGERR, "cshInit: bind() errno %d", errno);
        goto TryLater;
    }
    if (listen(cshS.ListenSd, CSH_MAX_SHELLS)) {
        cshDebug(DBGERR, "cshInit: listen() errno %d", errno);
        goto TryLater;
    }
    evloopReadReadyCreate(&cshS.Ready, "csh-listen",
        cshS.ListenSd, cshListen, NULL);
    evloopReadyRegister(&cshS.Ready);
    cshS.IsInitServer = 1;
    cshDebug(DBGINFO, "READY, USING PORT %d", cshS.Port);
    return 0;

    TryLater:
    close(cshS.ListenSd); cshS.ListenSd = -1;
    if (cshS.FindPort) cshS.Port++;
    if (cshS.Port >= 65535) {
        cshDebug(DBGERR, "Server init failure: too many retries");
        return 1;
    }
    cshDebug(DBGERR, "Server init failure: will try port %d later",
        cshS.Port);
    evloopTimeoutCreate(&cshS.Timeout, 
        "csh-startup", (void *)cshInitServer, NULL);
    if (cshS.FindPort) {
        evloopTimeoutRegister(&cshS.Timeout, 10/*secs*/, 0/*usecs*/);
    } else {
        evloopTimeoutRegister(&cshS.Timeout, 2/*secs*/, 0/*usecs*/);
    }
    return 1;
}


/*-F- cshInit -- set up command shell server.
 * If Port is passed by zero, it is drawn from env. variable
 * or else a default.
 * Note however, if Port is passed nonzero, then the CSH_FIND_PORT
 * feature is disabled regardless of environmental variable etc.
 */
void cshInit(
        int Port)       /* pass 0 for default, else port to listen on */
{
    const char *EnvVar;

    if (cshS.IsInit) return;
    cshS.IsInit = 1;

    cshS.ListenSd = -1;

    cshS.DebugModule = dbgModuleFind("csh");
    cshDebug(DBGDEBUG, "ENTER cshInit");

    /* Configure self acc. to environmental variables unless
     * port is passed to us by argument.
     */
    if (Port) {
        cshS.Port = Port;
        cshS.FindPort = 0;
        cshDebug(DBGINFO, "Set Port to %d from arg to cshInit", cshS.Port);
    }
    else {
        cshS.Port = CSH_PORT;
        EnvVar = getenv(CSH_PORT_ENV_NAME);
        if (EnvVar) {
            cshS.Port = atol(EnvVar);
            if (cshS.Port <= 0 || cshS.Port > 65535) {
                cshS.Port = 0;
                cshDebug(DBGINFO,
                    "Command shells disabled due to value `%s' for env. var. " 
                    CSH_PORT_ENV_NAME, EnvVar);
                return;
            }
            cshDebug(DBGINFO,
                "Set Port to %d from env var " CSH_PORT_ENV_NAME,
                cshS.Port);
        } else
        if (cshS.Port <= 0) {
            cshDebug(DBGINFO,
                "Command shells disabled (CSH_PORT)");
            return;
        }

        cshS.FindPort = CSH_FIND_PORT;
        EnvVar = getenv(CSH_FIND_PORT_ENV_NAME);
        if (EnvVar) {
            cshS.FindPort = atol(EnvVar);
        }
        if (cshS.FindPort && cshS.Port > 0) {
            cshDebug(DBGINFO, 
                "Other ports will be tried if that doesn't work");
        }
    }

    cshS.MaxShells = CSH_MAX_SHELLS;
    EnvVar = getenv(CSH_MAX_SHELLS_ENV_NAME);
    if (EnvVar) {
        cshS.MaxShells = atol(EnvVar);
        cshDebug(DBGINFO,
            "Set MaxShells to %d from env var " CSH_MAX_SHELLS_ENV_NAME,
            cshS.MaxShells);
        if (cshS.MaxShells <= 0) {
            cshDebug(DBGINFO,
                "Command shells disabled due to value `%s' for env. var. "
                CSH_MAX_SHELLS_ENV_NAME, EnvVar);
            return;
        }
    } else
    if (cshS.MaxShells <= 0) {
        cshDebug(DBGINFO,
            "Command shells disabled (CSH_MAX_SHELLS)");
        return;
    }

    /* Server initialization -- done later if temp failure */
    if (cshInitServer(NULL)) {
        return;
    }

    cshDebug(DBGDEBUG, "Did cshInit OK");
    return;
}


