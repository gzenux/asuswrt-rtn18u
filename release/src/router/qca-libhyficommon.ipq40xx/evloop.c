/*
 * Copyright (c) 2010 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*-M- evloop -- central event loop for single-threaded event-driven programs.
 *
 * Description:
 * evloop is suitable only for single-threaded programs which can be
 * written in an event-driven fashion, meaning that no code should
 * ever "block" or "sleep" other than the central event loop.
 * Typically main() will call initialization routines, and then disappear
 * into a call to evloopRun(), which makes occasional calls to 
 * registered callback functions when certain events happen.
 * These events are (as determined by the application)
 * the passage of a certain amount of time, or a (unix type)
 * socket or file ("descriptor") being ready to read or write.
 *
 * Callbacks can be registered in any single-thread context:
 * during the initializations before evloopRun() (at least some must be) 
 * and from any callback function.
 * Timeout callbacks automatically disable themselves when they expire.
 * By contrast, "ready" callbacks are called whenever a descriptor
 * is ready (to read or write depending on how registered) ... which
 * means that the callback function MUST actually read or write something,
 * or cancel the callback.
 * Generally a callback function should NOT do more than one call to
 * read() or write() as such would be blocking or might fail...
 * a write() might in any event write less than asked, so write buffering
 * should always be used.
 *
 * Callbacks are called with just one cookie, since that is usually
 * sufficient.
 * Should you need to use additional cookies, they can be set
 * with Cookie*Set functions and they can be obtained
 * using the Cookie*Get functions provided you can find the 
 * evloop object based on the first cookie.
 * One approach is to use the address of the evloop object as the
 * first cookie.
 * 
 * Implementation issues:
 * evloop is written for posix compliant (sp. linux) operating systems.
 * The assumption is made that timeouts may be honored milliseconds after scheduled
 * without harm, and for even longer periods after scheduling without any great
 * harm.
 * Since no system call to obtain "time since boot" with millisecond precision,
 * it is necessary to use the system call to get time of day time, which introduces
 * a problem in that the time of day may be changed arbitrarily using settimeofday()
 * by another process... the workaround for this issue requires that evloop sleep
 * for no more than a limited period (e.g. 20 seconds).
 */


#include <stdlib.h>
#include <poll.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#include <dbg.h>
#include <cmd.h>
#include <evloop.h>

#if 0   /* auto-extract only */
/*-D- Required includes
*/
/*--------------------------------------------------------------------------*/
#endif


/*--- EVLOOP_MAX_SLEEP_SEC -- maximum tme we will sleep before checking again.
 *      To avoid undue overhead, this should not be made "small", but note:
 *      IMPORTANT: 2*EVLOOP_MAX_SLEEP_SEC must be safely less than the threshold at which
 *      the time of day correction uses settimeofday() in preference to adjtime().
 *      Assuming that this threshold is 1 minute (60 seconds), a value of 20 is good
 *      since 2*20 == 40 is safely less than 60.
 */
#define EVLOOP_MAX_SLEEP_SEC 20

/*-D- EVLOOP_N_CONTEXT -- how many global variables set at each callback 
*  to provide a simple way of providing different contexts within the
*  same address space.
*  The variables are 
*     unsigned evloopContext[0] ... evloopContext[EVLOOP_N_CONTEXT-1]
*  and must be used according to some sort of program-wide strategy
*  for each program using evloop.
*  Each evloopTimeout or evloopReady has it's own copy of these
*  variables, copied from the global variables at creation time;
*  at each callback, they are copied back to the global variables.
*  The trick is to create static or global data as an array:
*       struct mydata myglobaldata[MY_N_CONTEXT];
*  and reference it as (assuming using evloopContext[0]):
*       myglobaldata[evloopContextGet(0))]
*  ... obviously the values assigned to evloopContext[0] must be
*  small integers less than MY_N_CONTEXT!
*
*  For portability, do NOT refer to evloopContext directly,
*  instead use access functions.
*/
#define EVLOOP_N_CONTEXT 0
/*-------------------------------------------------------------*/


/*-G- evloopContext -- see description below
*/
unsigned evloopContext[EVLOOP_N_CONTEXT];

#if 0   /* auto-extract only */
/*-D- evloopContextGet -- global variables set at each callback which
*  provide a simple way of providing different contexts within the
*  same address space.
*  The variables are 
*     unsigned evloopContext[0] ... evloopContext[EVLOOP_N_CONTEXT-1]
*  and must be used according to some sort of program-wide strategy
*  for each program using evloop.
*  Each evloopTimeout or evloopReady has it's own copy of these
*  variables, copied from the global variables at creation time;
*  at each callback, they are copied back to the global variables.
*  The trick is to create static or global data as an array:
*       struct mydata myglobaldata[MY_N_CONTEXT];
*  and reference it as (assuming using evloopContext[0]):
*       myglobaldata[evloopContextGet(0))]
*  ... obviously the values assigned to evloopContext[0] must be
*  small integers less than MY_N_CONTEXT!
*
*  For portability, do NOT refer to evloopContext directly,
*  instead use access functions.
*/
/* For efficiency, this must be inline! */
static inline unsigned evloopContextGet(int IContext)
{
    return evloopContext[IContext];
}
/*-------------------------------------------------*/
#endif  /* auto-extract only */


#if 0   /* auto-extract only */

/*-D- evloopTimeout -- control struct for event loop timeout detect.
 * DO NOT ACCESS FIELDS DIRECTLY! FOR FUTURE PORTABILITY AND 
 * ACCOUNTABILITY, USE THE PROVIDED ACCESS FUNCTIONS.
 */
struct evloopTimeout {
    struct evloopTimeout *Next;   /* for linked list */
    struct evloopTimeout *Prev;   /* for linked list */
    const char *Description;    /* for debugging */
    void (*CB)(void *Cookie1);        /* called on timeout */
    void *Cookie1;              /* app use */
    void *Cookie2;              /* app use */
    void *Cookie3;              /* app use */
    /* Timeout nodes are queued in order, with USecMore storing the additional
     * time to wait relative to the previous node... or relative to "now"
     * for the first node.
     */
    long long USecMore;         /* time to sleep after previous node */
    #if EVLOOP_N_CONTEXT > 0
    unsigned Context[EVLOOP_N_CONTEXT];
    #endif
};
static inline int evloopTimeoutArmedGet(struct evloopTimeout *T)
{
    return (T->Next != NULL);
}
static inline const char *evloopTimeoutDescriptionGet(struct evloopTimeout *T)
{
    return T->Description;
}
static inline void evloopTimeoutCookie1Set(
        struct evloopTimeout *T,
        void *Cookie1)
{
    T->Cookie1 = Cookie1;
}
static inline void *evloopTimeoutCookie1Get(struct evloopTimeout *T)
{
    return T->Cookie1;
}
static inline void evloopTimeoutCookie2Set(
        struct evloopTimeout *T,
        void *Cookie2)
{
    T->Cookie2 = Cookie2;
}
static inline void *evloopTimeoutCookie2Get(struct evloopTimeout *T)
{
    return T->Cookie2;
}
static inline void evloopTimeoutCookie3Set(
        struct evloopTimeout *T,
        void *Cookie3)
{
    T->Cookie3 = Cookie3;
}
static inline void *evloopTimeoutCookie3Get(struct evloopTimeout *T)
{
    return T->Cookie3;
}
#if EVLOOP_N_CONTEXT > 0
static inline unsigned evloopTimeoutContextValueGet(
        struct evloopTimeout *T,
        int IContext)
{
    return T->Context[IContext];
}
static inline void evloopTimeoutContextValueSet(
        struct evloopTimeout *T,
        int IContext,
        unsigned Value)
{
    /* NOTE: you should not have to use this function */
    T->Context[IContext] = Value;
}
#endif  // EVLOOP_N_CONTEXT > 0
/*-------------------------------------------------*/


/*-D- evloopReady -- control struct for event loop descriptor ready detect.
 * DO NOT ACCESS FIELDS DIRECTLY! FOR FUTURE PORTABILITY AND 
 * ACCOUNTABILITY, USE THE PROVIDED ACCESS FUNCTIONS.
 */
struct evloopReady {
    struct evloopReady *Next;   /* for linked list */
    struct evloopReady *Prev;   /* for linked list */
    const char *Description;    /* for debugging */
    int Fd;                     /* which file descriptor */
    int Mode;          /* one of EVLOOP_READY_xxx */
    void (*CB)(void *Cookie1);  /* called when ready */
    void *Cookie1;              /* app use */   
    void *Cookie2;              /* app use */
    void *Cookie3;              /* app use */
    unsigned Events;    /* internal use by evloop module */
    #if EVLOOP_N_CONTEXT > 0
    unsigned Context[EVLOOP_N_CONTEXT];
    #endif
};
static inline const char *evloopReadyDescriptionGet(struct evloopReady *R)
{
    return R->Description;
}
static inline int evloopReadyFdGet(struct evloopReady *R)
{
    return R->Fd;
}
static inline void evloopReadyCookie1Set(
        struct evloopReady *R,
        void *Cookie1)
{
    R->Cookie1 = Cookie1;
}
static inline void *evloopReadyCookie1Get(struct evloopReady *R)
{
    return R->Cookie1;
}
static inline void evloopReadyCookie2Set(
        struct evloopReady *R,
        void *Cookie2)
{
    R->Cookie2 = Cookie2;
}
static inline void *evloopReadyCookie2Get(struct evloopReady *R)
{
    return R->Cookie2;
}
static inline void evloopReadyCookie3Set(
        struct evloopReady *R,
        void *Cookie3)
{
    R->Cookie3 = Cookie3;
}
static inline void *evloopReadyCookie3Get(struct evloopReady *R)
{
    return R->Cookie3;
}
#if EVLOOP_N_CONTEXT > 0
static inline unsigned evloopReadyContextValueGet(
        struct evloopTimeout *R,
        int IContext)
{
    return R->Context[IContext];
}
static inline void evloopReadyContextValueSet(
        struct evloopReady *R,
        int IContext,
        unsigned Value)
{
    /* NOTE: you should not have to use this function */
    R->Context[IContext] = Value;
}
#endif  // EVLOOP_N_CONTEXT > 0
/*-------------------------------------------------*/


#endif  /* auto-extract only */

/*--- EVLOOP_READY_xxx -- "ready" modes.
 */
#define EVLOOP_READY_READ  0x1
#define EVLOOP_READY_WRITE 0x2
/*-------------------------------------------------*/

/*--- evloopState -- global data for evloop
 *      (except for evloopContext[] which is exported for efficiency).
 */
struct evloopState {
    int IsInit;
    struct dbgModule *DebugModule;
    struct evloopReady ReadyHead;       /* dummy node for linked list */
    int NReady; /* no. in Ready linked list (not including dummy node) */
    long long LastUSec;         /* last time of day in usec */
    struct evloopTimeout TimeoutHead;   /* dummy node for linked list */
    struct pollfd *Poll;        /* array of poll() syscall structs */
    int NPollAlloc;  /* no. of elems in allocated *Poll */
    int Abort;  /* set to leave main loop */
} evloopS;


/*--- evloopDebug -- print debug messages (see dbgf documentation)
 */
#define evloopDebug(...) dbgf(evloopS.DebugModule, __VA_ARGS__)

void evloopInit(void);  /* forward declaration */


/*-F- evloopTimeoutCreate -- set up timeout control (unregistered).
 *      After return from this function,
 *      the timeout struct can be registered and unregistered as needed.
 *      Do NOT call this if the timeout struct might be in use/registered.
 *      If the timeout struct is known to not be registered, then you
 *      may reuse the memory for any purpose (e.g. call free() or
 *      do another Create).
 *
 *      You may however change the cookies at any time after "Create", using 
 *      e.g. evloopTimeoutCookie1Set() etc.
 *      When registered timeout expires, the callback function CB
 *      whill be called back with the current value of Cookie1.
 */
void evloopTimeoutCreate(
        struct evloopTimeout *T,  /* control struct provided by app */
        const char *Description,    /* of nonvolatile string! for debugging */
        void (*CB)(void *Cookie1),
        void *Cookie1               /* app use */
        )
{
    if (!evloopS.IsInit)
        evloopInit();
    evloopDebug(DBGINFO, "ENTER evloopTimeoutInit `%s'", Description);

    memset(T, 0, sizeof(*T));
    T->Description = Description;
    T->CB = CB;
    T->Cookie1 = Cookie1;
    #if EVLOOP_N_CONTEXT == 1
    T->Context[0] = evloopContext[0];
    #elif EVLOOP_N_CONTEXT > 1
    {
        int IContext;
        for (IContext = 0; IContext < EVLOOP_N_CONTEXT; IContext++)
            T->Context[IContext] = evloopContext[IContext];
    #endif
    return;
}

/*--- evloopTimeoutRemove -- remove timeout node from queue
 */
/*private*/ static inline void evloopTimeoutRemove(
        struct evloopTimeout *T)  /* control struct provided by app */
{
    if (T->Next) {
        /* Add time to wait to next element (or to head which is harmless) */
        T->Next->USecMore += T->USecMore;
        T->Prev->Next = T->Next;
        T->Next->Prev = T->Prev;
        T->Next = T->Prev = NULL;       /* for future correctness */
    }
}
        

/*-F- evloopTimeoutRegister -- register to receive timeout notification.
 * Initially the control structure must have set up with eveloopTimeoutCreate.
 *
 * Once registered, it must not be written by the app 
 * (e.g. freed, or another call to evloopTimeoutCreate)
 * unless first unregistered... or if it is known with certainty to
 * have expired (better to cancel to be sure).
 * It is permitted to call evloopTimeoutRegister at any time
 * (after "Create") with a new timeout even if already registered...
 * any old timeout is forgotten.
 * The timeout is always relative to present (in the future).
 * The timeout is automatically cancelled when it expires,
 * at which point the callback (CB) function is called with the
 * current value of Cookie1.
 */
void evloopTimeoutRegister(
        struct evloopTimeout *T,  /* control struct provided by app */
        unsigned Seconds,           /* time in future relative from now */
        unsigned USec               /* microseconds component of rel. time */
        )
{
    struct evloopTimeout *T1;
    long long USecMore;

    if (!evloopS.IsInit)
        evloopInit();
    evloopDebug(DBGDEBUG, "ENTER evloopTimeoutRegister `%s' %d.%06d",
        T->Description, Seconds, USec);

    /* First, Remove from list if in one */
    evloopTimeoutRemove(T);

    USecMore = Seconds*1000000LL + USec;

    /* Add to global list sorted by time. Store only our time
     * difference from previous node.
     */
    for (T1 = evloopS.TimeoutHead.Next;
            T1 != &evloopS.TimeoutHead && USecMore >= T1->USecMore; 
            USecMore -= T1->USecMore, T1 = T1->Next) {;}
    /* Insert before first later node (or head) */
    T->Prev = T1->Prev;
    T->Next = T1;
    T->Prev->Next = T;
    T1->Prev = T;
    T->USecMore = USecMore;
    /* Subtract our time from the next node (or head, which is harmless) */
    T1->USecMore -= USecMore;
    return;
}


/*-F- evloopTimeoutUnregister -- cancel evloopTimeoutRegister registration.
 * Any pending timeout is cancelled.
 * OK to call even if not registered.
 * OK to call even if never "Create"d IFF the struct was zeroed
 * (as is the case for C static/global data).
 */
void evloopTimeoutUnregister(
        struct evloopTimeout *T   /* control struct provided by app */
        )
{
    /* remove from global list */
    evloopTimeoutRemove(T);
    /* leave all else alone */
    return;
}


/*-F- evloopTimeoutRemaining -- compute remaining timeout for a evloopTimeout.
*       Returns nonzero and sets output to 0 if timeout is not active.
*/
int evloopTimeoutRemaining(
        struct evloopTimeout *T,  /* control struct provided by app */
        unsigned *SecondsP,      /* NULL or out */
        unsigned *USecP)         /* NULL or out */
{
    long long USec = 0;
    struct evloopTimeout *T1;

    if (T->Next == NULL) 
        goto NotFound;

    for (T1 = evloopS.TimeoutHead.Next;
            T1 != &evloopS.TimeoutHead;
            T1 = T1->Next) {
        USec += T1->USecMore;
        if (T1 == T)
            goto Found;
    }
    evloopDebug(DBGERR, "evloopTimeoutRemaining: BAD TIMEOUT LINK FOUND");
    goto NotFound;

    NotFound:;
    if (SecondsP)
        *SecondsP = 0;      /* for consistency */
    if (USecP)
        *USecP = 0;
    return 1;

    Found:
    if (SecondsP)
        *SecondsP = USec / 1000000;
    if (USecP)
        *USecP = USec % 1000000;
    return 0;
}


/*-F- evloopReadReadyCreate -- init for descriptor ready notification.
 *
 * After "Create", the evloopReady object is in an "unregistered" state,
 * meaning that it is inactive.
 * You will need to call evloopReadRegister once initially
 * to activate, after which you can switch activation on and off
 * via calls to "Register" and "Unregister".
 *
 * Do NOT reuse the memory for other purposes or call "Create" again
 * UNLESS the evloopReady object is unregistered 
 * (call "Unregister" to make sure).
 */
void evloopReadReadyCreate(
        struct evloopReady *R,  /* control struct provided by app */
        const char *Description,    /* of nonvolatile string! for debugging */
        int Fd,                 /* file descriptor; -1 to cancel */
        void (*CB)(void *Cookie1),      /* called when ready */
        void *Cookie1               /* app use */
        )
{
    if (!evloopS.IsInit)
        evloopInit();
    evloopDebug(DBGINFO, "ENTER evloopReadReadyInit `%s'", Description);

    memset(R, 0, sizeof(*R));
    R->Description = Description;
    R->Fd = Fd;
    R->CB = CB;
    R->Cookie1 = Cookie1;
    R->Mode = EVLOOP_READY_READ;
    #if EVLOOP_N_CONTEXT == 1
    R->Context[0] = evloopContext[0];
    #elif EVLOOP_N_CONTEXT > 1
    {
        int IContext;
        for (IContext = 0; IContext < EVLOOP_N_CONTEXT; IContext++)
            R->Context[IContext] = evloopContext[IContext];
    #endif
    return;
}

 
/*-F- evloopWriteReadyCreate -- init for descriptor ready notification.
 *
 * After "Create", the evloopReady object is in an "unregistered" state,
 * meaning that it is inactive.
 * You will need to call evloopReadRegister once initially
 * to activate, after which you can switch activation on and off
 * via calls to "Register" and "Unregister".
 *
 * Do NOT reuse the memory for other purposes or call "Create" again
 * UNLESS the evloopReady object is unregistered 
 * (call "Unregister" to make sure).
 */
void evloopWriteReadyCreate(
        struct evloopReady *R,  /* control struct provided by app */
        const char *Description,    /* of nonvolatile string! for debugging */
        int Fd,                 /* file descriptor; -1 to cancel */
        void (*CB)(void *Cookie1),      /* called when ready */
        void *Cookie1               /* app use */
        )
{
    if (!evloopS.IsInit)
        evloopInit();
    evloopDebug(DBGINFO, "ENTER evloopWriteReadyCreate `%s'", Description);

    memset(R, 0, sizeof(*R));
    R->Description = Description;
    R->Fd = Fd;
    R->CB = CB;
    R->Cookie1 = Cookie1;
    R->Mode = EVLOOP_READY_WRITE;
    #if EVLOOP_N_CONTEXT == 1
    R->Context[0] = evloopContext[0];
    #elif EVLOOP_N_CONTEXT > 1
    {
        int IContext;
        for (IContext = 0; IContext < EVLOOP_N_CONTEXT; IContext++)
            R->Context[IContext] = evloopContext[IContext];
    #endif
    return;
}

 
/*-F- evloopReadyRegister -- register for descriptor ready notification.
 * Callback CB will be called when Fd is ready to read or write
 * (depending upon how created). 
 * CB is called with current value of Cookie1 as argument.
 *
 * Once registered, it must not be written by the app (e.g. freed
 * or new call to "Create") unless first unregistered.
 */
void evloopReadyRegister(
        struct evloopReady *R)  /* control struct provided by app */
{
    if (!evloopS.IsInit)
        evloopInit();
    evloopDebug(DBGDEBUG, "register ready `%s'", R->Description);

    /* Remove from list, if in the list, and then add to end.
     * This keeps nodes with pending Events at the front.
     */
    if (R->Next) {
        R->Next->Prev = R->Prev;
        R->Prev->Next = R->Next;
        evloopS.NReady--;
    }
    /* add to global list if not in it */
    R->Next = &evloopS.ReadyHead;
    R->Prev = evloopS.ReadyHead.Prev;
    R->Prev->Next = R->Next->Prev = R;
    evloopS.NReady++;

    /* Cancel any pending i/o indication, to be sure */
    R->Events = 0;      /* to be sure */
    return;
}

 

/*-F- evloopReadyUnregister -- cancel evloopReadyRegister registration.
 * The evloopReady struct is unmodified except for being removed
 * from the active list.
 * OK to call even if already unregistered.
 * OK to call even if never "Create"d IFF the memory was zeroed
 * (as is true for C static/global data).
 */
void evloopReadyUnregister(
        struct evloopReady *R)  /* control struct provided by app */
{
    if (!evloopS.IsInit)
        evloopInit();

    if (R->Next) {
        evloopDebug(DBGDEBUG, "Unregister `%s' fd=%d", R->Description, R->Fd);
        R->Next->Prev = R->Prev;
        R->Prev->Next = R->Next;
        R->Next = R->Prev = NULL;
        evloopS.NReady--;
    }
}


/*-F- evloopContextSet -- set global IContext'th variable to Value
*       This should normally only be done from main() or similar
*       in an initialization loop of contexts before calling evloopRun();
*       and will affect all subsequent creates.
*/
void evloopContextSet(int IContext, unsigned Value)
{
    if (!evloopS.IsInit)
        evloopInit();
    evloopDebug(DBGDEBUG, "evloopContextSet context %d value %u",
        IContext, Value);
    evloopContext[IContext] = Value;
    return;
}


/*--- evloopTimeoutFix -- fix up timeout chain 
*/
void evloopTimeoutFix(int Stage)
{
    /* Calculate elapsed time since last call to evloopOnce and
     * remove elapsed time from the timeout queue, thus expiring timeout nodes
     */
    long long USecNow;
    struct timeval TV = { };
    long long USecElapsed;
    struct evloopTimeout *T;

    (void) gettimeofday(&TV, NULL);
    USecNow = TV.tv_sec * 1000000LL + TV.tv_usec;

    if (evloopS.LastUSec == 0) {
        evloopDebug(DBGDEBUG, "evloopOnce: initial time; assume 0 elapsed time");
        USecElapsed = 0;
    } else {
        USecElapsed = USecNow - evloopS.LastUSec;
        if (USecElapsed < 0 || USecElapsed > 2*EVLOOP_MAX_SLEEP_SEC*1000000) {
            /* Obviously bad elapsed time.
             * This is presumeably due to settimeofday() call
             * modifying the system time.
             * Note that settimeofday() call is normally used
             * only for large time of day changes (e.g. more than a minute)... 
             * otherwise adjtime() is used which (more safely!)
             * spreads the time of day change over a period of time "invisibly".
             */
            evloopDebug(DBGINFO, "evloopOnce: bad elapsed time (%lld usec) ignored!", 
                USecElapsed);
            USecElapsed = 0;    /* most conservative change to avoid premature timeouts */
        }
        evloopDebug(DBGDUMP, "evloopTimeoutFix(%d): elapsed time is %u.%06u sec",
            Stage,
            (unsigned)(USecElapsed/1000000),
            (unsigned)(USecElapsed%1000000));
    }
    evloopS.LastUSec = USecNow; /* for next time in evloopOnce */

    /* Remove elapsed time from the queue.
     * Note that time to wait for each node is the sum of it's USecMore time and that
     * of all nodes before it in the queue.
     */
    for (T = evloopS.TimeoutHead.Next; USecElapsed >= 0 &&
                T != &evloopS.TimeoutHead; T = T->Next) {
        if (T->USecMore > USecElapsed) {
            T->USecMore -= USecElapsed;
            USecElapsed = 0;
        } else {
            USecElapsed -= T->USecMore;
            T->USecMore = 0;
        }
    }

    return;
}


/*-F- evloopOnce -- wait once for events and dispatch.
 */
/*static*/ void evloopOnce(void)
{
    struct evloopReady *R;
    struct evloopTimeout *T;
    int TimeoutMSec;
    int IPoll;
    int Status;
    unsigned Events;

    evloopDebug(DBGDUMP, "ENTER evloopOnce");

    /* Reduce timeout in timeout nodes due to time since last call to 
    *   evloopOnce().
    *   Arguably we should redo this after calling every callback
    *   in case the callback took a while to execute, although this
    *   could easily lead to infinite loop.
    */
    evloopTimeoutFix(0);

    /* Call expired timeout handlers until there are none expired,
     * after which T will either be at the head or will point to
     * the nearest timeout yet to expire.
     * NOTE that new timeouts may be added during callbacks, including
     * the addition of timeouts with zero time (thus, expired)...
     * this allows for infinite loops if the application is buggy,
     * but is handy for deferring operation a bit.
     */
    for (;;) {
        /* Take next timeout off of sorted list.
         * NOTE that the list can change during callbacks!
         */
        T = evloopS.TimeoutHead.Next;
        if (T == &evloopS.TimeoutHead)
            break;
        if (T->USecMore > 0)
            break;
        /* Remove from queue */
        evloopTimeoutRemove(T);
        /* Set global context as it was at create time */
        #if EVLOOP_N_CONTEXT == 1
        evloopContext[0] = T->Context[0];
        #elif EVLOOP_N_CONTEXT > 1
        {
            int IContext;
            for (IContext = 0; IContext < EVLOOP_N_CONTEXT; IContext++) {
                evloopContext[0] = T->Context[0];
            }
        }
        #endif
        /* Call callback */
        evloopDebug(DBGDUMP, "evloopOnce call t.o. c.b. for %s",
            (T->Description?T->Description:"?"));
        (*T->CB)(T->Cookie1);
        evloopDebug(DBGDUMP, "evloopOnce return from c.b.");
        if (evloopS.Abort) {
            evloopDebug(DBGDEBUG, "LEAVE evloopOnce -- abort");
            return;
        }
    }
    /* How long to sleep until next node? 
     * We assume for simplicity that zero time has passed since we sampled time
     * above... this is of course not correct, but we assume that some error
     * such as this will not be important so long as it does not accumulate...
     * and it will not accumulate using this algorithm.
     */
    if (T == &evloopS.TimeoutHead) {
        /* no timeouts pending */
        evloopDebug(DBGDEBUG, "evloopOnce: no timeout");
        TimeoutMSec = EVLOOP_MAX_SLEEP_SEC*1000;
    } else {
        TimeoutMSec = T->USecMore/1000 + 1/*round up*/;
        if (TimeoutMSec > EVLOOP_MAX_SLEEP_SEC*1000) 
            TimeoutMSec = EVLOOP_MAX_SLEEP_SEC*1000;
    }
    evloopDebug(DBGDEBUG, 
        "evloopOnce: using timeout == %d msec", TimeoutMSec);

    /* Allocate more room for system call params as necessary */
    if (evloopS.NPollAlloc < evloopS.NReady) {
        void *Temp;
        evloopS.NPollAlloc = evloopS.NReady+200/*arbitrary growth*/;
        Temp = realloc(evloopS.Poll, 
                evloopS.NPollAlloc*sizeof(evloopS.Poll[0]));
        if (!Temp) {
            evloopDebug(DBGERR, "realloc failure! ABORT!");
            /* can't proceed from here */
            exit(13/*arbitrary value between 1 and 255*/);
            /* just in case: */
            evloopS.NPollAlloc = 0;
            free(evloopS.Poll);
            evloopS.Poll = NULL;
            return;     /* just in case */
        }
        evloopS.Poll = Temp;
    }

    /* Use poll() system call, which requires setting up
     * an a polling array first.
     */
    for (IPoll = 0, R = evloopS.ReadyHead.Next; R != &evloopS.ReadyHead;
            IPoll++, R = R->Next) {
        evloopS.Poll[IPoll].fd = R->Fd;
        evloopS.Poll[IPoll].events = 0;
        if (R->Mode == EVLOOP_READY_READ)
            evloopS.Poll[IPoll].events |= POLLIN;
        else
        if (R->Mode == EVLOOP_READY_WRITE)
            evloopS.Poll[IPoll].events |= POLLOUT;
        evloopS.Poll[IPoll].revents = 0;        /* to be sure */
    }
    Status = poll(evloopS.Poll, IPoll, TimeoutMSec);
    evloopDebug(DBGDEBUG, "Awake w/ poll status %d", Status);
    if (Status < 0) {
        if (errno == EINTR) {
            /* may be normal... return to try again */
            evloopDebug(DBGDUMP, "LEAVE evloopOnce -- EINTR");
            return;
        }
        evloopDebug(DBGERR, "poll error %d", errno);
        return;
    }
    if (Status == 0) {
        /* Nothing ready... optimize */
        evloopDebug(DBGDUMP, "LEAVE evloopOnce -- nothing to do");
        return;
    }

    /* Copy events for safe keeping, since our list can change during
     * callbacks.
     */
    for (IPoll = 0, R = evloopS.ReadyHead.Next; 
            R != &evloopS.ReadyHead; IPoll++) {
        struct evloopReady *RNext = R->Next;
        Events = evloopS.Poll[IPoll].revents;
        R->Events = Events;
        if (Events) {
            /* Put at begin of list so we can find it easily */
            R->Next->Prev = R->Prev;
            R->Prev->Next = R->Next;
            R->Prev = &evloopS.ReadyHead;
            R->Next = R->Prev->Next;
            R->Prev->Next = R->Next->Prev = R;
            if (--Status == 0)
                break;      /* optimize */
        }
        R = RNext;
    }

    /* Fix up timeout list since the ready callbacks may well modify it,
    *   and we have been sleeping for a while!
    */
    evloopTimeoutFix(1);

    /* Now process out of our list. Non-zero Events will be at beginning.
     * The list can be changed at every callback, but non-zero Events
     * will remain at the beginning.
     */
    for (;;) {
        R = evloopS.ReadyHead.Next;
        Events = R->Events;
        if (Events == 0)        /* including hitting the head */
            break;
        R->Events = 0;  /* once only */
        /* Put at end of list now that it no longer contains nonzero Events */
        R->Next->Prev = R->Prev;
        R->Prev->Next = R->Next;
        R->Next = &evloopS.ReadyHead;
        R->Prev = R->Next->Prev;
        R->Prev->Next = R->Next->Prev = R;
        evloopDebug(DBGDUMP, "Calling Ready handler for `%s'", R->Description);
        /* Set global context as it was at create time */
        #if EVLOOP_N_CONTEXT == 1
        evloopContext[0] = R->Context[0];
        #elif EVLOOP_N_CONTEXT > 1
        {
            int IContext;
            for (IContext = 0; IContext < EVLOOP_N_CONTEXT; IContext++) {
                evloopContext[0] = R->Context[0];
            }
        }
        #endif
        /* Call the callback */
        evloopDebug(DBGDUMP, "evloopOnce call ready c.b. for %s",
            (R->Description?R->Description:"?"));
        (*R->CB)(R->Cookie1);
        evloopDebug(DBGDUMP, "evloopOnce return from ready c.b.");
        if (evloopS.Abort) {
            evloopDebug(DBGDEBUG, "LEAVE evloopOnce -- abort");
            return;
        }
    }

    evloopDebug(DBGDUMP, "LEAVE evloopOnce");
    return;
}

/*-F- evloopRun -- endless loop waiting for events and calling callbacks.
 * This will typically be the last thing called from main(),
 * following initializations.
 * It never returns unless evloopAbort() is called from some callback
 * function or signal handler.
 */
void evloopRun(void)
{
    if (!evloopS.IsInit)
        evloopInit();
    evloopDebug(DBGINFO, "ENTER evloopRun");
    evloopS.Abort = 0;
    evloopS.LastUSec = 0;
    while (!evloopS.Abort) {
        evloopOnce();
    }
    evloopDebug(DBGINFO, "LEAVE evloopRun");
}

/*-F- evloopAbort -- cause evloopRun to return to caller at next opportunity.
 * Unlike most other evloop functions, can be called from a signal handler.
 */
void evloopAbort(void)
{
    evloopS.Abort = 1;
}

/*-F- evloopRunPrepare
 */
void evloopRunPrepare(void)
{
    if (!evloopS.IsInit)
        evloopInit();
    evloopS.Abort = 0;
    evloopS.LastUSec = 0;
}

/*-F- evloopIsAbort
 */
int evloopIsAbort(void)
{
    return evloopS.Abort;
}

/*========================================================================*/
/*============= evloop Debugging menu ====================================*/
/*========================================================================*/



/* ------------------- s = status -------------------------------- */
const char *evloopMenuStatusHelp[] = {
    "s -- print evloop module status", 
    NULL
};

void evloopMenuStatusHandler(
        struct cmdContext *Context,
        const char *Cmd)
{
    struct evloopTimeout *T;
    struct evloopReady *R;
    long long USecMore = 0;

    cmdf(Context, "Pending timeouts:\n");
    for (T = evloopS.TimeoutHead.Next;
            T != &evloopS.TimeoutHead; T = T->Next) {
        USecMore += T->USecMore;
        cmdf(Context, "    %s [%p][%p][%p] %u.%06u\n",
            T->Description, T->Cookie1, T->Cookie2, T->Cookie3, 
            (unsigned)(USecMore/1000000),
            (unsigned)(USecMore%1000000));
    }
    cmdf(Context, "Waiting for ready:\n");
    for (R = evloopS.ReadyHead.Next;
            R != &evloopS.ReadyHead; R = R->Next) {
        const char *ModeString;
        switch (R->Mode) {
            case EVLOOP_READY_READ:
                ModeString = "READ";
            break;
            case EVLOOP_READY_WRITE:
                ModeString =  "WRITE";
            break;
            default:
                ModeString =  "UNKNOWN";
            break;
        }
        cmdf(Context, "    %s [%p][%p][%p] fd=%d %s\n",
            R->Description, R->Cookie1, R->Cookie2, R->Cookie3, R->Fd,
            ModeString);
    }
}

/* ------------------ evloop menu (added to main menu) -------------------------*/

struct cmdMenuItem evloopMenu[] = {
    CMD_MENU_STANDARD_STUFF(),
    {"s", evloopMenuStatusHandler, NULL, evloopMenuStatusHelp},
    CMD_MENU_END()
};

const char *evloopMenuHelp[] = {
    "evloop -- Event loop menu",
    NULL
};

const struct cmdMenuItem evloopMenuItem = {"evloop", cmdMenu, evloopMenu, evloopMenuHelp};


/*========================================================================*/
/*============ Init ======================================================*/
/*========================================================================*/


/*--- evloopInit -- first time init.
 * Automatically called as need be.
 */
/*static*/ void evloopInit(void)
{
    if (evloopS.IsInit)
        return;
    evloopS.IsInit = 1;
    evloopS.DebugModule = dbgModuleFind("evloop");
    evloopS.ReadyHead.Next = evloopS.ReadyHead.Prev = &evloopS.ReadyHead;
    evloopS.TimeoutHead.Next = evloopS.TimeoutHead.Prev = &evloopS.TimeoutHead;
    cmdMainMenuAdd(&evloopMenuItem);
    /* Disable SIGPIPE which is inappropriate for this type of program */
    signal(SIGPIPE, SIG_IGN);
    evloopDebug(DBGINFO, "evloopInit Done.");
}


