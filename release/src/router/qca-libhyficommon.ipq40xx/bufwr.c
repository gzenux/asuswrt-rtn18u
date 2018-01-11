/*
 * Copyright (c) 2010 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*-M- bufwr -- buffered writing for single-threaded event-driven programs.
 *
 * This module implements flow control for writing to e.g. TCP 
 * and UDP sockets.
 * A producer callback function is called whenever a buffer for the
 * produced data is below a low water mark of fullness AND the 
 * socket / descriptor is ready for writing.
 * The producer callback function should then generate some more data;
 * the amount of data it generates is not limited but care should be
 * taken not to generate too much at one time in order to avoid
 * excessive memory consumption.
 * Asyncronously, when the socket / descriptor is ready for writing,
 * data is written to the descriptor.
 *
 * The application must maintain a "struct bufwr" control block.
 * After the descriptor has been obtained, the control block is 
 * initialized via a call to bufwrCreate().
 * When the application callback is called, it should pass data
 * via bufwrWrite().
 * When the control block is no longer needed, it should be cleaned
 * via a call to bufwrDestroy*() (this close the file descriptor...
 * dup it if you need to keep it).
 *
 * Calls to bufwrWrite() may be made from any single-threaded context,
 * not just the callback function.
 * If the application callback does not have anything to write, it
 * doesn't have to; it may be called one or more times again but
 * will eventually not be called any more if no more has been written.
 * At any time, the application can (from some other context)
 * write more which will resume the cycle of calling the callback.
 *
 * Up to three cookies (Cookie1, Cookie2 and Cookie3) may be stored
 * by the application in the bufwr object.
 * Cookie1 is normally set by the Create() call, and may be changed
 * thereafter using the SetCookie1 function, and the other cookies
 * may be set after the Create() call using the SetCookie* functions.
 * The current value of Cookie1 is passed to the callback function,
 * and the other cookies can be obtained using the GetCookie* functions
 * provided that the burwr object can be located; one possibility
 * is to use the ptr to the burwr object as Cookie1 and then use
 * the GetCookie2 and GetCookie3 functions to get two cookies.
 */

#include <stdlib.h>
#include <poll.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
// #include <assert.h>

#include <dbg.h>
#include <bufwr.h>

#if 0   /* auto-extract only */
/*-D- Required includes
*/
#include <evloop.h>
/*--------------------------------------------------------------------------*/
#endif

/*--- WRBUF_KEEP_BUF_MAX -- above this, we try to prune down
 * allocations when buffer empties to avoid reserving heap for long
 * periods.
 */
#define WRBUF_KEEP_BUF_MAX 1024

/*--- WRBUF_ALLOC_DELTA -- to avoid repeated realloc'ing,
 * increase size by this much each time
 */
#define WRBUF_ALLOC_DELTA 1024

#if 0   /* auto-extract only */
/*-D- bufwr -- control structure for buffered writing.
 */
struct bufwr {
    struct evloopReady Ready;   /* Direct interface to event loop */
    void (*CB)(void *Cookie1);
            /* CB: NULL or called when pending bytes <= LowWater */
    void *Cookie1;              /* app use */   
    unsigned LowWater;
    unsigned char *Buf;         /* NULL or buffering */
    int BufSize;                /* nbytes alloc in *Buf if Buf != NULL */
    int NFull;                  /* how many bytes stored */
    unsigned Fatal : 1;         /* set on fatal error */
    unsigned IOError : 1;       /* set on write error */
    unsigned Quit : 1;          /* nonzero for delayed destroy */
    unsigned Allocated : 1;     /* if buffer was allocated w/ malloc */
    unsigned Fixed : 1;         /* if buffer will not be reallocated */
};

/*-D- bufwrErrorGet -- returns nonzero on fatal error.
 */
static inline int bufwrErrorGet(struct bufwr *B)
{
    return B->Fatal;
}

/*-D- bufwrWriteErrorGet -- returns nonzero on (fatal) write error.
*       This helps distinguish from memory allocation errors.
*/
static inline int bufwrWriteErrorGet(struct bufwr *B)
{
    return B->IOError;
}

/*-D- bufwrQGet -- return no. of bytes waiting to be written.
 */
static inline int bufwrQGet(struct bufwr *B)
{
    return B->NFull;
}

/*-D- bufwrDescriptionGet -- return buffer description.
 */
static inline const char *bufwrDescriptionGet(struct bufwr *B)
{
    return evloopReadyDescriptionGet(&B->Ready);
}

/*-D- bufwrFdGet -- return which descriptor.
 */
static inline int bufwrFdGet(struct bufwr *B)
{
    return evloopReadyFdGet(&B->Ready);
}

/*-D- bufwrCookie1Get -- return 1st application cookie.
 */
static inline void *bufwrCookie1Get(struct bufwr *B)
{
    return B->Cookie1;
}

/*-D- bufwrCookie2Get -- return 2nd application cookie.
 */
static inline void *bufwrCookie2Get(struct bufwr *B)
{
    return evloopReadyCookie2Get(&B->Ready);
}

/*-D- bufwrCookie3Get -- return 3rd application cookie.
 */
static inline void *bufwrCookie3Get(struct bufwr *B)
{
    return evloopReadyCookie3Get(&B->Ready);
}

/*-D- bufwrCookie1Set -- set 1st application cookie.
 */
static inline void bufwrCookie1Set(
        struct bufwr *B,
        void *Cookie1)
{
    B->Cookie1 = Cookie1;
}

/*-D- bufwrCookie2Set -- set 2nd application cookie.
 */
static inline void bufwrCookie2Set(
        struct bufwr *B,
        void *Cookie2)
{
    evloopReadyCookie2Set(&B->Ready, Cookie2);
}

/*-D- bufwrCookie3Set -- set 3rd application cookie.
 */
static inline void bufwrCookie3Set(
        struct bufwr *B,
        void *Cookie3)
{
    evloopReadyCookie3Set(&B->Ready, Cookie3);
}

/*-----------------------------------------*/
#endif /*auto-extract only */


/*--- bufwrState -- global data for bufwr
 */
struct bufwrState {
    int IsInit;
    struct dbgModule *DebugModule;
} bufwrS;


/*--- bufwrDebug -- print debug messages (see dbgf documentation)
 */
#define bufwrDebug(level, ...) \
        dbgf(bufwrS.DebugModule,(level),__VA_ARGS__)


/*--- bufwrInit -- first time init.
 */
void bufwrInit(void)
{
    if (bufwrS.IsInit)
        return;
    bufwrS.IsInit = 1;
    bufwrS.DebugModule = dbgModuleFind("bufwr");
    bufwrDebug(DBGINFO, "bufwrInit Done.");
}

/*--- bufwrGrow -- auto-increase the buffer size.
 * Do not call if B->Fixed; this implies not called if non-malloc'd buffer
 * other than NULL.
 */
/*static*/ int bufwrGrow(
        struct bufwr *B,
        int MinNewSize)
{
    int OldBufSize = B->BufSize;
    int NewBufSize = OldBufSize;
    void *Temp;

    /* round up to avoid repeated realloc's */
    while (NewBufSize < MinNewSize)
        NewBufSize += WRBUF_ALLOC_DELTA;

    Temp = realloc(B->Buf, NewBufSize);
    if (Temp == NULL) {
        bufwrDebug(DBGERR, "Malloc failure!");
        B->Fatal = 1;
        free(B->Buf);
        B->Buf = NULL;
        return 1;
    }
    B->Buf = Temp;
    B->BufSize = NewBufSize;
    B->Allocated = 1;
    return 0;
}

/*-F-  bufwrFlush -- force some data out of buffer
 * If FlushAll==0, can return after flushing only some
 * (can occur if a short write occurs).
 * If FlushAll != 0, returns only after flushing all or if error.
 *
 * Returns nonzero on fatal error (B->Fatal also set).
 */
int bufwrFlush(
        struct bufwr *B,
        int FlushAll)
{
    int NToWrite;
    int NWrote;
    struct evloopReady *R = &B->Ready;

    bufwrDebug(DBGDEBUG, "ENTER bufwrFlush fd=%d `%s'",
        evloopReadyFdGet(R), evloopReadyDescriptionGet(R));
    
    if (B->NFull <= 0)
        return 0;

    // assert(evloopReadyFdGet(R) > 0);
    for (;;) {
        NToWrite = B->NFull;
        NWrote = write(evloopReadyFdGet(R), B->Buf, NToWrite);
        if (NWrote < 0) {
            if (errno == EINTR) {
                continue;     /* try again */
            }
            bufwrDebug(DBGERR, "Write failure (errno %d) on fd %d for `%s'",
                errno, B->Ready.Fd, B->Ready.Description);
            B->Fatal = 1;
            B->IOError = 1;
            return 1;
        } else
        if (NWrote == 0) {
            bufwrDebug(DBGERR, "Write 0 bytes on fd %d for `%s'",
                B->Ready.Fd, B->Ready.Description);
            return 1;     /* try again later; we're still registered */
        } else {
            if (NWrote == NToWrite) {
                B->NFull = 0;
            } else {
                B->NFull -= NWrote;
                /* It may seem inefficient to do a memmove here,
                 * but this should actually only rarely happen that
                 * we get a partial write,
                 * and anyway the memmove is pretty fast and it simplifies
                 * the logic all around which is good!
                 */
                memmove(B->Buf, B->Buf+NWrote, B->NFull);
            }
        }
        /* Keep large allocations from hanging around wasting memory */
        if (B->NFull <= 0 && !B->Fixed && B->Allocated && 
                B->BufSize > WRBUF_KEEP_BUF_MAX) {
            free(B->Buf);
            B->Buf = NULL;
            B->BufSize = 0;
            B->Allocated = 0;
        }
        if (B->NFull <= 0 || !FlushAll)
            return 0;
        /* partial write case w/ FlushAll != 0 --- try to write some more */
    }
}


/* bufwrReady -- internal function, called back when we are ready to write.
 */
/*static*/ void bufwrReady(void *Cookie)
{
    /* We are called because we should be able to write w/out blocking */
    struct bufwr *B = Cookie;
    struct evloopReady *R = &B->Ready;
    int NToWrite = 0;

    if (B->Fatal)
        goto DoCallBack;

    bufwrDebug(DBGDEBUG, "ENTER bufwrReady fd=%d `%s'",
        evloopReadyFdGet(R), evloopReadyDescriptionGet(R));

    NToWrite = B->NFull;
    if (NToWrite > 0) {
        if (bufwrFlush(B, 0)) {
            evloopReadyUnregister(R);
        }

        /* See how much more there is to write */
        NToWrite = B->NFull;
    }

    /* If empty,
     * unregister in case the callback doesn't want to produce anything
     * right now... 
     * if it does produce something and calls bufwrWrite(),
     * then that will re-register us.
     */
    if (NToWrite == 0 || B->Fatal) {
        if (B->Quit) {
            bufwrDestroyNow(B);
            return;
        }
        evloopReadyUnregister(R);
    }

    DoCallBack:
    if (B->Quit)
        return; /* don't call CB after Destroy */
    /* If below low water mark, call callback to generate some more data
     * (i.e. call bufwrWrite()) 
     */
    if ((NToWrite <= B->LowWater || B->Fatal) && B->CB != NULL)  {
        (*B->CB)(B->Cookie1);
    }
}

/*-F- bufwrCreate -- set up write buffering
 * The descriptor Fd is "given" to bufwr, and will be closed by
 * bufwrDestroy*() ... dup it if you need to keep it.
 */
void bufwrCreate(
        struct bufwr *B,        /* control struct provided by app */
        const char *Description,    /* of nonvolatile string! for debugging */
        int Fd,                 /* descriptor to write to */
        int LowWater,           /* call CB when we have <= this many bytes */
        void (*CB)(void *Cookie1),      /* NULL, or called when ready */
        void *Cookie1               /* app use */
        )
{
    if (!bufwrS.IsInit)
        bufwrInit();
    bufwrDebug(DBGINFO, "ENTER bufwrCreate `%s'", Description);

    memset(B, 0, sizeof(*B));
    B->LowWater = LowWater;
    B->CB = CB;
    B->Cookie1 = Cookie1;
    evloopWriteReadyCreate(&B->Ready, Description, Fd, bufwrReady, B);
    evloopReadyRegister(&B->Ready);     /* callback when ready */
}

/*-F- bufwrBufferSet -- set buffer/size to use.
 * The buffer will now not be allowed to grow (except BufSize == 0).
 * Additions that would exceed the buffer result in immediate,
 * possibly blocking writes to the file descriptor.
 * This must be called after bufwrCreate but only when nothing is buffered.
 *
 * If BufSize is <= 0 and Buf is NULL the buffer is allowed to
 * grow again as needed.
 * If BufSize is <= 0 and Buf is non-NULL the buffer is not used
 * and all writes are done immediately even if they block.
 */
void bufwrBufferSet(
        struct bufwr *B,        /* control struct provided by app */
        void *Buf,      /* NULL to malloc; or buffer to use */
        int BufSize)    /* size of buffer / to malloc */
{
    if (B->NFull != 0) {
        bufwrDebug(DBGERR, "bufwrBufferSet on not empty!");
        return;
    }
    if (B->Allocated)
        free(B->Buf);
    B->Buf = NULL;
    B->BufSize = 0;
    B->Allocated = 0;
    B->Fixed = 0;

    if (BufSize <= 0) {
        if (Buf) {
            /* Force dis-use of buffer */
            B->Fixed = 1;
        }
        /* else return to auto-allocation */
        return;
    }
    /* Here for fixed allocation */
    if (Buf) {
        B->Buf = Buf;
    } else {
        if (bufwrGrow(B, BufSize))
            return;
        B->Allocated = 1;
    }
    B->Fixed = 1;
    B->BufSize = BufSize;
    return;
}

/*-F- bufwrDestroyNow -- take down write buffering
 * This unregisters and frees allocated buffer if any,
 * as well as freeing the file descriptor!
 * Any data not yet actually written will be lost.
 * Don't use B after this.
 */
void bufwrDestroyNow(
        struct bufwr *B)        /* control struct provided by app */
{
    evloopReadyUnregister(&B->Ready);
    if (B->Allocated)
        free(B->Buf);
    if (evloopReadyFdGet(&B->Ready) > 0)
        close(evloopReadyFdGet(&B->Ready));
    memset(B, 0, sizeof(*B));
}

/*-F- bufwrDestroyDelayed -- take down write buffering
 * after all output has been written.
 * Don't use B after this.
 */
void bufwrDestroyDelayed(
        struct bufwr *B)        /* control struct provided by app */
{
    if (B->Fatal || B->NFull == 0) {
        bufwrDestroyNow(B);
    } else {
        B->Quit = 1;
        evloopReadyRegister(&B->Ready);     /* to be sure */
    }
}


/*-F- bufwrWrite -- add bytes to be written when possible.
 * Returns nonzero on fatal error, after which the bufwr should
 * be destroyed.
 *
 * Feature: if "Fixed" flag is set, and a packet passed per call
 * to bufwrWrite(), the actual writes to sockets etc.
 * will preserve the packet boundaries (but may put multiple
 * packets into one).
 */
int bufwrWrite(
        struct bufwr *B,
        const char *Buf,
        int NBytes)     /* now much to write from Buf */
{
    struct evloopReady *R = &B->Ready;
    int NUsed;          /* no. of bytes waiting in buffer */
    int NRoom;          /* how many more bytes can be added */

    if (B->Fatal) 
        return 1;

    NUsed = B->NFull;
    NRoom = B->BufSize - NUsed - 1/*so we can tell empty from full*/;
    /* Expand buffer as needed to absorb extra writes.
     * The application is supposed to monitor the buffer space
     * used to keep it from getting too large.
     */
    if (NRoom < NBytes) {
        /* Not enough from for new data */
        if (B->Fixed) {
            /* We have a fixed size buffer and are not allowed to grow it.
             * "Fixed" should be used with datagram (UDP) applications
             * and may be used to prevent excessive buffer growth...
             * although at the cost of stalling the program.
             *
             * We write out what is in there to make room for more or at 
             * least to preserve ordering.
             * You might think we could add part of our new stuff to
             * the buffer, but we do NOT because this would cause
             * partial packets to be received when bufwr is used in 
             * conjunction with a datagram (UPD) socket... which
             * would be an extra burden on the receiver.
             * (bufwr does NOT prevent multiple packets from being
             * received together, but this is easier for the receiver
             * to handle).
             */
            if (NUsed != 0) {
                if (bufwrFlush(B, 1/*all*/)) {
                    return 1;
                }
            }
            NUsed = 0;
            NRoom = B->BufSize - NUsed - 1;
            if (NBytes > NRoom) {
                /* too big; write it out directly even if we block */
                while (NBytes > 0) {
                    int NWrote = write(evloopReadyFdGet(R), Buf, NBytes);
                    if (NWrote < 0) {
                        if (errno == EINTR) {
                            continue;     /* try again */
                        }
                        bufwrDebug(DBGERR, 
                        "Write failure (errno %d) on fd %d for `%s'",
                            errno, B->Ready.Fd, B->Ready.Description);
                        B->Fatal = 1;
                        B->IOError = 1;
                        return 1;
                    }
                    if (NWrote == 0) {
                        bufwrDebug(DBGERR, 
                        "Forced-Write failure (nbytes 0) on fd %d for `%s'",
                            B->Ready.Fd, B->Ready.Description);
                        B->Fatal = 1;
                        B->IOError = 1;
                        return 1;
                    }
                    NBytes -= NWrote;
                    Buf += NWrote;
                }
                goto ReRegister;
            }
        } else {
            if (bufwrGrow(B, NUsed+NBytes+1))
                return 1;
        }
    }
    /* Here we have room -- add new data to output buffer */
    memcpy(B->Buf+B->NFull, Buf, NBytes);
    B->NFull += NBytes;
    ReRegister:
    /* And register for callback to write when ready.
     * We could optimize by tracking if it is already registered,
     * but this is pretty cheap.
     */
    evloopReadyRegister(&B->Ready);
    return 0;
}

/*-F- bufwrWriteString -- add bytes to be written when possible.
 * No. of bytes determined by strlen.
 * Returns nonzero on fatal error, after which the bufwr should
 * be destroyed.
 */
int bufwrWriteString(
        struct bufwr *B,
        const char *Buf)        /* null terminated string */
{
    return bufwrWrite(B, Buf, strlen(Buf));
}

