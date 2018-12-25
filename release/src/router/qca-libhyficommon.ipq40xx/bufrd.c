/*
 * Copyright (c) 2010 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*-M- bufrd -- buffered reading for single-threaded event-driven programs.
 *
 * The reason for buffering reads is to allow the application to
 * group data out of the input stream.
 * Since the input stream may come in in chunks unaligned to the
 * intended blocking of the data, using buffering becomes essential.
 * The bufrd module also tracks error / end of file condition.
 *
 * The application maintains a "struct bufrd" control block.
 * After obtaining the socket/stream/file descriptor, the application
 * intializes the control block via a call to bufrdCreate(),
 * which sets up the buffering and polling of descriptor.
 * Thereafter, the application callback function is called whenever
 * more data is added (by bufrd) to the buffer.
 * The callback function should do the following:
 * -- Check for errors / EOF via bufrdErrorGet(). Close out if error.
 * -- Obtain buffer address and content size via calls to
 *      bufrdBufGet() and bufrdNBytesGet().
 * -- Check if the buffer obtains complete parsing units or not.
 *      If so, parse the unit and call bufrdConsume for each parsing unit
 *      (call bufrdBufGet() and bufrdNBytesGet() each time).
 *      It is permissible to modify the parsing unit in place if that
 *      helps.
 * When the buffering is no longer needed, it should be closed out
 * with bufrdDestroy() call. (This closes the file descriptor...
 * dup it if you need it).
 *
 * In case the application is not ready to process the data when the
 * callback is called, it may simply do nothing, but at some later
 * time the above described processing should be done from another context.
 *
 * Up to three cookies (Cookie1, Cookie2 and Cookie3) may be stored
 * by the application in the bufrd object.
 * Cookie1 is normally set by the Create() call, and may be changed
 * thereafter using the SetCookie1 function, and the other cookies
 * may be set after the Create() call using the SetCookie* functions.
 * The current value of Cookie1 is passed to the callback function,
 * and the other cookies can be obtained using the GetCookie* functions
 * provided that the bufrd object can be located; one possibility
 * is to use the ptr to the bufrd object as Cookie1 and then use
 * the GetCookie2 and GetCookie3 functions to get two cookies.
 */

#include <stdlib.h>
#include <poll.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <dbg.h>
#include <bufrd.h>

#if 0   /* auto-extract only */
/*-D- required includes
*/
#include <evloop.h>

/*-D- bufrd -- control structure for buffered reading.
 */
struct bufrd {
    struct evloopReady Ready;   /* Direct interface to event loop */
    /* CB: NULL or called when more is added to Buf.  */
    void (*CB)(void *Cookie1);
    void *Cookie1;              /* app use */   
    unsigned char *Buf;         /* NULL or buffering */
    int BufSize;                /* nbytes alloc in *Buf if Buf != NULL */
    int NBytes;                 /* no. of bytes waiting in Buf */
    int Fatal;                  /* nonzero on fatal error or EOF */
};

/*-D- bufrdErrorGet -- returns nonzero on fatal error.
 */
static inline int bufrdErrorGet(struct bufrd *B)
{
    return B->Fatal;
}

/*-D- bufrdBufGet -- get buffer location.
 * May return NULL if nothing is buffered.
 */
static inline void *bufrdBufGet(struct bufrd *B)
{
    return B->Buf;
}

/*-D- bufrdNBytesGet -- get buffer content size.
 */
static inline int bufrdNBytesGet(struct bufrd *B)
{
    return B->NBytes;
}

/*-D- bufrdDescriptionGet -- return buffer description.
 */
static inline const char *bufrdDescriptionGet(struct bufrd *B)
{
    return evloopReadyDescriptionGet(&B->Ready);
}

/*-D- bufrdFdGet -- return which descriptor.
 */
static inline int bufrdFdGet(struct bufrd *B)
{
    return evloopReadyFdGet(&B->Ready);
}

/*-D- bufrdCookie1Get -- return 1st application cookie.
 */
static inline void *bufrdCookie1Get(struct bufrd *B)
{
    return B->Cookie1;
}

/*-D- bufrdCookie2Get -- return 2nd application cookie.
 */
static inline void *bufrdCookie2Get(struct bufrd *B)
{
    return evloopReadyCookie2Get(&B->Ready);
}

/*-D- bufrdCookie3Get -- return 3rd application cookie.
 */
static inline void *bufrdCookie3Get(struct bufrd *B)
{
    return evloopReadyCookie3Get(&B->Ready);
}

/*-D- bufrdCookie1Set -- set 1st application cookie.
 */
static inline void bufrdCookie1Set(
        struct bufrd *B,
        void *Cookie1)
{
    B->Cookie1 = Cookie1;
}

/*-D- bufrdCookie2Set -- set 2nd application cookie.
 */
static inline void bufrdCookie2Set(
        struct bufrd *B,
        void *Cookie2)
{
    evloopReadyCookie2Set(&B->Ready, Cookie2);
}

/*-D- bufrdCookie3Set -- set 3rd application cookie.
 */
static inline void bufrdCookie3Set(
        struct bufrd *B,
        void *Cookie3)
{
    evloopReadyCookie3Set(&B->Ready, Cookie3);
}

/*----------------------------------------------*/
#endif  /* auto-extract only */

/*--- bufrdState -- global data for bufrd
 */
struct bufrdState {
    int IsInit;
    struct dbgModule *DebugModule;
} bufrdS;


/*--- bufrdDebug -- print debug messages (see dbgf documentation)
 */
#define bufrdDebug(level, ...)         dbgf(bufrdS.DebugModule,(level),__VA_ARGS__) 


/*--- bufrdInit -- first time init.
 */
void bufrdInit(void)
{
    if (bufrdS.IsInit)
        return;
    bufrdS.IsInit = 1;
    bufrdS.DebugModule = dbgModuleFind("bufrd");
    bufrdDebug(DBGINFO, "bufrdInit Done.");
}


/* bufrdReady -- internal function, called back when we are ready to read.
 */
/*static*/ void bufrdReady(void *Cookie)
{
    /* We are called because we should be able to read w/out blocking */
    struct bufrd *B = Cookie;
    struct evloopReady *R = &B->Ready;
    int NToRead = B->BufSize - B->NBytes;

    if (NToRead > 0) {
        int NRead = read(evloopReadyFdGet(R), B->Buf+B->NBytes, NToRead);
        if (NRead < 0) {
            bufrdDebug(DBGINFO, "Read error (errno %d) on fd %d `%s'",
                errno, evloopReadyFdGet(R), evloopReadyDescriptionGet(R));
            B->Fatal = 1;
        } else if (NRead == 0) {
            bufrdDebug(DBGINFO, "EOF on fd %d `%s'",
                evloopReadyFdGet(R), evloopReadyDescriptionGet(R));
            B->Fatal = 1;
        } else {
            B->NBytes += NRead;
        }
    }

    /* If full, unregister; consume call will register again */
    if (B->NBytes >= B->BufSize || B->Fatal) {
        evloopReadyUnregister(R);
    }
    /* Call callback function so long as we are making progress. */
    while (B->CB) {
        int NBytes = B->NBytes;
        (*B->CB)(B->Cookie1);
        if (B->NBytes == NBytes)
            break;      /* no progress made */
    }
}

/*-F- bufrdCreate -- set up read buffering
 * The descriptor Fd is "given" to bufrd, and will be closed by
 * bufrdDestroy() ... dup it if you need to keep it.
 */
void bufrdCreate(
        struct bufrd *B,        /* control struct provided by app */
        const char *Description,    /* of nonvolatile string! for debugging */
        int Fd,                 /* descriptor to write to */
        int BufSize,            /* how large a buffer to use */
        void (*CB)(void *Cookie1),      /* NULL, or called when ready */
        void *Cookie1               /* app use */
        )
{
    if (!bufrdS.IsInit)
        bufrdInit();
    bufrdDebug(DBGINFO, "ENTER bufrdCreate `%s'", Description);

    memset(B, 0, sizeof(*B));
    B->CB = CB;
    B->Cookie1 = Cookie1;
    B->Buf = malloc(BufSize);
    if (B->Buf == NULL) {
        bufrdDebug(DBGERR, "Malloc failure!");
        B->Fatal = 1;
    }
    B->BufSize = BufSize;
    evloopReadReadyCreate(&B->Ready, Description, Fd, bufrdReady, B);
    evloopReadyRegister(&B->Ready);
}

/*-F- bufrdDestroy -- take down read buffering
 * This unregisters and frees allocated buffer if any.
 */
void bufrdDestroy(
        struct bufrd *B         /* control struct provided by app */
        )
{
    if (!bufrdS.IsInit)
        bufrdInit();
    bufrdDebug(DBGINFO, "ENTER bufrdDestroy `%s'", 
        evloopReadyDescriptionGet(&B->Ready));

    evloopReadyUnregister(&B->Ready);
    if (evloopReadyFdGet(&B->Ready) > 0)
        close(evloopReadyFdGet(&B->Ready));
    if(B->Buf)free(B->Buf);
    memset(B, 0, sizeof(*B));
}

/*-F- bufrdConsume -- call when one or more bytes from front of buffer
 * have been processed and should not be seen again.
 */
void bufrdConsume(
        struct bufrd *B,        /* control struct provided by app */
        int NBytes)             /* no. of bytes to take off of buffer */
{
    int NLeft;

    if (!bufrdS.IsInit)
        bufrdInit();
    bufrdDebug(DBGDEBUG, "ENTER bufrdConsume `%s' %d bytes", 
        evloopReadyDescriptionGet(&B->Ready), NBytes);

    NLeft = B->NBytes - NBytes;
    if (NLeft < 0) {
        bufrdDebug(DBGERR, "Redundant bufrdConsume call!");
        return;
    }
    if (NLeft > 0)
        memmove(B->Buf, B->Buf+NBytes, NLeft);
    B->NBytes = NLeft;
    if (B->NBytes < B->BufSize)
        evloopReadyRegister(&B->Ready);
}


/*-F- bufrdLineDup -- returns copy of next text line in buffer,
 *      which is consumed.
 *      The text line must end with a newline character, which is
 *      replaced in the copy with a null character; however,
 *      an extra space is left in the allocation so that the
 *      newline may be restored (two null chars are put at end,
 *      the first of which can be replaced with a newline).
 *      If there is not a line of text available, returns NULL.
 *
 *      The returned memory must be freed via call to free().
 */
char *bufrdLineDup(
        struct bufrd *B)        /* control struct provided by app */
{
    char *Buf = bufrdBufGet(B);
    int Max = bufrdNBytesGet(B);
    int NBytes;
    char *Result;

    for (NBytes = 0; NBytes < Max; NBytes++) {
        if (Buf[NBytes] == '\n')
            goto Found;
    }
    return NULL;

    Found:
    Result = malloc(NBytes+2/* two nulls at end*/);
    if (Result == NULL) {
        bufrdDebug(DBGERR, "Malloc failure!");
        return NULL;
    }
    memcpy(Result, Buf, NBytes);
    Result[NBytes] = 0;         /* may be replaced with newline */
    Result[NBytes+1] = 0;       /* in case last null replaced w/ newline */
    bufrdConsume(B, NBytes+1);
    return Result;
}

