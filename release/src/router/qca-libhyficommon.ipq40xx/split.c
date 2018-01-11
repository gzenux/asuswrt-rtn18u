/*
 * Copyright (c) 2010 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*-M- split --  text processing utilities
 *  */

/*===========================================================================*/
/*================= Includes and Configuration ==============================*/
/*===========================================================================*/


/* C and system library includes */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <fcntl.h>


#if 0   /* auto-extract only */

/*-D- Required
 */


/*---------------------------------------------------------------------------*/

#endif  /* auto-extract only */

/*-F- splitSort -- sort the results of split (less)
 */
void splitSort(
        int MaxWords,
        int WordBufSize,
        char Words[MaxWords][WordBufSize])
{
    if(MaxWords <= 0 || WordBufSize <= 0) return;
    char *tmp= malloc(WordBufSize+1);
    if(!tmp) return;
    memset(tmp, 0, WordBufSize+1);
    int n, m;
    for(n=0; n<MaxWords; n++) {
        for(m=n; m<MaxWords; m++) {
            if(0 >= strcmp(Words[n], Words[m])) {
                strlcpy(tmp, Words[m], WordBufSize);
                strlcpy(Words[m], Words[n], WordBufSize);
                strlcpy(Words[n], tmp, WordBufSize);
                memset(tmp, 0, WordBufSize);
            }
        }
    }
    free(tmp);
    return;
}


/*-F- splitByToken -- split string into "words" separated by Token given, such
 *       as ',', ' ' etc.
 *
 *       Returns words as null-terminated strings in Dst where the words
 *       are spaced apart at WordBufSize bytes apart.
 *       Return value is number of words extracted.
 *       Buffer overflow causes a return value of -1.
 *
 *       This is useful where the client code declares memory like:
 *               char XXBuf[MaxWords][WordBufSize+1]
 *       and calls splitByToken as:
 *               int NWords = splitByToken(
 *                       XXSrc,
 *                       sizeof(XXBuf)/sizeof(XXBuf[0]),
 *                       sizeof(XXBuf[0]),
 *                       XXBuf,
 *                       Token);
 *       and can then access the individual strings as:
 *                       XXBuf[i]
 */
int splitByToken(
    const char *Src,    /* source string */
    int MaxWords,       /* max. no. of strings extracted */
    int WordBufSize,    /* spacing between strings */
    char *Dst,          /* logically 2D but physically flat (1D) allocation */
    const char Token)
{
    int NWords = 0;
    memset(Dst, 0, MaxWords*WordBufSize);       /* for null termination etc.*/
    for (;;) {
        const char *Tok;
        int WordLen;
        if (NWords >= MaxWords)
            goto Fail;
        Tok = strchr(Src, Token);
        if (Tok)
            WordLen = Tok - Src;
        else
            WordLen = strlen(Src);
        /* Leave room for terminating null character! */
        if (WordLen >= WordBufSize)
            goto Fail;
        /* leaves null terminator */
        memcpy(Dst + NWords*WordBufSize, Src, WordLen);
        NWords++;
        if (Tok)
            Src = Tok+1;
        else
            break;
    }
    return NWords;
Fail:
    return -1;
}

/*-F- splitLineByMultiSpace -- split line in config-file, such as pppoeconnmap,
 *       which is seperated by multi-space, into "words", and trim the
 *       left/right space of current line
 *
 *       Returns words as null-terminated strings in Dst where the words
 *       are spaced apart at WordBufSize bytes apart.
 *       Return value is number of words extracted.
 *       Buffer overflow causes a return value of -1.
 *
 *       This is useful where the client code declares memory like:
 *               char XXBuf[MaxWords][WordBufSize+1]
 *       and calls splitLineByMultiSpace as:
 *               int NWords = splitLineByMultiSpace(
 *                       XXSrc,
 *                       sizeof(XXBuf)/sizeof(XXBuf[0]),
 *                       sizeof(XXBuf[0]),
 *                       XXBuf);
 *       and can then access the individual strings as:
 *                       XXBuf[i]
 */

int splitLineByMultiSpace(
        const char* Src,
        int MaxWords, 
        int WordBufSize,
        char *Dst /* logically 2D but physically flat (1D) allocation */)
{
    int NWords = 0;
    memset(Dst, 0, MaxWords*WordBufSize);       /* for null termination etc.*/

    int SrcLen = strlen(Src);
    if(SrcLen == 0) 
        goto Fail;

    int IsNewWord = 0;
    int WordStartPos = 0;
    int n;
    for (n=0; n<SrcLen; n++) {
        if (NWords >= MaxWords) goto Fail;
        int WordLen = 0;
        if(Src[n] == ' ' || Src[n] == '\n' || Src[n] == '\0') {
            if(IsNewWord) {
                WordLen = n - WordStartPos;
                if (WordLen >= WordBufSize) goto Fail;
                /* leaves null terminator */
                memcpy(Dst + NWords*WordBufSize, Src+WordStartPos, WordLen);
                NWords++;
                IsNewWord = 0;
            }
        } else {
            if(Src[n] == '#') goto Fail; /* comment line */
            if(!IsNewWord) {
                IsNewWord = 1;
                WordStartPos = n;
            }
        }
    }
    return NWords;
Fail:
    return -1;
}
