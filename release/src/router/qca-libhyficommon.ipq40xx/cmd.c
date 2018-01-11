/*
 * Copyright (c) 2010 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/* cmd -- command string parsing, with menu structure.
 *                              Author: Ted Merrill, June 2008
 *
 * See cmd.txt for detailed documentation.
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>

#include <dbg.h>
#include <cmd.h>

#if 0   /* auto-extract only */
/*-D- Required includes
 */
#include <stdio.h>
#include <stdarg.h>
/*--------------------------------------------------*/
#endif

/*=======================================================================*/
/*============== Compile Time Configuration =============================*/
/*=======================================================================*/

#if 0   /* auto-extract only */
/*-D- CMD_STDOUT_REDIRECT_FEATURE -- nonzero if stdout file descriptor
 * can be switched during use, allowing printf to be directed to
 * the session issuing the command.
 */
#define CMD_STDOUT_REDIRECT_FEATURE() 1
/*----------------------------------------------------------------------*/
#endif  /* auto-extract only */

/*=======================================================================*/
/*============== Global State ===========================================*/
/*=======================================================================*/

struct {
    int IsInit;
    struct dbgModule *DebugModule;  /* debug messages for this module */
} cmdS;

/*-F- cmdInit -- optionally call to ensure early initialization
 * of cmd module.
 */
void cmdInit(void)
{
    if (cmdS.IsInit)
        return;
    cmdS.DebugModule = dbgModuleFind("cmd");
    cmdS.IsInit = 1;
    fflush(stdout);
    setlinebuf(stdout);
    return;
}

/* cmdDebug -- debug message printing for "cmd".
 * Not to be confused with "cmdf" which prints output to a cmd menu
 * user via the cmd context.
 */
#define cmdDebug(...) dbgf(cmdS.DebugModule, __VA_ARGS__)

/*=======================================================================*/
/*============== Parsing Utilities ======================================*/
/*=======================================================================*/

/*-F- isWordEnd -- return nonzero if the character is '\n','\0' or beacon character.
 */

int isWordEnd(char ch, char cbeacon)
{
	if (ch=='\n' || ch=='\0' || ch==cbeacon)
	    return 1;
	return 0;
}

/*-F- isValidPhoneNumber -- return nonzero if the string is valid phone number.
 * the valid phone number including the charachter '0-9', ' ', '*', '-', '#',
 * '(', ')'.
 */
int isValidPhoneNumber(const char *S)
{
    while (S&&!isWordEnd(*S, '/'))
    {
	if (*S>'9' || *S<'0')
	{
	    if (*S!=' ' && *S!='*' && *S!='-' && *S!='#' && *S!='(' && *S!=')')
		return 0;
	}

	S++;
    }
    return 1;
}

/*-F- cmdWordLenWithBeacon -- return the length of string S with terminated beacon*/
int cmdWordLenWithBeacon(const char *S, char cbeacon)
{
	int len=0;
	while (S&&!isWordEnd(*S, cbeacon)) S++,len++;

	return len;
}

/*-F- cmdWordNextWithBeacon -- return the next string which these strings separated
 *by the special beacon character.
 */
const char* cmdWordNextWithBeacon(const char *S, char cbeacon)
{
	if (S==NULL)
	    return S;

	while (!isWordEnd(*S, cbeacon)) S++;

	if (*S == cbeacon)
	    S++;

	return S;
}


/*-F- cmdIsWord -- returns nonzero if S begins with a word.
 * A word is non-whitespace.
 */
int cmdIsWord(const char *S)
{
    return (S && isgraph(*S));
}

/*-F- cmdWordLen -- returns length of word at begin of S.
 * A word is non-whitespace.
 * If S begins with whitespace, returns 0.
 */
int cmdWordLen(
        const char *S)  /* NOT NULL */
{
    int Len = 0;
    while (isgraph(*S)) S++, Len++;
    return Len;
}

/*-F- cmdWordDigits -- returns nonzero if word is made of digits
 * A word is non-whitespace; may be terminated by whitespace or null char.
 * Returns 1 if S is made of digits
 * Returns 0 otherwise
 */
int cmdWordDigits(const char *S)
{
    if (S == NULL) return 0;
    if (!isgraph(*S)) return 0;

    while (isdigit(*S) && isgraph(*S) ) S++;

    if (isgraph(*S)) return 0;

    return 1;   /* all characters are digits */
}

/*-F- cmdWordEq -- returns nonzero if two words are equal.
 * A word is non-whitespace; may be terminated by whitespace or null char.
 * Returns 0 if S1 and S2 are not both at words; a non-word can never
 * equal anything else.
 * Returns 0 if S1 or S2 is NULL.
 */
int cmdWordEq(const char *S1, const char *S2)
{
    if (S1 == NULL || S2 == NULL) return 0;
    if (!isgraph(*S1)) return 0;
    if (!isgraph(*S2)) return 0;
    while (isgraph(*S1) && isgraph(*S2) && *S1 == *S2) S1++, S2++;
    if (isgraph(*S1)) return 0;
    if (isgraph(*S2)) return 0;
    return 1;   /* matched words to end of each */
}

/*-F- cmdWordFirst -- skip leading whitespace
 * Returns NULL if S is NULL.
 */
const char *cmdWordFirst(const char *S)
{
    if (S == NULL) return NULL;
    while (*S && !isgraph(*S)) S++;
    return S;
}


/*-F- cmdWordNext -- skip word and following whitespace.
 * S should be sitting at a word; if it is sitting at whitespace,
 * we just skip the whitespace in an attempt to do something useful
 * in a broken situation.
 * A word is non-whitespace.
 * Returns NULL if S is NULL.
 */
const char *cmdWordNext(const char *S)
{
    if (S == NULL)
        return NULL;
    while (isgraph(*S)) S++;
    while (*S && !isgraph(*S)) S++;
    return S;
}

/*-F- cmdWordNth -- returns "" or pointer to Nth word (0 based).
*       Skips initial whitespace.
*       Words are defined as for cmdIsWord().
*       Returns "" if S is NULL or if there is no Nth word.
*       If return value points to empty string, there is no Nth word.
*/
const char *cmdWordNth(
        const char *S,
        int N)  /* which word to find */
{
    int I;
    if (S == NULL)
        return "";
    /* Skip initial whitespace if any */
    // S = cmdWordFirst(S);
    while (*S && !isgraph(*S)) S++;

    /* Skip First N words and following whitespace */
    for (I = 0; I < N; I++) {
        // S = cmdWordNext(S);
        while (isgraph(*S)) S++;
        while (*S && !isgraph(*S)) S++;
    }
    /* Return pointer to Nth word if there is one, or end of string */
    return S;
}


/*-F- cmdWordCopy -- copy up to Size-1 chars of the first word from S
*       into Buf, followed by a NUL char for termination.
*       No more than the word size is copied; if S does not begin with
*       a word then the word size is zero.
*       A NUL char is always put at the end except where Size is zero.
*
*       Returns nonzero if Size <= 0 or the word was truncated.
*/
int cmdWordCopy(
        char *Buf,      /* output buffer; not NULL */
        const char *S,  /* input or NULL */
        int Size)    /* bytes in Buf that can be modified */
{
    int Len = 0;
    int NCopy;
    int I;

    if (Size <= 0)
        return 1;
    if (S != NULL)
        Len = cmdWordLen(S);
    NCopy = Len;
    if (NCopy >= Size)
        NCopy = Size-1;
    for (I = 0; I < NCopy; I++) {
        Buf[I] = S[I];
    }
    Buf[I] = 0; /* NUL termination */
    return (NCopy != Len);
}


/*-F- cmdWordDup -- allocate and return a null-terminated copy of a word.
 * A word is non-whitespace.
 * Returns NULL on malloc failure.
 */
char *cmdWordDup(const char *S) {
    int Len = cmdWordLen(S);
    char *Copy = malloc(Len+1);
    if (Copy == NULL)
        return NULL;
    if (Len)
        memcpy(Copy, S, Len);
    Copy[Len] = 0;
    return Copy;
}

/*-F- cmdLineDup -- allocate and return a newline- or null-terminated copy
 * of line, minus trailing whitespace.
 * Returns NULL on malloc failure.
 */
char *cmdLineDup(const char *S) {
    int Len;
    char *Copy;
    if (!S)
        S = "";
    for (Len = 0; S[Len] != 0 && S[Len] != '\n'; Len++) {;}
    Copy = malloc(Len+1);
    if (Copy == NULL) return NULL;
    memcpy(Copy, S, Len);
    Copy[Len] = 0;
    /* Trim trailing whitespace */
    while (Len > 0 && !isgraph(Copy[Len-1])) Copy[--Len] = 0;
    return Copy;
}


/* TODO: add integer parsing fncs w/ full error checking */


/*-F- cmdDupEncodeHex -- encode a buffer as a string of hex characters.
*       (Big endian representation).
*       The returned value (malloc'd memory which must be freed!)
*       will be null terminated string of twice the length as the input.
*       Returns NULL on malloc failure.
*/
char *cmdDupEncodeHex(const void *Buf, int NBytes)
{
    char *Copy;
    const unsigned char *Src = Buf;
    int I;
    if (!Src) {
        NBytes = 0;
    }
    Copy = malloc(2/*for hex*/ * NBytes + 1/*for null*/);
    if (!Copy)
        return NULL;
    for (I = 0; I < NBytes; I++) {
        int C;
        C = (Src[I] >> 4) & 0xf;
        if (C < 10)
            C += '0';
        else
            C += ('A' - 10);
        Copy[2*I+0] = C;
        C = Src[I] & 0xf;
        if (C < 10)
            C += '0';
        else
            C += ('A' - 10);
        Copy[2*I+1] = C;
    }
    Copy[2*I] = 0;
    return Copy;
}

/*-F- cmdDupEscapeHex -- encode a string as a string of hex characters.
*       (Big endian representation).
*       The returned value (malloc'd memory which must be freed!)
*       will be null terminated string of twice the length as the input.
*       Returns NULL on malloc failure.
*/
char *cmdDupEscapeHex(const char *S)
{
    if (!S)
        S = "";
    return cmdDupEncodeHex(S, strlen(S));
}

/*-F- cmdDupUnescapeHex -- decode hex encoding into string.
*       (Big endian representation).
*       The returned value (malloc'd memory which must be freed!)
*       will be null terminated string of half the length as the input.
*       Returns NULL on malloc failure.
*
*       Stops at first conversion error!
*/
char *cmdDupUnescapeHex(const char *S)
{
    char *Copy;
    int Len;
    int I;
    for (Len = 0; ; Len++) {
        int C = S[Len];
        if (C >= '0' && C <= '9') ;
        else
        if (C >= 'a' && C <= 'f') ;
        else
        if (C >= 'A' && C <= 'F') ;
        else
            break;
    }
    Len /= 2;
    Copy = malloc(Len+1/*for null*/);
    if(!Copy)
        return NULL;
    for (I = 0; I < Len; I++) {
        int CLow;
        int CHigh;
        CHigh = S[2*I+0];
        if (CHigh >= '0' && CHigh <= '9')
            CHigh -= '0';
        else
        if (CHigh >= 'a' && CHigh <= 'f')
            CHigh = 10 + (CHigh-'a');
        else
        if (CHigh >= 'A' && CHigh <= 'F')
            CHigh = 10 + (CHigh-'A');
        else
            break;
        CLow = S[2*I+1];
        if (CLow >= '0' && CLow <= '9')
            CLow -= '0';
        else
        if (CLow >= 'a' && CLow <= 'f')
            CLow = 10 + (CLow-'a');
        else
        if (CLow >= 'A' && CLow <= 'F')
            CLow = 10 + (CLow-'A');
        else
            break;
        Copy[I] = (CHigh << 4) | CLow;
    }
    Copy[I] = 0;        /* null termination */
    return Copy;
}


/*-F- cmdDupEscapeC -- allocate a copy of string w/ character escape.
 *      Follows "C" rules for escaping:
 *              graphical and spaces unescaped except for  \
 *              \ --> \\
 *              other --> \ooo where "o" is octal digit
 *      If S is NULL, "" is implied.
 *      Returns NULL on malloc failure.
 */
char *cmdDupEscapeC(const char *S)
{
    char *Copy;
    int From;
    int To;
    if (!S)
        S = "";
    Copy = malloc(4*strlen(S)+1);
    if (!Copy)
        return NULL;
    for (From = 0, To = 0; S[From]; ) {
        int Ch = S[From++];
        if (Ch == 0) break;
        if (Ch == '\\') {
            Copy[To++] = Ch;
            Copy[To++] = Ch;
        } else
        if (isgraph(Ch) || Ch == ' ') {
            Copy[To++] = Ch;
        } else {
            sprintf(Copy+To, "\\%03o", Ch);
            To += 4;
        }
    }
    Copy[To] = 0;
    return Copy;
}

/*-F- cmdDupUnescapeC -- allocate a copy w/ reverse translation
 *      compared with cmdDupEscapeC.
 *
 *      If S is NULL, "" is implied.
 *      Returns NULL on malloc failure.
 */
char *cmdDupUnescapeC(const char *S)
{
    int From;
    int To;
    char *Copy;

    if (!S) S = "";
    Copy = strdup(S);
    if (!Copy)
        return NULL;
    for (From = 0, To = 0; Copy[From]; ) {
        int Ch = Copy[From++];
        if (Ch == '\\') {
            if (Copy[From] == 0)
                break;
            if (Copy[From] == '\\') {
                From++;
                Copy[To++] = '\\';      /* pass just one backslash through*/
            } else
            if (Copy[From] >= '0' && Copy[From] <= '7') {
                /* translate backslash and up to 3 octal digits
                 * as char w/ numerical value.
                 */
                int Sum = (Copy[From++] - '0');
                if (Copy[From] >= '0' && Copy[From] <= '7') {
                    Sum = Sum << 3;
                    Sum += (Copy[From++] - '0');
                    if (Copy[From] >= '0' && Copy[From] <= '7') {
                        Sum = Sum << 3;
                        Sum += (Copy[From++] - '0');
                    }
                }
                Copy[To++] = Sum;
            } else {
                Copy[To++] = Ch;        /* pass the backslash through */
            }
        } else {
            Copy[To++] = Ch;    /* pass everything else through */
        }
    }
    Copy[To] = 0;
    return Copy;
}


/*-D- CMD_ESCAPE_XML_CHAR_BUF_SIZE -- minimal size buffer for cmdEscapeXmlChar
 */
#define CMD_ESCAPE_XML_CHAR_BUF_SIZE 8
/*---------------------------------------------------*/

/*-F- cmdEscapeXmlChar -- translate one utf-8 byte into xml sequence.
 *      Follows XML rules for escaping (note we assume utf-8 encoding):
 *              code 0x00 (nul character) terminates string
 *              Control characters (codes 0x01-0x1F and 0x7F) are encoded as
 *                      &#decimal;
 *              where decimal is decimal value of control character.
 *              The following are specially translated:
 *                      "       &quot;
 *                      '       &apos;
 *                      &       &amp;
 *                      <       &lt;
 *                      >       &gt;
 *              Codes 0x80-0xFE are assumed to be parts of utf-8
 *              multi-character sequences.
 *              utf-8 multi-character sequences consist entirely of
 *              characters in the range 0x80-0xFD.
 *              There are some multi-character sequences that follow this
 *              rule but are not legal; we pass these through anyway.
 *              0xFE and 0xFF are illegal in utf8; we treat them as
 *              end of string.
 *      Returns number of output characters (0 at end of string),
 *      and puts output characters plus a terminating nul char into *Buf.
 */
int cmdEscapeXmlChar(
        char *Buf,     /* size at least CMD_ESCAPE_XML_CHAR_BUF_SIZE */
        unsigned char C)
{
    switch (C) {
        case 0x00: case 0xfe: case 0xff:
            *Buf = 0;   /* terminate */
        return 0;
        case 0x01: case 0x02: case 0x03: case 0x04:
        case 0x05: case 0x06: case 0x07: case 0x08:
        case 0x09: case 0x0a: case 0x0b: case 0x0c:
        case 0x0d: case 0x0e: case 0x0f: case 0x10:
        case 0x11: case 0x12: case 0x13: case 0x14:
        case 0x15: case 0x16: case 0x17: case 0x18:
        case 0x19: case 0x1a: case 0x1b: case 0x1c:
        case 0x1d: case 0x1e: case 0x1f: case 0x7f:
            sprintf(Buf, "&#%d;", C);
        return strlen(Buf);
        case '&':
            strcpy(Buf, "&amp;");
        return 5;
        case '"':
            strcpy(Buf, "&quot;");
        return 6;
        case '\'':
            strcpy(Buf, "&apos;");
        return 6;
        case '<':
            strcpy(Buf, "&lt;");
        return 4;
        case '>':
            strcpy(Buf, "&gt;");
        return 4;
        default:
            *Buf++ = C;
            *Buf = 0;
        return 1;
    }
}

/*-F- cmdUnescapeXmlChar -- reverse translation of one char.
 *      Returns number of >consumed< bytes (0 at end of string),
 *      and puts output characters plus a terminating nul char into *Buf.
 */
int cmdUnescapeXmlChar(
        char *Buf,      /* at least 2 bytes big */
        const char *S)  /* input */
{
    int C;
    int NBytes = 0;
    if (*S == 0) {
        *Buf = 0;
        return 0;
    }
    if (*S == '&') {
        if (S[1] == '#') {
            if (isdigit(S[2])) {
                NBytes = 2;
                C = 0;
                while (isdigit(S[NBytes])) {
                    C = 10*C + S[NBytes] - '0';
                    NBytes++;
                }
                if (S[NBytes] != ';')
                    goto Default;
                NBytes++;
                *Buf++ = C;
                *Buf = 0;
                return NBytes;
            }
            goto Default;
        }
        if (!strncmp(S, "&quot;", 6)) {
            *Buf++ = '"';
            *Buf = 0;
            return 6;
        }
        if (!strncmp(S, "&apos;", 6)) {
            *Buf++ = '\'';
            *Buf = 0;
            return 6;
        }
        if (!strncmp(S, "&amp;", 5)) {
            *Buf++ = '&';
            *Buf = 0;
            return 5;
        }
        if (!strncmp(S, "&lt;", 4)) {
            *Buf++ = '<';
            *Buf = 0;
            return 4;
        }
        if (!strncmp(S, "&gt;", 4)) {
            *Buf++ = '>';
            *Buf = 0;
            return 4;
        }
        /* fall through to default */
    }
    Default:
    *Buf++ = *S;
    *Buf = 0;
    return 1;
}


/*-F- cmdEscapeXmlLength -- pre-compute length of escaped xml string.
 * Returns 0 if S is NULL.
 */
int cmdEscapeXmlLength(
        const char *S)
{
    char Buf[CMD_ESCAPE_XML_CHAR_BUF_SIZE];
    int XLen;
    int Sum = 0;
    if (S)
    do {
        XLen = cmdEscapeXmlChar(Buf, *S++);
        Sum += XLen;
    } while (XLen > 0);
    return Sum;
}


/*-F- cmdUnescapeXmlLength -- pre-compute length of unescaped xml string.
 * Returns 0 if S is NULL.
 */
int cmdUnescapeXmlLength(
        const char *S)
{
    //const char *SStart = S;
    char Buf[2];
    int XLen,RLen= 0;
    if (S)
    do {
        XLen = cmdUnescapeXmlChar(Buf, S);
        S += XLen;
		if(XLen)RLen++;
    } while (XLen > 0);
    return RLen;
}




/*-F- cmdDupEscapeXml -- allocate a copy of string w/ character escape.
 *      If S is NULL, "" is implied.
 *      Returns NULL on malloc failure.
 */
char *cmdDupEscapeXml(const char *S)
{
    int CopySize;
    char *Copy;
    int From;
    int To;
    int XLen;

    if (!S)
        S = "";
    CopySize = cmdEscapeXmlLength(S);
    Copy = malloc(CopySize+1);
    if (!Copy)
        return NULL;
    From = 0; To = 0;
    do {
        XLen = cmdEscapeXmlChar(Copy+To, S[From++]);
        To += XLen;
    } while (XLen > 0);
    return Copy;
}

/*-F- cmdDupUnescapeXml -- allocate a copy w/ reverse translation
 *      compared with cmdDupEscapeXml.
 *
 *      If S is NULL, "" is implied.
 *      Returns NULL on malloc failure.
 */
char *cmdDupUnescapeXml(const char *S)
{
    int CopySize;
    char *Copy;
    int From;
    int To;
    int XLen;

    if (!S) S = "";
    CopySize = cmdUnescapeXmlLength(S);
    Copy = malloc(CopySize+1);
    if (!Copy)
        return NULL;
    From = 0; To = 0;

    do {
        XLen = cmdUnescapeXmlChar(Copy+To++, S+From);
        From += XLen;
    } while (XLen > 0);
    return Copy;
}



/*=======================================================================*/
/*============== Menu/Context Definition ================================*/
/*=======================================================================*/

#if 0   /* auto-extract only */
/*-D- cmdMenuItem -- matches a callback function to a command name.
 */
struct cmdContext;
struct cmdMenuItem {
    const char *CommandName;            /* for match to first word */
    /* Caution: command handler callback function MUST not sleep!
     */
    void (*CommandHandler)(
            struct cmdContext *Context, /* As passed down */
            const char *Cmd); /* command string, excludes command name */
    /* Menu must be a menu if used with CommandHandler == cmdMenu
     * or a proxy thereof else it can be used for anything else
     * (it's value may be obtained using cmdItemDataGet()).
     */
    struct cmdMenuItem *Menu;        /* NULL or Menu to use or private use */
    const char * const *HelpMessage;   /* printed from help command */
};
/*----------------------------------------------------------------*/
#endif  /* auto-extract only */

/* cmdEnv -- per context application data.
*       This is a feature of use for specially written applications.
*/
struct cmdEnv {
    /* Circular linked list of environmental value nodes */
    struct cmdEnv *Next;
    struct cmdEnv *Prev;
    const void *Key;          /* unique key to find this env. variable */
    void *Reserved1;    /* to force best alignment of data */
    /* the data follows (caution, might have alignment issue) */
};

/*
 * cmdContext -- operating environment
 * One of these is used per level of menu, linked together.
 */
struct cmdContext {
    struct cmdContext *Parent;
    struct cmdContext *Child;
    char *CommandName;          /* command name that got us here */
    const struct cmdMenuItem *Item;   /* item that got us here (we don't own)*/
    const struct cmdMenuItem *Menu;   /* menu we work off of (we don't own)*/
    void (*CommandHandler)(     /* command handler we're using */
            struct cmdContext *Context, /* As passed down */
            const char *Cmd); /* command string, excludes command name */
    int Pinned;         /* temporary keep context around */
    int Interactive;            /* if we should stick at this context */
    int AutoPrompt;     /* if we should do prompt after every command */
    /* Optional PromptHandler should do a cmdf(Context, .....) */
    void (*PromptHandler)(struct cmdContext *Context);
    int InputDirty;     /* handle holding buffer overflow */
    int Quit;           /* nonzero to force exit from context */
    FILE *OutF;         /* were to cmdf/dbgHere stuff to (NULL for stdout) */
    int OutFd;          /* where to printf to (0 or -1 to disable) */
    struct dbgOutput *DebugFork;        /* controls copying debug messages to shell */
    struct cmdEnv *Env;  /* NULL or pt to ring of per-context appl. data */
    void (*ExitHandler)(     /* optional, called on context destroy */
            struct cmdContext *Context);  /* As passed down */
};


/*
 * cmdReferenceContext -- copied for new session.
 */
/*private*/ struct cmdContext cmdReferenceContext;

/*=======================================================================*/
/*============== Context Management =====================================*/
/*=======================================================================*/

/*-F- cmdContextCreate -- allocate a new independent context.
 * The returned context is zeroed, and then intialized from the
 * reference context, if one is provided, else from the default
 * reference context.
 * The context may be used as is to use the main menu (or menu assigned
 * to the reference context);
 * otherwise, call cmdContextMenuSet() to assign a menu for it's use.
 * Returns NULL on malloc failure.
 *
 * Free up memory with cmdContextDestroy (not with free()).
 *
 * Changes to the context will not effect the "parent context".
 */
struct cmdContext *cmdContextCreate(
        struct cmdContext *ReferenceContext)       /* or NULL */
{
    struct cmdContext *Context = malloc(sizeof(*Context));
    if (Context == NULL)
        return NULL;
    if (!ReferenceContext)
        ReferenceContext = &cmdReferenceContext;
    *Context = *ReferenceContext;       /* set defaults */
    return Context;
}

/*-F- cmdContextDestroy -- deallocate a context safely.
 */
void cmdContextDestroy(struct cmdContext *Context)
{
    struct cmdEnv *Env;
    if (!Context)
        return;
    /* recursively destroy child contexts */
    if (Context->Child) {
        cmdContextDestroy(Context->Child);
    }
    /* Call ExitHandler if any, before further destruction */
    if (Context->ExitHandler)
        (*Context->ExitHandler)(Context);
    /* unlink from parent */
    if (Context->Parent) {
        Context->Parent->Child = NULL;
    }
    if (Context->DebugFork)
        dbgOutForkCancel(Context->DebugFork);
    Context->DebugFork = NULL;
    free(Context->CommandName);
    Context->CommandName = NULL;
    while ((Env = Context->Env) != NULL) {
        if (Env->Next == Env)
            Context->Env = NULL;
        else Context->Env = Env->Next;
        Env->Next->Prev = Env->Prev;
        Env->Prev->Next = Env->Next;
        free(Env);
    }
    free(Context);
    return;
}

/*-F- cmdContextMenuSet -- assign menu array to be used for context.
 * The menu array should be terminated by a zeroed item.
 * Note that the menu array must be nonvolatile for the time
 * that the context is used, since it is used by pointer (not copy).
 */
void cmdContextMenuSet(
        struct cmdContext *Context,     /* NULL to set defaults */
        struct cmdMenuItem *Menu)
{
    if (Context == NULL) Context = &cmdReferenceContext;
    Context->Menu = Menu;
    return;
}

/*-F- cmdContextCommandNameSet -- assign command name assoc. w/ context.
 * The name is terminated by whitespace or null char, and is copied.
 */
void cmdContextCommandNameSet(
        struct cmdContext *Context,     /* NULL to set defaults */
        const char *CommandName)
{
    if (Context == NULL) Context = &cmdReferenceContext;
    free(Context->CommandName);
    Context->CommandName = cmdWordDup(CommandName);
    return;
}

/*-F- cmdContextOutFdSet -- set fd for printfs.
 * The fd is NOT ever destroyed by cmd; it belongs to the caller.
 * For efficiency reasons, this is used only to the top level
 * context; it is used to temporarily redirect output to the shell
 * that is currently executing a command.
 */
void cmdContextOutFdSet(
        struct cmdContext *Context,     /* NULL to set defaults */
        int OutFd)              /* or 0 or -1 to disable */
{
    if (Context == NULL) Context = &cmdReferenceContext;
    Context->OutFd = OutFd;
    return;
}


/*-F- cmdContextOutFileSet -- assign FILE* to print stuff to.
 * The FILE is NOT ever destroyed by cmd; it belongs to the caller.
 *
 * Cancels any previous cmdDebugHere() if done at same context.
 */
void cmdContextOutFileSet(
        struct cmdContext *Context,     /* NULL to set defaults */
        FILE *OutF)     /* output file queue, or NULL for stdout */
{
    if (Context == NULL) Context = &cmdReferenceContext;
    if (Context->DebugFork)
        dbgOutForkCancel(Context->DebugFork);       /* to be sure */
    Context->DebugFork = NULL;
    Context->OutF = OutF;
    return;
}


/*-F- cmdContextOutFileGet -- returns FILE* to print stuff to.
 * This allows use of e.g. fprintf etc.
 */
FILE *cmdContextOutFileGet(
        struct cmdContext *Context)     /* NULL for defaults */
{
    if (Context == NULL) Context = &cmdReferenceContext;
    if (Context->OutF == NULL) return stdout;
    return Context->OutF;
}


/*-F- cmdContextAutoPromptSet -- (un)set mode to print prompt after command.
 *      Will print a prompt immediately...
 *      be sure to set out file first, if needed.
 */
void cmdContextAutoPromptSet(
        struct cmdContext *Context,     /* NULL to set defaults */
        int Set)
{
    int OldSet;
    if (Context == NULL) Context = &cmdReferenceContext;
    OldSet = Context->AutoPrompt;
    Context->AutoPrompt = Set;
    if (Set && !OldSet) {
        cmdAutoPrompt(Context); /* print a prompt now */
    }
    return;
}

/*-F- cmdContextExitHandlerSet -- set handler called just before
*       context destruction.
*       (Any child context have already been destroyed).
*/
void cmdContextExitHandlerSet(
        struct cmdContext *Context,     /* NULL to set defaults */
        void (*ExitHandler)(struct cmdContext *Context))
{
    if (Context == NULL) Context = &cmdReferenceContext;
    Context->ExitHandler = ExitHandler;
    return;
}

/*-F- cmdContextPromptHandlerSet -- set function to print prompt.
*       The PromptHandler is called only when a prompt is needed.
*       The PromptHandler should do a cmdf(Context, ....)
*       to print the prompt.
*/
void cmdContextPromptHandlerSet(
        struct cmdContext *Context,     /* NULL to set defaults */
        void (*PromptHandler)(struct cmdContext *Context))
{
    Context->PromptHandler = PromptHandler;
    return;
}

/*-F- cmdContextEnvDestroy -- remove environmental variable in given context
*/
void cmdContextEnvDestroy(
        struct cmdContext *Context,     /* NOT NULL */
        void *Key)              /* identify env. var */
{
    struct cmdEnv *Env;
    if (Context == NULL)
        return;
    while (Context->Parent)
        Context = Context->Parent;      /* find root context */
    Env = Context->Env;
    if (Env == NULL)
        return;
    do {
        if (Env->Key == Key)
            goto Found;
    } while ((Env = Env->Next) != Context->Env);
    /* not found */
    return;
    Found:
    if (Env == Context->Env) {
        if (Env->Next == Env) {
            Context->Env = NULL;
        } else {
            Context->Env = Env->Next;
        }
    }
    Env->Next->Prev = Env->Prev;
    Env->Prev->Next = Env->Next;
    free(Env);
    return;
}


/*-F- cmdContextEnvGet -- get environmental variable in given session.
*       The session is the (grand)parent context of Context.
*       The Key is a unique pointer value used only to name the variable;
*       what the pointer points to is irrelevent.
*       The environmental variable is a data structure that is allocated
*       and zeroed if not previously existing in the context.
*       The application may write the environment data as it wishes.
*
*       Returns NULL on error.
*/
void *cmdContextEnvGet(
        struct cmdContext *Context,     /* NOT NULL */
        const void *Key,              /* identify env. var */
        unsigned Size)  /* MUST be passed same every time */
{
    struct cmdEnv *Env;
    if (Context == NULL)
        return NULL;
    while (Context->Parent)
        Context = Context->Parent;      /* find root context */
    Env = Context->Env;
    if (Env == NULL)
        goto Add;
    do {
        if (Env->Key == Key)
            goto GotIt;
    } while ((Env = Env->Next) != Context->Env);
    /* not found */
    Add:
    Env = calloc(sizeof(*Env) + Size, 1);
    if (!Env)
        return NULL;
    Env->Key = Key;
    if (Context->Env) {
        /* add to end of list */
        Env->Next = Context->Env;
        Env->Prev = Context->Env->Prev;
        Env->Next->Prev = Env;
        Env->Prev->Next = Env;
    } else {
        /* new list */
        Env->Next = Env;
        Env->Prev = Env;
        Context->Env = Env;
    }
    GotIt:
    return (void *)(Env+1);     /* memory at end of node */
}




/*=======================================================================*/
/*============== Printing ===============================================*/
/*=======================================================================*/

/*-F- cmdf -- fprintf to correct place.
 * See cmdContextOutFileGet() for another alternative.
 */
void cmdf(
        struct cmdContext *Context,   /* NULL for default reference context */
        const char *Format,
        ...                     /* printf-like */
        )
{
    /* TODO: add gcc warning directive for printf like args */
    va_list ArgP;
    va_start(ArgP, Format);
    cmdv(Context, Format, ArgP);
    va_end(ArgP);
}


/*-F- cmdv -- vfprintf to correct place.
 * See cmdContextOutFileGet() for another alternative.
 */
void cmdv(
        struct cmdContext *Context,   /* NULL for default reference context */
        const char *Format,
        va_list ArgP
        )
{
    FILE *F;
    if (Context == NULL)
        Context = &cmdReferenceContext;
    F = Context->OutF;
    if (F == NULL)
        F = stdout;
    vfprintf(F, Format, ArgP);
    fflush(F);
}


/*=======================================================================*/
/*============== Builtin Handlers =======================================*/
/*=======================================================================*/

/*
 * cmdItemHelp -- shared code to print one item
 * Not for short help of multiple items.
 */
static void cmdHelpItem(
        struct cmdContext *Context, /* As passed down */
        const struct cmdMenuItem *Item,
        int Size)       /* 0=short, 1=medium, 2=long */
{
    int Line;
    if (!Item->HelpMessage || !Item->HelpMessage[0]) {
            cmdf(Context, "%s -- (no help message)\n", Item->CommandName);
    } else switch(Size) {
        case 0:     /* short -- do medium instead */
        case 1:     /* medium */
            /* The following assumes that the help message first line
             * begins with the (correct) command name.
             * This is not necessarily the case, but on the other hand
             * a typical first line would look like:
             *          name {arg1} [arg2] -- does something
             * and it is awkward to omit the name from the help message.
             * So we leave the name out of here.
             */
            cmdf(Context, "%s\n", Item->HelpMessage[0]);
        break;
        default:    /* long */
            cmdf(Context, "------ Help for %s -----\n", Item->CommandName);
            for (Line = 0; Item->HelpMessage[Line]; Line++ ) {
                cmdf(Context, "%s\n", Item->HelpMessage[Line]);
            }
            cmdf(Context, "------------------------\n");
        break;
     }
}

/*
 * cmdHelpShared -- shared code for very short, short/medium, long help
 */
static void cmdHelpShared(
        struct cmdContext *Context, /* As passed down */
        const char *Cmd,  /* command string excludes command name */
        int Size)       /* 0=very short, 1=short/medium, 2=long */
{
    const struct cmdMenuItem *Menu = Context->Parent->Menu;
    int Idx = 0;
    int Col = 0;

    if (Menu == NULL || Cmd == NULL) {
        return;
    }
    Cmd = cmdWordFirst(Cmd);
    if (Cmd && *Cmd) {
        while (Menu->CommandName != NULL) {
            if (cmdWordEq(Menu->CommandName, Cmd)) {
                break;
            }
            Menu++;
        }
        if (Menu->CommandName == NULL) {
            cmdf(Context, "No command: %.*s\n",
                cmdWordLen(Cmd), Cmd);
            return;
        }
        cmdHelpItem(Context, Menu, Size);
        return;
    }
    /* show all */
    switch (Size) {
        case 0: /* short */
            for (; Menu->CommandName != NULL; Menu++) {
                if (Idx && (Idx%4) == 0) {
                    cmdf(Context, "\n");
                    Col = 0;
                }
                cmdf(Context, "%-18s ", Menu->CommandName);
                Col += 19;
                Idx++;
            }
            if (Col) cmdf(Context, "\n");
        break;
        default:        /* medium, long */
            for (; Menu->CommandName != NULL; Menu++) {
                cmdHelpItem(Context, Menu, Size);
            }
        break;
    }
}

/*-G- cmdHelpShortHelp -- help for short help command
 */
const char *cmdHelpShortHelp[] = {
    "h [cmd] -- short help (first line of each help message).",
    NULL
};


/*-F- cmdHelpShort -- short help command
 * Used by CMD_MENU_STANDARD_STUFF() which should be at top of your menu.
 */
void cmdHelpShort(
        struct cmdContext *Context, /* As passed down */
        const char *Cmd)  /* command string excludes command name */
{
    cmdHelpShared(Context, Cmd, 1/*medium*/);
}


/*-G- cmdHelpLongHelp -- help for long help command
 * Used by CMD_MENU_STANDARD_STUFF() which should be at top of your menu.
 */
const char *cmdHelpLongHelp[] = {
    "help [cmd] -- long help.",
    "Displays full help message for each command.",
    NULL
};


/*-F- cmdHelpLong -- long help command
 */
void cmdHelpLong(
        struct cmdContext *Context, /* As passed down */
        const char *Cmd)  /* command string excludes command name */
{
    cmdHelpShared(Context, Cmd, 2/*long*/);
}

/*-G- cmdQuitHelp -- help for q command
 */
const char *cmdQuitHelp[] = {
    "q -- quit interactive menu",
    "Returns to previous interactive menu or may exit shell",
    NULL        /* terminator */
};


/*-F- cmdQuit -- q (quit) command
 * Any command handler can cause a quit from the menu that refers it
 * by calling cmdQuit(Context,NULL).
 */
void cmdQuit(
        struct cmdContext *Context, /* As passed down */
        const char *Cmd)  /* ignored... may be NULL */
{
    /* TODO: maybe this should find the interactive menu and quit it
     * Loop through contexts, setting Quit up through interactive one.
     */
    Context->Parent->Quit = 1;
}


/*-G- cmdExitHelp -- help for exit command
 */
const char *cmdExitHelp[] = {
    "exit [<status>] -- terminate server",
    "Default exit status is 0",
    NULL        /* terminator */
};


/*-F- cmdExit -- exit command
 * This causes the server to terminate.
 */
void cmdExit(
        struct cmdContext *Context, /* As passed down */
        const char *Cmd)  /* ignored... may be NULL */
{
    int ExitStatus = atol(Cmd);
    cmdf(Context, "Exit server!\n");
    cmdDebug(DBGINFO, "Exit server!");
    exit(ExitStatus);
}


/*-F- cmdNull -- a command that does nothing, in case you need it!
 */
void cmdNull(
        struct cmdContext *Context, /* As passed down */
        const char *Cmd)  /* ignored... may be NULL */
{
}

#if 0   /* auto-extract only */
/*-D- CMD_MENU_STANDARD_STUFF() -- put at top of most menus.
 * This provides commands for online help, and "q" command to quit menu.
 */
#define CMD_MENU_STANDARD_STUFF() \
    {"h", cmdHelpShort, NULL, cmdHelpShortHelp},        \
    {"help", cmdHelpLong, NULL, cmdHelpLongHelp},       \
    {"q", cmdQuit, NULL, cmdQuitHelp}
/*------------------------------------------------------------------*/
/*-D- CMD_MENU_END() -- put at bottom of most menus.
 * This terminates the menu!
 */
#define CMD_MENU_END()  {}
/*------------------------------------------------------------------*/
#endif  /* auto-extract only */


/*
 *  Copyright (c) 2010 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* cmdDbg -- dbg menu for cmd main menu.
 * This file is #included into cmd.c .
 */

const char * const cmdDbgHelpStatus[] = {
    "s -- print dbg status",
    "This includes level for all known modules",
    NULL
};

void cmdDbgStatus(
        struct cmdContext *Context, /* As passed down */
        const char *Cmd)
{
    dbgStatusPrint(cmdContextOutFileGet(Context));
}

const char * const cmdDbgHelpLevel[] = {
    "level [{<module>|all} [[=] {err|info|debug|dump}] -- print/change module debug level",
    "Using `all' instead of module name will modify level of all current",
    "and future modules.",
    "Instead of one of the named levels, a numeric level value may be used.",
    "The named levels are, in increasing order of verbosity: ",
    "    err -- important internal errors (not generally, external errors)",
    "    info -- important occasional events and external errors",
    "    debug -- messages useful for debugging particular module",
    "    dump -- even greater verbosity, e.g. packet dumps",
    NULL
};

void cmdDbgLevel(
        struct cmdContext *Context, /* As passed down */
        const char *Cmd)
{
    char *ModuleName = NULL;
    char *Line = NULL;
    if (cmdIsWord(Cmd)) {
        ModuleName = cmdWordDup(Cmd);
        if(!ModuleName)
        {
            cmdf(Context, "Malloc Failed for command.\n");
            return;
        }
        dbgLevelsPrint(cmdContextOutFileGet(Context), ModuleName);
        Line = cmdLineDup(Cmd); /* will be scribbled on */
        if (dbgModuleLevelFromBuf(Line)) {
            cmdf(Context, "Error parsing command.\n");
        }
    }
    dbgLevelsPrint(cmdContextOutFileGet(Context), ModuleName);
    free(ModuleName);
    free(Line);
}

const char * const cmdDbgHelpHere[] = {
    "here [-off] -- copy debug messages to current shell context",
    "With `-off' undoes the redirection",
    NULL
};

void cmdDbgHere(
        struct cmdContext *Context, /* As passed down */
        const char *Cmd)
{
    int Enable = 1;
    for ( ; cmdIsWord(Cmd); Cmd = cmdWordNext(Cmd)) {
        if (cmdWordEq(Cmd, "-off")) {
            Enable = 0;
        } else {
            cmdf(Context, "Invalid option");
            return;
        }
    }
    if (cmdDebugHere(Context, Enable)) {
        cmdf(Context, "Command failed\n");
    } else {
        if (Enable)
            cmdDebug(DBGINFO, "Forking debug messages to shell");
    }
}

const char *const cmdDbgHelpRedirect[] = {
    "redirect {[-a] <path>} | -off -- redirect dbg messages to file",
    "Options: ",
    "   -a -- append to file instead of overwriting. ",
    "   -off -- disable redirection, return to stdout. ",
    NULL
};

void cmdDbgRedirect(
        struct cmdContext *Context, /* As passed down */
        const char *Cmd)
{
    int Append = 0;
    char *Path = NULL;
    while (*Cmd == '-') {
        if (cmdWordEq(Cmd, "-a")) {
            Append = 1;
        }
        else if (cmdWordEq(Cmd, "-off")) {
            cmdDebug(DBGINFO, "Cancelling message redirection...");
            dbgFileRedirectCancel();
            cmdDebug(DBGINFO, "Cancelled message redirection.");
            return;
        } else {
            cmdf(Context, "Invalid option for `dbg redirect'");
            return;
        }
        Cmd = cmdWordNext(Cmd);
    }
    if (!cmdIsWord(Cmd)) {
        cmdf(Context, "Need a filepath to redirect to\n");
        return;
    }
    Path = cmdWordDup(Cmd);
    if (!Path)
        return;
    Cmd = cmdWordNext(Cmd);
    if (cmdIsWord(Cmd)) {
        cmdf(Context, "Too many args\n");
        free(Path);
        return;
    }
    if (dbgFileRedirect(Path, Append)) {
        cmdf(Context, "File open failure!\n");
    }
    free(Path);
}

struct cmdMenuItem cmdDbgMenu[] = {
    CMD_MENU_STANDARD_STUFF(),
    {"s", cmdDbgStatus, NULL, cmdDbgHelpStatus},
    {"level", cmdDbgLevel, NULL, cmdDbgHelpLevel},
    {"here", cmdDbgHere, NULL, cmdDbgHelpHere},
    {"redirect", cmdDbgRedirect, NULL, cmdDbgHelpRedirect},
    CMD_MENU_END()
};

const char * const cmdHelpDbgMenu[] = {
    "dbg -- debug printing control menu",
    NULL
};

/*=======================================================================*/
/*============== Default Main Menu ======================================*/
/*=======================================================================*/



#define CMD_MAIN_MENU_MAX 400
/*private*/ struct cmdMenuItem cmdMainMenu[CMD_MAIN_MENU_MAX+1] = {
    CMD_MENU_STANDARD_STUFF(),
    {"exit", cmdExit, NULL, cmdExitHelp},
    {"dbg", cmdMenu, cmdDbgMenu, cmdHelpDbgMenu},
    /* plus multiple empty entries that serve as termination,
     * and will be replaced as submenus are added
     * (except leaving one termination).
     */
};


/*=======================================================================*/
/*============== Menu Management / Handling =============================*/
/*=======================================================================*/

/*-F- cmdMenuAdd -- copy item to end of pre-zeroed menu buffer.
 * Returns nonzero on error (menu full).
 */
int cmdMenuAdd(
        struct cmdMenuItem *Menu,       /* menu buffer */
        int MaxItems,           /* size of buffer, allowing for null item */
        const struct cmdMenuItem *Item)
{
    int IItem;
    cmdInit();  /* to be sure */
    for (IItem = 0; IItem < MaxItems; IItem++) {
        if (Menu[IItem].CommandName == NULL) {
            memcpy(&Menu[IItem], Item, sizeof(*Item));
            return 0;
        }
    }
    cmdDebug(DBGERR, "ERROR: Menu full!");
    return 1;
}

/*-F- cmdMainMenuAdd -- copy item to main menu.
 * Returns nonzero on error (menu full).
 */
int cmdMainMenuAdd(const struct cmdMenuItem *Item)
{
    return cmdMenuAdd(cmdMainMenu, CMD_MAIN_MENU_MAX, Item);
}



/*-F- cmdMenu -- execute command string against arbitrary context.
 */
void cmdMenu(
        struct cmdContext *Context, /* must not be NULL */
        const char *S)
{
    const struct cmdMenuItem *Menu;
    const char *NextWord;

    if (S == NULL)
        return;
    if (Context == NULL)
        return;
    if (!Context->Menu) {
        Context->Menu = cmdMainMenu;
    }
    /* Advance to end of context list, to get current context */
    while (Context->Child) Context = Context->Child;
    S = cmdWordFirst(S);
    if (*S == 0) {
        int WasInteractive = Context->Interactive;
        /* end of command reached... stay in menu, interactively.
         * But we can't sleep (only single-threaded) so we must
         * return and later pick up the context.
         */
        Context->Interactive = 1;
        /* but wait... empty input can be trapped as a valid input
        *       but not on initial entry.
        */
        if (!WasInteractive)
            return;
        for (Menu = Context->Menu; Menu->CommandName != NULL; Menu++) {
            if (cmdWordEq(Menu->CommandName, ".empty")) {
                NextWord = "";
                goto Found;
            }
        }
        return;
    }
    NextWord = cmdWordNext(S);
    /* Here there is another word in the command string,
     * which should be the next (sub)command.
     */
    if (Context->Menu == NULL) {
        cmdDebug(DBGERR, "ERR: cmdMenu lacks menu!");
        Context->Interactive = 0;
        goto PopContext;
    }
    /* Search for an exact match in the menu */
    for (Menu = Context->Menu; Menu->CommandName != NULL; Menu++) {
        if (cmdWordEq(Menu->CommandName, S))
            goto Found;
    }
    /* Not found. But wait, we might have a wildcard handler */
    for (Menu = Context->Menu; Menu->CommandName != NULL; Menu++) {
        if (cmdWordEq(Menu->CommandName, ".wildcard")) {
            NextWord = S;       /* pass unfound to wildcard handler */
            goto Found;
        }
    }
    cmdf(Context, "(Sub)command not found: %.*s\n", cmdWordLen(S), S);
    cmdDebug(DBGERR, "(Sub)command not found: %.*s", cmdWordLen(S), S);
    return;

    Found:
    {
        struct cmdContext *NewContext;
        // const struct cmdMenuItem *NextMenu = Menu->Menu;  /* child */

        NewContext = malloc(sizeof(*NewContext) + cmdWordLen(S) + 1);
        if (NewContext == NULL) {
            cmdf(Context, "ERR: MALLOC FAILURE\n");
            cmdDebug(DBGERR, "ERR: malloc failure");
            goto PopContext;
        }
        memset(NewContext, 0, sizeof(*NewContext));
        NewContext->Parent = Context;
        Context->Child = NewContext;
        NewContext->OutF = Context->OutF;
        NewContext->Item = Menu;
        NewContext->CommandName = (void *)(NewContext+1);
        NewContext->CommandName = cmdWordDup(S);
        NewContext->Menu = Menu->Menu;
        NewContext->CommandHandler = Menu->CommandHandler;
        if (NewContext->CommandHandler == NULL) {
            cmdf(Context, "ERR: no command handler for menu item %s\n",
                Menu->CommandName);
            cmdDebug(DBGERR, "ERR: no command handler for menu item %s",
                Menu->CommandName);
            NewContext->CommandHandler = cmdNull;
        }
        /* optional entry handler for menus.
        *       This is called after matching the name of of a menu and
        *       starting a new context for that menu.
        *       Thus if the menu is used interactively, the entry
        *       handler is not called again until the menu is quit from
        *       and later re-entered.
        *       Pass remaining text in case it is useful... ?
        */
        if (NewContext->Menu)
        for (Menu = NewContext->Menu; Menu->CommandName != NULL; Menu++) {
            if (cmdWordEq(Menu->CommandName, ".entry")) {
                (*Menu->CommandHandler)(NewContext, NextWord);
                break;
            }
        }
        /* finally we call the handler */
        Context = NewContext;
        Context->Pinned++;
        (*Context->CommandHandler)(Context, NextWord);
        Context->Pinned--;
        /* after handler returns, see what context we have */
        if (Context->Child) {
            /* child context still there -- an interactive menu reached.
             * because we don't sleep, we must leave context alone
             * until there is more input, and meanwhile return
             */
        } else {
            /* non-interactive leaf reached -- pop context */
            goto PopContext;
        }
    }
    return;

    PopContext:
    /* Take down the menu layers until we get to a previous one
     * that was interactive, but don't take down the initial context
     * because the input handler needs that.
     */
    while (Context->Parent != NULL &&
                (Context->Interactive == 0 || Context->Quit) &&
                !Context->Pinned) {
        struct cmdContext *Parent = Context->Parent;
        cmdContextDestroy(Context);
        if (Parent == NULL) break;
        Context = Parent;
    }
    return;
}



/*=======================================================================*/
/*============== Interface from Shell ===================================*/
/*=======================================================================*/


/*-F- cmdPromptMake -- make prompt based upon menus traversed.
 * This is useful for interactive shells.
 * If the prompt would get too long, tries to be smart about it.
 */
void cmdPromptMake(
        struct cmdContext *Context,     /* must not be NULL */
        char *Buf,      /* where to put the prompt */
        int BufMax)     /* size of buf */
{
    int Len = 0;
    int Depth = 0;
    if (Context == NULL)
        return;
    BufMax--;   /* allow room for term. null char */
    BufMax--;   /* allow room for dot */
    BufMax--;   /* allow room for space at end */
    if (BufMax <= 1) return;
    Buf[Len++] = '@';
    Buf[Len] = 0;
    for (; Context; Context = Context->Child) {
        int NameLen;
        int Need;
        if (Context->CommandName == NULL)
            continue;
        Depth++;
        NameLen = strlen(Context->CommandName);
        Need = NameLen;
        if (Depth > 0) Need++;  /* precede with period */
        if (Len+Need > BufMax) {
            Len = 0;    /* throw away previous components */
            Need = (Depth>0)+NameLen;
            if (Need > BufMax) {
                if (BufMax >= 4)
                    strcpy(Buf, "...>");
                else
                if (BufMax >= 3)
                    strcpy(Buf, "..>");
                else
                if (BufMax >= 2)
                    strcpy(Buf, ".>");
                else
                    strcpy(Buf, ">");
                return;
            }
        }
        if (Depth > 1) Buf[Len++] = '.';
        strcpy(Buf+Len, Context->CommandName);
        Len += NameLen;
    }
    strcat(Buf, " ");
    return;
}


/*-F- cmdAutoPrompt -- emit auto-generated prompt, if enabled.
 *      Context is the root context, i.e. original context for session.
 */
void cmdAutoPrompt(
        struct cmdContext *Context)   /* must not be NULL */
{
    struct cmdContext *Current;
    if (Context == NULL)
        return;
    Current = Context;
    while (Current->Child)
        Current = Current->Child;
    if (Context->AutoPrompt && !Context->Quit) {
        if (Current->PromptHandler) {
            /* PromptHandler should do a cmdf(Context, "...prompt text...") */
            (*Current->PromptHandler)(Current);
        } else {
            char Prompt[50];
            cmdPromptMake(Context, Prompt, sizeof(Prompt));
            cmdf(Context, "%s", Prompt);
        }
    }
}



/*-F- cmdInputAdd -- add stream characters to buffering and invoke
 *      menu context for each line.
 *      Returns nonzero if stream termination is desired.
 */
int cmdInputAdd(
        struct cmdContext *Context,   /* must not be NULL */
        char *Buf,      /* buffer we're holding input in */
        int *BufFullP,  /* in/out: chars in buffer so far */
        int BufMax,     /* size of buffer */
        const char *Input,      /* input from stream */
        int InputSize   /* no. of bytes of input */
        )
{
    if (Context == NULL)
        return 1;
    while (InputSize > 0) {
        int Ch = *Input++;
        InputSize--;
        if (Context->Quit)
            break;
        if (Ch == '\n') {
            /* End of line */
            if (Context->InputDirty) {
                Context->InputDirty = 0;
            } else {
                /* execute the input line */

                #if CMD_STDOUT_REDIRECT_FEATURE()
                /* Replace where stdout goes temporarily for this
                 * command... this allows printf to be used instead of
                 * or in addition to cmdf (which will still work).
                 * However, this may be a bad idea for mult-threaded code.
                 */
                int SaveFd = -1;
                if (Context->OutFd > 0) {
                    fflush(stdout);
                    SaveFd = dup(1);    /* copy stdout fd */
                    if (SaveFd < 0) {
                        cmdDebug(DBGERR, "Failed to dup stdout!");
                    } else {
                        dup2(Context->OutFd, 1/*STDOUT*/);
                    }
                }
                #endif // CMD_STDOUT_REDIRECT_FEATURE()

                Buf[*BufFullP] = 0;
                cmdMenu(Context, Buf);
                *BufFullP = 0;
                fflush(stdout);
                cmdAutoPrompt(Context); /* prompt for next input */

                #if CMD_STDOUT_REDIRECT_FEATURE()
                if (SaveFd > 0) {
                    dup2(SaveFd, 1/*STDOUT*/);
                    close(SaveFd);
                }
                #endif // CMD_STDOUT_REDIRECT_FEATURE()
            }
        } else
        if (Context->InputDirty) {
            /* previous buffer overflow; throw away input to end of line */
        } else
        if (*BufFullP >= BufMax-1) {
            /* buffer overflow */
            *BufFullP = 0;      /* dump buffer */
            Context->InputDirty = 1;
        } else {
            Buf[*BufFullP] = Ch;
            (*BufFullP)++;
        }
    }
    return Context->Quit;
}


/*-F- cmdInputFromFile -- execute from a file.
 * Reads from file must not block! ... so it must be a disk file.
 * Generally you will need to create a new context to use for this.
 *
 * Returns nonzero on error.
 */
int cmdInputFromFile(
        struct cmdContext *Context,   /* must not be NULL */
        const char *FilePath,
        char *Buf,              /* or NULL for default buffer */
        int BufSize)            /* if Buf is not NULL */
{
    int BufFull = 0;
    char ReadBuf[4096];
    char BuiltinBuf[4096];
    int NRead = 0;
    int fd = -1;

    if (Context == NULL)
        return 1;
    fd = open(FilePath, O_RDONLY);
    if (fd < 0) {
        cmdDebug(DBGERR, "ERR: Failed to open cmd file %s", FilePath);
        return 1;
    }
    if (Buf == NULL) {
        Buf = BuiltinBuf;
        BufSize = sizeof(BuiltinBuf);
    }
    for (;;) {
        NRead = read(fd, ReadBuf, sizeof(ReadBuf));
        if ( NRead == 0) {
            break;
        }
        if ( NRead < 0) {
            /* TODO: check errno */
            cmdDebug(DBGERR, "Read error from file %s", FilePath);
            break;
        }
        if (cmdInputAdd(Context, Buf, &BufFull, BufSize, ReadBuf, NRead)) {
            cmdDebug(DBGERR, "Execution error from file %s", FilePath);
            break;
        }
    }
    close(fd);
    return NRead;
}

/*-F- cmdDebugHere -- fork debug messages to current session.
 * (The session is the (grand)parent context of Context).
 * Returns nonzero on error.
 * Does nothing (return 0) if already so redirected.
 *
 * With Enable==0, disables any previous fork.
 */
int cmdDebugHere(
        struct cmdContext *Context,   /* must not be NULL */
        int Enable
        )
{
    struct dbgOutput *Fork;
    if (!Context)
        return 1;
    /* Apply it to the root context, otherwise we lose it right away.
     */
    while (Context->Parent)
        Context = Context->Parent;
    if (Enable) {
        if (Context->DebugFork)
            return 0;   /* already done, leave it alone */
        Fork = dbgOutFork(Context->OutF);
        if (!Fork)
            return 1;
        Context->DebugFork = Fork;
    } else {
        if (Context->DebugFork)
            dbgOutForkCancel(Context->DebugFork);
        Context->DebugFork = NULL;
    }
    return 0;
}



/*-F- cmdInputLine -- Input a line from stream
 * This function will block the caller!
 * And it will not return until it reaches the ending of a line.
 * Returns the nubmer of characters, or -1 on errors
 */
int cmdInputLine(
        struct cmdContext *Context,   /* must not be NULL */
        char *Buf,              /* buffer  */
        int BufSize)            /* size of buffer */
{
    int Sd;
    int Flag;
    int nRead;
    int nChars = 0;

    Sd = fileno(Context->OutF);
    if (Sd < 0)
        return -1;

    /*block the socket*/
    Flag = fcntl(Sd, F_GETFL);
    (void) fcntl(Sd, F_SETFL, Flag & ~O_NONBLOCK);

    while(1) {
        nRead = read(Sd, Buf, BufSize);
        if (nRead < 0 || nRead == 0) {
        /*shell read error or shell read eof*/
            nChars = -1;
            break;
        }

        nChars += nRead;
        Buf += nRead;
        BufSize -= nRead;

        if (Buf[-1] == '\n' || Buf[-1] == '\r')
            break;
    }

    /*restore the flag*/
    (void) fcntl(Sd, F_SETFL, Flag);
    return nChars;
}


/*-F- cmdInputPacket -- Input Packet from stream
 * Returns bytes of data, or -1 on errors
 */
int cmdInputPacket(
        struct cmdContext *Context,   /* must not be NULL */
        char *Buf,              /* buffer */
        int BufSize)            /* size of buffer */
{
    char Line[256];
    unsigned int Data[16]; /*type "int" in case endian issue*/
    int  nBytes = 0;
    int  lineBytes;
    int  ret = -1;
    int  i;

    while(1) {
        memset(Line, 0, sizeof(Line));
        if (cmdInputLine(Context, Line, sizeof(Line)) <= 0)
            break;

        /*per wireshark format*/
        /*
            0000  00 00 0c 9f f3 28 00 26  c6 a1 b8 2c 08 00 45 00   .....(.& ...,..E.
            0010  00 28 1f 3e 40 00 80 06  49 08 0a 4b 3a 4a da 1e   .(.>@... I..K:J..
            0020  73 d6 dd 1e 00 50 55 18  ab a6 d9 7e 13 36 50 11   s....PU. ...~.6P.
            0030  40 bf 11 a8 00 00                                  @.....
        */
        lineBytes = sscanf(Line, "%*04x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
            &Data[0], &Data[1], &Data[2], &Data[3], &Data[4], &Data[5], &Data[6], &Data[7],
            &Data[8], &Data[9], &Data[10], &Data[11], &Data[12], &Data[13], &Data[14], &Data[15]);

        if (lineBytes < 0 )
        {
            /*ended with a NULL line*/
            if (*Line == '\n' || *Line == '\r')
                ret = nBytes;
            break;
        }

        if (BufSize < lineBytes)
            break;

        for (i = 0; i < lineBytes; i++)
            Buf[i] = (char) Data[i];

        Buf += lineBytes;
        BufSize -= lineBytes;
        nBytes += lineBytes;

        /*ended with less than 16 bytes*/
        if (lineBytes < 16)
        {
            ret = nBytes;
            break;
        }
    }

    return ret;
}

/*=======================================================================*/
/*============== End ====================================================*/
/*=======================================================================*/


