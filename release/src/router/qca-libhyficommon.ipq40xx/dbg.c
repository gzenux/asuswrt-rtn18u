/*
 * Copyright (c) 2010 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*-M- dbg -- debug printf system.
 *                              Author: Ted Merrill, June 2008
 *
 * The idea:
 * You put into your code statements such as:
 *      #include <dbg.h>
 *      ...
 *      struct dbgModule *fooDebugModule;
 *      ...
 *      fooDebugModule = dbgModuleFind("foo");
 *      ...
 *      #define foof(...) dbgf(fooDebugModule, __VA_ARGS__)
 *      ...
 *      foof(DBGDEBUG, "Entering function fooBar x=%d", x);
 *      ...
 * and the message will be printed to stderr (or can be redirected or
 * forked) only if debugs have been turned on for module "foo" at level
 * DBGDEBUG or higher... or if debugs have been turned on at this level
 * or higher globally.
 * And how to turn on such debugs? through environmental variable "DBG_LEVELS"
 * or by other means as provided (e.g. command line args, debugging menu, etc),
 * which take precedence over environmental variables in the order invoked.
 *
 * Environmental variables:
 *
 * DBG_LEVELS -- this environmental variable is read at startup.
 * It may contain multiple of the form <modulename>=<level>
 * separated by commas,
 * where <modulename> is a name that will (or may) be used by later
 * dbgf calls, <level> is one of the strings NONE, ERR, INFO,
 * DEBUG, or DUMP.
 * Also <modulename> can be "all" to set all modules to the new level:
 *      for example, DBG_LEVELS=all=DEBUG
 * The module name "unknown" may have a special meaning if software
 * fails to use dbgModuleFind() to obtain a handle (and use NULL instead).
 *
 * DBG_APPEND_FILE_PATH -- this environmental variable is read at startup
 * and if present determines file path to write debug messages to.
 * The output file is appended to, if it pre-exists.
 *
 * DBG_OUT_FILE_PATH -- this environmental variable is read at startup
 * and if present determines file path to write debug messages to.
 * The output file is first truncated, if it pre-exists.
 * (DBG_APPEND_FILE_PATH has precedence).
 *
 * TODO:
 * -- Add replication of messages to multiple FILEs
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>

#include <dbg.h>

#if 0   /* auto-extract only */
/*-D- Required includes
 */
#include <stdio.h>
#include <stdarg.h>
/*--------------------------------------------------*/
#endif


/* Set one of the following to 1 to enable a timestamp on messages,
 * or set all to 0 to disable timestamp.
 */
#define DBG_TIME_STAMP_ELAPSED_SEC_MSEC() 0
#define DBG_TIME_STAMP_HHMMSS() 0
#define DBG_TIME_STAMP_HHMMSSUUUUUU() 1
#define DBG_TIME_STAMP_MODULO_SEC_MSEC() 0




#if 0   /* auto-gen only */
/*-D- dbgLevel -- allows filtering according to levels of importance.
 */
enum dbgLevel {
    DBGNONE = -1,       /* suppress all dbg messages */
    DBGERR = 0,         /* for serious errors only */
        /* ERR: Serious errors are errors in the local firmware */
    DBGINFO = 1,        /* important information, including minor errors */
        /* INFO: Major events, and apparent errors of other hosts */
    DBGDEBUG = 2,       /* for typical debugging */
        /* DEBUG: Messages useful for debugging individual modules */
    DBGDUMP = 3         /* for volumnous outputs */
        /* DUMP: e.g. packet traces etc. */
};
/*-------------------------------------------------------------------*/
#endif


/*
 * dbgLevelNames -- must match enum dbgLevel
 */
struct {
    const char *LevelName;
    enum dbgLevel Level;
} dbgLevelNames[] =
{
    { "none" ,  -1 },
    { "ERR" ,   0 },
    { "info" ,  1 },
    { "debug" , 2 },
    { "dump" ,  3  },
    { NULL }  /* TERMINATOR */
};


/*
 * DBG_DEFAULT_LEVEL -- initial default level for modules.
 * This can be predefined, else the default defaults as below.
 */
#ifndef DBG_DEFAULT_LEVEL
#define DBG_DEFAULT_LEVEL DBGERR
#endif

/* 
 * DBG_ENV_VAR_NAME -- this variable is read at startup.
 * It may contain multiple of the form <modulename>=<level>
 * separated by commas,
 * where <modulename> is a name that will (or may) be used by later
 * dbgf calls, <level> is one of the strings NONE, ERR, INFO,
 * DEBUG, or DUMP.
 * Also <modulename> can be "all" to set all modules to the new level.
 */
#ifndef DBG_ENV_VAR_NAME
#define DBG_ENV_VAR_NAME "DBG_LEVELS"
#endif


/*
 * DBG_APPEND_FILE_PATH
 */
#ifndef DBG_APPEND_FILE_PATH
#define DBG_APPEND_FILE_PATH "DBG_APPEND_FILE_PATH"
#endif

/*
 * DBG_OUT_FILE_PATH
 */
#ifndef DBG_OUT_FILE_PATH
#define DBG_OUT_FILE_PATH "DBG_OUT_FILE_PATH"
#endif

 
/*
 * dbg hash definitions.
 * Hashing makes finding module information faster.
 */
#define DBG_HASH_SHIFT 8
#define DBG_N_HASH (1<<DBG_HASH_SHIFT)
#define DBG_HASH_MASK (DBG_N_HASH-1)

/*
 * dbgHashMake -- compute hash of name
 */
unsigned dbgHashMake(const char *Name)
{
    unsigned Hash = 0;
    while (*Name) {
        /* Rotate the hash so all bits are used; then combine with next char */
        Hash = (Hash << 1) | (1 & (Hash >> (DBG_HASH_SHIFT-1)));
        Hash ^= *Name++;
    }
    Hash &= DBG_HASH_MASK;
    return Hash;
}

#if 0   /* auto-extract only */
/*-D- dbgModule -- track debugging module information 
 */
struct dbgModule {
    /* do NOT access fields directly -- use access functions! */
    const char *ModuleName;
    unsigned NameHash;
    enum dbgLevel Level;
    struct dbgModule *HashNext;
    struct dbgModule *AddedNext;
};
/*--------------------------------------------------------------------*/
#endif


/*
 * dbgOutput -- controls forking dbg output
 */
struct dbgOutput {
    struct dbgOutput *Next;     /* double-linked list */
    struct dbgOutput *Prev;     /* double-linked list */
    FILE *OutF;         /* where to write to */
    int AutoClose;      /* close OutF if redirected again */
};

/*
 * dbgState -- global information.
 */
struct dbgState {
    int IsInit;
    enum dbgLevel DefaultLevel; /* default debug level for modules */
    struct dbgOutput Out;       /* default output, and head of list */
    char *ProgramName;  /* used as prefix for debugging lines */
    /* Modules are searched for using hashes */
    struct dbgModule *Modules[DBG_N_HASH];
    struct dbgModule *AddedFirst;
    struct dbgModule *AddedLast;
    /* Self use */
    struct dbgModule *DbgDebugModule;
    struct dbgModule *UnknownModule;
};

/*
 * dbgS -- the instance of global information
 */
/*private*/ struct dbgState dbgS;


#define dbgDebug(level, ...) \
        dbgf(dbgS.DbgDebugModule,(level),__VA_ARGS__)


/*--- dbgInit -- first time initialization.
 * Called automatically when needed or you can call to force
 * early initialization.
 */
void dbgInit(void)
{
    const char *EnvP;
    if (dbgS.IsInit) 
        return;
    dbgS.IsInit = 1;
    /* dbgProgramNameSet may have been called first... */
    if (!dbgS.ProgramName)
        dbgS.ProgramName = strdup("");      /* default, don't use */
    dbgS.Out.Next = dbgS.Out.Prev = &dbgS.Out;  /* init output list */
    dbgS.DefaultLevel = DBG_DEFAULT_LEVEL;
    EnvP = getenv(DBG_ENV_VAR_NAME);
    if (EnvP) {
        (void) dbgModuleLevelsFromString(EnvP);
    }

    /* Direct output */
    dbgS.Out.OutF = stderr;
    EnvP = getenv(DBG_APPEND_FILE_PATH);
    if (EnvP && *EnvP) {
        (void) dbgFileRedirect(EnvP, 1/*Append*/);
        EnvP = NULL;
    } else EnvP = getenv(DBG_OUT_FILE_PATH);
    if (EnvP && *EnvP) {
        (void) dbgFileRedirect(EnvP, 0/*Append*/);
        EnvP = NULL;
    }
    dbgS.DbgDebugModule = dbgModuleFind("dbg");
    dbgS.UnknownModule = dbgModuleFind("unknown");
    dbgDebug(DBGDEBUG, "dbgInit done OK");
    return;
}

/*-F- dbgProgramNameSet -- set program name to use in dbg messages.
 * This does not need to be same name as actual program, and in fact
 * is best kept very short ...
 * try to keep all program names <= 4 chars for best readability
 * on terminal windows of limited width.
 */
void dbgProgramNameSet(const char *Name) {
    int Len;
    if(dbgS.ProgramName)free(dbgS.ProgramName);
    /* If no name, display nothing at all */
    if (!Name || !*Name) {
        dbgS.ProgramName = strdup("");
    } else {
        /* otherwise, left fill with spaces to a minimum size,
        * so that messages from multiple programs will tend to line up.
        */
        #define MIN_LEN 4   /* min length of program name */
        Len = strlen(Name);
        dbgS.ProgramName = malloc(Len+MIN_LEN+1);
        if(!dbgS.ProgramName)
        {
            dbgDebug(DBGERR, "Malloc failed");
            return;
        }
        memset(dbgS.ProgramName, 0, Len+MIN_LEN+1);
        memset(dbgS.ProgramName, ' ', MIN_LEN);
        memcpy(dbgS.ProgramName, Name, Len);
    }
    dbgInit();  /* now we have program name, we can do init */
    return;
}

#if 0   /* auto-extract only */
/*-D- dbgInitOptions -- options to pass to dbgInit1
 *      The ProgramName should be a four letter name for best formatting.
 *      The EnvName is the name of an environmental variable to use for
 *      debug levels initialization.
 *      If this is NULL or there is no env. variable by the given name,
 *      the environmental variable DBG_LEVELS is used if present.
 */
struct dbgInitOptions {
    char *ProgramName;  /* NULL, but should be 4 letter program name */
    char *EnvName;      /* NULL; or instead of DBG_LEVELS */
};
/*----------------------------------------------------*/
#endif  /* auto-extract only */

/*-F- dbgInit1 -- first time initialization, with options.
 */
void dbgInit1(
        const struct dbgInitOptions *Opt)       /* input */
{
    const char *EnvP;
    const char *EnvName;

    if (dbgS.IsInit) 
        return;
    dbgS.IsInit = 1;    /* so dbgInit() will do nothing */
    dbgProgramNameSet(Opt->ProgramName);
    dbgS.Out.Next = dbgS.Out.Prev = &dbgS.Out;  /* init output list */
    dbgS.DefaultLevel = DBG_DEFAULT_LEVEL;
    EnvName = Opt->EnvName;
    if (EnvName == NULL)
        EnvName = DBG_ENV_VAR_NAME;
    EnvP = getenv(EnvName);
    if (EnvP == NULL)
        EnvP = getenv(DBG_ENV_VAR_NAME);
    if (EnvP) {
        (void) dbgModuleLevelsFromString(EnvP);
    }

    /* Direct output */
    dbgS.Out.OutF = stderr;
    EnvP = getenv(DBG_APPEND_FILE_PATH);
    if (EnvP && *EnvP) {
        (void) dbgFileRedirect(EnvP, 1/*Append*/);
        EnvP = NULL;
    } else EnvP = getenv(DBG_OUT_FILE_PATH);
    if (EnvP && *EnvP) {
        (void) dbgFileRedirect(EnvP, 0/*Append*/);
        EnvP = NULL;
    }
    dbgS.DbgDebugModule = dbgModuleFind("dbg");
    dbgS.UnknownModule = dbgModuleFind("unknown");
    dbgDebug(DBGDEBUG, "dbgInit1 done OK");
    return;
}



/*-F- dbgFILERedirect -- redirect output using FILE *
 */
void dbgFILERedirect(
        FILE *OutF,
        int AutoClose)  /* close if redirected again */
{
    if (!dbgS.IsInit) dbgInit();
    dbgDebug(DBGINFO, "Debug output redirecting...");
    if (dbgS.Out.AutoClose && dbgS.Out.OutF) 
        fclose(dbgS.Out.OutF);
    dbgS.Out.OutF = OutF;
    if (dbgS.Out.OutF) {
        dbgS.Out.AutoClose = AutoClose;
        dbgDebug(DBGINFO, "Debug output redirected");
    } else {
        dbgS.Out.OutF = stderr;
        dbgS.Out.AutoClose = 0;
        dbgDebug(DBGINFO, "Directed to stderr");
    }
    return;
}


/*-F- dbgFileRedirect -- redirect output to file.
 * Returns nonzero if error (can't write to file).
 */
int dbgFileRedirect(
        const char *FilePath,
        int Append)     /* nonzero to append to this file if it exists */
{
    FILE *OutF;
    if (!dbgS.IsInit) dbgInit();
    OutF = fopen(FilePath, (Append?"a":"w"));
    if (OutF == NULL) {
        dbgDebug(DBGERR, "Debug output redirection to %s FAILED", FilePath);
        return 1;
    }
    dbgFILERedirect(OutF, 1/*AutoClose*/);
    dbgDebug(DBGINFO, "Debug output redirected to %s (%s)", 
        FilePath, (Append?"append":"rewrite"));
    return 0;
}


/*-F- dbgFileRedirectCancel -- cancel message redirection
 */
void dbgFileRedirectCancel(void)
{
    dbgFILERedirect(NULL/* use stderr*/, 0/*AutoClose*/);
}


/*-F- dbgOutFork -- copy dbg output to another place.
 * CAUTION: non-responsive pipes etc. can cause
 * blocking of the main event loop!
 *
 * To undo the forking, call dbgOutForkCancel.
 * Make sure you do this before closing the output FILE.
 *
 * Returns NULL if error.
 */
struct dbgOutput * dbgOutFork(
        FILE *OutF
        )
{
    struct dbgOutput *Out;
    if (!OutF)
        return NULL;
    Out = malloc(sizeof(*Out));
    if (!Out)
        return NULL;
    memset(Out, 0, sizeof(*Out));
    Out->OutF = OutF;
    Out->Next = &dbgS.Out;
    Out->Prev = dbgS.Out.Prev;
    Out->Prev->Next = Out->Next->Prev = Out;
    return Out;
}

/*-F- dbgOutForkCancel -- remove dbg output forking.
 * Does not affect the default output stream.
 * Does not close OutF.
 */
void dbgOutForkCancel(
        struct dbgOutput *Out   /* from dbgOutFork; or NULL is ignored */
        )
{
    if (!Out)
        return;
    Out->Next->Prev = Out->Prev;
    Out->Prev->Next = Out->Next;
    memset(Out, 0, sizeof(*Out));       /* ease debugging */
    free(Out);
    return;
}

/*
 * dbgModuleFindOrAdd -- find module node matching module name ,
 * or add if not found.
 * Returns NULL if malloc error.
 */
static struct dbgModule *dbgModuleFindOrAdd(
        const char *Name, 
        unsigned Hash)          /* Hash precomputed for efficiency */
{
    struct dbgModule *MP;
    struct dbgModule *NewMP;
    const char *NewName;

    /* Optimize by searching only those matching hash */
    MP = dbgS.Modules[Hash];
    if (MP) for(;;) {
        struct dbgModule *NextMP;
        if (!strcmp(Name, MP->ModuleName))
            return MP;
        NextMP = MP->HashNext;
        /* Leave MP pointing at last module in hash list, if any */
        if (NextMP == NULL) break;
        MP = NextMP;
    }
    /* Not found -- must add */
    NewMP = calloc(1, sizeof(*NewMP));
    if (NewMP == NULL)
        return NULL;
    NewName = strdup(Name);
    if (NewName == NULL) {
        free(NewMP);
        return NULL;
    }
    NewMP->ModuleName = NewName;
    NewMP->NameHash = Hash;
    NewMP->Level = dbgS.DefaultLevel;
    NewMP->HashNext = NULL;
    if (MP)
        MP->HashNext = NewMP;
    else
        dbgS.Modules[Hash] = NewMP;
    if (dbgS.AddedLast) {
        dbgS.AddedLast->AddedNext = NewMP;
        dbgS.AddedLast = NewMP;
    } else {
        dbgS.AddedLast = dbgS.AddedFirst = NewMP;
    }
    return NewMP;
}


/*-F- dbgLevelFromString -- convert level name or numeral to number.
 *      Returns nonzero if error.
 */
int dbgLevelFromString(
    const char *S,      /* string to convert */
    enum dbgLevel *LevelP       /* output */
    )
{
    int I;
    /* accept a numeral */
    if ((S[0] == '-' && isdigit(S[1])) || isdigit(S[0])) {
            *LevelP = atol(S);
            return 0;
    }
    /* accept one of our level names, case insensitive comparison */
    for (I = 0; dbgLevelNames[I].LevelName != NULL; I++) {
        if (!strcasecmp(S, dbgLevelNames[I].LevelName)) {
            *LevelP = dbgLevelNames[I].Level;
            return 0;
        }
    }
    return -1;
}

/*-F- dbgLevelToString -- convert level to level name
 * Returns NULL if no match.
 */
const char *dbgLevelToString(enum dbgLevel Level)
{
    int I;
    for (I = 0; dbgLevelNames[I].LevelName != NULL; I++) {
        if (dbgLevelNames[I].Level == Level)
            return dbgLevelNames[I].LevelName;
    }
    return NULL;
}


/*-F- dbgModuleFind -- find module / add module to list of known modules.
 * The returned handled will be needed to make calls to change
 * per-module debugging attributes.
 * For efficiency, call this once and remember the handle.
 */
struct dbgModule * dbgModuleFind(const char *ModuleName)
{
    unsigned Hash;

    if (!dbgS.IsInit) dbgInit();
    Hash = dbgHashMake(ModuleName);
    return dbgModuleFindOrAdd(ModuleName, Hash);
}


/*-F- dbgModuleLevelSet -- set module debug level
 */
void dbgModuleLevelSet(
        struct dbgModule *MP, 
        int Level)
{
    if (!dbgS.IsInit) dbgInit();
    if (MP == NULL) 
        return;
    MP->Level = Level;
    return;
}


#if 0   /* auto-extract only */
/*-D- dbgModuleLevelGet -- get module debug level
*       Note that this may change at runtime!
*/
static inline enum dbgLevel dbgModuleLevelGet(
        struct dbgModule *MP)   /* if NULL, a harmless value is returned */
{
    if (MP)
        return MP->Level;
    return 999;  /* force a debug message so Init will be called */
}
/*-----------------------------------------------------------------------*/
#endif  /* auto-extract */


/*-F- dbgAllModulesLevelSet -- set all present and future modules to level.
 */
void dbgAllModulesLevelSet(enum dbgLevel Level)
{
    int IHash;
    if (!dbgS.IsInit) dbgInit();
    dbgS.DefaultLevel = Level;
    for (IHash = 0; IHash < DBG_N_HASH; IHash++ ) {
        if (dbgS.Modules[IHash] != NULL) {
            struct dbgModule *MP = dbgS.Modules[IHash];
            while (MP) {
                MP->Level = Level;
                MP = MP->HashNext;
            }
        }
    }
    return;
}

/*-F- dbgModuleLevelFromBuf -- store result of <modulename>[=]<level>
 * Returns nonzero if error.
 * Not an error if there is no <level> value.
 * <modulename> and <level> can be separated by whitespace and/or
 * equal sign.
 *
 * NOTE NOTE the passed buffer is scribbled over (within the bounds
 * of the original string).
 */
int dbgModuleLevelFromBuf(
        char *B)        /* we can scribble over this input */
{
    char *Value;
    char *End;
    char *ModuleName;
    struct dbgModule *MP;
    enum dbgLevel Level = dbgS.DefaultLevel;
    int GotLevel = 0;
    int NErrors = 0;

    /* Get name part of name=value */
    if(!B)
        return 1;
    while (*B && !isgraph(*B)) B++;      /* skip whitespace */
    for (End = B; isgraph(*End) && *End != '='; End++) {;}

	*End = 0;
	Value = End+1;
	while (*Value && (*Value == '=' || !isgraph(*Value)))
		Value++; /* skip whitespace and equal signs */
	for (End = Value; isgraph(*End); End++) {;}
	*End = 0;
	if (*Value == 0)
		{;}
	else if (dbgLevelFromString(Value, &Level))
		NErrors++;
	else
		GotLevel = 1;
    ModuleName = B;
    if (!strcmp(ModuleName, "all")) {
        if (GotLevel) {
            dbgAllModulesLevelSet(Level);
            dbgS.DefaultLevel = Level;
        }
    } else {
        unsigned Hash = dbgHashMake(ModuleName);
        MP = dbgModuleFindOrAdd(ModuleName, Hash);
        if (MP == NULL) 
            return 1;       /* malloc failure */
        if (GotLevel)
            MP->Level = Level;
        /* else we created node anyway */
    }
    return NErrors;
}


/*-F- dbgModuleLevelsFromString -- set levels of zero or more modules.
 * String may contain multiple of the form <modulename>=<level>
 * separated by commas,
 * where <modulename> is a name that will (or may) be used by later
 * dbgf calls, <level> is one of the strings NONE, ERR, INFO,
 * DEBUG, or DUMP.
 * Also <modulename> can be "all" to set all modules to the new level.
 *
 * Returns nonzero if there were any errors, in which case the
 * operation is completed as much as it can be.
 */
int dbgModuleLevelsFromString(const char *S)
{
    char *B;
    char *B1;
    char *EndAssign;
    int NErrors = 0;

    if (!dbgS.IsInit) dbgInit();

    if (S == NULL) return 0;
    B = strdup(S);
    if (B == NULL) return -1;
    B1 = B;
    for(;;) {
        EndAssign = strchr(B1,',');
        if (EndAssign) *EndAssign = 0;
        if (dbgModuleLevelFromBuf(B1)) 
            NErrors++;
        if (EndAssign) B1 = EndAssign+1;
        else break;
    }

    free(B);
    return NErrors;
}


/*
 * dbgTimeStampMake -- format a time stamp for prefixing messages.
 */
void dbgTimeStampMake(char Buf[/*big enough*/])
{
    #if DBG_TIME_STAMP_HHMMSS() || DBG_TIME_STAMP_HHMMSSUUUUUU()
    {
        struct timeval tp = { };
        time_t UnixTime;
        struct tm *LocalTime;
        unsigned hour, minute, second;

        (void) gettimeofday(&tp, NULL);
        UnixTime = tp.tv_sec;
        LocalTime = localtime(&UnixTime);
        if (LocalTime) {
            hour = LocalTime->tm_hour;
            minute = LocalTime->tm_min;
            second = LocalTime->tm_sec;
        } else {
            /* This should never happen, so just give dummy values if it
             * does.
             */
            hour = 0;
            minute = 0;
            second = 0;
        }
        #if DBG_TIME_STAMP_HHMMSSUUUUUU()
        sprintf(Buf, "%02u.%02u.%02u.%06ld ", hour, minute, second, tp.tv_usec);
        #else
        sprintf(Buf, "%02u.%02u.%02u ", hour, minute, second);
        #endif
    }
    #elif DBG_TIME_STAMP_ELAPSED_SEC_MSEC()
    {
        static int IsInit;
        static struct timeval tp0;
        struct timeval tp = { };
        unsigned Seconds;
        unsigned MSec;

        (void) gettimeofday(&tp, NULL);
        if (!IsInit) {
            IsInit = 1;
            tp0 = tp;
        }
        /* Note: ignore tp0.tv_usec (as if time started at begin of second */
        Seconds = tp.tv_sec - tp0.tv_sec;
        MSec = tp.tv_usec / 1000;
        sprintf(Buf, "%u.%03u ", Seconds, MSec);
    }
    #elif DBG_TIME_STAMP_MODULO_SEC_MSEC()
    {
        struct timeval tp = { };
        unsigned Seconds;
        unsigned CSec;

        (void) gettimeofday(&tp, NULL);
        /* Display seconds modulo some number;
         * modulo 1000 works well for base 10 display.
         */
        Seconds = tp.tv_sec % 1000;
        CSec = tp.tv_usec / 10000;
        sprintf(Buf, "%03u.%02u ", Seconds, CSec);
    }
    #else
    Buf[0] = 0;
    #endif
}

#if 0   /* auto-extract only. */
/* Use gccism "__attribute__" to force warnings for wrong args
 * for dbgf.
 * format(printf,3,4):
 *      printf -- printf like arguments
 *      3 -- format is arg 3
 *      4 -- args for format start with arg 4
 *
 * gcc doesn't handle __attribute__ in actual function,
 * so we have to do it like this.
 */

/*-D- dbgf -- conditionally print a debug message.
 * The message is printed if Level is less than or equal to the module level.
 * The module level defaults to global debug level.
 *
 * Return value is undefined.
 */
#ifdef __RELEASE__
#define dbgf(...) 
#else
int Dbgf(
        struct dbgModule *MP,
        enum dbgLevel Level,
        const char *Format,
        ...)    /* printf-like args */
        #ifdef __GNUC__
        __attribute__ ((format (printf, 3, 4)))
        #endif 
        ;
#define dbgf(...) Dbgf(__VA_ARGS__)
#endif
/*-------------------------------------------------------------------*/
#endif  /* auto-extract */
/*--- dbgf -- conditionally print a debug message.
 * The message is printed if Level is less than or equal to the module level.
 * The module level defaults to global debug level.
 * Return value is undefined.
 */
int Dbgf(
        struct dbgModule *MP,
        enum dbgLevel Level,
        const char *Format,
        ...)    /* printf-like args */
{
    va_list ArgP;
    char TimeBuf[60];
    const char *LevelName;
    struct dbgOutput *Out;

    if (!dbgS.IsInit) dbgInit();

    if (MP == NULL) {
        MP = dbgModuleFind("unknown");
    }
    if (!Format || !*Format)
        return 0;
    if (Level > MP->Level) 
        return 0;
    /* Prefix message with time, program, module name, message level */
    dbgTimeStampMake(TimeBuf);
    LevelName = dbgLevelToString(Level);

    for (Out = &dbgS.Out; ;) {
        if (LevelName) 
            fprintf(Out->OutF, "%s%s %-8s %-5s: ", 
                TimeBuf, dbgS.ProgramName, MP->ModuleName, LevelName);
        else
            fprintf(Out->OutF, "%s%s %-8s %-5d: ", 
                TimeBuf, dbgS.ProgramName, MP->ModuleName, Level);
        va_start(ArgP, Format);
        vfprintf(Out->OutF, Format, ArgP);
        va_end(ArgP);
        /* Add newline if one not given */
        if (Format[strlen(Format)-1] != '\n')
            fprintf(Out->OutF, "\n");
        fflush(Out->OutF);  /* avoid problems with latent or lost messages */
        Out = Out->Next;
        if (Out == &dbgS.Out)
            break;
    }
    return 0;
}

/*-F- dbgLevelsPrint -- print debug levels per module.
 * Pass NULL to print all modules.
 */
void dbgLevelsPrint(
        FILE *OutF,
        const char *ModuleName)     /* or NULL for all */
{
    if (dbgS.AddedFirst) {
        struct dbgModule *MP;
        if (!ModuleName) fprintf(OutF, "dbg debugging levels per module:\n");
        for (MP = dbgS.AddedFirst; MP; MP = MP->AddedNext) {
            const char *LevelName;
            dbgDebug(DBGDUMP, "Looking at MP=%p %s", MP, MP->ModuleName);
            if (ModuleName && strcmp(ModuleName, MP->ModuleName))
                continue;
            LevelName = dbgLevelToString(MP->Level);
            if (LevelName == NULL) LevelName = "";
            fprintf(OutF, "%-12s %d %s\n", 
                MP->ModuleName,
                MP->Level,
                LevelName);
        }
    } else {
        fprintf(OutF, "dbg -- no modules !?\n");
    }
    fflush(OutF);
}

/*-F- dbgStatusPrint -- print useful info about dbg state
 * including debug levels.
 */
void dbgStatusPrint(FILE *OutF)
{
    const char *LevelName;
    int IChoice;

    LevelName = dbgLevelToString(dbgS.DefaultLevel);
    if (LevelName == NULL) LevelName = "";
    fprintf(OutF, "Default debug level for new modules is %d %s\n",
        dbgS.DefaultLevel, LevelName);
    fprintf(OutF, "Standard level choices are:\n");
    for (IChoice = 0; IChoice < sizeof(dbgLevelNames)/sizeof(dbgLevelNames[0]);
            IChoice++) {
        if (!dbgLevelNames[IChoice].LevelName)
            break;
        fprintf(OutF, "    %s=%d", 
            dbgLevelNames[IChoice].LevelName,
            dbgLevelNames[IChoice].Level);
    }
    fprintf(OutF, "\n");
    fprintf(OutF, "(Names are case INsensitive)\n");
    dbgLevelsPrint(OutF, NULL);
    fflush(OutF);
}
