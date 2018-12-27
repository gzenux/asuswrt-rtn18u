/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   INSIDE Secure IPsec Virtual Adapter, debugging definitions
*/

#ifndef _SSH_VNICDBG_H
#define _SSH_VNICDBG_H

#ifndef NO_DBG_PRINT
#define NO_DBG_PRINT  /* Turn off the debug output */
#endif

#ifndef DOTRACE
#define DOTRACE 0 /* tracing on/off */
#endif

#if defined(DBG) && !defined(NO_DBG_PRINT)

#if DOTRACE
#define TRACELOG  DbgPrint("%s:%d (%s())\n", __FILE__, __LINE__, __FUNC__)
#else /* not DOTRACE */
#define TRACELOG
#endif /* not DOTRACE */

#define DEBUGFUNC(__F)  static const char __FUNC__[] = __F

#define DEBUGSTR(S)                                                \
{                                                                  \
  DbgPrint("%s:%d (%s()) - ", __FILE__, __LINE__, __FUNC__);       \
  DbgPrint S;                                                      \
}

#define DEBUGSTR2(S)    {DbgPrint S;}

#define DEBUGINT                                                   \
{                                                                  \
  DbgPrint("%s: Breakpoint at line %d (in function %s)\n",         \
           __FILE__, __LINE__, __FUNC__);                          \
  DbgBreakPoint();                                                 \
}

#undef ASSERT
#define ASSERT( exp )                                              \
if (!(exp))                                                        \
{                                                                  \ 
  DbgPrint("Assertion Failed: %s:%d %s\n",__FILE__,__LINE__,#exp); \
  DbgBreakPoint();                                                 \
}

























#else /* !defined(DBG) || defined(NO_DBG_PRINT) */ 

#define DEBUGFUNC(__F) static const char __FUNC__[] = ""
#define TRACELOG
#define DEBUGSTR(S) 
#define DEBUGSTR2(S)
#define DEBUGINT
#define DEBUG_OID_STRING(oid)

#endif /* !defined(DBG) || defined(NO_DBG_PRINT) */ 

#endif /* ifndef _SSH_VNICDBG_H */ 
