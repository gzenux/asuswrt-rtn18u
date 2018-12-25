/*
 * @File: qassert.h
 *
 * @Abstract: Assertion support
 *
 * @Notes: See below
 *
 * Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef qassert__h
#define qassert__h

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Assertion support:
 *
 * There are two types of assertions:
 * - Fatal assertion: When a required condition turned out to be false
 *   and the software module cannot recover from it (or there is no point
 *   for continuing the execution), use the following macro:
 *
 *   __ASSERT_FATAL
 *
 *   This macro will display the filename, line and function name, as well
 *   as the failed condition and any text which was provided by the programmer,
 *   similarly to any other text formatting function (such as printf).
 *   Once this information is presented, the program execution will be
 *   terminated abnormally, thus allowing the programmer to examine the
 *   error and fix it.
 *
 * - Standard assertion: When a required condition turned out to be false
 *   but the software module can recover (by assuming a default value for
 *   example), use the following macro:
 *
 *   __ASSERT
 *
 *   This macro has a similar functionality, however, it will not terminate
 *   the program execution, as it is assumed that for this assertion type,
 *   the program can recover. The macro returns 0 if the condition is false,
 *   or !0 if the condition is true.
 *
 *   Examples:
 *
 *   When and how to use the __ASSERT_FATAL macro:
 *
 *   int main( int argc, char *argv[] )
 *   {
 *      // Expect at least 1 parameter argument. Use when there is no point to
 *      // continue the execution without this information.
 *      __ASSERT_FATAL( argc >= 2, "Insufficient parameters: argc = %d", argc );
 *      ...
 *   }
 *
 *   When and how to use the __ASSERT macro:
 *
 *   int main( int argc, char *argv[] )
 *   {
 *      // Expect at least 1 parameter argument, use when we can work also without it
 *      if( __ASSERT( argc >= 2, "Insufficient parameters: argc = %d", argc ) )
 *      {
 *         // Continue normally, condition is true
 *         printf( "argc is indeed >= 2\n");
 *         ...
 *      }
 *      else
 *      {
 *         // Condition is false, write the recovery code here
 *         printf( "argc is < 2, assuming default value\n" );
 *         ...
 *      }
 *      ...
 *   }
 *
 *   Note that in this case, you would probably prefer to check only for the false
 *   condition in order to recover (otherwise, simply assume it's ok), for example:
 *
 *   if( !__ASSERT( argc >= 2, "Insufficient parameters: argc = %d", argc ) )
 *   {
 *       // Recover...
 *       ...
 *   }
 *
 */

/*
 * Assertion configuration options:
 *
 * CONFIG_ASSERT_DEBUG_MODE - Define to enable extended assertion debug information.
 * This option may be turned off for field operation in order to save space.
 *
 */

/* Enable extended assertion debug information */
#define CONFIG_ASSERT_DEBUG_MODE

/*
 * Macro magic stuff, do not edit!
 * -------------------------------
 */

/* May 2014 update: KW doesn't like NULL dereference, change it to exit(1) instead.
 */
#define __TERMINATE_FATAL( __val ) exit( __val ? 1 : 0 )
static inline int __TERMINATE(void)
{
	exit(1);
	return 1;
}

/* Generate a textual message about the assertion in debug mode only */
#ifdef CONFIG_ASSERT_DEBUG_MODE

#define __BUG_REPORT( _cond, _format, _args ... ) \
	fprintf( stderr, "%s:%d: Assertion error in function '%s' for condition '%s': " _format "\n", __FILE__, __LINE__, __FUNCTION__, # _cond, ##_args ) && fflush( NULL ) != (EOF-1)
#else
#define __BUG_REPORT( _cond, _format, _args ... ) 1

#endif /* CONFIG_ASSERT_DEBUG_MODE */

/* Check a condition, and report and crash in case the condition is false */
#define __ASSERT_FATAL( _cond, _format, _args ... ) \
do { if(!(_cond)) { __TERMINATE_FATAL( __BUG_REPORT( _cond, _format, ##_args ) ); } } while( 0 )

/* Check a condition, and report in case the condition is false */
#define __ASSERT( _cond, _format, _args ... ) \
( (_cond) ? !0 : __BUG_REPORT( _cond, _format, ##_args ) && __TERMINATE() )

#endif /* qassert__h */
