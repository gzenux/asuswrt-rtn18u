/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Displaying debugging, warning, and fatal error messages;
   sending messages to the system log.

   <keywords debugging messages, warning messages, error messages,
   message/debugging, message/warning, message/error, system log,
   log/system, utility functions/debugging, debug level>


   * Debugging Macros *

   USAGE:

      At the beginning of your C file, define the name of the module that
      the file belongs to as follows:

      <PRE>
      #define SSH_DEBUG_MODULE "ModuleName"
      </PRE>

      ModuleName consist of company name, product, module and submodule
      names. For example SshIpsecIpeDelete and SshIkePacketEncode.

      The module numbers are assigned in the sshdmod.h file and the
      mapping from numbers to names is found in the sshdmod.c file.

      Use SSH_TRACE, SSH_DEBUG and SSH_HEAVY_DEBUG to write a debug
      message. SSH_TRACE is compiled always in. SSH_DEBUG is compiled if
      DEBUG_LIGHT is defined, and SSH_HEAVY_DEBUG is compiled if
      DEBUG_HEAVY is defined.

      The correct way to call the macros is (SSH_TRACE works as an example):

      <PRE>
      SSH_TRACE([debug type define], ([format], [args], ...));
      </PRE>

      [debug type define] is one of the defines below (see DEBUG LEVELS).
      It is mapped into the debug level this message belongs to (zero
      most commonly viewed). [format] and [args] are passed to
      ssh_snprintf. See DEBUG LEVELS below for details.

      ssh_debug_initialize [see sshdmod.h] must be called in the
      beginning of the application.

      The debugging message will automatically include the file name and
      line number of the debugging macro. With some compilers, also the
      function name will be included.

      Use SSH_PRECOND(expr), SSH_POSTCOND(expr), SSH_ASSERT(expr) and
      SSH_INVARIANT(expr) to check that the evaluated value of `expr' is
      non-zero. If `expr' evaluates to zero, the program aborts
      immediately with a descriptive error message. Do not include in
      `expr' anything that causes side-effects, because these macros will
      be enabled only if DEBUG_LIGHT is defined. If DEBUG_LIGHT is not
      defined, SSH_PRECOND(expr) does nothing. In particular, it does NOT
      evaluate `expr', and this can change the behaviour of your code if
      `expr' contains statements with side-effects.

      Basically these four are the same macro, but they should be used in
      the following contexts:

      * SSH_PRECOND(...) is used to check at the beginning of a function
        that the arguments given to the function are in their ranges, and
        that the system in general is in a state where running the code
        of the function is allowable.

      * SSH_POSTCOND(...) is used to check that after the execution of a
        function's code the system is left in consistent state and the
        return value is in correct relation with the arguments.

      * SSH_INVARIANT(...) is used exclusively in for- and while-loops.
        It is used to check that a certain invariant holds for all
        iterations.

      * SSH_ASSERT(...) is a generic assert to be used when none of the
        three above can be used.

      * SSH_VERIFY(expr) will be _always_ compiled. -DNDEBUG,
        -DDEBUG_LIGHT and -DDEBUG_HEAVY do not have, in particular, any
        effect on it. SSH_VERIFY(expr) is roughly equivalent to

      <PRE>
        if (!(expr)) ssh_fatal("expr barfed")
      </PRE>

      * SSH_NOTREACHED barfs immediately if the place where
        SSH_NOTREACHED appears is actually reached during execution.
        SSH_NOTREACHED is not compiled unless DEBUG_LIGHT is defined. Here
        are simple examples:

   <PRE>
      int array_sum(int *array, int array_size)
      {
        int sum = 0;
        int i;

        SSH_PRECOND(array != NULL);
        SSH_PRECOND(array_size >= 1);

        for (i = 0; i < array_size; i++)
        {
          sum += array[i];
          SSH_INVARIANT(sum >= array[i]);
        }

        SSH_POSTCOND(i == array_size);
        return sum;
      }

      {
        ...
        SSH_VERIFY((ptr = get_ptr_from_somewhere()) != NULL);
        ...
      }

      {
        ...
        switch (zap)
          {
         case 1: goo(); break;
         case 2: foo(); break;
         default:
             SSH_NOTREACHED;
          }
        ...
      }
   </PRE>


   * Debug Levels *

      Not to be used inside loops:

      0) Software malfunctions

      1)

      2) (0-2 should also be logged using log-event)

      3) External non-fatal high level errors
          - incorrect format received from an outside source
          - failed negotiation

      4) Positive high level info
          - succeeded negotiation

      5) Start of a high or middle level operation
          - start of a negotiation
          - opening of a device
          - not to be used by functions which are called from inside loops

      Can be used inside loops:

      6) Uncommon situations which might be caused by a bug

      7) Nice-to-know info
          - Entering or exiting a function
          - A result of a low level operation

      8) Data block dumps
          - hash
          - keys
          - certificates
          - other non-massive data blocks

      9) Protocol packet dumps
          - TCP
          - UDP
          - ESP
          - AH

      10) Mid-results
          - inside loops
          - non-final results

      11-15) For programmers own debug use
          - own discretion
          - needed only by a person doing bughunt
*/

#ifndef SSHDEBUG_H
#define SSHDEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

/* *********************************************************************
 * Internal definitions
 * *********************************************************************/

/* Internal prototypes. */
char *ssh_debug_format(const char *fmt, ...)
       __ssh_printf_attribute__ ((format (printf, 1, 2)));
void ssh_debug_output(int level, const char *file, unsigned int line,
                      const char *module, const char *function, char *message);
Boolean ssh_debug_enabled(const char *module, int level);
void ssh_debug_hexdump(int level, const char *file, unsigned int line,
                       const char *module, const char *function,
                       size_t offset, const unsigned char *buf, size_t len);

void ssh_generic_assert(const char *expression,
                       const char *file, unsigned int line,
                        const char *module,
                        const char *function, int type)
  __ssh_noreturn__;

void ssh_debug_change_indentation(int change);


/* *********************************************************************
 * Debugging macros
 * *********************************************************************/

#ifdef __GNUC__
#define SSH_DEBUG_FUNCTION __FUNCTION__
#else /* __GNUC__ */
/* Visual Studio 2003 and later support __FUNCTION__ macro */
#if defined(_MSC_VER) && (_MSC_VER >= 1400)
#define SSH_DEBUG_FUNCTION __FUNCTION__
#else
#define SSH_DEBUG_FUNCTION NULL
#endif /* _MSC_VER */
#endif /* __GNUC__ */

#ifndef SSH_DEBUG_COMPILE_TIME_MAX_LEVEL
#define SSH_DEBUG_COMPILE_TIME_MAX_LEVEL 999999
#endif

/* True if tracing of `level'  messages is enabled for this module. */
#define SSH_TRACE_ENABLED(level)                        \
  ((SSH_DEBUG_COMPILE_TIME_MAX_LEVEL == 999999 ||       \
    (level) <= SSH_DEBUG_COMPILE_TIME_MAX_LEVEL) &&     \
   ssh_debug_enabled(SSH_DEBUG_MODULE, (level)))

/* Outputs a debug message.  This macro is always compiled into the binary. */
#define SSH_TRACE(level, varcall)                                       \
  do                                                                    \
  {                                                                     \
    if (SSH_TRACE_ENABLED(level))                                       \
      {                                                                 \
        ssh_debug_output((level), __FILE__, __LINE__, SSH_DEBUG_MODULE, \
                         SSH_DEBUG_FUNCTION,                            \
                         ssh_debug_format varcall);                     \
                                                                        \
      }                                                                 \
  }                                                                     \
  while (0)

/* Outputs a debug message with hex dump.  This macro is always compiled
   into the binary.
   char buf[10];

   SSH_TRACE_HEXDUMP(1,
                     ("Buffer (%d bytes):", sizeof(buf)),
                     buf, sizeof(buf)); */

#define SSH_TRACE_HEXDUMP(level, varcall, buf, len)                     \
  do                                                                    \
  {                                                                     \
    if (SSH_TRACE_ENABLED(level))                                       \
      {                                                                 \
        ssh_debug_output((level), __FILE__, __LINE__, SSH_DEBUG_MODULE, \
                         SSH_DEBUG_FUNCTION,                            \
                         ssh_debug_format varcall);                     \
        ssh_debug_hexdump((level), __FILE__, __LINE__,                  \
                          SSH_DEBUG_MODULE,                             \
                          SSH_DEBUG_FUNCTION,0, (buf), (len));          \
      }                                                                 \
  }                                                                     \
  while (0)

/* Check assertions. SSH_PRECOND, SSH_POSTCOND, SSH_ASSERT, SSH_INVARIANT
   and SSH_NOTREACHED are compiled only if DEBUG_LIGHT is defined.
   SSH_VERIFY is compiled always. */

#define _SSH_GEN_ASSERT(expr, type)                             \
  (SSH_PREDICT_TRUE((expr)) ?                                   \
  (void) 0 :                                                    \
  (void) ssh_generic_assert(                                    \
          #expr, __FILE__, __LINE__,                            \
          SSH_DEBUG_MODULE, SSH_DEBUG_FUNCTION, (type)))

#define SSH_VERIFY(expr)        _SSH_GEN_ASSERT(expr, 5)

#ifdef DEBUG_LIGHT
#define SSH_PRECOND(expr)       _SSH_GEN_ASSERT(expr, 0)
#define SSH_POSTCOND(expr)      _SSH_GEN_ASSERT(expr, 1)
#define SSH_ASSERT(expr)        _SSH_GEN_ASSERT(expr, 2)
#define SSH_INVARIANT(expr)     _SSH_GEN_ASSERT(expr, 3)
#define SSH_NOTREACHED          _SSH_GEN_ASSERT(0,    4)
#define SSH_ELSE_NOTREACHED     else SSH_NOTREACHED
#else
#ifdef __COVERITY__
#define SSH_PRECOND(expr)       _SSH_GEN_ASSERT(expr, 0)
#define SSH_POSTCOND(expr)      _SSH_GEN_ASSERT(expr, 1)
#define SSH_ASSERT(expr)        _SSH_GEN_ASSERT(expr, 2)
#define SSH_INVARIANT(expr)     _SSH_GEN_ASSERT(expr, 3)
#define SSH_NOTREACHED          _SSH_GEN_ASSERT(0,    4)
#define SSH_ELSE_NOTREACHED     else SSH_NOTREACHED
#else  /* __COVERITY__ */
#define SSH_PRECOND(x)          ((void) 0)
#define SSH_POSTCOND(x)         ((void) 0)
#define SSH_ASSERT(x)           ((void) 0)
#define SSH_INVARIANT(x)        ((void) 0)
#define SSH_NOTREACHED          { do {} while (0); }
#define SSH_ELSE_NOTREACHED     { do {} while (0); }
#endif /* __COVERITY__ */
#endif

#ifdef DEBUG_HEAVY
#define SSH_HEAVY_PRECOND(expr)       _SSH_GEN_ASSERT(expr, 0)
#define SSH_HEAVY_POSTCOND(expr)      _SSH_GEN_ASSERT(expr, 1)
#define SSH_HEAVY_ASSERT(expr)        _SSH_GEN_ASSERT(expr, 2)
#define SSH_HEAVY_INVARIANT(expr)     _SSH_GEN_ASSERT(expr, 3)
#else
#define SSH_HEAVY_PRECOND(x)          ((void) 0)
#define SSH_HEAVY_POSTCOND(x)         ((void) 0)
#define SSH_HEAVY_ASSERT(x)           ((void) 0)
#define SSH_HEAVY_INVARIANT(x)        ((void) 0)
#endif

/* SSH_DEBUG is compiled in only if DEBUG_LIGHT is defined. */
#ifdef DEBUG_LIGHT
#define SSH_DEBUG(level, varcall) SSH_TRACE((level), varcall)
#define SSH_DEBUG_HEXDUMP(level, varcall, buf, len) \
     SSH_TRACE_HEXDUMP((level), varcall, (buf), (len))
#define SSH_DEBUG_ENABLED(level) SSH_TRACE_ENABLED(level)
#else
#define SSH_DEBUG(level, varcall) do {} while (0)
#define SSH_DEBUG_HEXDUMP(level, varcall, buf, len) do {} while (0)
#define SSH_DEBUG_ENABLED(level) 0
#endif

/* DEBUG_HEAVY is compiled in only if DEBUG_HEAVY is defined. */
#ifdef DEBUG_HEAVY
#define SSH_HEAVY_DEBUG(level, varcall) SSH_TRACE((level), varcall)
#define SSH_HEAVY_DEBUG_HEXDUMP(level, varcall, buf, len) \
     SSH_TRACE_HEXDUMP((level), varcall, (buf), (len))
#define SSH_HEAVY_DEBUG_ENABLED(level) SSH_TRACE_ENABLED(level)
#else
#define SSH_HEAVY_DEBUG(level, varcall) do {} while (0)
#define SSH_HEAVY_DEBUG_HEXDUMP(level, varcall, buf, len) do {} while (0)
#define SSH_HEAVY_DEBUG_ENABLED(level) 0
#endif

/* SSH_DEBUG_INDENT is compiled in only if DEBUG_LIGHT is defined. */
#ifdef DEBUG_LIGHT
#define SSH_DEBUG_INDENT ssh_debug_change_indentation(2)
#define SSH_DEBUG_UNINDENT ssh_debug_change_indentation(-2)
#define SSH_DEBUG_INDENT_N(n) ssh_debug_change_indentation(n)
#define SSH_DEBUG_UNINDENT_N(n) ssh_debug_change_indentation(-n)
#else
#define SSH_DEBUG_INDENT do {} while(0)
#define SSH_DEBUG_UNINDENT  do {} while(0)
#define SSH_DEBUG_INDENT_N(n) do {} while(0)
#define SSH_DEBUG_UNINDENT_N(n)  do {} while(0)
#endif

/** Sets the debugging level for the named module.  Module names are
    case-sensitive, and the name may contain '*' and '?' as wildcards.
    Later assignments will override earlier ones if there is overlap. */
void ssh_debug_set_module_level(const char *module, unsigned int level);

/** Gets the debugging level of a module, or the global level if set */
int ssh_debug_get_module_level(const char *module);

/** Sets the debugging levels for several modules based on a string.
    The string is a comma-separated list of level assignments of the form
    "pattern=level".  Later assignments will override earlier ones if there
    is overlap. */
void ssh_debug_set_level_string(const char *string);

/** Sets the debugging level for all modules. */
void ssh_debug_set_global_level(unsigned int level);

/** Uninitialize the debug module to its initial state and free all
    allocated memory. Call this before exiting the program. */
void ssh_debug_uninit(void);

/** Stops debugging the modules. You can activate the modules
    again with ssh_debug_set_level_string function. */
void ssh_debug_clear_modules(void);

/** Sets the formatting string. If `override' is TRUE the string set
    will override one defined in UNIX environment. If `override' is
    FALSE the version from environment will have preference when set.
    If no format string is set a reasonable default is used with
    override naturally FALSE.

    The pointer given to ssh_debug_set_format_string must remain valid
    until the program exits or can be ensured in some other way that no
    more instances of SSH_TRACE, SSH_DEBUG and SSH_TRACE_HEXDUMP,
    SSH_VERIFY, SSH_PRECOND, SSH_POSTCOND, SSH_ASSERT, SSH_INVARIANT,
    SSH_NOTREACHED and possibly other similar debugging macros will be
    encountered before the program exits.  This is reasonable because
    it is assumed that if the string is set programmatically it is set
    from the argv[] list of the program or from a constant. In any
    other case dynamic allocation can be used.

    IMPORTANT NOTE: The format string cannot be changed during program
    execution. When the first debug message is printed the format
    string is compiled into an internal data structure for
    efficiency. Therefore this call will also have effect only before
    ANY debugging output has taken place.  */

void ssh_debug_set_format_string(const char *string, Boolean override);


/* *********************************************************************
 * Functions for debugging, warning, and fatal error messages
 * *********************************************************************/

/** Outputs a warning message. */
void ssh_warning(const char *fmt, ...)
       __ssh_printf_attribute__ ((format (printf, 1, 2)));

/** Outputs a debugging message. */
void ssh_debug(const char *fmt, ...)
       __ssh_printf_attribute__ ((format (printf, 1, 2)));

/** Outputs a fatal error message.  This function never returns. This function
    can be called also from other thread than SSH main thread. */
void ssh_fatal(const char *fmt, ...)
  __ssh_printf_attribute__ ((format (printf, 1, 2)))
  __ssh_noreturn__;

/** This type represents a function used to intercept debugging, warning,
    or fatal error messages. */
typedef void (*SshErrorCallback)(const char *message, void *context);

/** Defines callbacks that will receive the debug, warning, and fatal error
    messages.  Any of the callbacks can be NULL to specify default
    handling. */
void ssh_debug_register_callbacks(SshErrorCallback fatal_callback,
                                  SshErrorCallback warning_callback,
                                  SshErrorCallback debug_callback,
                                  void *context);

#ifndef KERNEL
/**
  Writes a string to ``stream'', so that even if ``stream'' is in
  non-blocking mode, all the data is written. You can use this in the
  application callbacks (above), to make sure that e.g. debug or
  warnings messages are not malformed or lost.
*/
void ssh_debug_print(FILE *stream, const char *buf);
#endif /* KERNEL */

/* *********************************************************************
 * Functions for logging data to the system log
 * *********************************************************************/

/** Log facility definitions.  Log facility identifies the subsystem that
    the message relates to; the platform-specific logging subsystem may e.g.
    direct messages from different facilities to different logs. */
typedef enum {
  /** The message is related to user authentication. */
  SSH_LOGFACILITY_AUTH,

  /** The message is related to security (other than authentication). */
  SSH_LOGFACILITY_SECURITY,

  /** The message is from a system daemon or service process running in
      the background. */
  SSH_LOGFACILITY_DAEMON,

  /** The message is from a normal program interacting with the user. */
  SSH_LOGFACILITY_USER,

  /** The message is related to the e-mail subsystem. */
  SSH_LOGFACILITY_MAIL,

  SSH_LOGFACILITY_LOCAL0,
  SSH_LOGFACILITY_LOCAL1,
  SSH_LOGFACILITY_LOCAL2,
  SSH_LOGFACILITY_LOCAL3,
  SSH_LOGFACILITY_LOCAL4,
  SSH_LOGFACILITY_LOCAL5,
  SSH_LOGFACILITY_LOCAL6,
  SSH_LOGFACILITY_LOCAL7
} SshLogFacility;

/** Log message severity definitions.  These identify the severity of the
    message. */
typedef enum {
  /** The message is information, and no action needs to be taken. */
  SSH_LOG_INFORMATIONAL,

  /** The message may indicate a significant event, but no action needs
      to be taken.  These might be summarized in a daily report. */
  SSH_LOG_NOTICE,

  /** The message is a warning about a potential problem. */
  SSH_LOG_WARNING,

  /** The message reports an error condition that probably needs attention. */
  SSH_LOG_ERROR,

  /** The message reports a critical error condition that needs immediate
      attention. */
  SSH_LOG_CRITICAL
} SshLogSeverity;

/** Sends a message to the system log.  The message is actually sent to the
    log callback if one is defined; otherwise, an implementation-specific
    mechanism is used. */
void ssh_log_event(SshLogFacility facility, SshLogSeverity severity,
                   const char *fmt, ...)
       __ssh_printf_attribute__ ((format (printf, 3, 4)));

/** This type defines the callback function that can be used to send
    messages to the system log. */
typedef void (*SshLogCallback)(SshLogFacility facility,
                               SshLogSeverity severity,
                               const char *message,
                               void *context);

/** Sets the callback for processing log messages.  All log messages will
    be passed to this function instead of the default function.  NULL specifies
    to use the default function. */
void ssh_log_register_callback(SshLogCallback log_callback,
                               void *context);

/** Returns the current log callback and its context. */
void ssh_log_get_callback(SshLogCallback *log_cb_return,
                          void **context_return);

/* *********************************************************************
 *   DEBUG LEVELS
 * *********************************************************************/

/* *********************************************************************
 * Debug type definitions for debug level mapping
 * *********************************************************************/

/* Use debug code definitions below, not the debug level numbers
   (except 11-15). */

/** Software malfunction. */
#define SSH_D_ERROR  0

/** Software failure, but caused by a packet coming from network. */
#define SSH_D_NETFAULT 3

/** Data formatted incorrectly coming from a network or other outside source.*/
#define SSH_D_NETGARB 3

/** Non-fatal failure in a high or middle-level operation. */
#define SSH_D_FAIL 3

/** Uncommon situation. */
#define SSH_D_UNCOMMON 6

/** Success in a high-level operation. */
#define SSH_D_HIGHOK 4

/** Success in a middle-level operation. */
#define SSH_D_MIDOK 7

/** Success in a low-level operation. */
#define SSH_D_LOWOK 9

/** Start of a high-level operation. */
#define SSH_D_HIGHSTART 5

/** Start of a middle-level operation. */
#define SSH_D_MIDSTART 8

/** Start of a low-level operation. */
#define SSH_D_LOWSTART 10

/** Nice-to-know information. */
#define SSH_D_NICETOKNOW 7

/** Data block dump. */
#define SSH_D_DATADUMP 8

/** Packet dump. */
#define SSH_D_PCKDMP 9

/** Middle result of an operation, loop-internal information. */
#define SSH_D_MIDRESULT 10

/** Programmer's own information for first version testing. */
#define SSH_D_MY1 11
#define SSH_D_MY2 12
#define SSH_D_MY3 13
#define SSH_D_MY4 14
#define SSH_D_MY5 15
#define SSH_D_MY 15

#ifdef __cplusplus
}
#endif

#endif /* SSHDEBUG_H */
