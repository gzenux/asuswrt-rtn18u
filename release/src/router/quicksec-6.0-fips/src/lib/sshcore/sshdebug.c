/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Displaying debugging, warning, and fatal error messages.
   Sending messages to the system log.
*/

#include "sshincludes.h"

#ifdef VXWORKS
#include "intLib.h"
#endif /* VXWORKS */

/* We have real globals in the kernel. */
#ifdef SSH_GLOBALS_EMULATION
#undef SSH_GLOBALS_EMULATION
#endif /* not SSH_GLOBALS_EMULATION */

#include "sshdebug.h"
#include "sshmatch.h"
#include "sshdsprintf.h"
#include "sshglobals.h"

/* Be very careful in calling debugging output from the debugging
   module itself. Careless introduction of debugging constructs could
   lead to a recursive loop. Do not add them if you do not know what
   you are doing.

   Here is a comprehensive list of debugging constructs appearing in
   the module itself:

   1. SSH_ASSERT in ssh_debug_output.
*/

#define SSH_DEBUG_MODULE "SshDebug"

#ifdef WINDOWS
#ifndef KERNEL
#include <tchar.h>
#endif
#endif /* WINDOWS */

#if defined(__GNUC__) || defined(_MSC_VER)
#define SSH_DEBUG_HAVE_FUNCTION_NAMES
#endif /* __GNUC__ || _MSC_VER */

#ifdef KERNEL
/* If compiling into a kernel, library functions are not necessarily
   usable. It is conservative to assume that indeed none of them
   are. */

#undef HAVE_GETENV
#undef HAVE_GETEUID
#undef HAVE_GETHOSTNAME
#undef HAVE_GETPID
#undef HAVE_GETUID
#undef HAVE_LOCALTIME
#undef HAVE_NANOSLEEP
#undef HAVE_SLEEP
#undef HAVE_USLEEP

#endif /* KERNEL */

/* If no debugging is enabled, take a tiny version of this module. */
#ifndef DEBUG_LIGHT
#ifndef TINY_DEBUG
#define TINY_DEBUG
#endif /* not TINY_DEBUG */
#endif /* not DEBUG_LIGHT */

#ifndef TINY_DEBUG
#define WANT_DEBUG_PARSER
#define WANT_COMPLEX_FORMATS
#endif /* TINY_DEBUG */

/* Include function name in the default format only if it is really
   available. */

#ifdef WANT_DEBUG_PARSER
#ifdef SSH_DEBUG_HAVE_FUNCTION_NAMES
#define SSH_DEBUG_DEFAULT_FMT "%m/%s:%n/%f: %M"
#else /* SSH_DEBUG_HAVE_FUNCTION_NAMES */
#define SSH_DEBUG_DEFAULT_FMT "%m/%s:%n: %M"
#endif /* SSH_DEBUG_HAVE_FUNCTION_NAMES */
#endif /* WANT_DEBUG_PARSER */

/* Define as macros, because ctype functions are not available in the
   kernel. */
#undef isdigit
#define isdigit(ch) ((ch) >= '0' && (ch) <= '9')
#undef isspace
#define isspace(ch) ((ch) == ' ' || (ch) == '\t' || (ch) == '\n')

/* Size of buffers used in formatting the messages in ssh_debug functions. */
#ifdef KERNEL
#define SSH_DEBUG_BUFFER_SIZE 256
#else /* KERNEL */
#define SSH_DEBUG_BUFFER_SIZE 8192
#endif /* KERNEL */


/* Data structure for module-specific debugging level settings. */
typedef struct SshDebugModuleLevelRec {
  /* Pointer to the next module-specific level setting. */
  struct SshDebugModuleLevelRec *next;

  /* Pattern specifying the modules for which this level is used.  The
     pattern may contain '*' and '?' as special characters.  It is allocated
     using ssh_xfree. */
  char *module;

  /* Debugging level for the modules whose name matches the given pattern. */
  int level;
} *SshDebugModuleLevel;

/* Prototypes */
void
ssh_debug_formatted(int level, const char *file, unsigned int line,
                    const char *module, const char *function,
                    unsigned char *buf);

#ifndef SSH_DEBUG_EXTERNAL
static void ssh_debug_cleanup_items(void);
#endif /* SSH_DEBUG_EXTERNAL */

/***************************************************************************
 * Global variables section
 */
SSH_GLOBAL_DECLARE(int, ssh_debug_initialized);
#define ssh_debug_initialized SSH_GLOBAL_USE(ssh_debug_initialized)
SSH_GLOBAL_DEFINE(int, ssh_debug_initialized);

/* The global debugging level.  This is used when no per-module level
   can be found for a particular module. */
SSH_GLOBAL_DECLARE(int, ssh_debug_global_level);
#define ssh_debug_global_level SSH_GLOBAL_USE(ssh_debug_global_level)
SSH_GLOBAL_DEFINE(int, ssh_debug_global_level);

/* Per-module debugging level settings.  These override the global
   level on a per-module basis.  The module name can be a pattern containing
   asterisk '*' characters as wildcards.  The settings are applied in the
   order in which they are in the list, first match overriding later
   matches. */
SSH_GLOBAL_DECLARE(SshDebugModuleLevel, ssh_debug_module_levels);
#define ssh_debug_module_levels SSH_GLOBAL_USE(ssh_debug_module_levels)
SSH_GLOBAL_DEFINE(SshDebugModuleLevel, ssh_debug_module_levels);

SSH_GLOBAL_DECLARE(int, ssh_debug_indent_level);
#define ssh_debug_indent_level SSH_GLOBAL_USE(ssh_debug_indent_level)
SSH_GLOBAL_DEFINE(int, ssh_debug_indent_level);

SSH_GLOBAL_DECLARE(SshErrorCallback, ssh_debug_debug_callback);
#define ssh_debug_debug_callback SSH_GLOBAL_USE(ssh_debug_debug_callback)
SSH_GLOBAL_DECLARE(void *, ssh_debug_error_context);
#define ssh_debug_error_context SSH_GLOBAL_USE(ssh_debug_error_context)

/* Global format parameters. */
typedef struct SshDebugFormatItemRec *SshDebugFormatItem;

SSH_GLOBAL_DECLARE(SshDebugFormatItem, ssh_debug_format_items);
#define ssh_debug_format_items SSH_GLOBAL_USE(ssh_debug_format_items)
SSH_GLOBAL_DEFINE(SshDebugFormatItem, ssh_debug_format_items);

SSH_GLOBAL_DECLARE(int, ssh_debug_format_needs_time);
#define ssh_debug_format_needs_time SSH_GLOBAL_USE(ssh_debug_format_needs_time)
SSH_GLOBAL_DEFINE(int, ssh_debug_format_needs_time);

SSH_GLOBAL_DECLARE(int, ssh_debug_msg_number);
#define ssh_debug_msg_number SSH_GLOBAL_USE(ssh_debug_msg_number)
SSH_GLOBAL_DEFINE(int, ssh_debug_msg_number);

#ifdef WANT_COMPLEX_FORMATS
SSH_GLOBAL_DECLARE(int, ssh_debug_format_wrapcol);
#define ssh_debug_format_wrapcol SSH_GLOBAL_USE(ssh_debug_format_wrapcol)
SSH_GLOBAL_DEFINE(int, ssh_debug_format_wrapcol);

SSH_GLOBAL_DECLARE(int, ssh_debug_format_wrapindent);
#define ssh_debug_format_wrapindent SSH_GLOBAL_USE(ssh_debug_format_wrapindent)
SSH_GLOBAL_DEFINE(int, ssh_debug_format_wrapindent);
#endif /* WANT_COMPLEX_FORMATS */

#ifdef WANT_DEBUG_PARSER
typedef const char *SshConstCharPtr;
SSH_GLOBAL_DECLARE(SshConstCharPtr, ssh_debug_default_format);
#define ssh_debug_default_format SSH_GLOBAL_USE(ssh_debug_default_format)
SSH_GLOBAL_DEFINE(SshConstCharPtr, ssh_debug_default_format);

SSH_GLOBAL_DECLARE(Boolean, ssh_debug_format_override_environment);
#define ssh_debug_format_override_environment \
   SSH_GLOBAL_USE(ssh_debug_format_override_environment)
SSH_GLOBAL_DEFINE(Boolean, ssh_debug_format_override_environment);
#endif /* WANT_DEBUG_PARSER */


/* The maximum width of displayed indentation. ssh_debug_indent_level
   can grow beyond this but the growth is not reflected on the
   display. However, unindent works correctly as expected. */
#define SSH_DEBUG_MAX_INDENT 40

/* This is not exported from globals. It's sole purpose is to make
   globals and debugging interoperate. It should not be needed
   elsewhere. */
#ifdef SSH_GLOBALS_EMULATION
Boolean ssh_global_check(const char *str);
#endif

/* Initializes error system if not done already. */
void ssh_error_maybe_initialize(void);

/* Initializes debug system if not done already. */
static void
ssh_debug_maybe_initialize(void)
{
  if
#ifdef SSH_GLOBALS_EMULATION
    /* On emulated environments the check is sufficient proof of
       initialization, the value can (does not have to) be
       ignored. */
    (!ssh_global_check("ssh_debug_initialized"))
#else
    (!ssh_debug_initialized)
#endif
    {
#ifndef SSH_DEBUG_EXTERNAL
      ssh_error_maybe_initialize();
#endif /* SSH_DEBUG_EXTERNAL */

      SSH_GLOBAL_INIT(ssh_debug_initialized, 1);

#ifdef SSH_DEBUG_EXTERNAL
      SSH_GLOBAL_INIT(ssh_debug_global_level, 999999);
#else /* SSH_DEBUG_EXTERNAL */
      SSH_GLOBAL_INIT(ssh_debug_global_level, 0);
#endif /* SSH_DEBUG_EXTERNAL */

      SSH_GLOBAL_INIT(ssh_debug_module_levels, NULL);
      SSH_GLOBAL_INIT(ssh_debug_indent_level, 0);

      SSH_GLOBAL_INIT(ssh_debug_format_items, NULL);
      SSH_GLOBAL_INIT(ssh_debug_msg_number, 0);

#ifdef WANT_COMPLEX_FORMATS
      SSH_GLOBAL_INIT(ssh_debug_format_wrapcol, 0);
      SSH_GLOBAL_INIT(ssh_debug_format_wrapindent, 0);
#endif /* WANT_COMPLEX_FORMATS */

#ifdef WANT_DEBUG_PARSER
      SSH_GLOBAL_INIT(ssh_debug_default_format, SSH_DEBUG_DEFAULT_FMT);
      SSH_GLOBAL_INIT(ssh_debug_format_override_environment, FALSE);
#endif /* WANT_DEBUG_PARSER */

    }
}

/* Formats an output string according to the sprintf-style variable-
   length argument list, and returns a string allocated with ssh_xmalloc
   containing the value.  The caller should free the string with ssh_xfree
   when no longer needed. */

char *ssh_debug_format(const char *format, ...)
{
  va_list args;
  unsigned char *p;

  va_start(args, format);
  ssh_dvsprintf(&p, format, args);
  va_end(args);

  return (char *) p;
}

/* Returns TRUE if debugging has been enabled for the given module
   at the given level.  Otherwise returns FALSE. */

Boolean ssh_debug_enabled(const char *module, int level)
{
#ifdef SSH_DEBUG_EXTERNAL
  return TRUE;
#else /* SSH_DEBUG_EXTERNAL */
  SshDebugModuleLevel dl;
  int debug_level;

  if (level > SSH_DEBUG_COMPILE_TIME_MAX_LEVEL)
    {
      return FALSE;
    }

  ssh_debug_maybe_initialize();

  /* Default to the global level. */
  debug_level = ssh_debug_global_level;

  /* Check for any per-module overrides. */
  for (dl = ssh_debug_module_levels; dl; dl = dl->next)
    {
      if (ssh_match_pattern(module, dl->module))
        {
          debug_level = dl->level;
          break;
        }
    }

  /* Message should be printed if it is at a level below or equal to the
     current level. */
  return (level <= debug_level);
#endif /* SSH_DEBUG_EXTERNAL */
}

int ssh_debug_get_module_level(const char *module)
{
  SshDebugModuleLevel dl;
  int debug_level;

  ssh_debug_maybe_initialize();

  /* Default to the global level. */
  debug_level = ssh_debug_global_level;

  /* Check for any per-module overrides. */
  for (dl = ssh_debug_module_levels; dl; dl = dl->next)
    {
      if (ssh_match_pattern(module, dl->module))
        {
          debug_level = dl->level;
          break;
        }
    }

  return debug_level;
}

/* Sets the global debugging level.  This overrides any previous per-module
   settings. */

void ssh_debug_set_global_level(unsigned int level)
{
  SshDebugModuleLevel dl;

  ssh_debug_maybe_initialize();

  /* Set the global level. */
  ssh_debug_global_level = level;

  /* Clear (free) any per-module settings. */
  while (ssh_debug_module_levels)
    {
      dl = ssh_debug_module_levels;
      ssh_debug_module_levels = dl->next;
      ssh_free(dl->module);
      ssh_free(dl);
    }
}

/* Sets the per-module debugging level for the given module.  The
   module name may contain wildcards ('*' and '?').  Any later
   setting overrides any previous settings for the matching modules. */

void ssh_debug_set_module_level(const char *module, unsigned int level)
{
  SshDebugModuleLevel dl;

  ssh_debug_maybe_initialize();

  /* Memory allocation failure on debug is ignored. */
  if (!(dl = ssh_malloc(sizeof(*dl))))
    return;

  if (!(dl->module = ssh_strdup(module)))
    {
      ssh_free(dl);
      return;
    }
  dl->level = level;
  dl->next = ssh_debug_module_levels;
  ssh_debug_module_levels = dl;
}

/* Uninitialize the debug module to its initial state and free all
   allocated memory. Call this before exiting the program. */

void ssh_debug_uninit(void)
{
  ssh_debug_clear_modules();
#ifndef SSH_DEBUG_EXTERNAL
  ssh_debug_cleanup_items();
#endif /* SSH_DEBUG_EXTERNAL */
}

/* Stops debugging the modules. You can activate the modules
   again with ssh_debug_set_level_string function. */

void ssh_debug_clear_modules(void)
{
  SshDebugModuleLevel p, n;

  ssh_debug_maybe_initialize();
  for (p = ssh_debug_module_levels; p != NULL; p = n)
    {
      n = p->next;
      ssh_free(p->module);
      ssh_free(p);
    }
  ssh_debug_module_levels = NULL;
}


/* Sets debugging levels as specified by the string.  The string
   is a comma-separated list of level assignments of the following format:
       pattern=level
   or  global=level
*/

void ssh_debug_set_level_string(const char *string)
{
  const char *name_start, *name_end;
  char *name;
  size_t name_len;
  long level_value;
  Boolean error;

#ifndef DEBUG_LIGHT
  {
    static int warned = 0;
    if (!warned)
      {




        warned = 1;
      }
  }
#endif /* !DEBUG_LIGHT */

  ssh_debug_maybe_initialize();
  while (*string)
    {
      error = FALSE;

      /* Skip whitespace */
      while (*string && isspace(*string))
        string++;

      /* Parse name */
      name_start = string;
      while (*string && !isspace(*string) && *string != '=' && *string != ',')
        string++;
      name_end = string;
      name_len = name_end - name_start;

      /* Skip whitespace */
      while (*string && isspace(*string))
        string++;

      level_value = -1;
      if (*string == '=')
        {
          string++;
          /* Skip whitespace */
          while (*string && isspace(*string))
            string++;

          if (isdigit(*string))
            {
              level_value = atoi(string);
              for (; *string && isdigit(*string); string++)
                ;
            }
          else
            {
              ssh_warning("ssh_debug_set_level_string: Invalid numeric "
                          "argument for %s", name_start);
              error = TRUE;
            }

          /* Skip whitespace */
          while (*string && isspace(*string))
            string++;
        }
      if (*string)
        {
          if (*string != ',')
            {
              if (!error)
                ssh_warning("ssh_debug_set_level_string: Ignored junk after "
                            "command : %s", string);
              while (*string && *string != ',')
                string++;
            }
          else
            {
              string++;
            }
        }

      if (name_len == 6 &&
          strncmp(name_start, "global", name_len) == 0)
        {
          if (level_value == -1)
            level_value = 0;
          ssh_debug_set_global_level((unsigned int)level_value);
        }
      else
        {
          if (level_value == -1)
            level_value = 0;
          if (name_len > 0 && isdigit(*name_start))
            {
              level_value = atoi(name_start);
              ssh_debug_set_global_level((unsigned int)level_value);
            }
          else
            {
              name = ssh_malloc(name_len + 1);

              if (name)
                {
                  memcpy(name, name_start, name_len);
                  name[name_len] = '\0';
                  ssh_debug_set_module_level(name, (unsigned int)level_value);
                  ssh_free(name);
                }
            }
        }
    }
}

/* Dumps the given memory block in hex to stderr, 16 bytes per line,
   prefixed with an offset and followed by an ascii representation
   (x for 32 < x < 127, '.' otherwise)

 offset__: 0001 0203 0405 0607 0809 0a0b 0c0d 0e0f  0123456789abcdef
*/

void ssh_debug_hexdump(int level, const char *file, unsigned int line,
                       const char *module, const char *function,
                       size_t offset, const unsigned char *data,
                       size_t buf_siz)
{
  size_t i, j, jmax;
  int c;
  unsigned char buf[100];

  if (data == NULL) buf_siz = 0;

  for (i = 0; i < buf_siz; i += 0x10)
    {
      ssh_snprintf(buf, sizeof(buf),
                   "%08x: ", (unsigned int)(i + offset));

      jmax = buf_siz - i;
      jmax = jmax > 16 ? 16 : jmax;

      for (j = 0; j < jmax; j++)
        {
          if ((j % 2) == 1)
            ssh_snprintf(buf + ssh_ustrlen(buf),
                         sizeof(buf) - ssh_ustrlen(buf),
                         "%02x ", (unsigned int)data[i+j]);
          else
            ssh_snprintf(buf + ssh_ustrlen(buf),
                         sizeof(buf) - ssh_ustrlen(buf),
                         "%02x", (unsigned int)data[i+j]);
        }
      for (; j < 16; j++)
        {
          if ((j % 2) == 1)
            ssh_snprintf(buf + ssh_ustrlen(buf),
                         sizeof(buf) - ssh_ustrlen(buf),
                         "   ");
          else
            ssh_snprintf(buf + ssh_ustrlen(buf),
                         sizeof(buf) - ssh_ustrlen(buf),
                         "  ");
        }

      ssh_snprintf(buf + ssh_ustrlen(buf),
                   sizeof(buf) - ssh_ustrlen(buf), " ");
      for (j = 0; j < jmax; j++)
        {
          c = data[i+j];
          c = c < 32 || c >= 127 ? '.' : c;
          ssh_snprintf(buf + ssh_ustrlen(buf),
                       sizeof(buf) - ssh_ustrlen(buf), "%c", c);
        }
      ssh_debug_formatted(level, file, line, module, function, buf);
    }
}

/* From sshfatal.c. */
#ifndef KERNEL
int ssh_debug_set_stream_unbuffered(FILE *stream);
void ssh_debug_print(FILE *stream, const char *buf);
#endif /* KERNEL */

#ifndef SSH_DEBUG_EXTERNAL
/* Outputs a formatted debugging message. */
void
ssh_debug_formatted(int level, const char *file, unsigned int line,
                    const char *module, const char *function,
                    unsigned char *buf)
{
  static int initd = 0;

  ssh_debug_maybe_initialize();
  if (!initd)
    {
      initd = 1;
#ifndef KERNEL
      ssh_debug_set_stream_unbuffered(stderr);
#endif /* not KERNEL */
    }
  /* Send the message to the registered callback for debug messages,
     or use default handling. */
  if (ssh_debug_debug_callback)
    {
      (*ssh_debug_debug_callback)((char *) buf, ssh_debug_error_context);
    }
  else
    {
#ifndef KERNEL
      ssh_debug_print(stderr, (char *) buf);
      ssh_debug_print(stderr, "\n");
#endif /* KERNEL */
    }
}
#endif /* SSH_DEBUG_EXTERNAL */

/* Outputs a debugging message. */

void ssh_debug(const char *fmt, ...)
{
  va_list va;
  unsigned char buf[SSH_DEBUG_BUFFER_SIZE];

  /* Format the message. */
  va_start(va, fmt);
  ssh_vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

  ssh_debug_formatted(0, __FILE__, __LINE__, "SshDebug", "ssh_debug", buf);
}

#ifndef SSH_DEBUG_EXTERNAL
/************************************************************************
 * Debug message formatting
 *
 */

/* Format item type identifiers. */

#define SSH_DEBUG_FORMAT_LEVEL          0
#define SSH_DEBUG_FORMAT_PID            1
#define SSH_DEBUG_FORMAT_MODULE         2
#define SSH_DEBUG_FORMAT_LINE           3
#define SSH_DEBUG_FORMAT_FUNC           4
#define SSH_DEBUG_FORMAT_FILE           5
#define SSH_DEBUG_FORMAT_MSG            6
#define SSH_DEBUG_FORMAT_LITERAL        7
#define SSH_DEBUG_FORMAT_MINUTES        8
#define SSH_DEBUG_FORMAT_HOURS          9
#define SSH_DEBUG_FORMAT_SECONDS       10
#define SSH_DEBUG_FORMAT_DAY           11
#define SSH_DEBUG_FORMAT_MONTH         12
#define SSH_DEBUG_FORMAT_YEAR          13
#define SSH_DEBUG_FORMAT_UID           14
#define SSH_DEBUG_FORMAT_EUID          15
#define SSH_DEBUG_FORMAT_NEWLINE       16
#define SSH_DEBUG_FORMAT_ORDINAL       17
#define SSH_DEBUG_FORMAT_TERMCONTROL   18
#define SSH_DEBUG_FORMAT_SLEEP         19
#define SSH_DEBUG_FORMAT_NOTHING       20
#define SSH_DEBUG_FORMAT_INDENT        21
#define SSH_DEBUG_FORMAT_MICRO_SECONDS 22

#define SSH_DEBUG_FORMAT_IF           100
#define SSH_DEBUG_FORMAT_END_IF       101
#define SSH_DEBUG_FORMAT_ELSE         102
#define SSH_DEBUG_FORMAT_ELSE_IF      103

#define SSH_DEBUG_FORMAT_IGNORE       200

/* Conditional types. */

/* 1. Compound conditionals. */

/* These connectives must have successive numbers. */

#define SSH_DEBUG_FORMAT_COND_NEG       0
#define SSH_DEBUG_FORMAT_COND_AND       1
#define SSH_DEBUG_FORMAT_COND_OR        2
#define SSH_DEBUG_FORMAT_COND_XOR       3
#define SSH_DEBUG_FORMAT_COND_IMPL      4
#define SSH_DEBUG_FORMAT_COND_NAND      5
#define SSH_DEBUG_FORMAT_COND_IMPL_R    6

#define SSH_DEBUG_FORMAT_FIRST_BIN_CONN 1
#define SSH_DEBUG_FORMAT_LAST_BIN_CONN  6

/* 2. Atomic conditionals. */

#define SSH_DEBUG_FORMAT_COND_MODNAME  10
#define SSH_DEBUG_FORMAT_COND_LEVELLT  11
#define SSH_DEBUG_FORMAT_COND_LEVELGT  12
#define SSH_DEBUG_FORMAT_COND_LEVELEQ  13
#define SSH_DEBUG_FORMAT_COND_MATCHMSG 14
#define SSH_DEBUG_FORMAT_COND_FUNCNAME 15
#define SSH_DEBUG_FORMAT_COND_FILENAME 16
#define SSH_DEBUG_FORMAT_COND_ROOT     17
#define SSH_DEBUG_FORMAT_COND_MAGIC    18

#define SSH_DEBUG_FORMAT_COND_NO_CONNECTIVE -1

/* Structure for building trees of conditional expressions. */

#ifdef WANT_COMPLEX_FORMATS

/* Include the typedef only if WANT_COMPLEX_FORMATS is used to detect
   inconsistencies in the conditional compilation of the debug
   system. */

typedef struct SshDebugConditionRec
{
  int type;
  union
  {
    char *string;
    int   number;
    struct
    {
      struct SshDebugConditionRec *cond1, *cond2;
    } subcond;
  } arg;
} *SshDebugCondition;

#endif /* WANT_COMPLEX_FORMATS */

/* Structure for building a list of formatting commands when the
   format string is parsed. */

struct SshDebugFormatItemRec
{
  struct SshDebugFormatItemRec *next;
  int type;
  char *arg;
  int numarg;

#ifdef WANT_COMPLEX_FORMATS
  int minwidth;
  int maxwidth;
  int align_right;
  SshDebugCondition condition;
  struct SshDebugFormatItemRec *jump;
#endif /* WANT_COMPLEX_FORMATS */

};

/* Structure for passing efficiently the arguments to ssh_debug_output
   to recursive evaluation of conditionals. */

/* Compile typedef only if the structure is really used to detect
   possible programming mistakes. */

#ifdef WANT_COMPLEX_FORMATS

typedef struct SshDebugOutputContextRec {
  int level;
  const char *file;
  unsigned int line;
  const char *module;
  const char *function;
  char *msg;
} *SshDebugOutputContext;

#endif /* WANT_COMPLEX_FORMATS */

#ifdef SSHDIST_PLATFORM_VXWORKS
#ifdef VXWORKS
#ifdef ENABLE_VXWORKS_RESTART_WATCHDOG
void ssh_debug_restart(void)
{
  ssh_debug_module_levels = NULL;
  ssh_debug_global_level = 0;
  ssh_debug_fatal_callback = NULL;
  ssh_debug_warning_callback = NULL;
  ssh_debug_debug_callback = NULL;
  ssh_debug_error_context = NULL;
  ssh_debug_log_callback = NULL;
  ssh_debug_log_context = NULL;
  ssh_debug_indent_level = 0;

  ssh_debug_format_items = NULL;
  ssh_debug_format_needs_time = 0;

#ifdef WANT_COMPLEX_FORMATS
  ssh_debug_format_wrapcol = 0;
  ssh_debug_format_wrapindent = 0;
#endif

#ifdef WANT_DEBUG_PARSER
  ssh_debug_default_format = SSH_DEBUG_DEFAULT_FMT;
  ssh_debug_format_override_environment = FALSE;
#endif

  ssh_debug_msg_number = 0;
}
#endif /* ENABLE_VXWORKS_RESTART_WATCHDOG */
#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */

/*************************************************************************
 *
 * Parser for debug strings starts here.
 * It is not compiled unless WANT_DEBUG_PARSER is defined,
 * which is by default unless KERNEL is defined.
 *
 */

#ifdef WANT_DEBUG_PARSER

/* Calculate jumps in a format command list after it has been built.
   Every 'IF', 'ELSEIF' and 'ELSE' is linked to the next 'ELSEIF',
   'ELSE' or 'ENDIF' (whichever appears first) on the same nesting
   depth.

   This is required only if WANT_COMPLEX_FORMATS is defined. */

#ifdef WANT_COMPLEX_FORMATS

static void ssh_debug_calculate_jumps(SshDebugFormatItem root)
{
  int depth;
  SshDebugFormatItem iter;

  for (; root != NULL; root = root->next)
    {
      root->jump = NULL;

      if (root->type == SSH_DEBUG_FORMAT_IF ||
          root->type == SSH_DEBUG_FORMAT_ELSE ||
          root->type == SSH_DEBUG_FORMAT_ELSE_IF)
        {
          iter = root->next;
          depth = 0;
          while (iter != NULL &&
                 (depth > 0 ||
                  (iter->type != SSH_DEBUG_FORMAT_ELSE_IF &&
                   iter->type != SSH_DEBUG_FORMAT_ELSE &&
                   iter->type != SSH_DEBUG_FORMAT_END_IF)))
            {
              iter = iter->next;
              if (iter->type == SSH_DEBUG_FORMAT_IF) depth++;
              if (iter->type == SSH_DEBUG_FORMAT_END_IF) depth--;
            }
          root->jump = iter;
        }
    }
}

#endif /* WANT_COMPLEX_FORMATS */

/* Find a string that is delimited between `bd' and `ed' that starts
   at `start' with `bd'. Write to `next' the pointer to the first
   character after the first `ed' found. Replace the first occurrence
   of `ed' with `\0', and write the pointer to the first character after
   `bd' to `arg'. In essence, `arg' contains the delimited string
   and `next' points after it. Return value is zero if no such delimited
   string can be found. In this case, `next' contains something
   unuseful. Non-zero return value designates success. */

static int ssh_debug_parse_arg_gen(char *start, char **next, char **arg,
                                   char bd, char ed)
{
  if (*start != bd) return 0;
  *arg = start + 1;
  while (*start != ed && *start != '\0') start++;
  if (*start == '\0') return 0;
  *start = '\0'; /* ) ==> \0 */
  *next = start + 1;
  return 1;
}

/* A shorthand for parsing a string delimited with parentheses. */

static int ssh_debug_parse_arg(char *start, char **next, char **arg)
{
  return ssh_debug_parse_arg_gen(start, next, arg, '(', ')');
}

#ifdef WANT_COMPLEX_FORMATS

/* Prototype required because we have two mutually recursive functions. */

static SshDebugCondition parse_condition(char **argptr);

/* parse_atomic_condition and parse_condition are two mutually recursive
   functions that perform top-down parsing of the conditional expressions.
   ssh_debug_parse_condition is the front-end.
   */

static SshDebugCondition parse_atomic_condition(char **argptr)
{
  SshDebugCondition c1, c2;
  char c;
  char *cond_arg;

  c = **argptr;

  (*argptr)++;

  switch (c)
    {
    case '(':
      c1 = parse_condition(argptr);
      if (**argptr != ')') return NULL;
      (*argptr)++;
      return c1;

    case '!':
      c1 = parse_atomic_condition(argptr);
      if (c1 == NULL) return NULL;
      if (!(c2 = ssh_malloc(sizeof(*c2))))
        {
          ssh_free(c1);
          return NULL;
        }
      c2->type = SSH_DEBUG_FORMAT_COND_NEG;
      c2->arg.subcond.cond1 = c1;
      return c2;

    case '*':
      if (!(c1 = ssh_malloc(sizeof(*c1))))
          return NULL;
      c1->type = SSH_DEBUG_FORMAT_COND_MAGIC;
      c1->arg.number = -2;
      return c1;

    case 'm':
    case 'M':
    case 'f':
    case 's':
      if (!ssh_debug_parse_arg(*argptr, argptr, &cond_arg))
        return NULL;

      if (!(c1 = ssh_malloc(sizeof(*c1))))
        return NULL;

      if (!(c1->arg.string = ssh_strdup(cond_arg)))
        {
          ssh_free(c1);
          return NULL;
        }
      switch (c)
        {
        case 'm': c1->type = SSH_DEBUG_FORMAT_COND_MODNAME; break;
        case 'M': c1->type = SSH_DEBUG_FORMAT_COND_MATCHMSG; break;
        case 'f': c1->type = SSH_DEBUG_FORMAT_COND_FUNCNAME; break;
        case 's': c1->type = SSH_DEBUG_FORMAT_COND_FILENAME; break;
        }
      return c1;

    case '<':
    case '>':
    case '=':
      if (!ssh_debug_parse_arg(*argptr, argptr, &cond_arg))
        return NULL;
      if (!(c1 = ssh_malloc(sizeof(*c1))))
        return NULL;

      c1->type = (c == '<' ? SSH_DEBUG_FORMAT_COND_LEVELLT :
                  c == '>' ? SSH_DEBUG_FORMAT_COND_LEVELGT :
                  SSH_DEBUG_FORMAT_COND_LEVELEQ);
      c1->arg.number = atoi(cond_arg);
      if (c1->arg.number < 0 || c1->arg.number > 1000)
      {
        ssh_free(c1);
        return NULL;
      }
      return c1;

    default:
      return NULL;
    }
}

static SshDebugCondition parse_condition(char **argptr)
{
  SshDebugCondition c1, c2, c3;
  int connective = SSH_DEBUG_FORMAT_COND_NO_CONNECTIVE;

  c1 = parse_atomic_condition(argptr);
  if (c1 == NULL) return NULL;

  switch (**argptr)
    {
    case '&': connective = SSH_DEBUG_FORMAT_COND_AND;    break;
    case '|': connective = SSH_DEBUG_FORMAT_COND_OR;     break;
    case '^': connective = SSH_DEBUG_FORMAT_COND_XOR;    break;
    case '~': connective = SSH_DEBUG_FORMAT_COND_NAND;   break;
    case '<': connective = SSH_DEBUG_FORMAT_COND_IMPL;   break;
    case '>': connective = SSH_DEBUG_FORMAT_COND_IMPL_R; break;
    }

  if (connective != SSH_DEBUG_FORMAT_COND_NO_CONNECTIVE)
    {
      (*argptr)++;
      c2 = parse_condition(argptr);
      if (c2 == NULL)
        {
          ssh_free(c1);
          return NULL;
        }

      if (!(c3 = ssh_malloc(sizeof(*c3))))
        {
          ssh_free(c1);
          ssh_free(c2);
          return NULL;
        }

      c3->type = connective;
      c3->arg.subcond.cond1 = c1;
      c3->arg.subcond.cond2 = c2;
      return c3;
    }

  return c1;
}

static void ssh_debug_free_condition(SshDebugCondition condition)
{
  switch (condition->type)
    {
    case SSH_DEBUG_FORMAT_COND_NEG:
      ssh_debug_free_condition(condition->arg.subcond.cond1);
      condition->arg.subcond.cond1 = NULL;
      break;
    case SSH_DEBUG_FORMAT_COND_AND:
    case SSH_DEBUG_FORMAT_COND_OR:
    case SSH_DEBUG_FORMAT_COND_XOR:
    case SSH_DEBUG_FORMAT_COND_NAND:
    case SSH_DEBUG_FORMAT_COND_IMPL:
    case SSH_DEBUG_FORMAT_COND_IMPL_R:
      ssh_debug_free_condition(condition->arg.subcond.cond1);
      condition->arg.subcond.cond1 = NULL;
      ssh_debug_free_condition(condition->arg.subcond.cond2);
      condition->arg.subcond.cond2 = NULL;
      break;
    case SSH_DEBUG_FORMAT_COND_MODNAME:
    case SSH_DEBUG_FORMAT_COND_MATCHMSG:
    case SSH_DEBUG_FORMAT_COND_FUNCNAME:
    case SSH_DEBUG_FORMAT_COND_FILENAME:
      ssh_free(condition->arg.string);
      break;
    case SSH_DEBUG_FORMAT_COND_LEVELLT:
    case SSH_DEBUG_FORMAT_COND_LEVELGT:
    case SSH_DEBUG_FORMAT_COND_LEVELEQ:
    case SSH_DEBUG_FORMAT_COND_ROOT:
    case SSH_DEBUG_FORMAT_COND_MAGIC:
    default:
      break;
    }
  ssh_free(condition);
}

static SshDebugCondition ssh_debug_parse_condition(char *arg)
{
  return parse_condition(&arg);
}

#endif /* WANT_COMPLEX_FORMATS */

/* ssh_debug_parse_format figures out the debug format string wanted and
   parses it to the global variables controlling debug formatting.

   In UNIX, the format string is got from the environment variable
   SSH_DEBUG_FMT, unless the string has been set using
   ssh_debug_set_format_string with environment override TRUE.  If the
   environment variable cannot be read, the format string set with
   ssh_debug_set_format_string is used in any case.  And, if none was
   set, a reasonable default is used instead.

   Windows systems work similarly but do not have the step of
   consulting the environment. */

static void ssh_debug_parse_format(void)
{
  char *fmt_string = NULL, *ref;
  char *arg, *temp;
  char c;
  SshDebugFormatItem item;
  SshDebugFormatItem *pptr = &(ssh_debug_format_items);

#ifdef HAVE_GETENV
  if (!ssh_debug_format_override_environment)
    fmt_string = (char *)getenv("SSH_DEBUG_FMT");
#endif /* HAVE_GETENV */

  if (fmt_string == NULL)
    {
      /* Cast to (char *) because ssh_debug_default_format
         is const char * */
      fmt_string = (char *)ssh_debug_default_format;
    }

  /* This is just debugging so it is not too severe if we run out of
     memory. */
  fmt_string = ssh_strdup(fmt_string);
  if (fmt_string == NULL)
    {
      ssh_warning("Out of memory while parsing debug format string");
      return;
    }

  ref = fmt_string;

  while (*fmt_string != '\0')
    {
      /* If we run out of memory, we just break out of the loop and
         ignore the rest of the debug format. */
      item = ssh_malloc(sizeof(*item));
      if (item == NULL)
        {
          ssh_warning("Out of memory while parsing debug format string");
          break;
        }
#ifdef WANT_COMPLEX_FORMATS
      item->align_right = 0;
      item->minwidth = 0;
      item->maxwidth = 1000;
#endif
      item->arg = NULL;

      if (*fmt_string == '%') /* escape starts */
        {
          fmt_string++;

          /* We jump here when extra formatting information has been
             read for an escape sequence that continues still,
             i.e. after processing '>(10)' in '%>(10)p'. */

          /* This is of course not necessary if WANT_COMPLEX_FORMATS
             is not defined. */

#ifdef WANT_COMPLEX_FORMATS
        continue_with_command:
#endif
          c = *fmt_string;
          fmt_string++;
          if (c == '\0') goto failure;
          switch (c)
            {

              /* Typesetting control; only enabled if
                 WANT_COMPLEX_FORMATS is defined. */

#ifdef WANT_COMPLEX_FORMATS

              /* 1. Extra flags: `<(n)' gives field max width, `>(n)'
                 min width and `$' specifies alignment to right. */

            case '<':
              if (!ssh_debug_parse_arg(fmt_string, &fmt_string, &arg))
                goto failure;
              item->maxwidth = atoi(arg);
              if (item->maxwidth < 1 || item->maxwidth > 1000)
                goto failure;
              goto continue_with_command;
              break;

            case '>':
              if (!ssh_debug_parse_arg(fmt_string, &fmt_string, &arg))
                goto failure;
              item->minwidth = atoi(arg);
              if (item->minwidth < 1 || item->minwidth > 1000)
                goto failure;
              if (item->minwidth > SSH_DEBUG_BUFFER_SIZE)
                item->minwidth = SSH_DEBUG_BUFFER_SIZE;
              goto continue_with_command;
              break;

            case '$':
              item->align_right = 1;
              goto continue_with_command;
              break;

#endif /* WANT_COMPLEX_FORMATS */

            case 'u':
#ifdef HAVE_GETUID
              item->type = SSH_DEBUG_FORMAT_UID;
#else /* HAVE_GETUID */
              ssh_warning("getuid() is not available for debugging output, "
                          "%%u ignored.");
              item->type = SSH_DEBUG_FORMAT_NOTHING;
#endif /* HAVE_GETUID */
              break;

            case 'e':
#ifdef HAVE_GETEUID
              item->type = SSH_DEBUG_FORMAT_EUID;
#else /* HAVE_GETEUID */
              ssh_warning("geteuid() is not available for debugging output, "
                          "%%e ignored.");
              item->type = SSH_DEBUG_FORMAT_NOTHING;
#endif /* HAVE_GETEUID */
              break;

            case 'p':
#ifdef HAVE_GETPID
              item->type = SSH_DEBUG_FORMAT_PID;
#else /* HAVE_GETPID */
              ssh_warning("getpid() is not available for debugging output, "
                          "%%p ignored.");
              item->type = SSH_DEBUG_FORMAT_NOTHING;
#endif /* HAVE_GETPID */
              break;

            case 'h':
              item->type = SSH_DEBUG_FORMAT_LITERAL;
              temp = NULL;
#ifdef HAVE_GETENV
              temp = (char *)getenv("HOST");
#endif /* HAVE_GETENV */
              if (temp == NULL)
#ifdef HAVE_GETHOSTNAME
                {
                  if ((item->arg = ssh_malloc(60)) != NULL)
                    {
                      if (gethostname(item->arg, 60) < 0)
                        {
                          ssh_strcpy(item->arg, "<host unknown>");
                        }
                      else
                        {
                          item->arg[59] = '\0';
                        }
                    }
                }
#else /* HAVE_GETHOSTNAME */
                {
                  item->arg = ssh_strdup("<host unknown>");
                }
#endif /* HAVE_GETHOSTNAME */
              else
                item->arg = ssh_strdup(temp);
              break;

              /* `%E(var)' expands to the value of the environment
                 variable `var'. The value of the variable is found
                 out during format string parsing (i.e. here), and
                 thus subsequence `putenv's do not change its value
                 here. */

            case 'E':
              if (!ssh_debug_parse_arg(fmt_string, &fmt_string, &arg))
                goto failure;
              item->type = SSH_DEBUG_FORMAT_LITERAL;
#ifdef HAVE_GETENV
              temp = (char *)getenv(arg);
              if (temp == NULL)
                {
                  if ((item->arg = ssh_malloc(strlen(arg) + 10)) != NULL)
                    ssh_snprintf(ssh_ustr(item->arg), strlen(arg) + 10,
                                 "<%s unset>", arg);
                }
              else
                {
                  item->arg = ssh_strdup(temp);
                }
#else /* HAVE_GETENV */
              ssh_warning("getenv() is not available for debugging output, "
                          "%%E(%s) ignored.", arg);
              item->type = SSH_DEBUG_FORMAT_NOTHING;
#endif /* HAVE_GETENV */
              break;

              /* `%Dx' formats a piece of the current date,
                 where x is
                   s -- seconds,
                   m -- minutes,
                   h -- hours,
                   d -- day,
                   t -- month, or
                   y -- year. */

            case 'D':
              ssh_debug_format_needs_time = 1;
              switch (*fmt_string)
                {
                case 'm': item->type = SSH_DEBUG_FORMAT_MINUTES; break;
                case 'h': item->type = SSH_DEBUG_FORMAT_HOURS; break;
                case 's': item->type = SSH_DEBUG_FORMAT_SECONDS; break;
                case 'u': item->type = SSH_DEBUG_FORMAT_MICRO_SECONDS; break;
                case 'd': item->type = SSH_DEBUG_FORMAT_DAY; break;
                case 't': item->type = SSH_DEBUG_FORMAT_MONTH; break;
                case 'y': item->type = SSH_DEBUG_FORMAT_YEAR; break;
                default: goto failure;
                }
              fmt_string++;
#ifndef HAVE_LOCALTIME
              ssh_warning("localtime() is not available for debugging output, "
                          "%%D construct ignored.");
              item->type = SSH_DEBUG_FORMAT_NOTHING;
#endif /* !HAVE_LOCALTIME */
              break;

#ifdef WANT_COMPLEX_FORMATS
              /* `%W(m)(i)' enables word-wrapping of debug messages.
                 No line of output will be longer than m characters,
                 and every line after the first one in a message
                 will be indented by i spaces. This does not actually
                 output anything. */

            case 'W':
              if (!ssh_debug_parse_arg(fmt_string, &fmt_string, &arg))
                goto failure;
              if (!ssh_debug_parse_arg(fmt_string, &fmt_string, &temp))
                goto failure;
              ssh_debug_format_wrapcol = atoi(arg);
              if (ssh_debug_format_wrapcol < 0 ||
                  ssh_debug_format_wrapcol > 1000)
                goto failure;
              ssh_debug_format_wrapindent = atoi(temp);
              if (ssh_debug_format_wrapindent < 0
                  || ssh_debug_format_wrapindent > 1000)
                goto failure;

              ssh_free(item);
              continue;

              break;

              /* %i adds `ssh_debug_indent_level' many spaces. It also
                 sets ssh_debug_format_wrapindent dynamically if
                 necessary. */
            case 'i':
              item->type = SSH_DEBUG_FORMAT_INDENT;
              break;

              /* `%I' disables the printing of the debug message.
                 While not useful as a format string of its own,
                 very useful inside conditionals. */

            case 'I':
              item->type = SSH_DEBUG_FORMAT_IGNORE;
              break;

              /* `%?[condition]...%/[condition]...%/[condition]...%:...%.'
                 is the conditional construct. `%?' reads "if",
                 `%/' "else if", `%:' "else" and `%.' "end if".  */


            case '?': /* conditional starts... */
            case '/':
              if (!ssh_debug_parse_arg_gen(fmt_string, &fmt_string, &arg,
                                           '[', ']'))
                goto failure;

              item->condition = ssh_debug_parse_condition(arg);
              if (item->condition == NULL)
                goto failure;
              item->type = ((c == '?')
                            ? SSH_DEBUG_FORMAT_IF
                            : SSH_DEBUG_FORMAT_ELSE_IF);
              break;

            case '.':
              item->type = SSH_DEBUG_FORMAT_END_IF;
              break;

            case ':':
              item->type = SSH_DEBUG_FORMAT_ELSE;
              break;

              /* `%c(n)' will just write the character` n in verbatim
                 to the output, and it is assumed it will take
                 zero width. */
            case 'c':
              if (!ssh_debug_parse_arg(fmt_string, &fmt_string, &arg))
                  goto failure;
              item->type = SSH_DEBUG_FORMAT_TERMCONTROL;
              item->arg = NULL;
              item->numarg = atoi(arg);
              if (item->numarg < 1 || item->numarg > 255) goto failure;
              break;

            case 'C':
              if (!ssh_debug_parse_arg(fmt_string, &fmt_string, &arg))
                  goto failure;
              item->type = SSH_DEBUG_FORMAT_TERMCONTROL;
              item->numarg = -1;
              item->arg = ssh_strdup(arg);
              break;

              /* '%c(n)' will cause the debug module to sleep n
                 milliseconds after the debug message has been
                 printed.

                 n must lie between 0 and 60,000,
                 which is one minute. */

            case 'S':
              if (!ssh_debug_parse_arg(fmt_string, &fmt_string, &arg))
                goto failure;
              item->type = SSH_DEBUG_FORMAT_SLEEP;
              item->numarg = atoi(arg);
              item->arg = NULL;
              if (item->numarg < 0 || item->numarg > 60000) goto failure;
              break;

#endif /* WANT_COMPLEX_FORMATS */
              /* Some boring items. */

            case 'l':
              item->type = SSH_DEBUG_FORMAT_LEVEL; break;

            case 'm':
              item->type = SSH_DEBUG_FORMAT_MODULE; break;

            case 'n':
              item->type = SSH_DEBUG_FORMAT_LINE; break;

            case 'f':
              item->type = SSH_DEBUG_FORMAT_FUNC;

#ifndef SSH_DEBUG_HAVE_FUNCTION_NAMES
              ssh_warning("Don't know how to get function name for "
                          "debugging output, %%f won't work.");
#endif

              break;

            case 's':
              item->type = SSH_DEBUG_FORMAT_FILE; break;

            case 'M':
              item->type = SSH_DEBUG_FORMAT_MSG; break;

            case 'o':
              item->type = SSH_DEBUG_FORMAT_ORDINAL; break;

            case 'N':
              item->type = SSH_DEBUG_FORMAT_NEWLINE; break;

            case '%':
              item->type = SSH_DEBUG_FORMAT_LITERAL;
              item->arg = ssh_strdup("%");
              break;

            default:
              ssh_warning("Invalid or unsupported "
                          "debug format control character '%c'.", c);
              item->type = SSH_DEBUG_FORMAT_LITERAL;
              if ((item->arg = ssh_malloc(2)) != NULL)
                {
                  item->arg[0] = c;
                  item->arg[1] = '\0';
                }
              break;
            }
        } /* end of escape character processing */
      else /* some literal data */
        {
          if (*fmt_string == '\n')
            {
              item->type = SSH_DEBUG_FORMAT_NEWLINE;
              fmt_string++;
            }
          else
            {
              while (*fmt_string < ' ' && *fmt_string != '\0')
                fmt_string++;
              temp = fmt_string;
              while (*fmt_string != '%' && *fmt_string != '\0')
                {
                  fmt_string++;
                }
              c = *fmt_string;
              *fmt_string = '\0';
              item->type = SSH_DEBUG_FORMAT_LITERAL;
              item->arg = ssh_strdup(temp);
              *fmt_string = c;
            }
        }

#ifdef WANT_COMPLEX_FORMATS
      /* Check consistency */
      if (item->minwidth > item->maxwidth)
        goto failure;
#endif /* WANT_COMPLEX_FORMATS */

      /* item contains now something interesting... */
      item->next = NULL;
      *(pptr) = item;
      pptr = &(item->next);
    }
  ssh_free(ref);

 /* succesful end of parsing */

#ifdef WANT_COMPLEX_FORMATS
  ssh_debug_calculate_jumps(ssh_debug_format_items);
#endif /* WANT_COMPLEX_FORMATS */

  return;

failure: /* something went wrong... give a warning and fall
            back to the simplest behaviour '%!' */

  ssh_warning("Invalid debug format string.");

#ifdef HAVE_GETENV
  if (!ssh_debug_format_override_environment)
    ssh_warning("Check the contents of your "
                "SSH_DEBUG_FMT environment variable.");
#endif

  /* Do not leak item. */
  ssh_free(item->arg);
  ssh_free(item);

  /* Release if there was anything previously */
  ssh_debug_cleanup_items();

  ssh_debug_format_items = ssh_malloc(sizeof(*ssh_debug_format_items));

  if (!ssh_debug_format_items)
    ssh_fatal("Could not allocate memory for fallback debug format items");

  ssh_debug_format_items->type = SSH_DEBUG_FORMAT_MSG;
  ssh_debug_format_items->next = NULL;
  ssh_debug_format_items->arg = NULL;

#ifdef WANT_COMPLEX_FORMATS

  ssh_debug_format_items->minwidth = 0;
  ssh_debug_format_items->maxwidth = 1000;

  ssh_debug_format_wrapindent = 0;
  ssh_debug_format_wrapcol = 0;
#endif /* WANT_COMPLEX_FORMATS */

  ssh_free(ref);

  return;
}

/* End of debug format string parser. */

#else /* WANT_DEBUG_PARSER */

#ifdef HAVE_LOCALTIME
/* This is a replacement of ssh_debug_parse_format() in the case when
   the real parser is not wanted. It creates a simple format sequence
   corresponding to the string '%Dh:%Dm:%Ds: %M', but without the real
   parser. */

static void ssh_debug_parse_format(void)
{
  /* THIS IS NOT THE REAL PARSER BUT A SUBSTITUTE IF
     'WANT_DEBUG_PARSER' IS NOT DEFINED. */

  SshDebugFormatItem item;
  int i;

  for (i = 6; i >= 0; i--)
    {
      item = ssh_calloc(1, sizeof(*item));
      if (item == NULL)
        return;

#ifdef WANT_COMPLEX_FORMATS
      item->minwidth = 0;
      item->maxwidth = 1000;
      item->align_right = 0;
#endif

      item->next = ssh_debug_format_items;
      ssh_debug_format_items = item;

      item->arg = NULL;

      switch (i)
        {
        case 0:
          ssh_debug_format_needs_time = 1;
          item->type = SSH_DEBUG_FORMAT_HOURS;
          break;

        case 1:
          item->type = SSH_DEBUG_FORMAT_LITERAL;
          item->arg = ssh_strdup(":");
          break;

        case 2:
          item->type = SSH_DEBUG_FORMAT_MINUTES;
          break;

        case 3:
          item->type = SSH_DEBUG_FORMAT_LITERAL;
          item->arg = ssh_strdup(":");
          break;

        case 4:
          item->type = SSH_DEBUG_FORMAT_SECONDS;
          break;

        case 5:
          item->type = SSH_DEBUG_FORMAT_LITERAL;
          item->arg = ssh_strdup(": ");
          break;

        case 6:
          item->type = SSH_DEBUG_FORMAT_MSG;
          break;

        default:
          break;
        }
    }
}

#else /* HAVE_LOCALTIME */
/* This is a replacement of ssh_debug_parse_format() in the case when
   the real parser is not wanted. It creates a simple format sequence
   corresponding to the string '%M', but without the real parser. */
static void ssh_debug_parse_format(void)
{
  /* THIS IS NOT THE REAL PARSER BUT A SUBSTITUTE IF
     'WANT_DEBUG_PARSER' IS NOT DEFINED. */

  SshDebugFormatItem item;

  item = ssh_malloc(sizeof(*item));
  if (item == NULL)
    return;

#ifdef WANT_COMPLEX_FORMATS
  item->minwidth = 0;
  item->maxwidth = 1000;
  item->align_right = 0;
#endif

  item->next = ssh_debug_format_items;
  ssh_debug_format_items = item;

  item->arg = NULL;
  item->type = SSH_DEBUG_FORMAT_MSG;
}
#endif /* HAVE_LOCALTIME */

#endif /* WANT_DEBUG_PARSER */

/* cleanup debug format items */

static void ssh_debug_cleanup_items(void)
{
  SshDebugFormatItem item;

  while (ssh_debug_format_items != NULL)
    {
      item = ssh_debug_format_items;
      ssh_debug_format_items = item->next;
#ifdef WANT_COMPLEX_FORMATS
      if (item->type == SSH_DEBUG_FORMAT_IF ||
          item->type == SSH_DEBUG_FORMAT_ELSE_IF)
        ssh_debug_free_condition(item->condition);
#endif /* WANT_COMPLEX_FORMATS */

      ssh_free(item->arg);
      ssh_free(item);
    }
}

/* The procedure for evaluating conditionals is compiled only
   if WANT_COMPLEX_FORMATS is defined. */

#ifdef WANT_COMPLEX_FORMATS

static int ssh_debug_eval_condition(SshDebugOutputContext context,
                                    SshDebugCondition condition)
{
  int r1, r2;
  int r = 0;

  if (condition->type >= SSH_DEBUG_FORMAT_FIRST_BIN_CONN
      &&
      condition->type <= SSH_DEBUG_FORMAT_LAST_BIN_CONN)
    {
      r1 = ssh_debug_eval_condition(context, condition->arg.subcond.cond1);
      r2 = ssh_debug_eval_condition(context, condition->arg.subcond.cond2);
      switch (condition->type)
        {
        case SSH_DEBUG_FORMAT_COND_AND: r = r1 && r2; break;
        case SSH_DEBUG_FORMAT_COND_OR: r = r1 || r2; break;
        case SSH_DEBUG_FORMAT_COND_XOR: r = (r1 ? !r2 : r2); break;
        case SSH_DEBUG_FORMAT_COND_IMPL: r = !(r1 && !r2); break;
        case SSH_DEBUG_FORMAT_COND_NAND: r = !(r1 && r2); break;
        case SSH_DEBUG_FORMAT_COND_IMPL_R: r = !(!r1 && r2); break;
        default:
          ssh_fatal("Internal bug in ssh_debug_eval_condition.");
          /* exited */
        }
      return r;
    }

  switch (condition->type)
    {
    case SSH_DEBUG_FORMAT_COND_NEG:
      return !(ssh_debug_eval_condition(context,
                                        condition->arg.subcond.cond1));
    case SSH_DEBUG_FORMAT_COND_MODNAME:
      if (context->module == NULL) return 0;
      return ssh_match_pattern(context->module, condition->arg.string);

    case SSH_DEBUG_FORMAT_COND_FILENAME:
      if (context->file == NULL) return 0;
      return ssh_match_pattern(context->file, condition->arg.string);

    case SSH_DEBUG_FORMAT_COND_MATCHMSG:
      return ssh_match_pattern(context->msg, condition->arg.string);

    case SSH_DEBUG_FORMAT_COND_FUNCNAME:
      if (context->function == NULL) return 0;
      return ssh_match_pattern(context->function, condition->arg.string);

    case SSH_DEBUG_FORMAT_COND_LEVELEQ:
      return (context->level == condition->arg.number);

    case SSH_DEBUG_FORMAT_COND_LEVELLT:
      return (context->level < condition->arg.number);

    case SSH_DEBUG_FORMAT_COND_LEVELGT:
      return (context->level > condition->arg.number);

    case SSH_DEBUG_FORMAT_COND_MAGIC:
      if (condition->arg.number == ssh_debug_msg_number - 1)
        r = 0;
      else
        r = 1;
      condition->arg.number = ssh_debug_msg_number;
      return r;

    default:
      ssh_fatal("Internal bug in ssh_debug_eval_condition.");
    }

  return 0; /* not reached, but makes compiler content */
}

#endif

#define SSH_DEBUG_TMP_BUF_SIZE 100

/* Output a debug message `msg'. This function is in principle
   internal to the debugging module, but in practice very global,
   because every SSH_DEBUG may expand to a direct call to it. */

void ssh_debug_output(int level,
                      const char *file, unsigned int line,
                      const char *module, const char *function,
                      char *msg)
{
  unsigned char buf[SSH_DEBUG_BUFFER_SIZE];
  unsigned char *current_ptr = buf;
  unsigned char temp[SSH_DEBUG_TMP_BUF_SIZE];
  const char *fragment;
  int total_len = 0;
  int l;
  SshDebugFormatItem iter;

#ifdef WANT_COMPLEX_FORMATS
  unsigned char buf2[SSH_DEBUG_BUFFER_SIZE];
  int sleeping_milliseconds = 0;
  int inhibit_wrap;
  struct SshDebugOutputContextRec context_rec;
  int may_split = 0;
  int column = 0;
  int s;
  int dynamic_indent = 0;
#define DINDENT + dynamic_indent
#else /* WANT_COMPLEX_FORMATS */
#define DINDENT
#endif

#ifdef WANT_COMPLEX_FORMATS
#define NO_SPLIT may_split = 0
#else
#define NO_SPLIT
#endif /* WANT_COMPLEX_FORMATS */

#ifdef HAVE_LOCALTIME
  struct SshCalendarTimeRec current_time[1] = { { 0 } };
  SshTimeValueStruct time_now = { 0 };
#endif /* HAVE_LOCALTIME */

  ssh_debug_msg_number++;

  /* Initialize the format list if not done yet */

  if (ssh_debug_format_items == NULL)
    {
      ssh_debug_parse_format();
      if (ssh_debug_format_items == NULL) /* still? */
        {
          ssh_warning("Internal error in ssh_debug_output "
                    "(ssh_debug_format_items == NULL).");
          ssh_free(msg);
          return;
        }
    }

  /* Fill in the context structure. Only needed for conditionals,
     so do not do if WANT_COMPLEX_FORMATS is not defined. */

#ifdef WANT_COMPLEX_FORMATS
  context_rec.level = level;
  context_rec.file = file;
  context_rec.line = line;
  context_rec.module = module;
  context_rec.function = function;
  context_rec.msg = msg;
#endif

#ifdef HAVE_LOCALTIME
  if (ssh_debug_format_needs_time != 0)
    {
      ssh_get_time_of_day(&time_now);
      ssh_calendar_time(time_now.seconds, current_time, TRUE);
    }
#endif

  *current_ptr = '\0';

  for (iter = ssh_debug_format_items; iter != NULL; iter = iter->next)
    {
      /* This is not used unless modifier flags are enabled. */
#ifdef WANT_COMPLEX_FORMATS
    iter_start:
#endif

      fragment = ssh_sstr(temp);

#ifdef WANT_COMPLEX_FORMATS
      may_split = 1;
#endif

      switch (iter->type)
        {

        case SSH_DEBUG_FORMAT_NOTHING:
          fragment = NULL;
          break;

          /* Compiled only if WANT_COMPLEX_FORMATS is defined */
          /* Sleep, ignore, conditionals. */

#ifdef WANT_COMPLEX_FORMATS
        case SSH_DEBUG_FORMAT_IGNORE:
          {
            ssh_free(msg);
            return;
          }

        case SSH_DEBUG_FORMAT_SLEEP:
          {
            if (sleeping_milliseconds < iter->numarg)
              sleeping_milliseconds = iter->numarg;
            fragment = NULL;
            break;
          }

        /* Conditionals */

        case SSH_DEBUG_FORMAT_IF:
        redo_condition_eval:
          if (ssh_debug_eval_condition(&context_rec, iter->condition))
            {
              iter = iter->next;
              if (iter == NULL)
                goto out_from_big_loop; /* exit loop */
              goto iter_start;
            }
          iter = iter->jump;
          if (iter == NULL)
            goto out_from_big_loop; /* exits loop */

          if (iter->type == SSH_DEBUG_FORMAT_END_IF) continue; /* end of if */
          if (iter->type == SSH_DEBUG_FORMAT_ELSE_IF)
            goto redo_condition_eval;
          if (iter->type == SSH_DEBUG_FORMAT_ELSE) continue; /* ok, do it */
          ssh_fatal("Internal bug in if-clause handling in ssh_debug_output.");
          /* never reached, actually */
          break;

        case SSH_DEBUG_FORMAT_ELSE_IF:
        case SSH_DEBUG_FORMAT_ELSE:
          iter = iter->jump;
          goto iter_start;

        case SSH_DEBUG_FORMAT_END_IF:
          continue;

        case SSH_DEBUG_FORMAT_INDENT:
          dynamic_indent = ssh_debug_indent_level;
          if (dynamic_indent > SSH_DEBUG_MAX_INDENT)
            dynamic_indent = SSH_DEBUG_MAX_INDENT;
          if (dynamic_indent > SSH_DEBUG_TMP_BUF_SIZE - 1)
            dynamic_indent = SSH_DEBUG_TMP_BUF_SIZE - 1;
          if (dynamic_indent > 0)
            memset(temp, ' ', dynamic_indent);
          temp[dynamic_indent] = '\0';
          break;

#endif /* WANT_COMPLEX_FORMATS */

          /* There are no ways to introduce conditionals into the
             formatting system if WANT_COMPLEX_FORMATS is not defined.
             Therefore, nothing needs to be done in the case
             WANT_COMPLEX_FORMATS is not defined. */

          /* These are compiled only if localtime() can be used. */
#ifdef HAVE_LOCALTIME

        case SSH_DEBUG_FORMAT_MINUTES:
          ssh_snprintf(temp, SSH_DEBUG_TMP_BUF_SIZE, "%02d",
                       current_time->minute);
          break;

        case SSH_DEBUG_FORMAT_SECONDS:
          ssh_snprintf(temp, SSH_DEBUG_TMP_BUF_SIZE, "%02d",
                       current_time->second);
          break;

        case SSH_DEBUG_FORMAT_MICRO_SECONDS:
          ssh_snprintf(temp, SSH_DEBUG_TMP_BUF_SIZE, "%06d",
                       time_now.microseconds);
          break;

        case SSH_DEBUG_FORMAT_DAY:
          ssh_snprintf(temp, SSH_DEBUG_TMP_BUF_SIZE, "%02d",
                       (int) current_time->monthday);
          break;

        case SSH_DEBUG_FORMAT_YEAR:
          ssh_snprintf(temp, SSH_DEBUG_TMP_BUF_SIZE, "%04d",
                       (int)current_time->year);
          break;

        case SSH_DEBUG_FORMAT_MONTH:
          ssh_snprintf(temp, SSH_DEBUG_TMP_BUF_SIZE, "%02d",
                       current_time->month + 1);
          break;

        case SSH_DEBUG_FORMAT_HOURS:
          ssh_snprintf(temp, SSH_DEBUG_TMP_BUF_SIZE, "%02d",
                       current_time->hour);
          break;

        case SSH_DEBUG_FORMAT_ORDINAL:
          ssh_snprintf(temp, SSH_DEBUG_TMP_BUF_SIZE, "%d",
                       ssh_debug_msg_number);
          break;
#endif
          /* Date constructs cannot be incorporated into the debug
             format unless HAVE_LOCALTIME is true; this is taken care
             by the parser. */

#ifdef HAVE_GETPID
        case SSH_DEBUG_FORMAT_PID:
          ssh_snprintf(temp, SSH_DEBUG_TMP_BUF_SIZE, "%d", getpid()); break;
#endif /* HAVE_GETPID */

#ifdef HAVE_GETUID
        case SSH_DEBUG_FORMAT_UID:
          ssh_snprintf(temp, SSH_DEBUG_TMP_BUF_SIZE, "%d", getuid()); break;
#endif /* HAVE_GETUID */

#ifdef HAVE_GETEUID
        case SSH_DEBUG_FORMAT_EUID:
          ssh_snprintf(temp, SSH_DEBUG_TMP_BUF_SIZE, "%d", geteuid()); break;
#endif /* HAVE_GETEUID */

          /* Similarly, the get*id constructs cannot be entered into
             the format if the corresponding functions are not
             usable. */

        case SSH_DEBUG_FORMAT_LITERAL:
          fragment = iter->arg;
          break;

        case SSH_DEBUG_FORMAT_LEVEL:
          ssh_snprintf(temp, SSH_DEBUG_TMP_BUF_SIZE, "%d", level);
          break;

        case SSH_DEBUG_FORMAT_MODULE:
          NO_SPLIT;
          if (module == NULL)
            fragment = "<unknown module>";
          else
            fragment = module;
          break;

        case SSH_DEBUG_FORMAT_LINE:
          NO_SPLIT;
          ssh_snprintf(temp, SSH_DEBUG_TMP_BUF_SIZE, "%d", line);
          break;

        case SSH_DEBUG_FORMAT_FUNC:
          NO_SPLIT;
          if (function == NULL)
            fragment = "<unknown function>";
          else
            fragment = function;
          break;

        case SSH_DEBUG_FORMAT_FILE:
          NO_SPLIT;
          if (file == NULL)
            fragment = "<unknown file>";
          else
            {
              /* Strip unix-style path components from file name. */
              if (strrchr(file, '/'))
                file = strrchr(file, '/') + 1;

              /* Strip msdos/windows style path components from file name. */
              if (strrchr(file, '\\'))
                file = strrchr(file, '\\') + 1;

              fragment = file;
            }
          break;

        case SSH_DEBUG_FORMAT_MSG:
          fragment = msg;
          break;

        case SSH_DEBUG_FORMAT_NEWLINE:
          if (total_len < SSH_DEBUG_BUFFER_SIZE - 2)
            {
              *current_ptr++ = '\r';
              *current_ptr++ = '\n';

#ifdef WANT_COMPLEX_FORMATS
              column = 0;
#endif
              total_len += 2;
            }
          fragment = NULL;
          break;

          /* Sending possible control characters verbatim is not
             enabled unless WANT_COMPLEX_FORMATS is defined. */

#ifdef WANT_COMPLEX_FORMATS

        case SSH_DEBUG_FORMAT_TERMCONTROL:
          if (iter->numarg > 0 && (total_len < SSH_DEBUG_BUFFER_SIZE - 1))
            {
              *current_ptr++ = (unsigned char)(iter->numarg);
              total_len++; fragment = NULL;
            }
          else
            {
              fragment = iter->arg;
              while (total_len < SSH_DEBUG_BUFFER_SIZE - 1 &&
                     *fragment != '\0')
                {
                  *current_ptr++ = *fragment++;
                  total_len++;
                }
              fragment = NULL;
            }
          break;

#endif /* WANT_COMPLEX_FORMATS */

        default:
#ifdef  KERNEL
          ssh_warning("Internal error in ssh_debug_output (unknown "
                      "iter->type=%d).", iter->type);
          fragment = NULL;
          break;
#else
          ssh_fatal("Internal error in ssh_debug_output.");
#endif
          /* exited */
        }

      /* If actually cannot fit any more, set fragment to NULL to
         disable all output. We need still evaluate the string to the
         end because there may be e.g. %I or %S waiting. */

      if (total_len == SSH_DEBUG_BUFFER_SIZE - 1)
        fragment = NULL;

      SSH_ASSERT(total_len <= SSH_DEBUG_BUFFER_SIZE - 1);

      if (fragment != NULL)
        {
          l = strlen(fragment);


          /* Wrapping and splitting is compiled only if
             WANT_COMPLEX_FORMATS is defined. Otherwise the string is
             just copied to the output, with proviso of fitting to the
             buffer of course. */

#ifdef WANT_COMPLEX_FORMATS

          /* Truncate if too long. If minimum width is specified,
             do not allow a split inside the item. If the item is
             too short, write a padded version to buf2 and use it. */

          if (iter->maxwidth < l) l = iter->maxwidth;
          if (iter->minwidth > 0)
            {
              may_split = 0;
            }

          if (iter->minwidth > l)
            {
              if (iter->align_right)
                {
                  memcpy(&buf2[iter->minwidth - l], fragment, l);
                  memset(buf2, ' ', iter->minwidth - l);
                }
              else
                {
                  memcpy(buf2, fragment, l);
                  memset(&buf2[l], ' ', iter->minwidth - l);
                }
              buf2[iter->minwidth] = '\0';
              l = iter->minwidth;
              fragment = ssh_sstr(buf2);
            }

          inhibit_wrap = 0;

        redo:

          /* Truncate fragment if it does not fit in the buffer */
          /* At this point there is room for at least one character
             in buf */

          if (total_len + l > SSH_DEBUG_BUFFER_SIZE - 1)
            l = (SSH_DEBUG_BUFFER_SIZE - 1) - total_len;

          if (l > 0)
            {
              s = l;

              /* We may need to perform a split if there is not
                 enough room for the fragment on this line.
                 `inhibit_wrap' is set to 1 when we have an item
                 that cannot/may not be split anywhere. */

              if (ssh_debug_format_wrapcol > 0 && inhibit_wrap == 0 &&
                  column + l > ssh_debug_format_wrapcol)
                {
                  if (!may_split) /* No split allowing, thus set inhibit_wrap
                                     to 1. Because the fragment does not fit,
                                     it is best to get a new line before
                                     we write the possibly too long fragment.
                                     Thus, if we are not at the first column,
                                     newline and proper indentation is
                                     written first. Otherwise directly
                                     back to `redo'. */
                    {
                      inhibit_wrap = 1;
                      if (column > ssh_debug_format_wrapindent DINDENT)
                        goto newline;
                      goto redo;
                    }

                  /* Find the first space that occurs before the line
                     length limit. */

                  while (l >= 0 &&
                         ((column + l > ssh_debug_format_wrapcol) ||
                          (fragment[l] != ' '))) l--;

                  if (l < 0) /* No space found, thus find first space
                                anywhere. */
                    {
                      l = (ssh_debug_format_wrapcol - column) + 1;
                      while (fragment[l] != ' ' && fragment[l] != '\0')
                        l++;
                      if (fragment[l] == '\0')
                        {
                          /* No spaces anywhere! */
                          inhibit_wrap = 1;
                          l = s;
                          /* Skip line if not at the beginning */
                          if (column > ssh_debug_format_wrapindent DINDENT)
                            goto newline;
                          goto redo;
                        }
                    }

                  /* Can split, fragment[l] is a space. Write data
                     at most until that. */

                  while (l > 0 && s > 0)
                    {
                      *current_ptr++ = *fragment++;
                      total_len++;
                      column++;
                      l--;
                      s--;
                    }

                  /* Remeasure length */
                  l = s;

                  /* discard following spaces */
                  while (*fragment == ' ') { fragment++; l--; }

                  /* Write newline, indent, and redo */

                newline:
                  if (total_len < (SSH_DEBUG_BUFFER_SIZE - 2))
                    {
                      *current_ptr++ = '\r';
                      *current_ptr++ = '\n';
                      column = 0;
                      total_len += 2;

                      while (total_len < (SSH_DEBUG_BUFFER_SIZE - 1) &&
                             column < ssh_debug_format_wrapindent DINDENT)
                        {
                          *current_ptr++ = ' ';
                          column++;
                          total_len++;
                        }
                    }
                  goto redo;
                }
              else
                {
                  /* fits, or must fit, in whole */
                  ssh_ustrncpy(current_ptr, ssh_custr(fragment), l);
                  current_ptr += l;
                  total_len += l;
                  column += l;
                }
            }

#else /* WANT_COMPLEX_FORMATS */
          if (total_len + l > SSH_DEBUG_BUFFER_SIZE - 1)
            l = (SSH_DEBUG_BUFFER_SIZE - 1) - total_len;
          ssh_strncpy(current_ptr, fragment, l);
          current_ptr += l;
          total_len += l;
#endif /* WANT_COMPLEX_FORMATS */
        }
    }

#ifdef WANT_COMPLEX_FORMATS
 out_from_big_loop:
#endif /* WANT_COMPLEX_FORMATS */

  /* Ok, buf contains now the real message, but it is not zero terminated
     yet. */

  buf[total_len] = '\0';

  /* Free the message and print the formatted version out */

  ssh_free(msg);
  ssh_debug_formatted(level, file, line, module, function, buf);

#ifdef WANT_COMPLEX_FORMATS
#ifdef HAVE_USLEEP
  if (sleeping_milliseconds > 0)
    usleep(sleeping_milliseconds * 1000);
#else /* HAVE_USLEEP */
#ifdef HAVE_NANOSLEEP
  {
    struct timespec rqtp;
    if (sleeping_milliseconds > 0)
      {
        rqtp.tv_sec = sleeping_milliseconds / 1000;
        rqtp.tv_nsec = (sleeping_milliseconds % 1000) * 1000000;
        nanosleep(&rqtp, NULL);
      }
  }
#else /* HAVE_NANOSLEEP */
#ifdef HAVE_SLEEP
  if (sleeping_milliseconds > 0)
    sleep((sleeping_milliseconds + 500) / 1000);
#endif /* HAVE_SLEEP */
#endif /* HAVE_NANOSLEEP */
#endif /* HAVE_USLEEP */
#endif /* WANT_COMPLEX_FORMATS */

  return;
}

#endif /* SSH_DEBUG_EXTERNAL */

void ssh_debug_set_format_string(const char *string, Boolean override)
{
#ifdef WANT_DEBUG_PARSER
  ssh_debug_maybe_initialize();
  ssh_debug_default_format = string;
  ssh_debug_format_override_environment = override;
#endif
}

/* Changes indentation. */
void ssh_debug_change_indentation(int change)
{
  ssh_debug_indent_level += change;
  if (ssh_debug_indent_level < 0)
    {
      ssh_warning("Debug indentation level set below zero (check your code).");
    }
}
