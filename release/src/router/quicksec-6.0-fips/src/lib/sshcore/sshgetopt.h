/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Header for ssh_getopt, ssh_getopt_long, ssh_getopt_long_only.

   <keywords getopt, utility functions/getopt>

   @internal
*/

#ifndef SSHGETOPT_H
#define SSHGETOPT_H

#include "sshglobals.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Values for SshGetOptDataRec::miss_arg
 *
 * ssh_getopt() uses field as boolean and returns only
 * value 0 or 1. ssh_getopt_long() may return any
 * of these values
 *
*/

/**  Command line option not found in 'longopts' array. */
#define SSH_GETOPT_MISS_ARG_INVALID_OPT 0

/**  Option takes an argument. */
#define SSH_GETOPT_MISS_ARG_MISSING_ARG 1

/**  Option in the command line is ambiguous - long option parsing only. */
#define SSH_GETOPT_MISS_ARG_AMBIGUOUS_OPT 2

/**  Option does not take an argument - long option parsing only. */
#define SSH_GETOPT_MISS_ARG_EXCESS_ARG 3

/**  Invalid has_arg value in the longopts array - long option parsing only. */
#define SSH_GETOPT_MISS_ARG_INVALID_HAS_ARG 4

/**  Fatal internal parsing error - long option parsing only. */
#define SSH_GETOPT_MISS_ARG_FATAL 5

/** The SshGetOptDataRec structure. */
struct SshGetOptDataRec {
  int err;        /**  Error message is printed if nonzero. */
  int ind;        /**  Index into next argv element to be handled. */
  int val;        /**  1 for '-' and 0 for '+' options. */
  int opt;        /**  Option checked for validity. */
  int reset;      /**  Reset ssh_getopt for next call. */
  char *arg;      /**  Argument associated with option. */
  int miss_arg;   /**  0: unknown opt, 1: missing arg, 2-5: other long
                       opt err. */
  int arg_num;    /**  Nonzero if arg is legal number. */
  int arg_val;    /**  Numerical value of arg if legal number. */
  int allow_plus; /**  Nonzero if also '+' arguments are allowed. */
  char *current;  /**  Internal current pointer for option parsing. */
};

typedef struct SshGetOptDataRec SshGetOptDataStruct;
typedef struct SshGetOptDataRec *SshGetOptData;

#ifndef SSHGETOPT_C

SSH_GLOBAL_DECLARE(struct SshGetOptDataRec, ssh_getopt_default_data);
#define ssh_getopt_default_data SSH_GLOBAL_USE_INIT(ssh_getopt_default_data)

#define ssh_opterr               (ssh_getopt_default_data.err)
#define ssh_optind               (ssh_getopt_default_data.ind)
#define ssh_optval               (ssh_getopt_default_data.val)
#define ssh_optopt               (ssh_getopt_default_data.opt)
#define ssh_optreset             (ssh_getopt_default_data.reset)
#define ssh_optarg               (ssh_getopt_default_data.arg)
#define ssh_optmissarg           (ssh_getopt_default_data.miss_arg)
#define ssh_optargnum            (ssh_getopt_default_data.arg_num)
#define ssh_optargval            (ssh_getopt_default_data.arg_val)
#define ssh_optallowplus         (ssh_getopt_default_data.allow_plus)

#endif /*  ! SSHGETOPT_C */

/**
    This struct contents can be used as an initializer to the static version
    of struct SshGetOptDataRec.

    Note: REMEMBER TO UPDATE THIS IF YOU CHANGE THE SshGetOptDataRec
    STRUCTURE!

 */
#define SSH_GETOPT_DATA_INITIALIZER \
                                { 1, 1, 0, 0, 0, NULL, 0, 0, 0, 0, "" }

/**
    Works like getopt(3).  If data pointer is NULL, the internal data
    is stored into the global 'ssh_getopt_default_data' structure,
    that can be accessed through ssh_opt* macros.  If data is not
    NULL, the structure should be initialized with
    ssh_getopt_init_data() before the first call of ssh_getopt().

 */
int ssh_getopt(int argc, char **argv, const char *ostr, SshGetOptData data);

/**
 * Initialize pre-allocated SshGetOptData data structure.
 */
void ssh_getopt_init_data(SshGetOptData data);

#ifdef VXWORKS
void ssh_getopt_restart(void);
#endif /* VXWORKS */

/* ----------- ssh_getopt_long() & ssh_getopt_long_only() ---------------- */

/**
 * Valid values for SshLongOptionRec::has_arg
 */
#define SSH_GETOPT_LONG_NO_ARGUMENT 0
#define SSH_GETOPT_LONG_REQUIRED_ARGUMENT 1
#define SSH_GETOPT_LONG_OPTIONAL_ARGUMENT 2

/**
    The 'longopts' argument of ssh_getopt_long() and
    ssh_getopt_long_only() is an array of 'struct SshLongOptionRec'
    records. The array is terminated by an element which name is a
    NULL pointer.

    @param has_arg
    The 'has_arg' parameter can have the following values:

    - SSH_GETOPT_LONG_NO_ARGUMENT        = option does not take an argument
    - SSH_GETOPT_LONG_REQUIRED_ARGUMENT  = option requires an argument
    - SSH_GETOPT_LONG_OPTIONAL_ARGUMENT  = option can have an optional argument

    @param flag
    If 'flag' is a null pointer, then the value of 'val' is returned
    by ssh_getopt_long().

    If 'flag' is not a null pointer, then the value of 'val' is stored
    in the variable pointed by the 'flag'.  In this case
    ssh_getopt_long() returns zero.

 */

struct SshLongOptionRec
{
  const char *name;
  int has_arg;
  int *flag;
  int val;
};

typedef struct SshLongOptionRec SshLongOptionStruct, *SshLongOption;
typedef const struct SshLongOptionRec *SshLongOptionConst;

/**
    Works like getopt_long(3). Structure 'data' is used like in
    ssh_getopt().

    If a long option is found, function returns either 0 (zero) or
    the value specified in 'longopts' array (see. above). 'longind'
    (if given) is the index to the found option in the 'longopts' array.
    Return value is stored into 'data->opt'. 'data->arg' points
    to the possible option argument. 'data->arg_num' and 'data->arg_val'
    are updated. 'data->ind' points to the next argv element to be parsed.

    If no long option is found, 'longind' is -1 at return. Function's
    return value depends on whether there was a valid short option or not.

    At the end of options, -1 is returned. There may still be
    non-option arguments in the 'argv' left (starting from 'argv[data->ind]').

    In the case of error, '?' is returned. If 'data->opt' == '\0' then
    there has been error in long option parsing. In every other case
    error was detected during short option parsing, and 'data->opt'
    indicates the invalid option.  In both cases,  'data->miss_arg' gives
    more information about error. In long option parsing fails, the
    faulty argv-element can be found in 'argv[data->ind-1]'.

    '+'-options are not accepted as long options.

    Short options are internally parsed using ssh_getopt().

    Differences with the GNU getopt_long implementation:

    - Non-option arguments are never permuted. Behaviour of the SSH
      implementation corresponds to the GNU implementation with
      POSIXLY_CORRECT environment variable defined.

    - If shortopts contains "W;" then GNU treats command line -W foo
      as long option --foo. ssh_getopt_long() does not implement this
      feature.

 */
int ssh_getopt_long(int argc, char *const *argv, const char *shortopts,
                    SshLongOptionConst longopts, int *longind,
                    SshGetOptData data);

/**
 * Works like getopt_long_only(3). Structure 'data' is used like in
 * ssh_getopt() and ssh_getopt_long.
 */
int ssh_getopt_long_only(int argc, char *const *argv, const char *shortopts,
                         SshLongOptionConst longopts, int *longind,
                         SshGetOptData data);

#ifdef __cplusplus
}
#endif

#endif /* ! SSHGETOPT_H */

/* eof (sshgetopt.h) */
