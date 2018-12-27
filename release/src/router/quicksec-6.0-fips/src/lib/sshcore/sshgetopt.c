/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
                                            ssh_getopt_long_only)

   Source for ssh_getopt, ssh_getopt_long, ssh_getopt_long_only.

   The idea of argv traversal is from the BSD source code (ssh_getopt).
*/

#define SSHGETOPT_C

#define SSH_DEBUG_MODULE "SshGetOpt"

#include "sshincludes.h"
#include "sshgetopt.h"
#include "sshglobals.h"

SSH_GLOBAL_DECLARE(struct SshGetOptDataRec, ssh_getopt_default_data);
SSH_GLOBAL_DEFINE_INIT(struct SshGetOptDataRec, ssh_getopt_default_data) =
  SSH_GETOPT_DATA_INITIALIZER;
#define ssh_getopt_default_data SSH_GLOBAL_USE_INIT(ssh_getopt_default_data)

void ssh_getopt_init_data(SshGetOptData data)
{
  static const struct SshGetOptDataRec def = SSH_GETOPT_DATA_INITIALIZER;
  *data = def;
  return;
}

#ifdef VXWORKS
void ssh_getopt_restart(void)
{
  memset(&ssh_getopt_default_data, 0, sizeof(struct SshGetOptDataRec));
  ssh_getopt_default_data.err = 1;
  ssh_getopt_default_data.ind = 1;
  ssh_getopt_default_data.current = "";
}
#endif /* VXWORKS */

static int ssh_str_is_number(char *str)
{
  if (!str)
    return 0;
  if ((*str == '-') || (*str == '+'))
    str++;
  if (!(*str))
    return 0;
  for (/*NOTHING*/; *str; str++)
    if ((*str < '0') || (*str > '9'))
      return 0;
  return 1;
}

int ssh_getopt(int argc, char **argv, const char *ostr, SshGetOptData data)
{
  char *optidx;

  if (data == NULL)
    data = &ssh_getopt_default_data;

  if (data->reset || !(*(data->current)))
    {
      data->reset = 0;
      if (data->ind < argc)
        {
          data->current = argv[data->ind];
        }
      else
        {
          data->current = "";
          return -1;
        }
      if (*(data->current) == '-')
        {
          data->val = 1;
        }
      else if ((data->allow_plus) && (*(data->current) == '+'))
        {
          data->val = 0;
        }
      else
        {
          data->current = "";
          return -1;
        }
      if (data->current[1] && (*(++(data->current)) == '-')
          && (data->current[1] == '\0'))
        {
          /* "--" */
          data->current = "";
          data->ind++;
          return -1;
        }
    }
  if ((data->opt = (int)*((data->current)++)) == ((int)':') ||
      (!(optidx = strchr(ostr, data->opt))))
    {
      if (data->opt == (int)'-')
        {
          /* if '-' is not an option, options, this ends the parsing */
          return -1;
        }
      /* option is illegal */
      if (!(*(data->current)))
        data->ind++;
      if (data->err && (*ostr != ':'))
        {
          fprintf(stderr, "illegal option -- %c\n", data->opt);
        }
      data->miss_arg = 0;
      return '?';
    }
  if (*(++optidx) == ':')
    {
      Boolean optional_arg = FALSE;

      if (*(optidx + 1) == ':')
        {
          optional_arg = TRUE;
          optidx++;
        }

      /* option with argument */
      if (*(data->current))
        {
          /* argument in the same element */
          data->arg = data->current;
          if (ssh_str_is_number(data->arg))
            {
              data->arg_num = 1;
              data->arg_val = atoi((data->arg));
            }
          else
            {
              data->arg_num = 0;
            }
        }
      else if (!optional_arg && argc > ++(data->ind))
        {
          /* argument in the next element */
          data->arg = argv[data->ind];
          if (ssh_str_is_number(data->arg))
            {
              data->arg_num = 1;
              data->arg_val = atoi(data->arg);
            }
          else
            {
              data->arg_num = 0;
            }
        }
      else
        {
          if (optional_arg)
            goto no_err;

          /* argument missing */
          data->current = "";
          if (*ostr == ':')
            return ':';
          if (data->err)
            {
              fprintf(stderr,
                      "option requires an argument -- %c\n",
                      data->opt);
            }
          data->miss_arg = 1;
          return '?';
        }
      data->current = "";
      data->ind++;
    }
  else
    {
    no_err:
      /* no argument */
      data->arg = NULL;
      data->arg_num = 0;
      if (!(*(data->current)))
        data->ind++;
    }
  return data->opt;
}


/* -------------- ssh_getopt_long() implementation -------------------- */

/* values for the 'caller' parameter of ssh_getopt_long_private() */
#define SSH_GETOPT_LONG_CALL 0
#define SSH_GETOPT_LONG_ONLY_CALL 1
/* return values for ssh_getopt_strmatch() */
#define SSH_GETOPT_STRMATCH_NONE      0
#define SSH_GETOPT_STRMATCH_PARTIAL   1
#define SSH_GETOPT_STRMATCH_EXACT     2
/* return values for ssh_getopt_find_long_option_name() */
#define SSH_GETOPT_LONGOPT_NO_MATCH  (-1)
#define SSH_GETOPT_LONGOPT_AMBIGUOUS (-2)


/*
   Check if 'little' matches exactly or partially
   to 'big'.

   Returns:
      SSH_GETOPT_STRMATCH_NONE
      SSH_GETOPT_STRMATCH_PARTIAL
      SSH_GETOPT_STRMATCH_EXACT
 */

static int
ssh_getopt_strmatch(const char *big, const char *little)
{
  if (big != NULL && little != NULL)
    {
      while (*little != '\0' && *big != '\0' && *big == *little)
        {
          big++;
          little++;
        }
      if (*little == '\0')
          return (*big == '\0') ? SSH_GETOPT_STRMATCH_EXACT :
            SSH_GETOPT_STRMATCH_PARTIAL;
    }
  return SSH_GETOPT_STRMATCH_NONE;
}

/*
   Find an option name 'optname' from a long option array
   'longopts'. Match can be partial, but it must be non-ambiguous,
   so the whole 'longopts' vector is searched.

   Returns:

   >=0 = matched index
   SSH_GETOPT_LONGOPT_NO_MATCH
   SSH_GETOPT_LONGOPT_AMBIGUOUS
 */
static int
ssh_getopt_find_long_option_name(const char *optname,
                                 SshLongOptionConst longopts)
{
  int i=0;
  int match = SSH_GETOPT_LONGOPT_NO_MATCH;
  Boolean ambiguous = FALSE;

  if (longopts == NULL || optname == NULL)
    return -1;

  while (longopts[i].name != NULL)
    {
      switch (ssh_getopt_strmatch(longopts[i].name,optname))
        {
        case SSH_GETOPT_STRMATCH_EXACT:
          return i; /* return immediately if we find an exact match */

        case SSH_GETOPT_STRMATCH_PARTIAL:
          if (match != SSH_GETOPT_LONGOPT_NO_MATCH)
             /* If a previous match exists. Raise ambiguous flag,
                but still look for possible exact match */
             /* This behaviour is different from the CYGWIN implementation,
                which stops searching here. How about GNU? */
            ambiguous = TRUE;
          match = i;
          break;

        default:
          break;
        }

      i++;
    }

  return (ambiguous) ? SSH_GETOPT_LONGOPT_AMBIGUOUS : match;
}

/*
 * The actual long options parsing function
 */
static int
ssh_getopt_long_private (int argc, char *const *argv, const char *shortopts,
                         SshLongOptionConst longopts, int *longind,
                         SshGetOptData data, int caller)
{
  char *c; /* 'input' char */
  unsigned char errmsg[80];
  const int errmsglen = sizeof(errmsg) - 1;
  char *token = NULL; /* long option name */
  int lind = -1; /* local 'longind', index to found 'longopts' */
  enum {                   /* Parsing states */
    /* initial state */
    LONGOPT_BEGIN,

    /* interemediate states */
    LONGOPT_ISOPT,         /* option detected */
    LONGOPT_ISLONGOPT,     /* longopt detected */
    LONGOPT_ISLONGOPTONLY, /* longopt_only handling */
    LONGOPT_ARGUMENT,      /* argument extraction */

    /* final states */
    LONGOPT_ERROR,         /* parse error */
    LONGOPT_END,           /* successful exit */
    LONGOPT_END_OF_OPTIONS /* non-option argument encountered */

  } state = LONGOPT_BEGIN;

  SSH_ASSERT(argv != NULL);
  SSH_ASSERT(shortopts != NULL);
  SSH_ASSERT(longopts != NULL);

  if (data == NULL)
      data = &ssh_getopt_default_data;

  data->arg = NULL;

  if (data->ind >= argc)
    return -1;

  c = argv[data->ind];

  if (longind)
    *longind = -1;

  while (1)
    {
      switch (state)
        {
        case LONGOPT_BEGIN:

          /* Begin parsing an argv element */

          if (*c == '-')
            {
              ++c;
              state = LONGOPT_ISOPT;
            }
          else if (*c == '+' && data->allow_plus)
            {
              /* This is a short option. */
              return ssh_getopt(argc, (char **)argv, shortopts, data);
            }
          else
            {
              state = LONGOPT_END_OF_OPTIONS;
            }
          break;

        case LONGOPT_ISOPT:

          /* The argv element contains an option. Let's find out
             here, what kind of an option */

          if (*c == '\0')
            {
              ssh_snprintf(errmsg, errmsglen,
                       "invalid argument %s", argv[data->ind]);
              data->miss_arg = SSH_GETOPT_MISS_ARG_INVALID_OPT;
              state = LONGOPT_ERROR;
            }
          else if (*c == '-')
            {
              ++c;
              token = c;
              state = LONGOPT_ISLONGOPT;
            }
          else if (caller == SSH_GETOPT_LONG_ONLY_CALL)
            {
              /* if caller is getopt_long_only(), we prefer
                 to think that this may be a long option */
              token = c;
              state = LONGOPT_ISLONGOPTONLY;
            }
          else
            {
              /* parse this argv element as short option(s) */
              return ssh_getopt(argc, (char **)argv, shortopts, data);
            }
          break;

        case LONGOPT_ISLONGOPT:

          /* Two successive hyphens in the command line detected.
             Look for a long option name here. Previous state must
             assign a value for 'token' */

          SSH_ASSERT(token != NULL);

          if (*c != '\0' && *c != '=')
            {
                ++c; /* next char of the option name */
            }
          else
            {
              if (*c == '\0' && c == token) /* no option name */
                {
                  /* no option name means end of options */
                  data->ind++;
                  state = LONGOPT_END_OF_OPTIONS;
                }
              else /* (c== '\0' && option name found) || c == '=') */

                   /* note: option '--=' (zero length) matches to every
                      option and is thus ambigous if more than one options
                      is defined */
                {
                  char tmp = *c;

                  *c = '\0'; /* terminate token temporarily */
                  lind = ssh_getopt_find_long_option_name(token, longopts);
                  *c = tmp; /* cancel termination */

                  if (lind < 0)
                    {
                      switch (lind)
                        {
                        case SSH_GETOPT_LONGOPT_AMBIGUOUS:
                          data->miss_arg = SSH_GETOPT_MISS_ARG_AMBIGUOUS_OPT;
                          break;
                        case SSH_GETOPT_LONGOPT_NO_MATCH:
                          data->miss_arg = SSH_GETOPT_MISS_ARG_INVALID_OPT;
                          break;
                        default:
                          data->miss_arg = SSH_GETOPT_MISS_ARG_FATAL;
                        }

                      ssh_snprintf(errmsg, errmsglen,
                               "%s option '%s'",
                               (lind==SSH_GETOPT_LONGOPT_AMBIGUOUS) ?
                                 "ambiguous":"invalid",
                               argv[data->ind]);
                      state = LONGOPT_ERROR;
                    }
                  else
                      state = LONGOPT_ARGUMENT;
                }
            }

          break;

        case LONGOPT_ISLONGOPTONLY:

          /* Option detected and this function was called by getopt_long_only.
             Now we first have to look for a valid long option name. If
             not found, parse this argv element as short option(s).
             Previous state must assign a value for 'token' */


          SSH_ASSERT(token != NULL);

          if (*c != '\0' && *c != '=')
            {
                ++c; /* next char of the option name */
            }
          else
            {
              char tmp = *c;

              *c = '\0'; /* terminate token temporarily */
              lind = ssh_getopt_find_long_option_name(token, longopts);
              *c = tmp; /* cancel termination */

              if (lind < 0)
                {
                  /* no such long opt - parse this as short options */
                  return ssh_getopt(argc, (char **)argv, shortopts, data);
                }
              else
                {
                  state = LONGOPT_ARGUMENT;
                }
            }

          break;

        case LONGOPT_ARGUMENT:

          /* A valid long option name was found. Now look for the argument.
             Previous state has to assign value for 'lind'. Valid
             values for input char 'c' are '\0' and '=' */

          SSH_ASSERT(*c == '\0' || *c == '=');
          SSH_ASSERT(lind >= 0);




          if (*c == '=')
            {
              if (longopts[lind].has_arg > 0)
                {
                  data->arg = c+1;
                  state = LONGOPT_END;
                }
              else
                {
                  ssh_snprintf(errmsg, errmsglen,
                               "option '--%s' does not take arguments",
                               longopts[lind].name);
                  data->miss_arg = SSH_GETOPT_MISS_ARG_EXCESS_ARG;
                  state = LONGOPT_ERROR;
                }
            }
          else if (*c == '\0') /* optname valid, possible argument in the
                  next argv element */
            {
              switch (longopts[lind].has_arg)
                {
                case SSH_GETOPT_LONG_REQUIRED_ARGUMENT:
                  if (data->ind < argc-1)
                    {
                      data->arg = argv[++data->ind];
                      state = LONGOPT_END;
                    }
                  else
                    {
                      ssh_snprintf(errmsg, errmsglen,
                                   "option '--%s' requires an argument",
                                   longopts[lind].name);
                      data->miss_arg = SSH_GETOPT_MISS_ARG_MISSING_ARG;
                      state = LONGOPT_ERROR;
                    }
                  break;

                case SSH_GETOPT_LONG_OPTIONAL_ARGUMENT:
                  /*
                     optional argument cannot be in the next
                     argv element. Parsing problem exist if
                     the option is the last one before non-option
                     arguments.
                   */

                  /* no break here ! */

                case SSH_GETOPT_LONG_NO_ARGUMENT:
                  data->arg = NULL;
                  state = LONGOPT_END;
                  break;

                default:
                  ssh_snprintf(errmsg, errmsglen,
                               "invalid values in the long options vector");
                  data->miss_arg = SSH_GETOPT_MISS_ARG_INVALID_HAS_ARG;
                  state = LONGOPT_ERROR;
                  break;
                }
            }

          else
            {
              ssh_snprintf(errmsg, errmsglen,
                           "ILLEGAL INPUT (0x%02x) - FATAL PARSING ERROR", *c);
              data->miss_arg = SSH_GETOPT_MISS_ARG_FATAL;
              state = LONGOPT_ERROR;
            }
          break;

        case LONGOPT_END:

          /* A long option found successfully. data->arg points to argument,
             if present. Assign here values for 'data->arg_num' and
             'data->arg_val' fields. Option flag handling. */

          data->ind++;

          /* check if the argument is numeric */
          if ((data->arg_num = ssh_str_is_number(data->arg)))
              data->arg_val = atoi((data->arg));

          if (longopts[lind].flag != NULL)
            {
              /* assign the value for flag, if defined */
              *longopts[lind].flag = longopts[lind].val;
              data->opt = 0;
            }
          else
            {
              data->opt = longopts[lind].val;
            }

          if (longind)
              *longind = lind;

          return data->opt;

        case LONGOPT_ERROR:

          /* An error encountered */

          data->ind++;
          data->opt = 0;
          errmsg[errmsglen] = '\0'; /* force termination, pedantic */
          if (data->err)
            {
              fprintf(stderr, "%s: %s\n", argv[0], errmsg);
            }

          if (longind)
              *longind = lind;

          return (int)'?';

        case LONGOPT_END_OF_OPTIONS:

          /* No more options */
          return -1;

        default:

          /* Should never be here ! */

          ssh_snprintf(errmsg, errmsglen,
                       "UNKNOWN STATE - FATAL PROGRAM ERROR");
          data->miss_arg = SSH_GETOPT_MISS_ARG_FATAL;
          break;

        } /* end switch(state) */

    } /* end  while */
}


int
ssh_getopt_long (int argc, char *const *argv, const char *shortopts,
             SshLongOptionConst longopts, int *longind,
             SshGetOptData data)
{
  return ssh_getopt_long_private(argc, argv, shortopts, longopts, longind,
                                 data, SSH_GETOPT_LONG_CALL);

}

int
ssh_getopt_long_only (int argc, char *const *argv,
                      const char *shortopts,
                      SshLongOptionConst longopts, int *longind,
                      SshGetOptData data)
{
  return ssh_getopt_long_private(argc, argv, shortopts, longopts, longind,
                                 data, SSH_GETOPT_LONG_ONLY_CALL);

}


/* eof (sshgetopt.c) */
