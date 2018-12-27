/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshregression.h"
#include "sshmatch.h"
#include "sshdebug.h"
#include "sshglobals.h"

char   *ssh_regression_pattern;
int     ssh_regression_number;
Boolean ssh_regression_abort_at_error;
int     ssh_regression_errors;
char   *ssh_regression_maintainer;
char   *ssh_regression_module;
char  **ssh_regression_argv;

void ssh_regression_init(int *argc, char ***argv,
                         char *module, char *maintainer)
{
  int n = *argc;
  int i;

  ssh_regression_argv = ssh_xmalloc(n * sizeof(char *));
  memcpy(ssh_regression_argv, *argv, sizeof(char *) * n);
  *argv = ssh_regression_argv;

  ssh_regression_pattern = "*";
  ssh_regression_abort_at_error = TRUE;
  ssh_debug_set_level_string("*=0");
  ssh_regression_errors = 0;
  ssh_regression_number = 0;

  if (maintainer != NULL)
    ssh_regression_maintainer = ssh_xstrdup(maintainer);

  ssh_regression_module = ssh_xstrdup(module);

  for (i = 0; i < n; i++)
    {
    redo:
      if (i == n) break;

      if (!strcmp(ssh_regression_argv[i], "--test") && (i + 1) < n)
        {
          ssh_regression_pattern = ssh_xstrdup(ssh_regression_argv[i + 1]);
          memmove(&ssh_regression_argv[i],
                  &ssh_regression_argv[i + 2],
                  sizeof(char *) * (n - (i + 2)));
          n -= 2;
          goto redo;
        }

      if (!strcmp(ssh_regression_argv[i], "--all"))
        {
          ssh_regression_abort_at_error = FALSE;
          memmove(&ssh_regression_argv[i],
                  &ssh_regression_argv[i + 1],
                  sizeof(char *) * (n - (i + 1)));
          n -= 1;
          goto redo;
        }

      if (!strcmp(ssh_regression_argv[i], "--debug") && (i + 1) < n)
        {
          ssh_debug_set_level_string(ssh_regression_argv[i + 1]);
          memmove(&ssh_regression_argv[i],
                  &ssh_regression_argv[i + 2],
                  sizeof(char *) * (n - (i + 2)));
          n -= 2;
          goto redo;
        }
    }

  *argc = n;

  fprintf(stderr, "Starting regression testing for `%s'.\n",
          ssh_regression_module);
}

void ssh_regression_finish(void)
{
  int rv;

  fprintf(stderr, "\n");
  if (ssh_regression_abort_at_error && ssh_regression_errors)
    {
      fprintf(stderr, "[Aborted after the first error.]\n");
    }
  else
    {
      fprintf(stderr, "Regression testing finished, ");

      switch (ssh_regression_errors)
        {
        case 0:
          fprintf(stderr, "no errors encountered.\n");
          break;
        case 1:
          fprintf(stderr, "one error encountered.\n");
          break;
        default:
          fprintf(stderr, "%d errors encountered.\n", ssh_regression_errors);
          break;
        }
    }
  if (!ssh_regression_errors)
    {
      rv = 0;
      goto done;
    }

  fprintf(stderr, "\nFailing regression testing is an unexpected result.\n"
          "Please contact the maintainer [%s] for support and maintenance.\n",
          ssh_regression_maintainer);

  rv = ssh_regression_errors;
  if (rv > 100) rv = 100;
 done:
  ssh_xfree(ssh_regression_maintainer);
  ssh_xfree(ssh_regression_module);
  ssh_xfree(ssh_regression_argv);

  ssh_util_uninit();
  exit(rv);
}

void ssh_regression_section(const char *name)
{
  int w;
  fprintf(stderr, "==[%s]", name);
  w = 75 - strlen(name);
  while (w)
    {
      fputc('=', stderr);
      w--;
    }
  fprintf(stderr, "\n");
}
