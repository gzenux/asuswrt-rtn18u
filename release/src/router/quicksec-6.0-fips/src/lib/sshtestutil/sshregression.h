/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshregression.h
*/

#ifndef SSH_REGRESSION_H_INCLUDED
#define SSH_REGRESSION_H_INCLUDED

#include "sshmatch.h"
#include "sshtimemeasure.h"

void ssh_regression_init(int *argc, char ***argv,
                         char *module_name,
                         char *maintainer_address);

void ssh_regression_finish(void);

extern char   *ssh_regression_pattern;
extern int     ssh_regression_number;
extern Boolean ssh_regression_abort_at_error;
extern int     ssh_regression_errors;

void ssh_regression_section(const char *name);

#define SSH_REGRESSION_TEST_GEN(descr, init, timer, func, args)               \
do                                                                            \
{                                                                             \
  if (ssh_match_pattern(#func, ssh_regression_pattern))                       \
    {                                                                         \
      Boolean __result;                                                       \
      struct SshTimeMeasureRec __measure;                                     \
                                                                              \
      do                                                                      \
        {                                                                     \
          init;                                                               \
        }                                                                     \
      while (0);                                                              \
                                                                              \
      fprintf(stderr, "%3d. `%s' (%s) ... ",                                  \
              ++ssh_regression_number, descr, #func);                         \
                                                                              \
                                                                              \
      if (timer)                                                              \
        {                                                                     \
          ssh_time_measure_init(&__measure);                                  \
          ssh_time_measure_start(&__measure);                                 \
        }                                                                     \
                                                                              \
      __result = func args;                                                   \
                                                                              \
      if (timer)                                                              \
        {                                                                     \
          ssh_time_measure_stop(&__measure);                                  \
        }                                                                     \
                                                                              \
      if (__result)                                                           \
        {                                                                     \
          if (timer)                                                          \
            {                                                                 \
              SshUInt64 __secs;                                               \
              SshUInt32 __nanosecs;                                           \
                                                                              \
              ssh_time_measure_get_value(&__measure,                          \
                                         &__secs, &__nanosecs);               \
              fprintf(stderr, "ok (%lu.%02u s)\n",                            \
                      (unsigned long)__secs,                                  \
                      (unsigned int)(__nanosecs/10000000));                   \
            }                                                                 \
          else                                                                \
            {                                                                 \
              fprintf(stderr, "ok\n");                                        \
            }                                                                 \
        }                                                                     \
      else                                                                    \
        {                                                                     \
          fprintf(stderr, "FAILED\n");                                        \
          ssh_regression_errors++;                                            \
          if (ssh_regression_abort_at_error)                                  \
            {                                                                 \
              ssh_regression_finish();                                        \
            }                                                                 \
        }                                                                     \
    }                                                                         \
}                                                                             \
while (0)

#define SSH_REGRESSION_TEST(descr, func, args) \
SSH_REGRESSION_TEST_GEN(descr, (void)0, FALSE, func, args)

#define SSH_REGRESSION_TEST_TIME(descr, func, args) \
SSH_REGRESSION_TEST_GEN(descr, (void)0, TRUE, func, args)

#define SSH_REGRESSION_TEST_INIT(descr, init, func, args) \
SSH_REGRESSION_TEST_GEN(descr, init, FALSE, func, args)

#endif /* SSH_REGRESSION_H_INCLUDED */
