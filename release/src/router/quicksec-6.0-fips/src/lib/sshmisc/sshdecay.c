/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Decaying counter calculations
*/

#include "sshincludes.h"
#include "sshdecay.h"
#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "SshDecay"

/* Decaying counters are used to get average running statistics out from the
   last n seconds. Each counter is allocated using ssh_decay_counter_allocate
   and that will start timer that will update the counter every m seconds. If n
   is less than 100 then m is n/10 seconds, if n is less than 300 then m is
   n/30 seconds, otherwise it is n/60 seconds. You can add numbers to counter
   using ssh_decay_counter_add, and you can get the current running statistics
   value from the counter using ssh_decay_counter_get function. When counter is
   no longer needed you can delete it using ssh_decay_counter_delete. */

/* Counter object */
struct SshDecayCounterRec {
  SshTimeoutStruct tmout;
  SshUInt64 last_value;
  SshUInt64 current;
  SshUInt64 multiplier;
  SshUInt64 divisior;
  SshTime next_time;
  SshTime timer;
};

/* Decay timer */
void ssh_decay_counter_timer(void *context)
{
  SshDecayCounter counter = context;
  SshTime now;

  counter->current *= counter->multiplier;
  counter->current /= 1000000;
  counter->last_value = counter->current / counter->divisior;
  SSH_DEBUG(SSH_D_LOWOK, ("Updating decay counter, value = %ld",
                          (unsigned long) counter->last_value));

  counter->next_time += counter->timer;
  now = ssh_time();
  if (counter->next_time < now)
    ssh_register_timeout(&counter->tmout, 0, 0,
                         ssh_decay_counter_timer, context);
  else
    ssh_register_timeout(&counter->tmout,
                         (long)(counter->next_time - now), 0,
                         ssh_decay_counter_timer, context);
}

/* Magic numbers are calculated using forumula:

   x = leftover ^ (1 / (decay_time / timer_time)),
   s = 1 / (1 - x) - 1
   m = timer_time * s

   where

   decay_time is the decaying time (1, 5, 15, 60 min) in
   seconds,

   timer_time is the time how often this callback is called,

   leftover is the value left after decay_time (0.75 means that the statistics
   will be within 10% if exact value after one decay_time). The smaller it is,
   the faster the decaying counter is to notice changes. The larger it is the
   more accurate the numbers are.

   x is the multiplier used every timer_time to multiply the
   statistics values,

   s is the sum of x+x^2+x^3+...,

   m is the correction value used calculate bytes/packets per second.

   To calc the values again run following perl script:

        $timer_time = 1;
        $leftover = 0.75;
        sub calc {
            my($decay_time) = @_;
            $x = $leftover ** ($timer_time / $decay_time);
            $s = 1 / (1 - $x) - 1;
            $m = $timer_time * $s;
        #    printf("%d\t%d\t%d\t%d\n", $decay_time/60, $x*1000000,
        #           $s * 1000, $m);
            printf("#define MUL_%d\t%d\n#define DIV_%d\t%d\n",
                   $decay_time, $x * 1000000, $decay_time, $s * 1000);
        }
        calc(10);
        calc(30);
        calc(60);

   So the first numbers are when the decaying is called 10 times per
   decay_time, and second 30 times and last 60 times per decay_time. */

typedef struct SshDecayCounterConstsRec {
  unsigned long multiplier;
  unsigned long divisior;
} *SshDecayCounterConsts;

const struct SshDecayCounterConstsRec ssh_decay_counter_consts[][3] =
{
  { /* 0.1 */
    { /* 10 times / interval */ 794328, 3862 },
    { /* 30 times / interval */ 926118, 12535 },
    { /* 60 times / interval */ 962350, 25560 },
  },
  { /* 0.25 */
    { /* 10 times / interval */ 870550, 6725 },
    { /* 30 times / interval */ 954841, 21144 },
    { /* 60 times / interval */ 977159, 42782 },
  },
  { /* 0.5 */
    { /* 10 times / interval */ 933032, 13932 },
    { /* 30 times / interval */ 977159, 42782 },
    { /* 60 times / interval */ 988514, 86062 },
  },
  { /* 0.75 */
    { /* 10 times / interval */ 971641, 34262 },
    { /* 30 times / interval */ 990456, 103782 },
    { /* 60 times / interval */ 995216, 208063 },
  },
  { /* 0.9 */
    { /* 10 times / interval */ 989519, 94413 },
    { /* 30 times / interval */ 996494, 284236 },
    { /* 60 times / interval */ 998245, 568973 },
  },
};

/* Allocate new decaying counter, and initialize it to zero. This will start
   timers to process counter. The decaying counter will calculate running
   average from the last `interval' seconds  */
SshDecayCounter ssh_decay_counter_allocate(SshDecayCounterType type,
                                           SshTime interval)
{
  SshDecayCounter counter;

  if ((counter = ssh_calloc(1, sizeof(*counter))) == NULL)
    return NULL;

  if (interval <= 100)
    {
      counter->timer = interval / 10;
      counter->multiplier = ssh_decay_counter_consts[type][0].multiplier;
      counter->divisior = ssh_decay_counter_consts[type][0].divisior *
        counter->timer / 1000;
    }
  else if (interval <= 300)
    {
      counter->timer = interval / 30;
      counter->multiplier = ssh_decay_counter_consts[type][1].multiplier;
      counter->divisior = ssh_decay_counter_consts[type][1].divisior *
        counter->timer / 1000;
    }
  else
    {
      counter->timer = interval / 60;
      counter->multiplier = ssh_decay_counter_consts[type][2].multiplier;
      counter->divisior = ssh_decay_counter_consts[type][2].divisior *
        counter->timer / 1000;
    }
  counter->next_time = ssh_time() + counter->timer;
  SSH_DEBUG(SSH_D_HIGHSTART, ("Allocated counter, interval = %ld "
                              "(timer = %ld), multiplier = %ld, "
                              "divisior = %ld",
                              (unsigned long) interval,
                              (unsigned long) counter->timer,
                              (unsigned long) counter->multiplier,
                              (unsigned long) counter->divisior));
  ssh_register_timeout(&counter->tmout,
                       (long)counter->timer, 0, ssh_decay_counter_timer,
                        counter);
  return counter;
}

/* Destroy decaying counter */
void ssh_decay_counter_delete(SshDecayCounter counter)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Destroying decay counter"));
  ssh_cancel_timeouts(ssh_decay_counter_timer, counter);
  ssh_free(counter);
}

/* Add number to the decaying timer. */
void ssh_decay_counter_add(SshDecayCounter counter, SshUInt64 value)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Adding %ld to decay counter",
                          (unsigned long) value));
  counter->current += value;
}

/* Get number from the decaying timer */
SshUInt64 ssh_decay_counter_get(SshDecayCounter counter)
{
  return counter->last_value;
}
