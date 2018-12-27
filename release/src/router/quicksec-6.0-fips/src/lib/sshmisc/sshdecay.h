/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Decaying counter calculations
*/

#ifndef SSHDECAY_H
#define SSHDECAY_H

#include "sshtime.h"

/* Decaying counters are used to get average running statistics out from the
   last n seconds. Each counter is allocated using ssh_decay_counter_allocate
   and that will start timer that will update the counter every m seconds. If n
   is less than 100 then m is n/10 seconds, if n is less than 300 then m is
   n/30 seconds, otherwise it is n/60 seconds. You can add numbers to counter
   using ssh_decay_counter_add, and you can get the current running statistics
   value from the counter using ssh_decay_counter_get function. When counter is
   no longer needed you can delete it using ssh_decay_counter_delete. */

/* Counter object */
typedef struct SshDecayCounterRec *SshDecayCounter;

/* Counter types. The SSH_DECAY_COUNTER_VERY_FAST will detect changes quicly,
   but it is also quite inaccurate. The SSH_DECAY_COUNTER_VERY_SLOW detect
   changes slowly, but it will be very accurate. */
typedef enum {
  SSH_DECAY_COUNTER_VERY_FAST = 0,
  SSH_DECAY_COUNTER_FAST = 1,
  SSH_DECAY_COUNTER_NORMAL = 2,
  SSH_DECAY_COUNTER_SLOW = 3,
  SSH_DECAY_COUNTER_VERY_SLOW = 4
} SshDecayCounterType;

/* Allocate new decaying counter, and initialize it to zero. This will start
   timers to process counter. The decaying counter will calculate running
   average from the last `interval' seconds. */
SshDecayCounter ssh_decay_counter_allocate(SshDecayCounterType type,
                                           SshTime interval);

/* Destroy decaying counter */
void ssh_decay_counter_delete(SshDecayCounter counter);

/* Add number to the decaying timer. */
void ssh_decay_counter_add(SshDecayCounter counter, SshUInt64 value);

/* Get number from the decaying timer */
SshUInt64 ssh_decay_counter_get(SshDecayCounter counter);

#endif /* SSHDECAY_H */
