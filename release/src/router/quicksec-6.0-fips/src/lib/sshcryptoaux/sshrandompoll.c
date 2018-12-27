/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Periodically poll the system for noise and add it to the random number
   generator.
*/

#include "sshincludes.h"
#include "sshglobals.h"
#include "sshtimeouts.h"
#include "sshcrypt.h"
#include "sshcryptoaux.h"
#include "sshentropy.h"

#define SSH_DEBUG_MODULE "CryptoRandomPoll"

typedef struct SshRandomPollRec {
  Boolean registered;
  SshTime last_collect_time;
} SshRandomPollStruct, *SshRandomPoll;

SSH_GLOBAL_DECLARE(SshRandomPollStruct, ssh_random_poll_state);
#define ssh_random_poll_state SSH_GLOBAL_USE(ssh_random_poll_state)

SSH_GLOBAL_DEFINE(SshRandomPollStruct, ssh_random_poll_state);

/******************* Retrieve noise from operating env ******************/

void random_poll_add_light_noise(SshRandomPoll state)
{
  unsigned char noise_bytes[512] = {'\0'};
  size_t return_length;
  size_t entropy_bits = 0;
  SshTime now;

  /* First check the time since last noise collection and ignore noise request
     if not enough time has gone. */
  now = ssh_time();
  if (now - state->last_collect_time <= SSH_RANDOM_POLL_MIN_INTERVAL)
    return;

  state->last_collect_time = now;

  if (!ssh_get_system_noise(noise_bytes, 512, &return_length, &entropy_bits))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get noise"));
      return;
    }

  /* Add collected entropic (hopefully) bytes */
  ssh_random_add_noise(noise_bytes, return_length, entropy_bits);
}

/******************* Random noise source provider ***********************/

/* Noise signal callback. Crypto library calls this function whenever it's
   entropy level is low. */
void
random_noise_poll_signal_cb(void *context)
{
  /* Add noise to crypto library. */
  random_poll_add_light_noise(&ssh_random_poll_state);
}

void
ssh_random_noise_polling_init(void)
{
  SshRandomPollStruct poll;

  if (SSH_GLOBAL_CHECK(ssh_random_poll_state)
      && ssh_random_poll_state.registered)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Random noise polling is already initialized"));
      return;
    }

  /* Initialize global state. */
  memset(&poll, 0, sizeof(poll));
  SSH_GLOBAL_INIT(ssh_random_poll_state, poll);

  /* Register noise source to crypto library. */
  if (ssh_crypto_library_register_noise_request(random_noise_poll_signal_cb,
                                                &ssh_random_poll_state))
    {
      ssh_random_poll_state.registered = TRUE;
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Registered noise source to crypto library"));
    }
  else
    {
      ssh_random_poll_state.registered = FALSE;
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to register noise source to crypto library"));
    }
}

void
ssh_random_noise_polling_uninit(void)
{
  if (!SSH_GLOBAL_CHECK(ssh_random_poll_state)
      || !ssh_random_poll_state.registered)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Random noise polling is already in uninitialized state"));
      return;
    }

  /* Unregister noise source. */
  if (ssh_crypto_library_unregister_noise_request(random_noise_poll_signal_cb,
                                                  &ssh_random_poll_state))
    {
      ssh_random_poll_state.registered = FALSE;
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Unregistered noise source from crypto library"));
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to unregister noise source from crypto library"));
    }
}
