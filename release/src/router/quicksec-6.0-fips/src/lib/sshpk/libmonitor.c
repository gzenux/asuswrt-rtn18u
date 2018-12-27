/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Crypto library monitoring functions.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "libmonitor.h"
#include "sshglobals.h"

/* Global working pointer, that'll indicate the position of applications
   routine for handling these calls. */

SSH_GLOBAL_DECLARE(SshCryptoProgressMonitor,
                   ssh_crypto_progress_monitor_function);
SSH_GLOBAL_DEFINE_INIT(SshCryptoProgressMonitor,
                       ssh_crypto_progress_monitor_function) = NULL_FNPTR;
#define ssh_crypto_progress_monitor_function \
  SSH_GLOBAL_USE_INIT(ssh_crypto_progress_monitor_function)

typedef void *SshCryptoProgressContext;
SSH_GLOBAL_DECLARE(SshCryptoProgressContext, ssh_crypto_progress_context);
SSH_GLOBAL_DEFINE_INIT(SshCryptoProgressContext,
                       ssh_crypto_progress_context) = NULL;
#define ssh_crypto_progress_context \
  SSH_GLOBAL_USE_INIT(ssh_crypto_progress_context)

#ifdef SSHDIST_PLATFORM_VXWORKS
#ifdef VXWORKS
#ifdef ENABLE_VXWORKS_RESTART_WATCHDOG
void ssh_crypto_restart(void)
{
  ssh_crypto_progress_monitor_function = NULL;
  ssh_crypto_progress_context = NULL;
}
#endif /* ENABLE_VXWORKS_RESTART_WATCHDOG */
#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */

/* Interface from library. */

void ssh_crypto_progress_monitor(SshCryptoProgressID id,
                                 unsigned int time_value)
{
  if (ssh_crypto_progress_monitor_function != NULL_FNPTR)
    (*ssh_crypto_progress_monitor_function)(id, time_value,
                                            ssh_crypto_progress_context);
}

/* Interface from application. */

void
ssh_crypto_library_register_progress_func(SshCryptoProgressMonitor
                                          monitor_function,
                                          void *progress_context)
{
  if (monitor_function == NULL_FNPTR)
    {
      ssh_crypto_progress_monitor_function = NULL_FNPTR;
      ssh_crypto_progress_context = NULL;
      return;
    }

  ssh_crypto_progress_monitor_function = monitor_function;
  ssh_crypto_progress_context = progress_context;
  return;
}

/* libmonitor.c */
