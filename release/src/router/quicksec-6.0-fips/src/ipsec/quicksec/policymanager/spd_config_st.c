/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Configuration thread that schedules user's configuration changes to
   the main thread.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmStConfig"

/*************************** Config thread states ***************************/

SSH_FSM_STEP(ssh_pm_st_config_start)
{
  SshPm pm = (SshPm) thread_context;

  /* Wait until PM does not have an active configuration batch. */
  if (pm->batch_active)
    SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);

  /* Check policy manager shutdown. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      /* Abort this configuration update batch. */

      SSH_DEBUG(SSH_D_FAIL,
                ("Policy manager is shutting down: aborting batch"));

      /* Free pending additions and deletions. */
      if (pm->config_pending_additions)
        ssh_adt_clear(pm->config_pending_additions);
      if (pm->config_pending_deletions)
        ssh_adt_clear(pm->config_pending_deletions);

      /* Notify user. */
      (*pm->config_callback)(pm, FALSE, pm->config_callback_context);

      /* Notify the main thread that we have finished. */
      pm->config_active = 0;
      SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);

      /* We are done. */
      return SSH_FSM_FINISH;
    }

  /* Transfer pending additions and deletions to the final batch
     containers. */
  ssh_pm_config_pending_to_batch(pm);

  /* Set completion callback. */
  pm->batch.status_cb = pm->config_callback;
  pm->batch.status_cb_context = pm->config_callback_context;

  /* The batch is now ready.  Let's notify the main thread. */
  pm->batch_active = 1;
  pm->batch_changes = 0;
  SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);

  /* And we are done. */
  pm->config_active = 0;

  return SSH_FSM_FINISH;
}
