/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Common states for Quick-Mode initiator and responder.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmQmCommon"

/********************************** States **********************************/

SSH_FSM_STEP(ssh_pm_st_qm_terminate)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Terminating Quick-Mode negotiation"));

  /* Update auto-start status for initiator negotiations. */
  ssh_pm_qm_update_auto_start_status(pm, qm);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  if (qm->vip != NULL)
    {
      SSH_ASSERT(qm->tunnel != NULL);
      SSH_ASSERT(qm->tunnel->vip == qm->vip);

      /* Signal vip thread to add created SA selector routes. */
      if (!qm->vip->unusable)
        {
          qm->vip->add_routes = 1;
          ssh_fsm_condition_broadcast(&pm->fsm, &qm->vip->cond);
        }

      /* Release the vip reference. */
      ssh_pm_virtual_ip_free(pm, SSH_IPSEC_INVALID_INDEX, qm->tunnel);
      qm->vip = NULL;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* Mark the SPI entry as not having a negotiation anymore. In a normal
     successful case this information has been cleared in the SA handler.
     In a error case it is done here. */
  if (qm->spi_neg_started)
    {
      if (!ssh_pm_spi_mark_neg_finished(pm, qm->old_outbound_spi,
                                        qm->old_inbound_spi))
        SSH_DEBUG(SSH_D_FAIL, ("Old outbound SPI entry not found."));
      qm->spi_neg_started = 0;
    }







  /* Trigger IKE SA timer to clear/setup childless IKE SA deletion timer. */
  if (qm->p1 != NULL && ssh_pm_get_status(pm) == SSH_PM_STATUS_ACTIVE)
    ssh_pm_ike_sa_timer_event(pm, (void *)qm->p1, ssh_time());

  /* Unlink Phase-1 structure if we have a reference to it. */
  if (qm->p1)
    qm->p1 = NULL;

  /* Unlink Exchange data */
  if (qm->ed)
    {
      SSH_PM_ASSERT_ED(qm->ed);
      qm->ed->application_context = NULL;
    }

  /* Destroy this thread.  The thread destructor will free our
     context. */
  return SSH_FSM_FINISH;
}
