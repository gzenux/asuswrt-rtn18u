/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Policy manager; Certificate validator notifying deleted objects.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "sshadt.h"
#include "sshadt_bag.h"

#define SSH_DEBUG_MODULE "SshPmCmNotify"

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT

#if 0
/* Somewhat expensive mechanism to avoid crashes when the validator
   has decided to discard an object we have storing with forced
   reload. This function is not needed, if the application does not
   call ssh_cm_reset() before all tunnels and negotiations related to
   those are torn down (and ike library has called appropriate
   sa_freed()' callbacks */
void
ssh_pm_cm_certificate_notify_callback(void *context,
                                      SshCMNotifyEventType event,
                                      SshCMCertificate object)
{
  SshPm pm = (SshPm) context;
  SshPmP1 p1;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Validator %ss the certificate handle %p",
             (event == SSH_CM_EVENT_CERT_NEW) ? "create"
             : (event == SSH_CM_EVENT_CERT_FREE) ? "free"
             : (event == SSH_CM_EVENT_CERT_REVOKED) ? "revoke"
             : "notifie",
             object));

  if (event == SSH_CM_EVENT_CERT_FREE)
    {
      int i;
      SshADTHandle h;

      for (i = 0; i < pm->num_cas; i++)
        if (pm->cas[i]->cert == object)
          pm->cas[i]->cert = NULL;

      /* The object can be at tunnels (u.ike.local_cert, cas) */
      for (h = ssh_adt_enumerate_start(pm->tunnels);
           h != SSH_ADT_INVALID;
           h = ssh_adt_enumerate_next(pm->tunnels, h))
        {
          SshPmTunnel tunnel;

          tunnel = ssh_adt_get(pm->tunnels, h);
          if (tunnel && tunnel->ike_tn)
            {
              if (tunnel->u.ike.local_cert_kid == object)
                tunnel->u.ike.local_cert = NULL;
            }
        }

      for (p1 = pm->active_p1_negotiations; p1; p1 = p1->n->next)
        {
          if (p1->auth_cert == object)
            p1->auth_cert = NULL;
          if (p1->auth_ca_cert == object)
            p1->auth_ca_cert = NULL;
        }

      /* The object can be at P1 (auth_cert, auth_ca_cert) */
      for (i = 0; i < SSH_PM_IKE_SA_HASH_TABLE_SIZE; i++)
        {
          for (p1 = pm->ike_sa_hash[i]; p1; p1 = p1->hash_next)
            {
              if (p1->auth_cert == object)
                p1->auth_cert = NULL;
              if (p1->auth_ca_cert == object)
                p1->auth_ca_cert = NULL;
            }
        }
    }
}
#endif
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
