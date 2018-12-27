/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Phase-II policy functions for IKEv1 fallback.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#ifdef SSHDIST_IKEV1
#include "isakmp.h"
#include "ikev2-fb.h"
#include "ikev2-fb-st.h"

#define SSH_DEBUG_MODULE "SshIkev2FallbackP2"



/*--------------------------------------------------------------------*/
/* Phase II new connections                                           */
/*--------------------------------------------------------------------*/

#ifdef SSHDIST_ISAKMP_CFG_MODE

void ikev2_fb_cfg_negotiation_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  SSH_DEBUG(SSH_D_LOWOK, ("Freeing fallback negotiation context"));

  ikev2_fb_negotiation_clear_pm_data(neg);
  ikev2_fallback_negotiation_free(neg->fb, neg);
  return;
}

SSH_FSM_STEP(ikev2_fb_cfg_negotiation_wait_done)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation)thread_context;

  if (!neg->cfg_done)
    return SSH_FSM_SUSPENDED;

  return SSH_FSM_FINISH;
}

SshIkev2FbNegotiation
ikev2_fb_alloc_cfgmode_negotiation(SshIkePMPhaseII pm_info)
{
  SshIkev2Fb fb = (SshIkev2Fb) pm_info->pm->upper_context;
  SshIkev2FbNegotiation neg;
  SshIkev2Sa ike_sa;

  ike_sa = (SshIkev2Sa) pm_info->phase_i->policy_manager_data;

  /* Allocate and init context for this negotiation. */
  if ((neg = ikev2_fallback_negotiation_alloc(fb)) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of negotation contexts."));
      return NULL;
    }

  /* Take a reference to allocated `neg' and set it to
     `pm_info->policy_manager_data'. */
  ikev2_fb_phase_ii_set_pm_data(pm_info, neg);

  /* Save `neg->p2_info' for responder cfgmode negotiations here. */
  SSH_ASSERT(neg->p2_info == NULL);
  neg->p2_info = pm_info;

  neg->server = (SshIkev2Server)
    ssh_ike_get_server_by_negotiation(pm_info->negotiation);
  neg->ike_sa = ike_sa;
  SSH_IKEV2_IKE_SA_TAKE_REF(neg->ike_sa);
  neg->ike_sa->last_input_stamp = ssh_time();

  if ((neg->ed = ikev2_allocate_exchange_data(neg->ike_sa)) == NULL)
    goto error;
  neg->ed->state = SSH_IKEV2_STATE_IKE_AUTH_LAST;

  if (ikev2_allocate_exchange_data_ipsec(neg->ed) != SSH_IKEV2_ERROR_OK)
    goto error;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Accepting new Cfg/XAuth negotiation: local=%s:%s, remote=%s:%s",
             pm_info->local_ip, pm_info->local_port,
             pm_info->remote_ip, pm_info->remote_port));

  /* Start the main thread controlling this negotiation */
  ssh_fsm_thread_init(fb->fsm, neg->thread,
                      ikev2_fb_cfg_negotiation_wait_done,
                      NULL_FNPTR,
                      ikev2_fb_cfg_negotiation_destructor, neg);

  return neg;

 error:
  SSH_ASSERT(neg != NULL);
  /* Release reference to `neg' from `pm_info->policy_manager_data'. */
  ikev2_fb_phase_ii_clear_pm_data(pm_info, neg);
  /* Free negotiation. */
  ikev2_fallback_negotiation_free(fb, neg);
  return NULL;
}

#endif /* SSHDIST_ISAKMP_CFG_MODE */

void
ikev2_fb_new_connection_phase_ii(SshIkePMPhaseII pm_info,
                                 SshPolicyNewConnectionCB callback_in,
                                 void *callback_context_in)
{
#ifdef SSHDIST_ISAKMP_CFG_MODE
  SshIkev2FbNegotiation neg;

  neg = ikev2_fb_alloc_cfgmode_negotiation(pm_info);

  (*callback_in)((neg != NULL) ? TRUE : FALSE, SSH_IKE_FLAGS_USE_DEFAULTS,
                 -1, -1, -1, -1, -1, -1, -1, callback_context_in);
  return;

#else /* SSHDIST_ISAKMP_CFG_MODE */
  (*callback_in)(TRUE, SSH_IKE_FLAGS_USE_DEFAULTS,
                 -1, -1, -1, -1, -1, -1, -1,
                 callback_context_in);
  return;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
}

/*--------------------------------------------------------------------*/
/* Notifications                                                      */
/*--------------------------------------------------------------------*/

void
ikev2_fb_delete(SshIkePMPhaseII pm_info,
                Boolean authenticated,
                SshIkeProtocolIdentifiers protocol_id,
                int number_of_spis,
                unsigned char **spis,
                size_t spi_size)
{
  SshIkev2ProtocolIdentifiers protocol;
  SshIkev2ExchangeData ed;
  SshIkev2Sa ike_sa;
  int i;

  ike_sa = (SshIkev2Sa) pm_info->phase_i->policy_manager_data;
  ike_sa->last_input_stamp = ssh_time();

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("%s IPSec SA delete notification from IKE SA %p, "
             "from %s%@ for protocol %s containing %d SPIs",
             authenticated ? "Authenticated" : "Unauthenticated",
             ike_sa, pm_info->remote_ip,
             ikev2_fb_ike_port_render, pm_info->remote_port,
             ssh_find_keyword_name(ikev2_fb_ike_protocol_identifiers,
                                   protocol_id),
             number_of_spis));

  if (!authenticated)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Ignoring unauthenticated delete notification"));
      return;
    }

  /* NOTE: Phase-2 statistics */

  switch (protocol_id)
    {
    case SSH_IKE_PROTOCOL_IPSEC_AH:
      protocol = SSH_IKEV2_PROTOCOL_ID_AH;
      break;

    case SSH_IKE_PROTOCOL_IPSEC_ESP:
      protocol = SSH_IKEV2_PROTOCOL_ID_ESP;
      break;

    case SSH_IKE_PROTOCOL_IPCOMP:
    case SSH_IKE_PROTOCOL_RESERVED:
    case SSH_IKE_PROTOCOL_ISAKMP:
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "Rejecting IPSec SA delete notification "
                    "from %s%@ since it was for protocol %s",
                    pm_info->remote_ip,
                    ikev2_fb_ike_port_render, pm_info->remote_port,
                    ssh_find_keyword_name(ikev2_fb_ike_protocol_identifiers,
                                          protocol_id));
      return;
    default:
      SSH_NOTREACHED;
      return;
    }

  if (spi_size != 4)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "Rejecting IPSec SA delete notification "
                    "from %s%@ since the SPI size %d does not match "
                    "the expected value 4",
                    pm_info->remote_ip,
                    ikev2_fb_ike_port_render, pm_info->remote_port,
                    spi_size);
      return;
    }

  ed = ikev2_allocate_exchange_data(ike_sa);
  if (ed == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No memory to allocate IKE exchange data, "
                             "ignoring delete notification"));
      return;
    }
  ed->state = SSH_IKEV2_STATE_INFORMATIONAL;

  /* Inform the policy manager about the deleted spi's */
  for (i = 0; i < number_of_spis; i++)
    {
      SshUInt32 spi;
      spi = SSH_GET_32BIT(spis[i]);

      SSH_DEBUG(SSH_D_LOWSTART,
                ("FB; Calling v2 policy function ipsec_spi_delete_received"));
      (*ike_sa->server->sad_interface->ipsec_spi_delete_received)(
                                                    ike_sa->server->sad_handle,
                                                    ed,
                                                    protocol,
                                                    1,
                                                    &spi,
                                                    NULL_FNPTR, NULL);
    }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* Handle pending NAT-T operations */
  ikev2_fb_phase_ii_pending_natt_operations(ike_sa, ed,
                                            (SshIkev2FbNatTInfo)
                                            pm_info->policy_manager_data);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  ikev2_free_exchange_data(ike_sa, ed);
  return;
}


/*--------------------------------------------------------------------*/
/* Notifications                                                      */
/*--------------------------------------------------------------------*/

void
ikev2_fb_notification(SshIkePMPhaseII pm_info,
                      Boolean authenticated,
                      SshIkeProtocolIdentifiers proto,
                      unsigned char *spi,
                      size_t spi_size,
                      SshIkeNotifyMessageType type,
                      unsigned char *data,
                      size_t data_size)
{
  SshIkev2Sa ike_sa;
  char buf[64];
  SshIkev2NotifyState notify_state;
  SshIkev2NotifyMessageType ikev2_notify_type;

  notify_state = authenticated ? SSH_IKEV2_NOTIFY_STATE_AUTHENTICATED_INITIAL :
    SSH_IKEV2_NOTIFY_STATE_UNAUTHENTICATED_INITIAL;

  ike_sa = (SshIkev2Sa) pm_info->phase_i->policy_manager_data;
  ike_sa->last_input_stamp = ssh_time();

  SSH_DEBUG(SSH_D_LOWOK, ("Phase-II %snotification call entered, IKE SA %p",
                          (authenticated ? "authenticated " : ""), ike_sa));

  switch (type)
    {
    case SSH_IKE_NOTIFY_MESSAGE_INITIAL_CONTACT:
    case SSH_IKE_NOTIFY_MESSAGE_INVALID_SPI:
      if (authenticated)
        {
          SshIkev2ExchangeData ed;

          ed = ikev2_allocate_exchange_data(ike_sa);
          if (ed == NULL)
            return;
          ed->state = SSH_IKEV2_STATE_INFORMATIONAL;

          ikev2_notify_type = ikev2_fb_v1_notify_type_to_v2_notify_type(type);
          (*ike_sa->server->sad_interface->notify_received)(
                                                    ike_sa->server->sad_handle,
                                                    notify_state,
                                                    ed,
                                                    (int) proto,
                                                    spi, spi_size,
                                                    ikev2_notify_type,
                                                    NULL, 0);

          ikev2_free_exchange_data(ike_sa, ed);
          return;
        }
      break;

    case SSH_IKE_NOTIFY_MESSAGE_R_U_THERE:
      if (authenticated)
        {
          ike_sa->last_input_stamp = ssh_time();

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
          {
            SshIkev2ExchangeData ed = ikev2_allocate_exchange_data(ike_sa);
            if (ed == NULL)
              {
                SSH_DEBUG(SSH_D_ERROR, ("ed alloc failed"));
                return;
              }

            /* Handle pending NAT-T operations */
            ikev2_fb_phase_ii_pending_natt_operations(ike_sa, ed,
                                                 (SshIkev2FbNatTInfo)
                                                 pm_info->policy_manager_data);

            ikev2_free_exchange_data(ike_sa, ed);
          }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

          (void)ssh_ike_connect_notify((SshIkeServerContext)ike_sa->server,
                                       ike_sa->v1_sa,
                                       NULL, NULL,
                                       SSH_IKE_NOTIFY_FLAGS_WANT_ISAKMP_SA,
                                       SSH_IKE_DOI_IPSEC,
                                       SSH_IKE_PROTOCOL_ISAKMP,
                                       spi, spi_size,
                                       SSH_IKE_NOTIFY_MESSAGE_R_U_THERE_ACK,
                                       data, data_size);
          return;
        }
      break;

    case SSH_IKE_NOTIFY_MESSAGE_R_U_THERE_ACK:
      if (authenticated && data_size > 3 && ike_sa->dpd_context != NULL)
        {
          SshIkev2FbNegotiation neg = ike_sa->dpd_context;

          if (ike_sa->dpd_cookie == SSH_GET_32BIT(data))
            {
              ike_sa->dpd_cookie++;
              ssh_fsm_set_next(neg->thread,
                               ikev2_fb_i_info_negotiation_result);
              ssh_fsm_continue(neg->thread);
            }
        }
      break;

    case SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN:
    case SSH_IKE_NOTIFY_MESSAGE_INVALID_ID_INFORMATION:
      /* Normally no proposal chosen will get processed from the
         ssh_policy_negotiation_done_qm() function, but from MS
         responder we do not get the proper SPI back, and that
         function is never called. We handle the case here by checking
         for zero content SPI, and if failing, we'll kill the phase-1 */
      if (authenticated &&
          spi_size == 4 && SSH_GET_32BIT(spi) == 0)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                       "Authenticated Phase-2 notification "
                       "`%s' (%d) (size %d bytes) "
                       "from %s%@ for protocol %s spi[0...%d]=%s "
                       "causes IKE SA deletion and QM abort",
                       ssh_find_keyword_name(ssh_ike_status_keywords, type),
                       type,
                       data_size,
                       pm_info->remote_ip,
                       ikev2_fb_ike_port_render, pm_info->remote_port,
                       ssh_find_keyword_name(ikev2_fb_ike_protocol_identifiers,
                                              proto),
                       spi_size,
                       ikev2_fb_util_data_to_hex(buf, sizeof(buf),
                                                 spi, spi_size));

          ssh_ike_abort_negotiation(pm_info->phase_i->negotiation,
                                    SSH_IKE_REMOVE_FLAGS_SEND_DELETE);
        }
      else
      if (authenticated && spi_size == 16)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                       "Authenticated Phase-2 notification"
                       " `%s' (%d) data size %d "
                       "from %s%@ for protocol %s with invalid spi[0...%d]=%s "
                       "causes IKE SA deletion and QM abort",
                       ssh_find_keyword_name(ssh_ike_status_keywords, type),
                       type,
                       data_size,
                       pm_info->remote_ip,
                       ikev2_fb_ike_port_render, pm_info->remote_port,
                       ssh_find_keyword_name(ikev2_fb_ike_protocol_identifiers,
                                             proto),
                       spi_size,
                       ikev2_fb_util_data_to_hex(buf, sizeof(buf),
                                                 spi, spi_size));
        }
      break;

    default:
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "%s Phase-2 notification `%s' (%d) (size %d bytes) "
                    "from %s%@ for protocol %s spi[0...%d]=%s",
                    authenticated ? "Authenticated " : "Unauthenticated",
                    ssh_find_keyword_name(ssh_ike_status_keywords, type),
                    type,
                    data_size,
                    pm_info->remote_ip,
                    ikev2_fb_ike_port_render, pm_info->remote_port,
                    ssh_find_keyword_name(ikev2_fb_ike_protocol_identifiers,
                                          proto),
                    spi_size,
                    ikev2_fb_util_data_to_hex(buf, sizeof(buf),
                                              spi, spi_size));
      break;
    }
}



/*--------------------------------------------------------------------*/

void ikev2_fb_phase_ii_sa_freed(SshIkePMPhaseII pm_info)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Phase-II free Entered"));

  if (pm_info->policy_manager_data)
    {
      /* Free ike_float_info */
      if (pm_info->exchange_type == SSH_IKE_XCHG_TYPE_INFO)
        {
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
          /* Free IKE NAT-T float structure. */
          ikev2_fb_ike_float_free(pm_info->policy_manager_data);
          pm_info->policy_manager_data = NULL;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
        }
#ifdef SSHDIST_ISAKMP_CFG_MODE
      /* Free reference to fallback negotiation. */
      else if (pm_info->exchange_type == SSH_IKE_XCHG_TYPE_CFG)
        {
          /* Normally the reference to fallback negotiation is freed
             in fallback thread destructor or when starting the next
             round of xauth negotiation. This code is entered in error
             cases where the isakmp library frees the pm_info before
             fallback thread has terminated. */
          SshIkev2FbNegotiation neg = pm_info->policy_manager_data;
          if (neg)
            {
              /* Clear `p2_info' backpointer from fallback negotiation. */
              if (neg->p2_info == pm_info)
                neg->p2_info = NULL;

              /* Release reference to `neg' from
                 `pm_info->policy_manager_data'. */
              ikev2_fb_phase_ii_clear_pm_data(pm_info, neg);
              ikev2_fallback_negotiation_free(neg->fb, neg);
            }
        }
#endif /* SSHDIST_ISAKMP_CFG_MODE */

      SSH_ASSERT(pm_info->policy_manager_data == NULL);
    }
}



/*--------------------------------------------------------------------*/

void
ikev2_fb_negotiation_done_phase_ii(SshIkePMPhaseII pm_info,
                                   SshIkeNotifyMessageType code)
{
#ifdef SSHDIST_ISAKMP_CFG_MODE
  SshIkev2FbNegotiation neg;

  neg = (SshIkev2FbNegotiation) pm_info->policy_manager_data;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Entered IKE error code %s (%d), IKE SA %p",
             ssh_ike_error_code_to_string(code), code,
             pm_info->phase_i->policy_manager_data));

  if (neg != NULL)
    {
      /* This negotiation is now completed, wake up the main thread. */
      neg->cfg_done = 1;
      neg->v1_error = code;
      neg->ike_error = ikev2_fb_v1_notify_message_type_to_v2_error_code(code);
      /* Wake up the main thread */
      ssh_fsm_continue(neg->thread);
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */
}

#endif /* SSHDIST_IKEV1 */
