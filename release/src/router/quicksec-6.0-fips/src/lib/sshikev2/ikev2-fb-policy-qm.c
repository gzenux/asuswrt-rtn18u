/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Quick Mode policy functions for IKEv1 fallback.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshikev2-util.h"

#ifdef SSHDIST_IKEV1
#include "isakmp.h"
#include "ikev2-fb.h"
#include "ikev2-fb-st.h"

#define SSH_DEBUG_MODULE "SshIkev2FallbackQm"

/*--------------------------------------------------------------------*/
/* New QM connection                                                  */
/*--------------------------------------------------------------------*/

void ikev2_fb_qm_negotiation_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  SSH_DEBUG(SSH_D_LOWOK, ("Freeing fallback negotiation context"));

  if (neg->sav2)
    {
      ssh_ikev2_sa_free(neg->server->sad_handle, neg->sav2);
      neg->sav2 = NULL;
    }

  /* Free the references to fallback negotiation. */
  ikev2_fb_negotiation_clear_pm_data(neg);
  ikev2_fallback_negotiation_free(neg->fb, neg);

  return;
}

SSH_FSM_STEP(ikev2_fb_qm_negotiation_wait_sa_installation)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  if (neg->aborted)
    return SSH_FSM_FINISH;

  if (!neg->ipsec_sa_installed)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Suspending until the IPSec SA is installed (neg %p)", neg));
      return SSH_FSM_SUSPENDED;
    }

  if (!neg->ipsec_sa_done)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Suspending until the IPSec SA done "
                              "notification is received (neg %p)", neg));
      return SSH_FSM_SUSPENDED;
    }

  ikev2_fb_ipsec_complete(neg);
  return SSH_FSM_FINISH;
}

void
ikev2_fb_new_connection_phase_qm(SshIkePMPhaseQm pm_info,
                                 SshPolicyNewConnectionCB callback_in,
                                 void *callback_context_in)
{
  SshIkev2Fb fb = (SshIkev2Fb) pm_info->pm->upper_context;
  SshIkeServerContext ike_server;
  SshIkev2FbNegotiation neg;
  SshIkev2Sa ike_sa;

  SSH_ASSERT(pm_info->phase_i != NULL);
  SSH_ASSERT(pm_info->phase_i->policy_manager_data != NULL);
  ike_sa = (SshIkev2Sa) pm_info->phase_i->policy_manager_data;

  /* Allocate and init context for this negotiation. */
  if ((neg = ikev2_fallback_negotiation_alloc(fb)) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of negotation contexts."));
      (*callback_in)(FALSE, SSH_IKE_FLAGS_USE_DEFAULTS,
                     -1, -1, -1, -1, -1, -1, -1, callback_context_in);
      return;
    }

  /* Take a reference to allocated `neg' and set it to
     `pm_info->policy_manager_data'. */
  ikev2_fb_phase_qm_set_pm_data(pm_info, neg);

  /* Save `neg->qm_info' here for responder negotiations. */
  SSH_ASSERT(neg->qm_info == NULL);
  neg->qm_info = pm_info;

  /* Lookup the server object used in the negotiation. */
  ike_server = ssh_ike_get_server_by_negotiation(pm_info->negotiation);
  SSH_ASSERT(ike_server != NULL);

  neg->server = (SshIkev2Server)ike_server;

  neg->ike_sa = ike_sa;
  SSH_IKEV2_IKE_SA_TAKE_REF(neg->ike_sa);
  neg->ike_sa->last_input_stamp = ssh_time();

  if ((neg->ed = ikev2_allocate_exchange_data(neg->ike_sa)) == NULL)
    goto error;
  neg->ed->state = SSH_IKEV2_STATE_CREATE_CHILD;

  if (ikev2_allocate_exchange_data_ipsec(neg->ed) != SSH_IKEV2_ERROR_OK)
    goto error;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Accepting new Quick-Mode negotiation: "
             "local=%s:%s, remote=%s:%s (neg %p)",
             pm_info->local_ip, pm_info->local_port,
             pm_info->remote_ip, pm_info->remote_port,
             neg));

  /* Start the main thread controlling this negotiation */
  ssh_fsm_thread_init(fb->fsm, neg->thread,
                      ikev2_fb_qm_negotiation_wait_sa_installation,
                      NULL_FNPTR,
                      ikev2_fb_qm_negotiation_destructor, neg);

  (*callback_in)(TRUE, SSH_IKE_FLAGS_USE_DEFAULTS,
                 -1, -1, -1, -1, -1, -1, -1, callback_context_in);
  return;

 error:
  SSH_DEBUG(SSH_D_LOWOK, ("New connection failed (neg %p)", neg));
  SSH_ASSERT(neg != NULL);
  /* Release reference to `neg' from `pm_info->policy_manager_data'. */
  ikev2_fb_phase_qm_clear_pm_data(pm_info, neg);
  /* Free negotiation. */
  ikev2_fallback_negotiation_free(fb, neg);

  (*callback_in)(FALSE, SSH_IKE_FLAGS_USE_DEFAULTS,
                 -1, -1, -1, -1, -1, -1, -1, callback_context_in);
  return;
}


/*--------------------------------------------------------------------*/
/* QM nonce data length                                               */
/*--------------------------------------------------------------------*/

void
ikev2_fb_qm_nonce_data_len(SshIkePMPhaseQm pm_info,
                           SshPolicyNonceDataLenCB callback_in,
                           void *callback_context_in)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Entered"));
  (*callback_in)(16, callback_context_in);
}

/*--------------------------------------------------------------------*/
/* IPsec SA responder side proxy identities                           */
/*--------------------------------------------------------------------*/

void
ikev2_fb_qm_local_id(SshIkePMPhaseQm pm_info,
                     SshPolicyIsakmpIDCB callback_in,
                     void *callback_context_in)
{
  SshIkePayloadID id = NULL;

  if (pm_info->local_i_id)
    {
      id = ssh_ike_id_dup(pm_info->local_i_id);
      if (id == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Out of memory while allocating local Quick-Mode "
                     "responder ID: aborting negotiation"));
          SSH_VERIFY(ssh_ike_abort_negotiation(pm_info->negotiation, 0)
                     == SSH_IKE_ERROR_OK);
          goto out;
        }
    }

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Using %@ as local QM identity", ssh_ike_id_render, id));

 out:
  (*callback_in)(id, callback_context_in);
}

/*--------------------------------------------------------------------*/
/* QM remote identity                                                 */
/*--------------------------------------------------------------------*/

void
ikev2_fb_qm_remote_id(SshIkePMPhaseQm pm_info,
                      SshPolicyIsakmpIDCB callback_in,
                      void *callback_context_in)
{
  SshIkePayloadID id = NULL;

  if (pm_info->remote_i_id)
    {
      id = ssh_ike_id_dup(pm_info->remote_i_id);
      if (id == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Out of memory while allocating remote Quick-Mode "
                     "responder ID: aborting negotiation"));
          SSH_VERIFY(ssh_ike_abort_negotiation(pm_info->negotiation, 0)
                     == SSH_IKE_ERROR_OK);
          goto out;
        }
    }

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Using %@ as remote QM identity", ssh_ike_id_render, id));

 out:
  (*callback_in)(id, callback_context_in);
}

/*--------------------------------------------------------------------*/
/* IPsec SA Selection                                                 */
/*--------------------------------------------------------------------*/

void ikev2_fb_ipsec_spi_allocate_cb(SshIkev2Error error_code,
                                    SshUInt32 spi,
                                    void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  if (error_code == SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("New IPSec SPI %lx allocated successfully (neg %p)",
                 (unsigned long) spi, neg));
      neg->inbound_spi = spi;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Error: IPSec SPI allocate failed: %s (neg %p)",
                             ssh_ikev2_error_to_string(error_code), neg));
      neg->ike_error = error_code;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
}

void
ikev2_fb_notify_request_cb(SshIkev2Error error_code,
                           SshIkev2ProtocolIdentifiers protocol_id,
                           unsigned char *spi,
                           size_t spi_size,
                           SshIkev2NotifyMessageType notify_message_type,
                           unsigned char *notification_data,
                           size_t notification_data_size,
                           void *context)
{
  SshIkev2FbNegotiation neg = context;

  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  if (notify_message_type == SSH_IKEV2_NOTIFY_USE_TRANSPORT_MODE)
    {
      if (neg->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE)
        {
          if (neg->ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_IETF_DRAFT)
            neg->encapsulation =
              IPSEC_VALUES_ENCAPSULATION_MODE_UDP_DRAFT_TRANSPORT;
          else
            neg->encapsulation = IPSEC_VALUES_ENCAPSULATION_MODE_UDP_TRANSPORT;
        }
      else
        {
          neg->encapsulation = IPSEC_VALUES_ENCAPSULATION_MODE_TRANSPORT;
        }
    }
  else if (notify_message_type == SSH_IKEV2_NOTIFY_IPCOMP_SUPPORTED)
    {
      neg->ipcomp_cpi_in = SSH_GET_16BIT(notification_data);

      if (neg->initiator)
        {
          if (neg->ipcomp_num < sizeof(neg->ipcomp_algs))
            {
              neg->ipcomp_algs[neg->ipcomp_num] = notification_data[2];
              neg->ipcomp_num++;
            }
          else
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Too many IPCOMP mechanisms for proposal"));
            }
        }
      else
        {
          memset(neg->ipcomp_algs, 0, sizeof(neg->ipcomp_algs));
          neg->ipcomp_selected = TRUE;
          neg->ipcomp_num = 1;
          neg->ipcomp_algs[0] = notification_data[2];
        }
    }
  else if (notify_message_type == SSH_IKEV2_NOTIFY_INITIAL_CONTACT)
    {
      neg->initial_contact = 1;
    }
  else if (notify_message_type == 0)
    {
      SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
    }
  return;
}

void
ikev2_fb_spd_select_qm_sa_cb(SshIkev2Error error_code,
                             int ikev2_proposal_index,
                             SshIkev2PayloadTransform
                             selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX],
                             void *context)
{
  SshIkev2FbNegotiation neg = context;
  SshIkeIpsecSelectedSAIndexes selected = NULL;
  SshIkePayloadSA sa;
  int ikev1_proposal_index, ikev1_ipsec_transform_index;
  int ikev1_ipcomp_transform_index, i, iproto;
  SshIkev2ProtocolIdentifiers selected_sa_protocol;

  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  sa = &neg->sa_table_in[0]->pl.sa;

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKEv2 SA select failed with error %s",
                             ssh_ikev2_error_to_string(error_code)));
      goto error;
    }







  /* Check if ISAKMP library has freed the qm negotiation. */
  if (neg->qm_info == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("QM negotiation has disappeared"));
      neg->ike_error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
      goto error;
    }

  if (selected_transforms == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No IPSec SA transforms selected"));
      goto error;
    }

  /* Store information on the selected SA to the IPSec exchange data. */
  for (i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
    {
      neg->ed->ipsec_ed->ipsec_sa_transforms[i] = selected_transforms[i];
    }

  selected_sa_protocol = neg->ed->ipsec_ed->ipsec_sa_protocol =
    neg->sav2->protocol_id[ikev2_proposal_index];

  /* Set the inbound SPI to the IPSec exchange data */
  neg->ed->ipsec_ed->spi_inbound = neg->inbound_spi;

  SSH_DEBUG(SSH_D_LOWOK, ("Inbound SPI %lx",
                          (unsigned long) neg->inbound_spi));

  SSH_ASSERT(neg->number_of_sas_in == 1);
  selected = ssh_calloc(neg->number_of_sas_in, sizeof(*selected));
  if (selected == NULL)
    goto error;

  /* Check to see which proposal and ESP/AH/IPComp transform index
     was selected. */
  if (!ikev2_fb_select_ipsec_transform_index(selected_transforms,
                                             selected_sa_protocol,
                                             neg->qm_info->negotiation,
                                             sa,
                                             neg->ipcomp_proposals,
                                             neg->ipcomp_algs[0],
                                             &ikev1_proposal_index,
                                             &ikev1_ipsec_transform_index,
                                             &ikev1_ipcomp_transform_index))
    {
    error:
      SSH_DEBUG(SSH_D_FAIL,
                ("SA selection failed, no matching proposal (neg %p)", neg));
      ikev2_fb_free_sa_indexes(selected, neg->number_of_sas_in);
      neg->selected = NULL;
      SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
      return;
    }
  selected[0].proposal_index = ikev1_proposal_index;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Selected proposal indices are v2=%d, v1=%d num protocols is %d",
             ikev2_proposal_index, ikev1_proposal_index,
             sa->proposals[ikev1_proposal_index].number_of_protocols));

  selected[0].number_of_protocols
    = sa->proposals[ikev1_proposal_index].number_of_protocols;
  selected[0].transform_indexes
    = ssh_calloc(selected[0].number_of_protocols, sizeof(int));
  selected[0].spi_sizes
    = ssh_calloc(selected[0].number_of_protocols, sizeof(size_t));
  selected[0].spis
    = ssh_calloc(selected[0].number_of_protocols,
                 sizeof(unsigned char *));

  if (selected[0].transform_indexes == NULL ||
      selected[0].spi_sizes == NULL ||
      selected[0].spis == NULL)
    goto error;

  for (iproto = 0; iproto < selected[0].number_of_protocols; iproto++)
    {
      SshIkePayloadPProtocol proto =
        &sa->proposals[ikev1_proposal_index].protocols[iproto];

      if ((selected->spis[iproto] = ssh_malloc(4)) == NULL)
        goto error;

      switch (proto->protocol_id)
        {
        case SSH_IKE_PROTOCOL_IPCOMP:
          selected->spi_sizes[iproto] = 2;
          SSH_PUT_16BIT(selected->spis[iproto], neg->ipcomp_cpi_in);

          selected[0].transform_indexes[iproto] = ikev1_ipcomp_transform_index;
          break;
        default:
          selected->spi_sizes[iproto] = 4;
          SSH_PUT_32BIT(selected->spis[iproto], neg->inbound_spi);

          /* Check the proposed lifetimes against that of our policy to see
             whether we should send a responder lifetime notification */
          if (ikev2_fb_check_ipsec_responder_lifetimes(neg->ed,
                                                       neg->sa_life_seconds,
                                                       neg->sa_life_kbytes))
            {
              /* Let's send a responder lifetime notify. */
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Sending a responder lifetime notification: "
                         "life_sec=%lu, life_kb=%lu",
                         neg->ed->ipsec_ed->sa_life_seconds,
                         neg->ed->ipsec_ed->sa_life_kbytes));
              selected[0].expire_secs = neg->ed->ipsec_ed->sa_life_seconds;
              selected[0].expire_kb = neg->ed->ipsec_ed->sa_life_kbytes;
            }
          selected[0].transform_indexes[iproto] = ikev1_ipsec_transform_index;
        }
    }

  neg->selected = selected;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
  return;
}

static Boolean
ikev2_fb_construct_notify(SshIkev2FbNegotiation neg,
                          SshIkev2ProtocolIdentifiers protocol,
                          SshIkev2NotifyMessageType type,
                          Boolean authentic,
                          size_t spi_size, const unsigned char *spi,
                          size_t data_size, const unsigned char *data)
{
  SshIkev2PayloadNotify notify;

  notify = ssh_obstack_calloc(neg->ed->obstack, sizeof(*notify));
  if (notify == NULL)
    {
    failed:
      SSH_DEBUG(SSH_D_ERROR,
                ("Error: Out of memory allocating notify (neg %p)", neg));
      neg->ike_error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      return FALSE;
    }

  /* We do not know the protocol here */
  notify->protocol = protocol;
  notify->notify_message_type = type;
  notify->authenticated = authentic;

  if (spi_size)
    {
      if ((notify->spi_data =
           ssh_obstack_memdup(neg->ed->obstack, spi, spi_size)) == NULL)
        goto failed;
    }
  notify->spi_size = spi_size;

  if (data_size)
    {
      if ((notify->notification_data =
           ssh_obstack_memdup(neg->ed->obstack, data, data_size)) == NULL)
        goto failed;
    }
  notify->notification_size = data_size;

  notify->next_notify = neg->ed->notify;
  neg->ed->notify = notify;
  return TRUE;
}

SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_start)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;
  SshIkeAttributeAuthMethValues ignore_auth_method;

  if (neg->qm_info == NULL)
    {
      neg->selected = NULL;
      neg->ike_error = SSH_IKEV2_ERROR_INVALID_SYNTAX;
      SSH_FSM_SET_NEXT(ikev2_fb_st_select_qm_sa_finish);
      return SSH_FSM_CONTINUE;
    }

  /* Convert the SA payload to IKEv2 format. */
  SSH_ASSERT(neg->sav2 == NULL);

  neg->sav2 = ikev2_fb_sav1_to_sav2(neg->server->sad_handle,
                                    neg->qm_info->negotiation,
                                    &neg->sa_table_in[0]->pl.sa,
                                    neg->ipcomp_proposals,
                                    &ignore_auth_method,
                                    &neg->sa_life_seconds,
                                    &neg->sa_life_kbytes,
                                    &neg->encapsulation,
                                    sizeof(neg->ipcomp_algs),
                                    &neg->ipcomp_num,
                                    neg->ipcomp_algs,
                                    neg->ipcomp_cpi_out);

  if (neg->sav2 == NULL)
    {
      /* No proposals that do not contain IPcomp, next try extracting
         the proposals that do contain IPcomp. */
      if (!neg->ipcomp_proposals)
        {
          neg->ipcomp_proposals = TRUE;
          SSH_FSM_SET_NEXT(ikev2_fb_st_select_qm_sa_start);
          return SSH_FSM_CONTINUE;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failing negotiation, no proposal chosen (neg %p)", neg));
          neg->selected = NULL;
          neg->ike_error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
          SSH_FSM_SET_NEXT(ikev2_fb_st_select_qm_sa_finish);
          return SSH_FSM_CONTINUE;
        }
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Proposed IPSec SA Lifetimes: sec=%d kb=%d",
                          (int) neg->sa_life_seconds,
                          (int) neg->sa_life_kbytes));

  SSH_FSM_SET_NEXT(ikev2_fb_st_select_qm_sa_build_notify);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_build_notify)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;
  SshIkeIpsecAttributeEncapsulationModeValues encap;

  SSH_FSM_SET_NEXT(ikev2_fb_st_select_qm_sa_alloc_spi);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  encap = neg->encapsulation;

  /* Construct notify payloads and add them to the IKE exchange data. This
     way the policy manager gets access to information that is not encoded
     in IKEv2 SA payloads but which is required for SA selection, namely
     whether IPComp and transport mode are supported.

     Note that we do not call the notify_received policy call here because
     the policy manager does not process the IPComp/transport mode notifies
     from that policy call, but instead does so in a delayed fashion by
     parsing the notify payloads in the exchange data. */

  if (encap == IPSEC_VALUES_ENCAPSULATION_MODE_TRANSPORT ||
      encap == IPSEC_VALUES_ENCAPSULATION_MODE_UDP_TRANSPORT ||
      encap == IPSEC_VALUES_ENCAPSULATION_MODE_UDP_DRAFT_TRANSPORT)
    {
      (void)
        ikev2_fb_construct_notify(neg,
                                  0,
                                  SSH_IKEV2_NOTIFY_USE_TRANSPORT_MODE,
                                  TRUE,
                                  0, NULL, 0, NULL);
    }
  if (neg->ipcomp_num > 0)
    {
      int i;

      for (i = 0; i < neg->ipcomp_num; i++)
        {
          unsigned char data[3];

          SSH_PUT_16BIT(data, neg->ipcomp_cpi_out[i]);
          data[2] = neg->ipcomp_algs[i];

          (void)
            ikev2_fb_construct_notify(neg,
                                      0,
                                      SSH_IKEV2_NOTIFY_IPCOMP_SUPPORTED,
                                      TRUE,
                                      0, NULL, sizeof(data), data);
        }
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_alloc_spi)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_select_qm_sa_notify_request);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  /* Responder side SPI allocation. */
  if (neg->inbound_spi == 0)
    {
      SSH_FSM_ASYNC_CALL(SSH_IKEV2_FB_V2_CALL(neg, ipsec_spi_allocate)
                         (neg->server->sad_handle,
                          neg->ed,
                          ikev2_fb_ipsec_spi_allocate_cb,
                          neg));

      SSH_NOTREACHED;
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_notify_request)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_select_qm_sa_check_notifies);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  /* Request notify payloads. This is currently only called since the PM
     does some bookkeeping with regard to transport mode encapsulation
     from within this call. */
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_FB_V2_CALL(neg, notify_request)
                     (neg->server->sad_handle, neg->ed,
                      ikev2_fb_notify_request_cb,
                      neg));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_check_notifies)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_select_qm_sa_select);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  /* Check if IPComp was proposed but not selected. */
  if (!neg->initiator && neg->ipcomp_proposals && !neg->ipcomp_selected)
    {
      SSH_DEBUG(SSH_D_FAIL, ("SA selection failed with IPComp"));
      neg->ike_error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_select)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_select_qm_sa_finish);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    goto error;

  /* Now perform the SA selection */
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_FB_V2_CALL(neg, select_ipsec_sa)
                     (neg->server->sad_handle, neg->ed,
                      neg->sav2,
                      ikev2_fb_spd_select_qm_sa_cb,
                      neg));

 error:
  (*neg->callbacks.u.qm_sa)(NULL, neg->callbacks.callback_context);
  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_finish)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  /* All done, return the selected transforms to the ISAKMP library. */
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    {
      (*neg->callbacks.u.qm_sa)(NULL, neg->callbacks.callback_context);
    }
  else
    {
      /* If SA rule selection failed without considering the IPcomp
         proposals then retry this time using the IPcomp proposals. */
      if (!neg->selected && !neg->initiator && !neg->ipcomp_proposals)
        {
          SSH_DEBUG(SSH_D_FAIL, ("SA selection failed without IPComp, "
                                 "retrying with IPComp proposals"));
          neg->ipcomp_proposals = TRUE;
          neg->ipcomp_num = 0;
          ssh_ikev2_sa_free(neg->server->sad_handle, neg->sav2);
          neg->sav2 = NULL;
          SSH_FSM_SET_NEXT(ikev2_fb_st_select_qm_sa_start);
          return SSH_FSM_CONTINUE;
        }
      (*neg->callbacks.u.qm_sa)(neg->selected,
                                neg->callbacks.callback_context);

    }
  neg->selected = NULL;
  return SSH_FSM_FINISH;
}

void
ikev2_fb_select_qm_sa_sub_thread_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  /* Free reference to fallback negotiation structure. */
  ikev2_fallback_negotiation_free(neg->fb, neg);
}

void
ikev2_fb_qm_select_sa(SshIkePMPhaseQm pm_info,
                      SshIkeNegotiation negotiation,
                      int number_of_sas_in,
                      SshIkePayload *sa_table_in,
                      SshPolicyQmSACB callback_in,
                      void *callback_context_in)
{
  SshIkev2Fb fb = (SshIkev2Fb) pm_info->pm->upper_context;
  SshIkev2FbNegotiation neg;

  neg = SSH_IKEV2_FB_QM_GET_P1_NEGOTIATION(pm_info);
  if (neg == NULL || neg->ike_error != SSH_IKEV2_ERROR_OK)
    {
      goto error;
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("Select QM SA policy call entered, IKE SA %p (neg %p)",
             pm_info->phase_i->policy_manager_data, neg));

  /* Set the proposed traffic selectors to the IPsec exchange data. */
  if (pm_info->local_i_id)
    {
      neg->ed->ipsec_ed->ts_local =
        ikev2_fb_tsv1_to_tsv2(neg->server->sad_handle, pm_info->local_i_id);
    }

  /* Remote did not send any proxy IDs, default to local IP (RFC2409, 5.5) */
  else
    {
      neg->ed->ipsec_ed->ts_local =
        ssh_ikev2_ts_allocate(neg->server->sad_handle);
      if (neg->ed->ipsec_ed->ts_local != NULL)
        {
          SshIpAddrStruct addr;
          SSH_VERIFY(ssh_ipaddr_parse(&addr, pm_info->local_ip));
          SSH_VERIFY(ssh_ikev2_ts_item_add(neg->ed->ipsec_ed->ts_local,
                                           0, &addr, &addr, 0, 0xffff)
                     == SSH_IKEV2_ERROR_OK);
        }
    }

  /* Replace FQDN remote ID with the IKE peer's remote IP if NAT-T is used */
  if (neg->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE &&
      pm_info->remote_i_id &&
      pm_info->remote_i_id->id_type == IPSEC_ID_FQDN)
    {
      neg->ed->ipsec_ed->ts_remote =
        ssh_ikev2_ts_allocate(neg->server->sad_handle);
      if (neg->ed->ipsec_ed->ts_remote)
        {
          SshIpAddrStruct addr;
          SshUInt16 s_port, e_port;

          SSH_VERIFY(ssh_ipaddr_parse(&addr, pm_info->remote_ip));
          s_port = pm_info->remote_i_id->port_number;
          if (pm_info->remote_i_id->port_number != 0)
            e_port = pm_info->remote_i_id->port_number;
          else
            e_port = 0xffff;

          SSH_VERIFY(ssh_ikev2_ts_item_add(neg->ed->ipsec_ed->ts_remote,
                                           pm_info->remote_i_id->protocol_id,
                                           &addr, &addr, s_port, e_port)
                     == SSH_IKEV2_ERROR_OK);
        }
    }
  else if (pm_info->remote_i_id)
    {
      neg->ed->ipsec_ed->ts_remote =
        ikev2_fb_tsv1_to_tsv2(neg->server->sad_handle,pm_info->remote_i_id);
    }
  /* Remote did not send any proxy IDs, default to remote IP (RFC2409, 5.5) */
  else
    {
      neg->ed->ipsec_ed->ts_remote =
        ssh_ikev2_ts_allocate(neg->server->sad_handle);
      if (neg->ed->ipsec_ed->ts_remote != NULL)
        {
          SshIpAddrStruct addr;
          SSH_VERIFY(ssh_ipaddr_parse(&addr, pm_info->remote_ip));
          SSH_VERIFY(ssh_ikev2_ts_item_add(neg->ed->ipsec_ed->ts_remote,
                                           0, &addr, &addr, 0, 0xffff)
                     == SSH_IKEV2_ERROR_OK);
        }
    }

  if (neg->ed->ipsec_ed->ts_local == NULL ||
      neg->ed->ipsec_ed->ts_remote == NULL)
    {
      (*callback_in)(NULL, callback_context_in);
      return;
    }
  ssh_ikev2_ts_take_ref(neg->server->sad_handle, neg->ed->ipsec_ed->ts_local);
  ssh_ikev2_ts_take_ref(neg->server->sad_handle, neg->ed->ipsec_ed->ts_remote);

  /* This is a responder negotiation to ts_r is the local traffic selector
     and ts_i is the remote traffic selector. */
  neg->ed->ipsec_ed->ts_r = neg->ed->ipsec_ed->ts_local;
  neg->ed->ipsec_ed->ts_i = neg->ed->ipsec_ed->ts_remote;

  /* Store the SA proposals */
  neg->number_of_sas_in = number_of_sas_in;
  neg->sa_table_in = sa_table_in;

  /* We only support proposals consisting of one SA. */
  if (neg->number_of_sas_in != 1)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Multiple SA's not supported"));
      goto error;
    }

  /* Store the completion callback and its context. */
  neg->callbacks.u.qm_sa = callback_in;
  neg->callbacks.callback_context = callback_context_in;

  /* First extract the proposals that do not contain IPcomp as a protocol */
  neg->ipcomp_proposals = FALSE;

  /* Take a reference to fallback negotiation structure for the sub thread.
     It will be freed in the sub thread destructor. */
  IKEV2_FB_NEG_TAKE_REF(neg);

  ssh_fsm_thread_init(fb->fsm, neg->sub_thread,
                      ikev2_fb_st_select_qm_sa_start,
                      NULL_FNPTR,
                      ikev2_fb_select_qm_sa_sub_thread_destructor, neg);
  return;

 error:
  (*callback_in)(NULL, callback_context_in);
  return;
}

/*--------------------------------------------------------------------*/
/* Notifications                                                      */
/*--------------------------------------------------------------------*/

void
ikev2_fb_phase_qm_notification(SshIkePMPhaseQm pm_info,
                               SshIkeProtocolIdentifiers proto,
                               unsigned char *spi,
                               size_t spi_size,
                               SshIkeNotifyMessageType type,
                               unsigned char *data,
                               size_t data_size)
{
  SshIkev2FbNegotiation neg;
  char buffer[64];

  neg = SSH_IKEV2_FB_QM_GET_P1_NEGOTIATION(pm_info);
  if (neg == NULL)
    return;

  SSH_DEBUG(SSH_D_LOWOK, ("QM notification call entered, IKE SA %p (neg %p)",
                          pm_info->phase_i->policy_manager_data, neg));

  switch (type)
    {
    case SSH_IKE_NOTIFY_MESSAGE_RESPONDER_LIFETIME:
      {
        int i;
        SshUInt32 *life;
        SshUInt32 kb, sec;

        life = NULL;
        kb = 0;
        sec = 0;

        i = 0;
        while (i + 4 <= data_size)
          {
            SshUInt16 lifetype;
            SshUInt32 value;

            if (!ssh_ike_decode_data_attribute_int(data + i,
                                                   data_size - i,
                                                   &lifetype, &value, 0L))
              {
                SSH_DEBUG(3, ("ssh_ike_decode_data_attribute_int returned "
                              "error"));
                return;
              }

            switch (lifetype)
              {
              case IPSEC_CLASSES_SA_LIFE_TYPE: /* Life type selector */
                if (life != NULL)
                  {
                    SSH_DEBUG(3, ("Two life types, without duration"));
                    return;
                  }
                if (value == IPSEC_VALUES_LIFE_TYPE_SECONDS)
                  {
                    life = &sec;
                  }
                else if (value == IPSEC_VALUES_LIFE_TYPE_KILOBYTES)
                  {
                    life = &kb;
                  }
                else
                  {
                    SSH_DEBUG(3, ("Invalid life type"));
                    return;
                  }
                break;

              case IPSEC_CLASSES_SA_LIFE_DURATION: /* Life type value */
                if (life == NULL)
                  {
                    SSH_DEBUG(3, ("Life duration without type"));
                    return;
                  }
                if (*life != 0)
                  {
                    SSH_DEBUG(3, ("Same life duration value given twice"));
                    return;
                  }
                *life = value;
                life = NULL;
              }
            i += ssh_ike_decode_data_attribute_size(data + i, 0L);
          }

        if (sec != 0)
          {
            if (neg->ed->ipsec_ed->sa_life_seconds == 0 ||
                neg->ed->ipsec_ed->sa_life_seconds > sec)
              neg->ed->ipsec_ed->sa_life_seconds = sec;
          }
        if (kb != 0)
          {
            if (neg->ed->ipsec_ed->sa_life_kbytes == 0 ||
                neg->ed->ipsec_ed->sa_life_kbytes > kb)
              neg->ed->ipsec_ed->sa_life_kbytes = kb;
          }

        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Received responder lifetime notification: "
                   "life_secs=%lu, life_kbytes=%lu",
                   (unsigned long) sec, (unsigned long) kb));
      }
      /* fallthrough */

    default:
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "QM notification `%s' (%d) (size %d bytes) "
                    "from %s%@ for protocol %s spi[0...%d]=%s",
                    ssh_find_keyword_name(ssh_ike_status_keywords, type),
                    type,
                    data_size,
                    pm_info->remote_ip,
                    ikev2_fb_ike_port_render, pm_info->remote_port,
                    ssh_find_keyword_name(ikev2_fb_ike_protocol_identifiers,
                                          proto),
                    spi_size - 1,
                    ikev2_fb_util_data_to_hex(buffer, sizeof(buffer),
                                              spi, spi_size));
    }
}

/*--------------------------------------------------------------------*/
/* Quick-Mode done                                                    */
/*--------------------------------------------------------------------*/

/* This function can get called before the IKEv2 SA handler has completed
   in the policy manager. */
void
ikev2_fb_negotiation_done_qm(SshIkePMPhaseQm pm_info,
                             SshIkeNotifyMessageType code)
{
  SshIkev2Error error_code;
  SshIkev2FbNegotiation neg;

  neg = (SshIkev2FbNegotiation) pm_info->policy_manager_data;

  SSH_DEBUG(SSH_D_LOWOK, ("Entered IKE error code %s (%d) (neg %p)",
                          ssh_ike_error_code_to_string(code), code, neg));

  if (neg != NULL)
    {
      /* On error, the IPSec SA handler will not be called, so set the
         ipsec_sa_installed field to 1 so the Quick-Mode thread will
         not block. */
      if (code != SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
        neg->ipsec_sa_installed = 1;

      /* Map the IKEv1 error code to its IKEv2 equivalent. The
         ipsec_sa_done policy call will be called with this error code
         once IPSec SA installation is completed. */
      error_code = ikev2_fb_v1_notify_message_type_to_v2_error_code(code);

      /* Don't overwrite an error code from the IPSec SA install call */
      if (neg->ike_error == SSH_IKEV2_ERROR_OK)
        {
          neg->ike_error = error_code;
          neg->v1_error = code;
        }

      /* This negotiation is now completed */
      neg->ipsec_sa_done = 1;

      /* Wake up the main thread */
      ssh_fsm_continue(neg->thread);
    }
}

/*--------------------------------------------------------------------*/
/* IPsec SA handler                                                   */
/*--------------------------------------------------------------------*/

/* Callback for the ipsec_sa_install policy call. */
void ikev2_fb_ipsec_sa_install_done(SshIkev2Error error_code,
                                    void *context)
{
  SshIkev2FbNegotiation neg = context;

  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  /* Don't overwrite an error code from the IPSec SA done call */
  if (neg->ike_error == SSH_IKEV2_ERROR_OK)
    neg->ike_error = error_code;

  /* The IPSec SA has now been installed */
  neg->ipsec_sa_installed = 1;

  SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA install done error %d (neg %p)",
                          neg->ike_error, neg));

  /* Wake up the main thread */
  ssh_fsm_continue(neg->thread);
}

void
ikev2_fb_sa_handler(SshIkeNegotiation negotiation,
                    SshIkePMPhaseQm pm_info,
                    int number_of_sas, SshIkeIpsecSelectedSA sas,
                    SshIkeIpsecKeymat keymat,
                    void *sa_callback_context)
{
  SshIkev2FbNegotiation neg;

  neg = SSH_IKEV2_FB_QM_GET_P1_NEGOTIATION(pm_info);
  if (neg == NULL)
    return;

  neg->ike_sa->last_input_stamp = ssh_time();

  SSH_DEBUG(SSH_D_LOWOK, ("SA handler entered, IKE SA %p (neg %p)",
                          pm_info->phase_i->policy_manager_data, neg));

  if (number_of_sas != 1)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Quick-Mode does not result in one bundle"));
      goto error;
    }

  if (neg->ed->callback)
    {
      int i, iproto;
      SshIkev2PayloadTransform *t;
      SshIkeIpsecSelectedProtocol p;
      SshIkeIpsecAttributeEncapsulationModeValues encap;

      /* Assert that `neg->qm_info' is set correctly. */
      SSH_ASSERT(neg->qm_info == pm_info);

      for (i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
        neg->ed->ipsec_ed->ipsec_sa_transforms[i] = &neg->transforms[i];

      /* Fill in the selected transforms into ipsec_ed */

      t = neg->ed->ipsec_ed->ipsec_sa_transforms;

      for (iproto = 0; iproto < sas[0].number_of_protocols; iproto++)
        {
          p = &sas[0].protocols[iproto];
          if (p->protocol_id == SSH_IKE_PROTOCOL_IPSEC_ESP)
            {
              t[SSH_IKEV2_TRANSFORM_TYPE_ENCR]->id =
                ikev2_fb_v1_esp_id_to_v2_id(p->transform_id.generic);
              if (p->attributes.key_length)
                t[SSH_IKEV2_TRANSFORM_TYPE_ENCR]->transform_attribute =
                  (0x800e << 16) | p->attributes.key_length;

              if (p->attributes.auth_algorithm)
                t[SSH_IKEV2_TRANSFORM_TYPE_INTEG]->id =
                  ikev2_fb_v1_auth_id_to_v2_id(p->attributes.auth_algorithm);
              else
                t[SSH_IKEV2_TRANSFORM_TYPE_INTEG] = NULL;
            }
          else if (p->protocol_id == SSH_IKE_PROTOCOL_IPSEC_AH)
            {
              t[SSH_IKEV2_TRANSFORM_TYPE_INTEG]->id =
                ikev2_fb_v1_ah_id_to_v2_id(p->transform_id.generic);
              t[SSH_IKEV2_TRANSFORM_TYPE_ENCR] = NULL;
            }
          else if (p->protocol_id == SSH_IKE_PROTOCOL_IPCOMP)
            {
              if (p->spi_size_out == 2)
                {
                  int j;

                  for (j = 0; j < neg->ipcomp_num; j++)
                    {
                      if (neg->ipcomp_algs[j] == p->transform_id.ipcomp)
                        {
                          neg->ipcomp_num = 1;
                          neg->ipcomp_algs[0] = p->transform_id.ipcomp;
                          neg->ipcomp_cpi_out[0] = SSH_GET_16BIT(p->spi_out);
                          break;
                        }
                    }
                }
            }

          if (p->attributes.group_desc)
            t[SSH_IKEV2_TRANSFORM_TYPE_D_H]->id =
                (int) p->attributes.group_desc;
          else
            t[SSH_IKEV2_TRANSFORM_TYPE_D_H] = NULL;

          t[SSH_IKEV2_TRANSFORM_TYPE_ESN]->id = (p->attributes.longseq_size)
            ? SSH_IKEV2_TRANSFORM_ESN_ESN
            : SSH_IKEV2_TRANSFORM_ESN_NO_ESN;

          /* For initiator, notify policymanager about transport mode */
          encap = p->attributes.encapsulation_mode;
          if (encap == IPSEC_VALUES_ENCAPSULATION_MODE_TRANSPORT ||
              encap == IPSEC_VALUES_ENCAPSULATION_MODE_UDP_TRANSPORT ||
              encap == IPSEC_VALUES_ENCAPSULATION_MODE_UDP_DRAFT_TRANSPORT)
            {
              (void)
                ikev2_fb_construct_notify(neg,
                                          0,
                                          SSH_IKEV2_NOTIFY_USE_TRANSPORT_MODE,
                                          TRUE,
                                          0, NULL, 0, NULL);
            }
        }

      if (neg->ipcomp_num > 0)
        {
          for (i = 0; i < neg->ipcomp_num; i++)
            {
              unsigned char data[3];

              SSH_PUT_16BIT(data, neg->ipcomp_cpi_out[i]);
              data[2] = neg->ipcomp_algs[i];

              (void)
                ikev2_fb_construct_notify(neg,
                                          0,
                                          SSH_IKEV2_NOTIFY_IPCOMP_SUPPORTED,
                                          TRUE,
                                          0, NULL, sizeof(data), data);
            }
        }
    }

  /* Set the outbound SPI to the IPSec exchange data */
  if (sas->protocols[0].spi_size_out != 4)
    goto error;
  neg->ed->ipsec_ed->spi_outbound = SSH_GET_32BIT(sas->protocols[0].spi_out);

  SSH_DEBUG(SSH_D_LOWOK, ("Outbound SPI %lx",
                          (unsigned long) neg->ed->ipsec_ed->spi_outbound));

  if (!ikev2_fb_fill_keymat(neg->ed, negotiation, sas, keymat))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot generate IKEv2 keying material"));
      goto error;
    }

  SSH_IKEV2_FB_V2_CALL(neg, ipsec_sa_install)
    (neg->server->sad_handle, neg->ed, ikev2_fb_ipsec_sa_install_done, neg);
  return;

 error:

  /* Even in the case of error, we call the IKEv2 SA installation
     policy call. The key material is cleared to ensure the installation
     will fail at the policy manager. */
  ssh_free(neg->ed->ipsec_ed->ikev1_keymat);
  neg->ed->ipsec_ed->ikev1_keymat = NULL;
  neg->ed->ipsec_ed->ikev1_keymat_len = 0;

  SSH_IKEV2_FB_V2_CALL(neg, ipsec_sa_install)
    (neg->server->sad_handle, neg->ed, ikev2_fb_ipsec_sa_install_done, neg);
}

/*--------------------------------------------------------------------*/
/* Quick-Mode freed                                                   */
/*--------------------------------------------------------------------*/

void ikev2_fb_qm_sa_freed(SshIkePMPhaseQm pm_info)
{
  SshIkev2FbNegotiation neg;

  SSH_DEBUG(SSH_D_LOWOK, ("QM free Entered"));

  /* Clear `qm_info' backpointer from fallback negotiation structure. */
  neg = pm_info->policy_manager_data;
  if (neg)
    {
      SSH_ASSERT(neg->qm_info == NULL || neg->qm_info == pm_info);
      neg->qm_info = NULL;

      /* Release reference to `neg' from `pm_info->policy_manager_data'. */
      ikev2_fb_phase_qm_clear_pm_data(pm_info, neg);
      ikev2_fallback_negotiation_free(neg->fb, neg);
    }
}
#endif /* SSHDIST_IKEV1 */
