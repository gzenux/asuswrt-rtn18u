/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Initiator Quick Mode functions for IKEv1 fallback.
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
#define SSH_DEBUG_MODULE "SshIkev2FallbackInitQm"


/*--------------------------------------------------------------------*/
/*    Callbacks                                                       */
/*--------------------------------------------------------------------*/

void ikev2_fb_ipsec_complete(SshIkev2FbNegotiation neg)
{
  SSH_ASSERT(neg->completed == 0);

  if (neg->sub_operation)
    {
      ssh_operation_abort(neg->sub_operation);
      neg->sub_operation = NULL;
    }

  if (SSH_FSM_THREAD_EXISTS(neg->sub_thread)
      && !SSH_FSM_IS_THREAD_DONE(neg->sub_thread))
    {
      SSH_ASSERT(!SSH_FSM_IS_THREAD_RUNNING(neg->sub_thread));
      ssh_fsm_uninit_thread(neg->sub_thread);
    }

  if (!neg->aborted && !neg->completed)
    {
      SSH_IKEV2_FB_V2_NOTIFY(neg, ipsec_sa_done)(neg->server->sad_handle,
                                                 neg->ed,
                                                 neg->ike_error);
      SSH_IKEV2_FB_LOG_V1_ERROR(neg->v1_error);

      if (neg->ed->callback)
        {
          (*neg->ed->callback)(neg->ed->ike_sa->server->sad_handle,
                               neg->ike_sa,
                               neg->ed,
                               neg->ike_error);
          neg->ed->callback = NULL_FNPTR;
          ssh_operation_unregister_no_free(
                  neg->ed->ipsec_ed->operation_handle);
          neg->ed->ipsec_ed->flags &= ~SSH_IKEV2_IPSEC_OPERATION_REGISTERED;
        }
      neg->completed = 1;
    }
}

static void
ikev2_fb_i_ipsec_negotiation_cb(SshIkeNotifyMessageType error,
                                SshIkeNegotiation negotiation,
                                void *callback_context)
{
  SshIkev2FbNegotiation neg = NULL;
  SshIkePMPhaseQm qm_info;

  /* Take fallback negotiation from `policy_manager_data' to safely
     deal with negotiation abort. */
  qm_info = ikev2_fb_get_qm_info(negotiation);
  if (qm_info && qm_info->policy_manager_data)
    neg = (SshIkev2FbNegotiation) qm_info->policy_manager_data;

  SSH_DEBUG(SSH_D_LOWOK, ("Connect IPSec done callback, status %s (neg %p)",
                          ssh_ike_error_code_to_string(error),
                          neg));

  /* If `neg' is NULL then the negotiation has been aborted and
     freed already and the Quick-Mode thread is gone. */
  if (neg == NULL)
    return;

  /* If `neg->qm_negotiation' is NULL then this is an error case
     and the callback was called synchronously from the running
     thread. */
  if (neg->qm_negotiation != NULL)
    {
      neg->qm_negotiation = NULL;
      if (SSH_FSM_THREAD_EXISTS(neg->thread)
          && !SSH_FSM_IS_THREAD_DONE(neg->thread))
        ssh_fsm_continue(neg->thread);
    }

  if (error != SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
    {
      neg->ike_error = ikev2_fb_v1_notify_message_type_to_v2_error_code(error);
      neg->v1_error = error;
      SSH_ASSERT(neg->ike_error != SSH_IKEV2_ERROR_OK);
    }
  else
    {
      neg->ike_sa->last_input_stamp = ssh_time();
    }
}

/*--------------------------------------------------------------------*/
/* Sub thread states for initiator Qm negotiations                    */
/*--------------------------------------------------------------------*/


SSH_FSM_STEP(ikev2_fb_st_i_qm_sa_alloc_spi)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_i_qm_sa_notify_request);
  SSH_FSM_ASYNC_CALL({
    SSH_IKEV2_FB_V2_CALL(neg,
                         ipsec_spi_allocate)(neg->server->sad_handle,
                                             neg->ed,
                                             ikev2_fb_ipsec_spi_allocate_cb,
                                             neg);
  });
}

SSH_FSM_STEP(ikev2_fb_st_i_qm_sa_notify_request)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_i_qm_sa_request);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL({
    SSH_IKEV2_FB_V2_CALL(neg, notify_request)(neg->server->sad_handle,
                                              neg->ed,
                                              ikev2_fb_notify_request_cb,
                                              neg);
  });
}

SSH_FSM_STEP(ikev2_fb_st_i_qm_sa_request)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_i_qm_result);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL({
    SSH_IKEV2_FB_V2_CALL(neg, fill_ipsec_sa)(neg->server->sad_handle,
                                             neg->ed,
                                             ikev2_fb_sa_request_cb,
                                             neg);
  });
}

SSH_FSM_STEP(ikev2_fb_st_i_qm_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  /* sub_thread is now done */
  SSH_ASSERT(neg->sub_operation == NULL);

  ssh_fsm_continue(neg->thread);
  return SSH_FSM_FINISH;
}

void
ikev2_fb_i_qm_sub_thread_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  /* Free reference to fallback negotiation structure. */
  ikev2_fallback_negotiation_free(neg->fb, neg);
}

/*--------------------------------------------------------------------*/
/* Main thread states for initiator Qm negotiations                   */
/*--------------------------------------------------------------------*/

SSH_FSM_STEP(ikev2_fb_i_qm_negotiation_start)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_DEBUG(SSH_D_MIDSTART, ("QM negotiation start"));

  /* Advance initiator state */
  neg->ed->state = SSH_IKEV2_STATE_CREATE_CHILD;

  /* Take a reference to fallback negotiation structure for the sub thread.
     It will be freed in the sub thread destructor. */
  IKEV2_FB_NEG_TAKE_REF(neg);

  SSH_FSM_SET_NEXT(ikev2_fb_i_qm_negotiation_negotiate);
  ssh_fsm_thread_init(neg->fb->fsm, neg->sub_thread,
                      ikev2_fb_st_i_qm_sa_alloc_spi,
                      NULL_FNPTR,
                      ikev2_fb_i_qm_sub_thread_destructor, neg);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_i_qm_negotiation_negotiate)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;
  SshIkePayloadID qm_local, qm_remote;
  SshIkePayloadSA *qm_sa;
  Boolean qm_tunnel;
  SshIkeErrorCode ret;
  SshUInt32 flags = 0L;
  SshIkeNegotiation qm_negotiation = NULL;

  SSH_DEBUG(SSH_D_MIDSTART, ("QM negotiation negotiate"));

  if (neg->ed->ike_sa->v1_sa == NULL)
    neg->ike_error = SSH_IKEV2_ERROR_SA_UNUSABLE;

  if (neg->ike_error != (int) SSH_IKE_ERROR_OK)
    {
      SSH_FSM_SET_NEXT(ikev2_fb_i_qm_negotiation_result);
      return SSH_FSM_CONTINUE;
    }

  if (neg->sav2 == NULL)
    {
      return SSH_FSM_SUSPENDED;
    }

  SSH_FSM_SET_NEXT(ikev2_fb_i_qm_negotiation_result);

  switch (neg->encapsulation)
    {
    case IPSEC_VALUES_ENCAPSULATION_MODE_TRANSPORT:
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
    case IPSEC_VALUES_ENCAPSULATION_MODE_UDP_TRANSPORT:
    case IPSEC_VALUES_ENCAPSULATION_MODE_UDP_DRAFT_TRANSPORT:
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
      qm_tunnel = FALSE;
      break;

    default:
      qm_tunnel = TRUE;
    }

  if ((qm_sa = ssh_malloc(sizeof(*qm_sa))) != NULL)
    {
      int i;
      for (i = 0; i < neg->sav2->number_of_transforms_used; i++)
        if (neg->sav2->transforms[i].type == SSH_IKEV2_TRANSFORM_TYPE_D_H)
          flags |= SSH_IKE_IPSEC_FLAGS_WANT_PFS;

      qm_sa[0] = ikev2_fb_sav2_to_sav1(neg->sav2,
                                       0L,
                                       neg->ed->ipsec_ed->sa_life_seconds,
                                       neg->ed->ipsec_ed->sa_life_kbytes,
                                       qm_tunnel,
                                       neg->ike_sa->flags,
                                       neg->inbound_spi,
                                       neg->ipcomp_num,
                                       neg->ipcomp_algs,
                                       neg->ipcomp_cpi_in);
      if (qm_sa[0] == NULL)
        {
          ssh_free(qm_sa);
          qm_sa = NULL;

          neg->ike_error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
          return SSH_FSM_CONTINUE;
        }

      neg->ed->ipsec_ed->ipsec_sa_protocol = neg->sav2->protocol_id[0];
      neg->ed->ipsec_ed->spi_inbound = neg->inbound_spi;
    }
  else
    {
      neg->ike_error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      return SSH_FSM_CONTINUE;
    }

  /* Policy manager passes the triggering packet only if the policy
     rule does not define any traffic selectors. In this case the
     SA traffic selectors are taken from the triggering packet. */
  if (neg->ed->ipsec_ed->source_ip &&
      SSH_IP_DEFINED(neg->ed->ipsec_ed->source_ip))
    {
      SshIkev2PayloadTS ts;
      SshUInt16 sport, eport;

      /* Allocate new ts */
      ts = ssh_ikev2_ts_allocate(neg->server->sad_handle);
      if (ts == NULL)
        {
          ret = SSH_IKE_ERROR_OUT_OF_MEMORY;
          goto ts_error;
        }

      sport = 0;
      eport = 0xffff;
      if (neg->ed->ipsec_ed->source_port)
        sport = eport = neg->ed->ipsec_ed->source_port;

      (void)ssh_ikev2_ts_item_add(ts,
                                  neg->ed->ipsec_ed->protocol,
                                  neg->ed->ipsec_ed->source_ip,
                                  neg->ed->ipsec_ed->source_ip,
                                  sport, eport);

      /* Free reference taken by IKEv2 library */
      if (neg->ed->ipsec_ed->ts_local)
        ssh_ikev2_ts_free(neg->server->sad_handle,
                          neg->ed->ipsec_ed->ts_local);

      neg->ed->ipsec_ed->ts_local = ts;
    }

  /* Do the same for remote ts */
  if (neg->ed->ipsec_ed->destination_ip &&
      SSH_IP_DEFINED(neg->ed->ipsec_ed->destination_ip))
    {
      SshIkev2PayloadTS ts;
      SshUInt16 sport, eport;

      ts = ssh_ikev2_ts_allocate(neg->server->sad_handle);
      if (ts == NULL)
        {
          ret = SSH_IKE_ERROR_OUT_OF_MEMORY;
          goto ts_error;
        }

      sport = 0;
      eport = 0xffff;
      if (neg->ed->ipsec_ed->destination_port)
        sport = eport = neg->ed->ipsec_ed->destination_port;

      (void)ssh_ikev2_ts_item_add(ts,
                                  neg->ed->ipsec_ed->protocol,
                                  neg->ed->ipsec_ed->destination_ip,
                                  neg->ed->ipsec_ed->destination_ip,
                                  sport, eport);

      if (neg->ed->ipsec_ed->ts_remote)
        ssh_ikev2_ts_free(neg->server->sad_handle,
                          neg->ed->ipsec_ed->ts_remote);

      neg->ed->ipsec_ed->ts_remote = ts;
    }

  qm_local = ikev2_fb_tsv2_to_tsv1(neg->ed->ipsec_ed->ts_local);

  qm_remote = ikev2_fb_tsv2_to_tsv1(neg->ed->ipsec_ed->ts_remote);

  /* Free the IKEv2 SA payload */
  ssh_ikev2_sa_free(neg->server->sad_handle, neg->sav2);
  neg->sav2 = NULL;

  /* Take a reference to fallback negotiation, it will be put to
     `pm_info->policy_manager_data' by the isakmp library. */
  IKEV2_FB_NEG_TAKE_REF(neg);

  /* `neg->qm_negotiation' is used for detecting error condition in
     ikev2_fb_i_ipsec_negotiation_cb(). */
  SSH_ASSERT(neg->qm_negotiation == NULL);

  ret = ssh_ike_connect_ipsec((SshIkeServerContext)neg->server,
                              &qm_negotiation,
                              neg->ed->ike_sa->v1_sa,
                              NULL, NULL, /* destination comes from IKE SA */
                              qm_local, qm_remote,
                              1, qm_sa,
                              neg,
                              flags,
                              ikev2_fb_i_ipsec_negotiation_cb,
                              NULL);

  if (ret == SSH_IKE_ERROR_OK && qm_negotiation != NULL)
    {
      /* Save `neg->qm_info' so that `neg->qm_info->policy_manager_data'
         can be cleared before pm_info is freed. Allthough isakmp library
         calls policy callbacks synchronously from ssh_connect_ipsec(),
         `qm_info' is not used for the first packet. */
      neg->qm_negotiation = qm_negotiation;
      neg->qm_info = ikev2_fb_get_qm_info(neg->qm_negotiation);

      /* All is fine, we'll wait for QM to complete */
      return SSH_FSM_SUSPENDED;
    }

  /* Error, isakmp library has called callbacks synchronously. */
  else if (ret == SSH_IKE_ERROR_OK && qm_negotiation == NULL)
    {
      /* Isakmp library has freed `qm_sa', `qm_local' and `qm_remote',
         called the completion callback and freed `policy_manager_data'. */
      qm_sa = NULL;
    }

  /* Direct error, free the ID and SA payloads */
  else
    {
      ssh_ike_id_free(qm_local);
      ssh_ike_id_free(qm_remote);

      /* Free the reference to fallback negotiation. */
      ikev2_fallback_negotiation_free(neg->fb, neg);
    }

 ts_error:
  if (qm_sa)
    {
      ssh_ike_free_sa_payload(qm_sa[0]);
      ssh_free(qm_sa);
    }

  if (ret == SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND)
    {
      /* Mark IKEv2 error, and indicate this SA to the application.
         It should restart from the scratch. */
      neg->ike_error = SSH_IKEV2_ERROR_SA_UNUSABLE;
    }
  else
    {
      /* Other failure. */
      neg->ike_error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_i_qm_negotiation_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_DEBUG(SSH_D_MIDSTART, ("QM negotiation result"));

  if (neg->ike_error == SSH_IKEV2_ERROR_OK)
    {
      SSH_FSM_SET_NEXT(ikev2_fb_qm_negotiation_wait_sa_installation);
      return SSH_FSM_CONTINUE;
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK, ("QM negotiation error %d (neg %p)",
                              neg->ike_error, neg));
      ikev2_fb_ipsec_complete(neg);
      return SSH_FSM_FINISH;
    }
}

/* Abort callback for IKEv1 negotiations. */
static void ikev2_fb_sa_abort(void *context)
{
  SshIkev2FbNegotiation neg = context;

  SSH_DEBUG(SSH_D_MIDSTART, ("Aborting QM negotiation %p", neg));

  SSH_ASSERT(neg->ike_sa != NULL);

  /* Mark the negotiation context aborted. We'll need this information
     as IKEv1 library will call callbacks after
     ssh_ike_abort_negotiation has been called, but we must not call
     neither PM, nor IKE from the sub state machines. */
  neg->aborted = 1;
  neg->ike_error = SSH_IKEV2_ERROR_SA_UNUSABLE;
  if (neg->ed)
    {
      neg->ed->callback = NULL_FNPTR;
      if (neg->ed->ipsec_ed)
        neg->ed->ipsec_ed->flags &= ~SSH_IKEV2_IPSEC_OPERATION_REGISTERED;
      if (neg->ed->info_ed)
        neg->ed->info_ed->flags &= ~SSH_IKEV2_INFO_OPERATION_REGISTERED;
    }

  /* Abort any PM policy function calls */
  if (neg->sub_operation)
    {
      ssh_operation_abort(neg->sub_operation);
      neg->sub_operation = NULL;

      if (SSH_FSM_THREAD_EXISTS(neg->sub_thread))
        {
          SSH_ASSERT(!SSH_FSM_IS_THREAD_RUNNING(neg->sub_thread));
          if (!SSH_FSM_IS_THREAD_DONE(neg->sub_thread))
            ssh_fsm_uninit_thread(neg->sub_thread);
        }
    }

#ifdef SSHDIST_ISAKMP_CFG_MODE
  ssh_cancel_timeout(neg->cfgmode_timeout);

  if (neg->ike_sa->v1_cfg_negotiation)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Aborting CFG negotiation %p (neg %p)",
                              neg->ike_sa->v1_cfg_negotiation, neg));

      if (neg->ike_sa->v1_sa)
        ssh_ike_abort_negotiation(neg->ike_sa->v1_cfg_negotiation, 0L);
      neg->ike_sa->v1_cfg_negotiation = NULL;
    }
  else
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    if (neg->qm_negotiation)
      {
        SSH_DEBUG(SSH_D_LOWOK, ("Aborting QM negotiation %p (neg %p)",
                                neg->qm_negotiation, neg));

        /* Abort the ongoing IKE QM if the IKE SA still exists. */
        if (neg->ike_sa->v1_sa)
          ssh_ike_abort_negotiation(neg->qm_negotiation, 0L);
        neg->qm_negotiation = NULL;
        ikev2_free_exchange_data(neg->ike_sa, neg->ed);
        neg->ed = NULL;
      }
    else if (neg->ike_sa->v1_sa &&
             !(neg->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE))
      {
        /* We have ongoing P1 SA negotiation. */

        SSH_DEBUG(SSH_D_LOWOK, ("Aborting IKE SA negotiation %p (neg %p)",
                                neg->ike_sa->v1_sa, neg));

        /* Free ED now, as after this function returns the caller may
           free the SA */

        ssh_ike_abort_negotiation(neg->ike_sa->v1_sa, 0L);
        ikev2_free_exchange_data(neg->ike_sa, neg->ed);
        neg->ed = NULL;
      }
    else
      {
        /* We are either about to start P1 or QM */
        if (neg->ike_sa->v1_sa == NULL)
          {
            if (neg->ikev1_sa_unallocated != 0)
              {
                SSH_DEBUG(SSH_D_LOWSTART,
                          ("FB; Calling v2 policy function ike_sa_delete"));
                (*neg->ike_sa->server->sad_interface->ike_sa_delete)
                  (neg->ike_sa->server->sad_handle, neg->ike_sa,
                   NULL_FNPTR, NULL);
              }

            SSH_DEBUG(SSH_D_LOWOK, ("Finishing IKE SA negotiation (neg %p)",
                                    neg));
            ssh_fsm_set_next(neg->thread, ikev2_fb_i_p1_negotiation_result);
          }
        else
          {
            SSH_DEBUG(SSH_D_LOWOK, ("Finishing QM negotiation (neg %p)", neg));
            ssh_fsm_set_next(neg->thread, ikev2_fb_i_qm_negotiation_result);
          }
      }

  /* The negotiation main thread is always suspended and waiting for isakmp
     library call completion. Therefore ssh_fsm_continue(). */
  ssh_fsm_continue(neg->thread);
}

SshOperationHandle
ikev2_fb_initiate_ipsec_sa(SshIkev2ExchangeData ed)
{
  SshIkev2FbNegotiation neg = NULL;
  SshIkev2Fb fb;

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
  if ((ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) != 0
      && (ed->ipsec_ed->ts_local == NULL || ed->ipsec_ed->ts_remote == NULL))
    {
      /* Null traffic selectors indicate that no IPsec SA is
         wanted. */
      SSH_DEBUG(SSH_D_MIDSTART, ("Completing without QM negotiation"));
      (*ed->callback)(ed->ike_sa->server->sad_handle, ed->ike_sa, ed,
                      SSH_IKEV2_ERROR_OK);
      ed->callback = NULL_FNPTR;
      return NULL;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

  fb = ed->ike_sa->server->context->fallback;
  if (fb == NULL)
    goto immediate_error;

  neg = ikev2_fallback_negotiation_alloc(fb);
  if (neg == NULL)
    goto immediate_error;

  neg->initiator = 1;
  neg->server = ed->ike_sa->server;
  neg->ed = ed;
  neg->ike_sa = ed->ike_sa;
  SSH_IKEV2_IKE_SA_TAKE_REF(neg->ike_sa);

  if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
    {
      /* Free the ref taken by the actual IKEv2 ED allocation code */
      SSH_IKEV2_IKE_SA_FREE(ed->ike_sa);
      ssh_fsm_thread_init(fb->fsm, neg->thread,
                          ikev2_fb_i_qm_negotiation_start,
                          NULL_FNPTR,
                          ikev2_fb_qm_negotiation_destructor,
                          neg);
    }
  else
    {
      if (neg->ed->ike_ed->exchange_type == SSH_IKE_XCHG_TYPE_NONE)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Initiator has not specified exchange type"));
          goto immediate_error;
        }

      neg->ed->ike_ed->auth_method = (int) SSH_IKE_AUTH_METHOD_ANY;

      /* Set `p1_negotiation_context' pointer, it is cleared in thread
         destructor. */
      neg->ed->ike_sa->p1_negotiation_context = neg;

      /* Mark that IKEv2 SA must be deleted if negotiation is aborted
         before starting the IKEv1 operation. */
      neg->ikev1_sa_unallocated = 1;

      ssh_fsm_thread_init(fb->fsm, neg->thread,
                          ikev2_fb_i_p1_negotiation_start,
                          NULL_FNPTR,
                          ikev2_fb_p1_negotiation_destructor,
                          neg);
    }

  ssh_operation_register_no_alloc(ed->ipsec_ed->operation_handle,
                                  ikev2_fb_sa_abort,
                                  neg);
  ed->ipsec_ed->flags |= SSH_IKEV2_IPSEC_OPERATION_REGISTERED;
  return ed->ipsec_ed->operation_handle;

 immediate_error:
  if (neg != NULL)
    ikev2_fallback_negotiation_free(fb, neg);

  if ((ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) == 0)
    SSH_IKEV2_IKE_SA_TAKE_REF(ed->ike_sa);

  (*ed->callback)(ed->ike_sa->server->sad_handle,
                  ed->ike_sa,
                  ed,
                  SSH_IKEV2_ERROR_INVALID_ARGUMENT);
  ed->callback = NULL_FNPTR;

  if ((ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) == 0)
    {
      SSH_DEBUG(SSH_D_LOWSTART,
                ("FB; Calling v2 policy function ike_sa_delete"));
      (*ed->ike_sa->server->sad_interface->ike_sa_delete)
        (ed->ike_sa->server->sad_handle, ed->ike_sa, NULL_FNPTR, NULL);
    }

  ssh_ikev2_ipsec_exchange_destroy(ed);
  return NULL;
}
#endif /* SSHDIST_IKEV1 */
