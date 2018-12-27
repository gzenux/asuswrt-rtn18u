/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Phase-I policy functions for IKEv1 fallback.
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

#define SSH_DEBUG_MODULE "SshIkev2FallbackP1"


/*--------------------------------------------------------------------*/
/* Phase I new connections. This also handles the main thread states  */
/* for responder side Phase-I's                                       */
/*--------------------------------------------------------------------*/

void ikev2_fb_ike_sa_allocate_cb(SshIkev2Error error_code,
                                 SshIkev2Sa ike_sa,
                                 void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  neg->ike_error = error_code;

  if (error_code == SSH_IKEV2_ERROR_OK)
    {
      SSH_ASSERT(ike_sa != NULL);

      SSH_DEBUG(SSH_D_LOWOK,
                ("New IKE SA allocated successfully %p (neg %p)",
                 ike_sa, neg));

      ike_sa->server = neg->server;
      ike_sa->flags |= SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1;
      SSH_IKEV2_IKE_SA_TAKE_REF(ike_sa);

      neg->ike_sa = ike_sa;
      SSH_IKEV2_IKE_SA_TAKE_REF(neg->ike_sa);

      /* Set `p1_negotiation_context' pointer, it is cleared in thread
         destructor. */
      ike_sa->p1_negotiation_context = neg;
    }
  else
    {
      SSH_ASSERT(ike_sa == NULL);

      SSH_DEBUG(SSH_D_FAIL, ("Error: IKE SA allocate failed: %d (neg %p)",
                             error_code, neg));
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
}


SSH_FSM_STEP(ikev2_fb_st_new_p1_connection_start)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_new_p1_connection_result);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  /* Allocate an IKE SA for this negotiation */
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_FB_V2_CALL(neg, ike_sa_allocate)
                     (neg->server->sad_handle,
                      neg->initiator ? TRUE : FALSE,
                      ikev2_fb_ike_sa_allocate_cb,
                      neg));

  SSH_NOTREACHED;
}

SSH_FSM_STEP(ikev2_fb_st_new_p1_connection_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  if (neg->ike_error == SSH_IKEV2_ERROR_OK)
    {
      /* Allocate exchange data for the negotiation */
      if ((neg->ed = ikev2_allocate_exchange_data(neg->ike_sa)) == NULL)
        {
          neg->ike_error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
          goto error;
        }

      /* Set the exchange data state. */
      neg->ed->state = SSH_IKEV2_STATE_IKE_INIT_SA;

      if (ikev2_allocate_exchange_data_ike(neg->ed) != SSH_IKEV2_ERROR_OK)
        {
          neg->ike_error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
          goto error;
        }
      neg->ed->ike_ed->exchange_type = neg->p1_info->exchange_type;
      neg->ed->ike_ed->auth_method = (int) SSH_IKE_AUTH_METHOD_ANY;

      if (ikev2_allocate_exchange_data_ipsec(neg->ed) != SSH_IKEV2_ERROR_OK)
        {
          neg->ike_error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
          goto error;
        }

      /* Set the IKEv2 SA as policy manager data of the IKE PhaseI
         object, and the handle to the ISAKMP library's IKEv1 SA in
         the IKEv2 SA. */
      neg->p1_info->policy_manager_data = neg->ike_sa;
      neg->ike_sa->v1_sa = neg->p1_info->negotiation;

      /* Store the server and remote address and port information to
         the IKEv2 SA. */
      SSH_VERIFY(ssh_ipaddr_parse(neg->ike_sa->remote_ip,
                                  neg->p1_info->remote_ip));
      neg->ike_sa->remote_port = ssh_uatoi(neg->p1_info->remote_port);


      /* Set the NAT-T flags in IKEv2 SA */
      /* NOTE: Should check for DISABLE_NAT_T and reject connection */
      if (neg->p1_info->server_flags & SSH_IKE_SERVER_FLAG_NAT_T_LOCAL_PORT)
        neg->ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE;

      /* Set the IKEv2 initiator SPI from the IKEv1 cookie (for
         logging purposes) */
      memcpy(neg->ike_sa->ike_spi_i,
             neg->p1_info->cookies->initiator_cookie,
             sizeof(neg->ike_sa->ike_spi_i));

      /* Update the responder SPI from the value allocated by the policy
         manager (overriding the SPI originally allocated by the IKEv1
         library). */
      if (!ssh_isakmp_update_responder_cookie(neg->p1_info->negotiation,
                                              neg->ike_sa->ike_spi_r))
        {
          neg->ike_error = SSH_IKEV2_ERROR_INVALID_SYNTAX;
          goto error;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Accepting new Phase-1 negotiation: "
                 "local=%s:%s, remote=%s:%s%s (neg %p)",
                 neg->p1_info->local_ip, neg->p1_info->local_port,
                 neg->p1_info->remote_ip, neg->p1_info->remote_port,
                 ((neg->ike_sa->flags &
                   SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE) ?
                  " using NAT-T" : ""), neg ));

      (*neg->callbacks.u.new_connection)(TRUE,
                                         SSH_IKE_FLAGS_USE_DEFAULTS,
                                         -1, -1, -1, -1, -1, -1, -1,
                                         neg->callbacks.callback_context);
      return SSH_FSM_FINISH;
    }
  else
    {
    error:
      SSH_DEBUG(SSH_D_FAIL,
                ("Rejecting new Phase-1 negotiation: "
                 "local=%s:%s, remote=%s:%s (neg %p)",
                 neg->p1_info->local_ip, neg->p1_info->local_port,
                 neg->p1_info->remote_ip, neg->p1_info->remote_port,
                 neg));

      /* IKEv1 will not call us back, so we need to arrange the
         negotiation thread to terminate. */
      neg->ike_sa_done = 1;
      ssh_fsm_continue(neg->thread);

      (*neg->callbacks.u.new_connection)(FALSE,
                                         SSH_IKE_FLAGS_USE_DEFAULTS,
                                         -1, -1, -1, -1, -1, -1, -1,
                                         neg->callbacks.callback_context);
      return SSH_FSM_FINISH;
    }
}

void
ikev2_fb_new_p1_connection_sub_thread_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  /* Free reference to fallback negotiation structure. */
  ikev2_fallback_negotiation_free(neg->fb, neg);
}

void ikev2_fb_p1_negotiation_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  SSH_DEBUG(SSH_D_LOWOK, ("Freeing fallback negotiation context"));

  /* Free the IKEv2 SA payload */
  if (neg->sav2)
    {
      ssh_ikev2_sa_free(neg->server->sad_handle, neg->sav2);
      neg->sav2 = NULL;
    }

  if (neg->ike_sa)
    neg->ike_sa->p1_negotiation_context = NULL;

  /* Free the references to fallback negotiation. */
  ikev2_fb_negotiation_clear_pm_data(neg);
  ikev2_fallback_negotiation_free(neg->fb, neg);

  return;
}

SSH_FSM_STEP(ikev2_fb_p1_negotiation_allocate_sa)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_p1_negotiation_wait_sa_done);

  /* Take a reference to fallback negotiation structure for the sub thread.
     It will be freed in the sub thread destructor. */
  IKEV2_FB_NEG_TAKE_REF(neg);

  /* Start a sub-thread for IKE SA allocation */
  ssh_fsm_thread_init(neg->fb->fsm, neg->sub_thread,
                      ikev2_fb_st_new_p1_connection_start,
                      NULL_FNPTR,
                      ikev2_fb_new_p1_connection_sub_thread_destructor, neg);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_p1_negotiation_wait_sa_done)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  if (!neg->ike_sa_done)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Suspending until the IKE SA is done (neg %p)",
                              neg));
      return SSH_FSM_SUSPENDED;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Phase-I negotiation is now done (neg %p)", neg));

  if (neg->ike_sa)
    {
      if (neg->ed)
        {
          /* Inform the policy manager the Phase-I negotiation is completed */
          SSH_IKEV2_FB_V2_NOTIFY(neg, ike_sa_done)(neg->server->sad_handle,
                                                   neg->ed,
                                                   neg->ike_error);
          SSH_IKEV2_FB_LOG_V1_ERROR(neg->v1_error);
        }
      else
        {
          /* Delete the IKE SA. */
          SSH_IKEV2_FB_V2_NOTIFY(neg, ike_sa_delete)(neg->server->sad_handle,
                                                     neg->ike_sa,
                                                     NULL_FNPTR, NULL);
        }
    }

  return SSH_FSM_FINISH;
}

void
ikev2_fb_new_connection(SshIkePMPhaseI pm_info,
                        SshPolicyNewConnectionCB callback_in,
                        void *callback_context_in)
{
  SshIkev2Fb fb = (SshIkev2Fb) pm_info->pm->upper_context;
  SshIkeServerContext ike_server;
  SshIkev2FbNegotiation neg;

  SSH_DEBUG(SSH_D_LOWOK, ("New ISAKMP connection from remote address %s/%s",
                          pm_info->remote_ip, pm_info->remote_port));

  if (pm_info->exchange_type == SSH_IKE_XCHG_TYPE_AGGR &&
      fb->num_aggr_mode_responder_active >=
      fb->params.max_num_aggr_mode_active)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Too many active aggressive mode negotiations"));
      (*callback_in)(FALSE,
                     SSH_IKE_FLAGS_USE_DEFAULTS,
                     -1, -1, -1, -1, -1,
                     -1, -1,
                     callback_context_in);
      return;
    }

  if ((neg = ikev2_fallback_negotiation_alloc(fb)) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of negotation contexts."));
      (*callback_in)(FALSE,
                     SSH_IKE_FLAGS_USE_DEFAULTS,
                     -1, -1, -1, -1, -1,
                     -1, -1,
                     callback_context_in);
      return;
    }
  /* Increment the number of active aggressive mode negotiations. */
  if (pm_info->exchange_type == SSH_IKE_XCHG_TYPE_AGGR)
    {
      neg->aggr_mode_responder = 1;
      fb->num_aggr_mode_responder_active++;
    }

  /* Lookup the server object used in the negotiation. */
  ike_server = ssh_ike_get_server_by_negotiation(pm_info->negotiation);
  SSH_ASSERT(ike_server != NULL);

  neg->server = (SshIkev2Server)ike_server;

  /* Store the completion callback and its context. */
  neg->callbacks.u.new_connection = callback_in;
  neg->callbacks.callback_context = callback_context_in;

  /* Responder grabs pm_info here, initiator at first policy call
     (request vendor ids) */
  neg->p1_info = pm_info;

  /* Start the main thread controlling this negotiation */
  ssh_fsm_thread_init(fb->fsm, neg->thread,
                      ikev2_fb_p1_negotiation_allocate_sa,
                      NULL_FNPTR, ikev2_fb_p1_negotiation_destructor,
                      neg);
}


/*--------------------------------------------------------------------*/
/* ISAKMP nonce data length                                           */
/*--------------------------------------------------------------------*/

void
ikev2_fb_isakmp_nonce_data_len(SshIkePMPhaseI pm_info,
                               SshPolicyNonceDataLenCB callback_in,
                               void *callback_context_in)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Entered"));
  (*callback_in)(16, callback_context_in);
  return;
}

/*--------------------------------------------------------------------*/
/* IKE SA Identities                                                  */
/*--------------------------------------------------------------------*/


/* Duplicate an IKEv2 identity payload. Returns NULL on error. */
static SshIkev2PayloadID
ikev2_fb_ikev2_payload_id_dup(SshIkev2ExchangeData ed, SshIkev2PayloadID id)
{
  SshIkev2PayloadID dup = NULL;

  if (id == NULL)
    return NULL;

  if ((dup = ssh_obstack_alloc(ed->obstack, sizeof(*dup))) == NULL)
    return NULL;
  memset(dup, 0, sizeof(*dup));

  if ((dup->id_data =
       ssh_obstack_memdup(ed->obstack, id->id_data, id->id_data_size)) == NULL)
    return NULL;

  dup->id_type = id->id_type;
  dup->id_reserved = id->id_reserved;
  dup->id_data_size = id->id_data_size;
  return dup;
}

void ikev2_fb_id_request_cb(SshIkev2Error error_code,
                            Boolean local,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                            Boolean another_auth_follows,
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                            const SshIkev2PayloadID id_payload,
                            void *context)
{
  SshIkev2FbNegotiation neg = context;

  SSH_ASSERT(local == TRUE);
  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  if (id_payload)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Local id payload is %@",
                              ssh_ikev2_payload_id_render, id_payload));

      /* Convert the IKEv2 identity to IKEv1 format. */
      if ((neg->ikev1_id = ikev2_fb_idv2_to_idv1(id_payload)) == NULL)
        {
          SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
          return;
        }

      /* Store the IKEv2 identity in the exchange data as the policy manager
         will need this. */
      if (neg->ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
        {
          neg->ed->ike_ed->id_i =
            ikev2_fb_ikev2_payload_id_dup(neg->ed, id_payload);

          if (neg->ed->ike_ed->id_i == NULL)
            {
              ssh_ike_id_free(neg->ikev1_id);
              neg->ikev1_id = NULL;
            }
        }
      else
        {
          neg->ed->ike_ed->id_r =
            ikev2_fb_ikev2_payload_id_dup(neg->ed, id_payload);

          if (neg->ed->ike_ed->id_r == NULL)
            {
              ssh_ike_id_free(neg->ikev1_id);
              neg->ikev1_id = NULL;
            }
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Local identity was not found (neg %p)", neg));
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
}

SSH_FSM_STEP(ikev2_fb_st_id_request)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_id_request_result);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  /* Fetch our local identity */
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_FB_V2_CALL(neg, id)
                     (neg->server->sad_handle, neg->ed, TRUE,
                      0,
                      ikev2_fb_id_request_cb,
                      neg));
#else /* SSH_IKEV2_MULTIPLE_AUTH */
  /* Fetch our local identity */
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_FB_V2_CALL(neg, id)
                     (neg->server->sad_handle, neg->ed, TRUE,
                      ikev2_fb_id_request_cb,
                      neg));
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ikev2_fb_st_id_request_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  /* Return the IKEv1 identity to the ISAKMP library. */
  (*neg->callbacks.u.id)(neg->ikev1_id, neg->callbacks.callback_context);
  neg->ikev1_id = NULL;

  return SSH_FSM_FINISH;
}

void
ikev2_fb_id_request_sub_thread_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  /* Free reference to fallback negotiation structure. */
  ikev2_fallback_negotiation_free(neg->fb, neg);
}

void
ikev2_fb_isakmp_id(SshIkePMPhaseI pm_info,
                   SshPolicyIsakmpIDCB callback_in,
                   void *callback_context_in)
{
  SshIkev2FbNegotiation neg;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    goto error;

  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    {
    error:
      (*callback_in)(NULL, callback_context_in);
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("IKE ID policy call entered, IKE SA %p (neg %p)",
                          neg->ike_sa, neg));

  SSH_ASSERT(neg->p1_info->remote_id != NULL);

  /* First store the remote peer's identity to the IKEv2 exchange
     data structure since the policy manager will access this identity. */
  if (neg->ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
      if (neg->ed->ike_ed->id_r == NULL)
        neg->ed->ike_ed->id_r = ikev2_fb_idv1_to_idv2(neg->ed,
                                                      neg->p1_info->remote_id);

      if (neg->ed->ike_ed->id_r == NULL)
        {
          (*callback_in)(NULL, callback_context_in);
          return;
        }
    }
  else
    {
      if (neg->ed->ike_ed->id_i == NULL)
        neg->ed->ike_ed->id_i = ikev2_fb_idv1_to_idv2(neg->ed,
                                                      neg->p1_info->remote_id);

      if (neg->ed->ike_ed->id_i == NULL)
        {
          (*callback_in)(NULL, callback_context_in);
          return;
        }
    }

  /* Store the completion callback and its context. */
  neg->callbacks.u.id = callback_in;
  neg->callbacks.callback_context = callback_context_in;

  /* Take a reference to fallback negotiation structure for the sub thread.
     It will be freed in the sub thread destructor. */
  IKEV2_FB_NEG_TAKE_REF(neg);

  ssh_fsm_thread_init(neg->fb->fsm, neg->sub_thread, ikev2_fb_st_id_request,
                      NULL_FNPTR,
                      ikev2_fb_id_request_sub_thread_destructor, neg);
}

/*--------------------------------------------------------------------*/
/* IKE SA Vendor Identities                                           */
/*--------------------------------------------------------------------*/

void
ikev2_fb_isakmp_vendor_id(SshIkePMPhaseI pm_info,
                          unsigned char *vendor_id,
                          size_t vendor_id_len)
{
  SshIkev2FbNegotiation neg;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    return;

  SSH_DEBUG(SSH_D_LOWOK, ("Received vendor ID, length %d, IKE SA %p (neg %p)",
                          vendor_id_len, neg->ike_sa, neg));

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  ikev2_fb_check_recvd_natt_vendor_id(neg, vendor_id, vendor_id_len);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  SSH_IKEV2_FB_V2_NOTIFY(neg, vendor_id)(neg->server->sad_handle, neg->ed,
                                         vendor_id, vendor_id_len);
}

/*--------------------------------------------------------------------*/

void ikev2_fb_vid_request_cb(SshIkev2Error error_code,
                             const unsigned char *vendor_id,
                             size_t vendor_id_len,
                             void *context)
{
  SshIkev2FbNegotiation neg = context;
  int i;

  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  /* If a memory error occurred while processing a previous vendor ID
     payload, we have already called the VID request callback and so we
     should ignore this vendor ID. */
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return;

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Error: VID request failed: %d (neg %p) ", error_code, neg));
      neg->ike_error = error_code;
      goto error;
    }

  /* A vendor id length of zero means the policy manager has sent us all
     relevant vendor ID's, in this case we call the done callback. */
  if (vendor_id_len == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("No more VIDs"));

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      ikev2_fb_check_sent_natt_vendor_ids(neg);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

      (*neg->callbacks.u.request_vid)(neg->num_vendor_ids, neg->vendor_ids,
                                      neg->vendor_id_lens,
                                      neg->callbacks.callback_context);
      return;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("Got a VID of length %d (neg %p)",
                             vendor_id_len, neg));

  if ((neg->vendor_id_lens =
       ssh_realloc(neg->vendor_id_lens,
                   neg->num_vendor_ids * sizeof(size_t),
                   (neg->num_vendor_ids + 1) * sizeof(size_t))) == NULL)
    goto error;

  neg->vendor_id_lens[neg->num_vendor_ids] = vendor_id_len;

  if ((neg->vendor_ids =
       ssh_realloc(neg->vendor_ids,
                   neg->num_vendor_ids * sizeof(unsigned char *),
                   (neg->num_vendor_ids + 1) * sizeof(unsigned char *)))
      == NULL)
    goto error;

  if ((neg->vendor_ids[neg->num_vendor_ids] =
       ssh_memdup(vendor_id, vendor_id_len)) == NULL)
    goto error;

  neg->num_vendor_ids++;
  return;

 error:

  if (neg->vendor_ids)
    {
      for (i = 0; i < neg->num_vendor_ids; i++)
        ssh_free(neg->vendor_ids[i]);
      ssh_free(neg->vendor_ids);
    }

  ssh_free(neg->vendor_id_lens);

  neg->vendor_ids = NULL;
  neg->vendor_id_lens = NULL;
  neg->num_vendor_ids = 0;

  (*neg->callbacks.u.request_vid)(0, NULL, NULL,
                                  neg->callbacks.callback_context);
  return;
}

void
ikev2_fb_isakmp_request_vendor_ids(SshIkePMPhaseI pm_info,
                                   SshPolicyRequestVendorIDsCB callback_in,
                                   void *callback_context_in)
{
  SshIkev2FbNegotiation neg;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    {
      (*callback_in)(0, NULL, NULL, callback_context_in);
      return;
    }

  if (neg->p1_info == NULL)
    {
      /* Initiator grabs ike library pm_info here, responder at new
         connection */
      neg->p1_info = pm_info;
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("Request vendor ID's policy call entered, IKE SA %p (neg %p)",
             neg->ike_sa, neg));

  SSH_ASSERT(neg->ike_error == SSH_IKEV2_ERROR_OK);

  /* Store the completion callback and its context. */
  neg->callbacks.u.request_vid = callback_in;
  neg->callbacks.callback_context = callback_context_in;

  /* Request our vendor ID's from the policy manager. */
  SSH_IKEV2_FB_V2_CALL(neg, vendor_id_request)
    (neg->server->sad_handle, neg->ed, ikev2_fb_vid_request_cb, neg);
}

/*--------------------------------------------------------------------*/
/* IKE SA Shared Secrets                                              */
/*--------------------------------------------------------------------*/

void ikev2_fb_find_pre_shared_key_cb(SshIkev2Error error_code,
                                     const unsigned char *key_out,
                                     size_t key_out_len,
                                     void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  if (error_code == SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Found preshared key"));

      /* Copy the key as the IKE library does not take its own
         copy of the key. */
      neg->psk = ssh_memdup(key_out, key_out_len);
      neg->psk_len = (neg->psk != NULL) ? key_out_len : 0;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Preshared key lookup failed, error '%s' (neg %p)",
                 ssh_ikev2_error_to_string(error_code), neg));
      neg->psk = NULL;
      neg->psk_len = 0;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
  return;
}

SSH_FSM_STEP(ikev2_fb_st_find_pre_shared_key)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_find_pre_shared_key_result);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL(SSH_IKEV2_FB_V2_CALL(neg, shared_key)
                     (neg->server->sad_handle, neg->ed, TRUE,
                      ikev2_fb_find_pre_shared_key_cb,
                      neg));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ikev2_fb_st_find_pre_shared_key_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  (*neg->callbacks.u.find_pre_shared_key)(neg->psk, neg->psk_len,
                                          neg->callbacks.callback_context);

  neg->psk = NULL;
  neg->psk_len = 0;
  return SSH_FSM_FINISH;
}

void
ikev2_fb_find_pre_shared_key_sub_thread_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  /* Free reference to fallback negotiation structure. */
  ikev2_fallback_negotiation_free(neg->fb, neg);
}

void
ikev2_fb_find_pre_shared_key(SshIkePMPhaseI pm_info,
                             SshPolicyFindPreSharedKeyCB callback_in,
                             void *callback_context_in)
{
  SshIkev2FbNegotiation neg;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    {
      (*callback_in)(NULL, 0, callback_context_in);
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Find pre-shared key policy call entered, "
                          "IKE SA %p (neg %p)", neg->ike_sa, neg));

  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    {
      (*callback_in)(neg->psk, neg->psk_len, callback_context_in);
      neg->psk = NULL;
      return;
    }

  neg->ed->state = SSH_IKEV2_STATE_IKE_AUTH_LAST;

  /* The PSK hash already been retrieved for IKE initiators, so we can
     return it immediately to the IKE library. */
  if (neg->psk)
    {
      (*callback_in)(neg->psk, neg->psk_len, callback_context_in);
      neg->psk = NULL;
      return;
    }

  /* Store the completion callback and its context. */
  neg->callbacks.u.find_pre_shared_key = callback_in;
  neg->callbacks.callback_context = callback_context_in;

  /* Take a reference to fallback negotiation structure for the sub thread.
     It will be freed in the sub thread destructor. */
  IKEV2_FB_NEG_TAKE_REF(neg);

  ssh_fsm_thread_init(neg->fb->fsm, neg->sub_thread,
                      ikev2_fb_st_find_pre_shared_key,
                      NULL_FNPTR,
                      ikev2_fb_find_pre_shared_key_sub_thread_destructor, neg);
}


/*--------------------------------------------------------------------*/
/* IKE SA Algorithm Selection                                         */
/*--------------------------------------------------------------------*/

void
ikev2_fb_spd_select_sa_cb(SshIkev2Error error_code,
                          int proposal_index,
                          SshIkev2PayloadTransform
                          selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX],
                          void *context)
{
  SshIkev2FbNegotiation neg = context;
  int *transform_index = NULL;
  int sa_lifetime = 0;
  int i;

  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKEv2 SA select failed with error %s (neg %p)",
                             ssh_ikev2_error_to_string(error_code), neg));
      goto error;
    }

  /* Set the selected algorithms to the IKEv2 SA (needed by the
     policy manager) */
  if (ikev2_fill_in_algorithms(neg->ike_sa, selected_transforms)
      != SSH_IKEV2_ERROR_OK)
    goto error;

  /* Record the selected group to the IKEv2 exchange data. */
  for (i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
    {
      if (selected_transforms[i] == NULL)
        continue;

      if (selected_transforms[i]->type == SSH_IKEV2_TRANSFORM_TYPE_D_H)
        {
          neg->ed->ike_ed->group_number = selected_transforms[i]->id;
          SSH_DEBUG(SSH_D_MIDOK, ("Diffie-Hellman group number %d selected",
                                  neg->ed->ike_ed->group_number));
          break;
        }
    }
  SSH_ASSERT(neg->ed->ike_ed->group_number != 0);


  if ((transform_index = ssh_calloc(1, sizeof(int))) == NULL)
    goto error;

  /* Check from the original IKEv1 SA payload to see which
     transform index was selected. */
  if (!ikev2_fb_select_ike_transform_index(selected_transforms,
                                           neg->p1_info->negotiation,
                                           &neg->sav1->pl.sa,
                                           transform_index))
    {
    error:
      if (transform_index)
        ssh_free(transform_index);

      SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
      return;
    }


  /* Use the minimum from ours and initiator's lifetimes, but if the
     initiator did not propose anything, use our value. */
  if (neg->ike_sa_life_seconds &&
      neg->ike_sa_life_seconds < neg->ed->ike_ed->sa_life_seconds)
    {
      /* Initiator's value is smaller than ours. */
      sa_lifetime = neg->ike_sa_life_seconds;
    }
  else
    {
      /* Initiator did not propose anything or ours is smaller. */
      sa_lifetime = neg->ed->ike_ed->sa_life_seconds;
    }
  /* Set the (possibly) modified lifetimes to the IKE exchange data. */
  neg->ed->ike_ed->sa_life_seconds = sa_lifetime;

  SSH_DEBUG(SSH_D_LOWOK, ("Set IKE SA lifetime to %d seconds", sa_lifetime));

  neg->p1_info->sa_start_time = ssh_time();
  neg->p1_info->sa_expire_time = neg->p1_info->sa_start_time + sa_lifetime;

  neg->proposal_index = 0;
  neg->transform_index = transform_index;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
  return;
}

SSH_FSM_STEP(ikev2_fb_st_select_ike_sa)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_select_ike_sa_finish);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL(SSH_IKEV2_FB_V2_CALL(neg, select_ike_sa)
                     (neg->server->sad_handle, neg->ed,
                      neg->sav2,
                      ikev2_fb_spd_select_sa_cb,
                      neg));

  SSH_NOTREACHED;
}

SSH_FSM_STEP(ikev2_fb_st_select_ike_sa_finish)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  /* All done, return the proposal and transform index to the ISAKMP library */
  (*neg->callbacks.u.sa)(neg->proposal_index, 1, neg->transform_index,
                         neg->callbacks.callback_context);

  neg->transform_index = NULL;
  return SSH_FSM_FINISH;
}

void
ikev2_fb_select_ike_sa_sub_thread_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  /* Free reference to fallback negotiation structure. */
  ikev2_fallback_negotiation_free(neg->fb, neg);
}

void
ikev2_fb_isakmp_select_sa(SshIkePMPhaseI pm_info,
                          SshIkeNegotiation negotiation,
                          SshIkePayload sa_in,
                          SshPolicySACB callback_in,
                          void *callback_context_in)
{
  SshIkev2FbNegotiation neg;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    goto error;

  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    {
    error:
      (*callback_in)(-1, 0, NULL, callback_context_in);
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("Select IKE SA policy call entered, IKE SA %p (neg %p)",
             neg->ike_sa, neg));

  /* Initialize in the state of no proposal chosen. */
  neg->transform_index = NULL;
  neg->proposal_index = -1;

  /* Store the completion callback and its context. */
  neg->callbacks.u.sa = callback_in;
  neg->callbacks.callback_context = callback_context_in;

  /* Convert the IKEv1 SA payload to IKEv2 format. Store the proposed
     authentication method. We need that on key selection later. */
  neg->sav1 = sa_in;
  SSH_ASSERT(neg->sav2 == NULL);

  neg->sav2 =
      ikev2_fb_ikesav1_to_ikesav2(
              neg->server->sad_handle,
              pm_info->negotiation,
              &sa_in->pl.sa,
              &neg->ed->ike_ed->auth_method,
              &neg->ike_sa_life_seconds);

#ifdef SSHDIST_IKE_XAUTH
  if ((neg->ed->ike_ed->auth_method >=
       SSH_IKE_VALUES_AUTH_METH_HYBRID_I_RSA_SIGNATURES)
      &&
      (neg->ed->ike_ed->auth_method <=
       SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION_REVISED))
    neg->ike_sa->xauth_enabled = 1;
#endif /* SSHDIST_IKE_XAUTH */

  if (neg->sav2 == NULL)
    {
      (*callback_in)(-1, 0, NULL, callback_context_in);
      return;
    }

  /* Take a reference to fallback negotiation structure for the sub thread.
     It will be freed in the sub thread destructor. */
  IKEV2_FB_NEG_TAKE_REF(neg);

  ssh_fsm_thread_init(neg->fb->fsm, neg->sub_thread, ikev2_fb_st_select_ike_sa,
                      NULL_FNPTR,
                      ikev2_fb_select_ike_sa_sub_thread_destructor, neg);
  return;
}

/*--------------------------------------------------------------------*/
/* IKE SA New group mode                                              */
/*--------------------------------------------------------------------*/
void ikev2_fb_ngm_select_sa(SshIkePMPhaseII pm_info,
                            SshIkeNegotiation negotiation,
                            SshIkePayload sa_in,
                            SshPolicySACB callback_in,
                            void *callback_context_in)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Entered"));

  (*callback_in)(-1, 0, NULL, callback_context_in);
}


/*--------------------------------------------------------------------*/
/* Phase I notification                                              */
/*--------------------------------------------------------------------*/

void
ikev2_fb_phase_i_notification(SshIkePMPhaseI pm_info,
                              Boolean encrypted,
                              SshIkeProtocolIdentifiers protocol_id,
                              unsigned char *spi,
                              size_t spi_size,
                              SshIkeNotifyMessageType
                              notify_message_type,
                              unsigned char *notification_data,
                              size_t notification_data_size)
{
  SshIkev2FbNegotiation neg;
  SshIkev2Sa ike_sa;
  char buf[64];
  SshIkev2NotifyState notify_state;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    return;
  ike_sa = neg->ike_sa;
  ike_sa->last_input_stamp = ssh_time();

  SSH_DEBUG(SSH_D_LOWOK,
            ("Phase-I notification call entered, IKE SA %p (neg %p)",
             ike_sa, neg));

  notify_state = encrypted ? SSH_IKEV2_NOTIFY_STATE_AUTHENTICATED_INITIAL :
    SSH_IKEV2_NOTIFY_STATE_UNAUTHENTICATED_INITIAL;

  switch (notify_message_type)
    {
    case SSH_IKE_NOTIFY_MESSAGE_INITIAL_CONTACT:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Got initial contact notification"));
      if (encrypted)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Registering initial contact notification from `%s%@'",
                     pm_info->remote_ip,
                     ikev2_fb_ike_port_render, pm_info->remote_port));

          /* Inform the policy manager of the notify message. */
          (*neg->ed->ike_sa->server->sad_interface->notify_received)(
                                           neg->ed->ike_sa->server->sad_handle,
                                           notify_state,
                                           neg->ed,
                                           SSH_IKEV2_PROTOCOL_ID_NONE,
                                           spi, spi_size,
                                           SSH_IKEV2_NOTIFY_INITIAL_CONTACT,
                                           NULL, 0);
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Ignoring plain-text initial contact notification "
                     "from `%s%@'",
                     pm_info->remote_ip,
                     ikev2_fb_ike_port_render, pm_info->remote_port));
        }
      break;

    case SSH_IKE_NOTIFY_MESSAGE_REPLAY_STATUS:
      SSH_DEBUG(SSH_D_HIGHSTART,
                ("Replay status notification from %s%@",
                 pm_info->remote_ip,
                 ikev2_fb_ike_port_render, pm_info->remote_port));
      break;

    case SSH_IKE_NOTIFY_MESSAGE_RESPONDER_LIFETIME:
      SSH_DEBUG(SSH_D_HIGHSTART,
                ("Responder lifetime notification from %s%@",
                 pm_info->remote_ip,
                 ikev2_fb_ike_port_render, pm_info->remote_port));
      break;

    case SSH_IKE_NOTIFY_MESSAGE_CISCO_PSK_HASH:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Got PSK hash notification"));
      break;

    default:
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "%s Phase-1 notification `%s' (%d) (size %d bytes) "
                    "from %s%@ for protocol %s spi[0...%d[=%s",
                    encrypted ? "Encrypted" : "Plain-text",
                    ssh_find_keyword_name(ssh_ike_status_keywords,
                                          notify_message_type),
                    notify_message_type,
                    notification_data_size,
                    pm_info->remote_ip,
                    ikev2_fb_ike_port_render, pm_info->remote_port,
                    ssh_find_keyword_name(ikev2_fb_ike_protocol_identifiers,
                                          protocol_id),
                    spi_size,
                    ikev2_fb_util_data_to_hex(buf, sizeof(buf),
                                              spi, spi_size));
    }
}



/*--------------------------------------------------------------------*/
/* SA/negotiation management                                          */
/*--------------------------------------------------------------------*/
void ikev2_fb_isakmp_sa_freed(SshIkePMPhaseI pm_info)
{
  SshIkev2Sa ike_sa = (SshIkev2Sa) pm_info->policy_manager_data;
  SshIkev2FbNegotiation neg;

  SSH_DEBUG(SSH_D_MIDOK, ("Received notification from the ISAKMP library "
                          "that the IKE SA %p is freed", ike_sa));

  /* Break connection to the fallback policy manager data. */
  pm_info->policy_manager_data = NULL;
  if (ike_sa != NULL)
    {
      /* Clear `p1_info' backpointer from fallback negotiation. */
      neg = (SshIkev2FbNegotiation) ike_sa->p1_negotiation_context;
      if (neg)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Clearing p1_info from fallback negotiation %p", neg));
          neg->p1_info = NULL;
        }

      /* Clear the IKEv1 SA handle from the IKEv2 SA. */
      if (ike_sa->v1_sa)
        {
          ike_sa->v1_sa = NULL;
          SSH_DEBUG(SSH_D_LOWSTART,
                    ("FB; Calling v2 policy function ike_sa_delete"));

          (*ike_sa->server->sad_interface->ike_sa_delete)
            (ike_sa->server->sad_handle, ike_sa, NULL_FNPTR, NULL);
        }
    }
}

void
ikev2_fb_negotiation_done_isakmp(SshIkePMPhaseI pm_info,
                                 SshIkeNotifyMessageType code)
{
  SshIkev2FbNegotiation neg;
  SshIkev2Sa ike_sa = (SshIkev2Sa) pm_info->policy_manager_data;

  if (ike_sa == NULL)
    return;

  /* This call should never happen for a completed IKE SA. */
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
    return;

  neg = (SshIkev2FbNegotiation) ike_sa->p1_negotiation_context;
  ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE;

  if (neg != NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Entered IKE error code %s (%d), IKE SA %p (neg %p)",
                 ssh_ike_error_code_to_string(code),
                 code, ike_sa, neg));

      neg->ike_error = ikev2_fb_v1_notify_message_type_to_v2_error_code(code);
      neg->v1_error = code;

      /* Initiatialize DPD cookie for our side */
      while ((ike_sa->dpd_cookie = ssh_rand() & 0x0fffffff) == 0);

      /* The Phase-I is now completed */
      neg->ike_sa_done = 1;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      /* Handle pending NAT-T operations. */
      if (neg->ike_error == SSH_IKEV2_ERROR_OK)
        ikev2_fb_phase1_pending_natt_operations(neg);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

      /* Set NAT-T flags in IKEv2 SA. NAT-T is used at this stage
         if the START_WITH_NAT_T flags was set in ssh_ike_connect */
      if (pm_info->server_flags & SSH_IKE_SERVER_FLAG_NAT_T_LOCAL_PORT)
        ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE;

      /* Wake up the main thread, which will call the IKEv2 IKE SA
         done policy call. */
      ssh_fsm_continue(neg->thread);
    }
}
#endif /* SSHDIST_IKEV1 */
