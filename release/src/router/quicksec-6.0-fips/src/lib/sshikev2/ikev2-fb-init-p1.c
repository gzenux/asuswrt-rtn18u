/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Initiator Phase I functions for IKEv1 fallback.
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

#define SSH_DEBUG_MODULE "SshIkev2FallbackInitP1"

/* This macro indicates if the IKE SA is waiting for a server initiated
   CFGmode or XAUTH exchange to complete. */
#define IKEV2_FB_CLIENT_WAITING_CFG(ike_sa) \
      (ike_sa->server_cfg_pending ||        \
      (ike_sa->xauth_enabled && !ike_sa->xauth_done))

/*--------------------------------------------------------------------*/
/* Sub thread states for initiator Phase-I negotiations               */
/*--------------------------------------------------------------------*/

#ifdef SSHDIST_ISAKMP_CFG_MODE
static void ikev2_fb_i_p1_cfg_poll_timer(void *context);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/* To initiate using IKEv1 we need to collect the IKE SA proposal
   (need proposal, authentication method and life-times), exchange
   type (aggressive or main) and local identity. */

SSH_FSM_STEP(ikev2_fb_st_i_ike_id_request)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_i_ike_notify_request);
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  SSH_FSM_ASYNC_CALL({
    SSH_IKEV2_FB_V2_CALL(neg, id)(neg->server->sad_handle,
                                  neg->ed,
                                  TRUE,
                                  0,
                                  ikev2_fb_id_request_cb,
                                  neg);
  });
#else /* SSH_IKEV2_MULTIPLE_AUTH */
  SSH_FSM_ASYNC_CALL({
    SSH_IKEV2_FB_V2_CALL(neg, id)(neg->server->sad_handle,
                                  neg->ed,
                                  TRUE,
                                  ikev2_fb_id_request_cb,
                                  neg);
  });
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
}

SSH_FSM_STEP(ikev2_fb_st_i_ike_notify_request)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_i_ike_psk_request);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL({
    SSH_IKEV2_FB_V2_CALL(neg, notify_request)(neg->server->sad_handle,
                                              neg->ed,
                                              ikev2_fb_notify_request_cb,
                                              neg);
  });
}

SSH_FSM_STEP(ikev2_fb_st_i_ike_psk_request)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_i_ike_psk_result);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL({
    SSH_IKEV2_FB_V2_CALL(neg, shared_key)(neg->server->sad_handle,
                                          neg->ed,
                                          TRUE,
                                          ikev2_fb_find_pre_shared_key_cb,
                                          neg);
  });
}

SSH_FSM_STEP(ikev2_fb_st_i_ike_psk_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  if (neg->psk)
    {
#ifdef SSHDIST_IKE_XAUTH
      if (neg->ike_sa->hybrid_enabled)
        {
          neg->ed->ike_ed->auth_method =
            SSH_IKE_VALUES_AUTH_METH_HYBRID_I_RSA_SIGNATURES;
        }
      else
#endif /* SSHDIST_IKE_XAUTH */
        {
          neg->ed->ike_ed->auth_method =
            SSH_IKE_VALUES_AUTH_METH_PRE_SHARED_KEY;
        }
      SSH_FSM_SET_NEXT(ikev2_fb_st_i_ike_sa_request);
      return SSH_FSM_CONTINUE;
    }

#ifdef SSHDIST_IKE_CERT_AUTH
  SSH_FSM_SET_NEXT(ikev2_fb_st_i_ike_private_key_request);
#else /* SSHDIST_IKE_CERT_AUTH */
  neg->ike_error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
  SSH_FSM_SET_NEXT(ikev2_fb_st_i_ike_sa_result);
#endif /* SSHDIST_IKE_CERT_AUTH */

  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_CERT_AUTH
SSH_FSM_STEP(ikev2_fb_st_i_ike_private_key_request)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_i_ike_sa_request);

  neg->find_private_key_op = 1;

  SSH_FSM_ASYNC_CALL({
    SSH_IKEV2_FB_V2_CALL(neg, get_certificates)(
                                              neg->server->sad_handle,
                                              neg->ed,
                                              ikev2_fb_request_certificates_cb,
                                              neg);
  });

}
#endif /* SSHDIST_IKE_CERT_AUTH */


void ikev2_fb_sa_request_cb(SshIkev2Error error,
                            SshIkev2PayloadSA sa,
                            void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  if (error != SSH_IKEV2_ERROR_OK)
    {
      neg->ike_error = error;
    }
  else
    {
      neg->sav2 = sa;
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
}

SSH_FSM_STEP(ikev2_fb_st_i_ike_sa_request)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_i_ike_sa_result);

#ifdef SSHDIST_IKE_CERT_AUTH
  if (neg->private_key != NULL)
    {
      char *type;

      if (ssh_private_key_get_info(neg->private_key,
                                   SSH_PKF_KEY_TYPE, &type,
                                   SSH_PKF_END) == SSH_CRYPTO_OK)
        {
          if (strncmp(type, "if-modn", 7) == 0)
            {
              neg->ed->ike_ed->auth_method =
                SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES;
            }
          else if (strncmp(type, "dl-modp", 7) == 0)
            {
              neg->ed->ike_ed->auth_method =
                SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES;
            }
#ifdef SSHDIST_CRYPT_ECP
          else if (strcmp(type, "ec-modp") == 0)
            {
              size_t len =
                ssh_private_key_max_signature_output_len(neg->private_key);

              switch (len)
                {
                case 64:
                  neg->ed->ike_ed->auth_method =
                    SSH_IKE_VALUES_AUTH_METH_ECP_DSA_256;
                  break;
                case 96:
                  neg->ed->ike_ed->auth_method =
                    SSH_IKE_VALUES_AUTH_METH_ECP_DSA_384;
                  break;
                case 132:
                  neg->ed->ike_ed->auth_method =
                    SSH_IKE_VALUES_AUTH_METH_ECP_DSA_521;
                  break;
                default:
                  neg->ike_error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
                  return SSH_FSM_CONTINUE;
                }
            }
#endif /* SSHDIST_CRYPT_ECP */
          else
            {
              neg->ike_error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
              return SSH_FSM_CONTINUE;
            }
        }
    }
#endif /* SSHDIST_IKE_CERT_AUTH */


#ifdef SSHDIST_ISAKMP_CFG_MODE
  /* Overwrite with cfgmode attribute request, if neccessary */
  SSH_FSM_SET_NEXT(ikev2_fb_st_i_conf_request);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  if (neg->ikev1_id == NULL
      || neg->ed->ike_ed->auth_method == (int) SSH_IKE_AUTH_METHOD_ANY)
    {
      neg->ike_error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_ASYNC_CALL({
    SSH_IKEV2_FB_V2_CALL(neg, fill_ike_sa)(neg->server->sad_handle,
                                           neg->ed,
                                           ikev2_fb_sa_request_cb,
                                           neg);
  });
}

#ifdef SSHDIST_ISAKMP_CFG_MODE
SSH_FSM_STEP(ikev2_fb_st_i_conf_request)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_i_ike_sa_result);

  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL({
    SSH_IKEV2_FB_V2_CALL(neg,
                         conf_request)(neg->server->sad_handle,
                                       neg->ed,
                                       ikev2_fb_conf_cb,
                                       neg);
  });
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */

SSH_FSM_STEP(ikev2_fb_st_i_ike_sa_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

#ifdef SSHDIST_ISAKMP_CFG_MODE
  neg->ed->conf = neg->v2_conf;
  neg->v2_conf = NULL;
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  /* sub_thread is now done, wake up the main thread to start negotiation. */
  SSH_ASSERT(neg->sub_operation == NULL);

  ssh_fsm_continue(neg->thread);
  return SSH_FSM_FINISH;
}

void
ikev2_fb_i_ike_sub_thread_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  /* Free reference to fallback negotiation structure. */
  ikev2_fallback_negotiation_free(neg->fb, neg);
}

/*--------------------------------------------------------------------*/
/* Main thread states for initiator Phase-I negotiations              */
/*--------------------------------------------------------------------*/


SSH_FSM_STEP(ikev2_fb_i_p1_negotiation_start)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  /* Set initial initiator state */
  neg->ed->state = SSH_IKEV2_STATE_IKE_INIT_SA;

  /* Take a reference to fallback negotiation structure for the sub thread.
     It will be freed in the sub thread destructor. */
  IKEV2_FB_NEG_TAKE_REF(neg);

  SSH_FSM_SET_NEXT(ikev2_fb_i_p1_negotiation_negotiate);
  ssh_fsm_thread_init(neg->fb->fsm, neg->sub_thread,
                      ikev2_fb_st_i_ike_id_request,
                      NULL_FNPTR,
                      ikev2_fb_i_ike_sub_thread_destructor, neg);
  return SSH_FSM_CONTINUE;
}

static void
ikev2_fb_i_ike_negotiation_cb(SshIkeNotifyMessageType error,
                              SshIkeNegotiation negotiation,
                              void *callback_context)
{
  SshIkev2FbNegotiation neg = callback_context;
  SshIkeStatisticsStruct stats;

  SSH_DEBUG(SSH_D_LOWOK, ("Connect IKE done callback, status %s (neg %p)",
                          ssh_ike_error_code_to_string(error), neg));

  if (error != SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
    {
      neg->ike_error = ikev2_fb_v1_notify_message_type_to_v2_error_code(error);
      neg->v1_error = error;
      SSH_ASSERT(neg->ike_error != SSH_IKEV2_ERROR_OK);
    }

  if (neg->p1_info == NULL)
    goto error;

  if (neg->ed && neg->ed->ike_ed)
    {
      /* Store identities, algorithms and IKE responder SPI into IKEv2
         Exchange. They may be needed at the policy manager. */
      neg->ed->ike_ed->id_i =
        ikev2_fb_idv1_to_idv2(neg->ed,
                              neg->p1_info->this_end_is_initiator
                              ? neg->p1_info->local_id
                              : neg->p1_info->remote_id);
      neg->ed->ike_ed->id_r =
        ikev2_fb_idv1_to_idv2(neg->ed,
                              neg->p1_info->this_end_is_initiator
                              ? neg->p1_info->remote_id
                              : neg->p1_info->local_id);
      neg->ike_sa->last_input_stamp = ssh_time();

      /* Convert IKEv1 algorithm names to IKEv2 format. */
      if (ssh_ike_isakmp_sa_statistics(neg->ike_sa->v1_sa, &stats)
          == SSH_IKE_ERROR_OK)
        {
          SshIkev2TransformID id;
          const unsigned char *encr_name;
          long number;

          number = ssh_find_keyword_number(
                                   ssh_ike_encryption_algorithms,
                                   ssh_csstr(stats.encryption_algorithm_name));

          id = ikev2_fb_v1_encr_id_to_v2_id(number);

          /* Include the key length attribute for variable key
             length ciphers */
          encr_name = stats.encryption_algorithm_name;
          if (!ikev2_fb_cipher_is_fixed_key_length(encr_name))
            id |= (stats.encryption_key_length * 8) << 16;

          neg->ed->ike_sa->encrypt_algorithm = (unsigned char *)
            ssh_find_keyword_name(ssh_ikev2_encr_algorithms, id);

          number =
            ssh_find_keyword_number(ssh_ike_hmac_prf_algorithms,
                                    ssh_csstr(stats.prf_algorithm_name));
          neg->ed->ike_sa->prf_algorithm = (unsigned char *)
            ssh_find_keyword_name(ssh_ikev2_prf_algorithms,
                                  ikev2_fb_v1_hash_id_to_v2_prf_id(number));

          number =
            ssh_find_keyword_number(ssh_ike_hash_algorithms,
                                    ssh_csstr(stats.hash_algorithm_name));
          neg->ed->ike_sa->mac_algorithm = (unsigned char *)
            ssh_find_keyword_name(ssh_ikev2_mac_algorithms,
                                  ikev2_fb_v1_hash_id_to_v2_integ_id(number));


          if (neg->ed->ike_sa->encrypt_algorithm == NULL ||
              neg->ed->ike_sa->prf_algorithm == NULL ||
              neg->ed->ike_sa->mac_algorithm == NULL)
            {
              if (neg->v1_error == SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
                neg->ike_error = SSH_IKEV2_ERROR_INVALID_SYNTAX;
              goto error;
            }
        }
      else
        {
          if (neg->v1_error == SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
            neg->ike_error = SSH_IKEV2_ERROR_INVALID_SYNTAX;
          goto error;
        }
      SSH_ASSERT(memcmp(neg->ed->ike_sa->ike_spi_i,
                        neg->p1_info->cookies->initiator_cookie,
                        sizeof(neg->ed->ike_sa->ike_spi_i)) == 0);

      /* Set the IKEv2 responder SPI from the IKEv1 cookie
         (for logging purposes) */
      memcpy(neg->ed->ike_sa->ike_spi_r,
             neg->p1_info->cookies->responder_cookie,
             sizeof(neg->ed->ike_sa->ike_spi_r));
    }

  /* Now we have collected all the information needed. In case of
     error we'll clear the v1_sa to indicate this ikev2 fallback sa
     should not be cleared at isakmp-sa-freed processing, but at the
     negotiation result state. */
  if (error != SSH_IKE_NOTIFY_MESSAGE_CONNECTED && !neg->aborted)
    {
      neg->ike_sa->v1_sa = NULL;
    }

  if (SSH_FSM_THREAD_EXISTS(neg->thread)
      && !SSH_FSM_IS_THREAD_DONE(neg->thread))
    ssh_fsm_continue(neg->thread);

  SSH_ASSERT(neg->ike_sa != NULL);

  /* Free the reference to fallback negotiation. */
  ikev2_fallback_negotiation_free(neg->fb, neg);

  return;

 error:

  /* On error, call the completion callbacks here, and kill
     the thread, as otherwise it would be aborted before
     reaching the ikev2_fb_i_p1_negotiation_result state */

  SSH_DEBUG(SSH_D_LOWOK, ("IKE negotiation error %d (neg %p)",
                          neg->ike_error, neg));

  SSH_ASSERT(neg->ike_error != SSH_IKEV2_ERROR_OK);

  if (!neg->aborted)
    {
      SSH_ASSERT(neg->ed != NULL);
      if (neg->ike_sa)
        {
          /* Inform the policy manager the Phase-I negotiation is completed */
          SSH_IKEV2_FB_V2_NOTIFY(neg, ike_sa_done)(neg->server->sad_handle,
                                                   neg->ed,
                                                   neg->ike_error);
          SSH_IKEV2_FB_LOG_V1_ERROR(neg->v1_error);
        }

      /* Make the completion callback */
      if (neg->ed->callback)
        (*neg->ed->callback)(neg->server->sad_handle,
                             neg->ike_sa,
                             neg->ed,
                             neg->ike_error);
      neg->ed->callback = NULL_FNPTR;

      if (neg->ike_sa)
        {
          if (neg->p1_info)
            neg->p1_info->policy_manager_data = NULL;

          neg->ike_sa->v1_sa = NULL;
          SSH_IKEV2_FB_V2_NOTIFY(neg, ike_sa_delete)
            (neg->server->sad_handle, neg->ike_sa, NULL_FNPTR, NULL);
        }

      /* Kill thread */
      if (neg->ed->ipsec_ed &&
          (neg->ed->ipsec_ed->flags & SSH_IKEV2_IPSEC_OPERATION_REGISTERED))
        {
          ssh_operation_unregister_no_free(
                  neg->ed->ipsec_ed->operation_handle);
          neg->ed->ipsec_ed->flags &= ~SSH_IKEV2_IPSEC_OPERATION_REGISTERED;
        }
      if (neg->ed->info_ed &&
          (neg->ed->info_ed->flags & SSH_IKEV2_INFO_OPERATION_REGISTERED))
        {
          ssh_operation_unregister_no_free(neg->ed->info_ed->operation_handle);
          neg->ed->info_ed->flags &= ~SSH_IKEV2_INFO_OPERATION_REGISTERED;
        }
    }

  if (SSH_FSM_THREAD_EXISTS(neg->thread)
      && !SSH_FSM_IS_THREAD_DONE(neg->thread)
      && !SSH_FSM_IS_THREAD_RUNNING(neg->thread))
    ssh_fsm_uninit_thread(neg->thread);

  SSH_ASSERT(neg->ike_sa != NULL);

  /* Free the reference to fallback negotiation. */
  ikev2_fallback_negotiation_free(neg->fb, neg);
}

SSH_FSM_STEP(ikev2_fb_i_p1_negotiation_negotiate)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;
  unsigned char p1_addr[SSH_IP_ADDR_STRING_SIZE], p1_port[8];
  SshIkePayloadSA p1_proposal;
  int i;
  SshUInt32 connect_flags;
  SshIkeAttributeAuthMethValues auth_method;
  SshIkeErrorCode ret;

  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    {
      SSH_FSM_SET_NEXT(ikev2_fb_i_p1_negotiation_result);
      return SSH_FSM_CONTINUE;
    }

  if (neg->sav2 == NULL)
    return SSH_FSM_SUSPENDED;

  SSH_FSM_SET_NEXT(ikev2_fb_i_p1_negotiation_result);

  ssh_ipaddr_print(neg->ed->ike_sa->remote_ip, p1_addr, sizeof(p1_addr));
  ssh_snprintf(ssh_sstr(p1_port), sizeof(p1_port), "%d",
               neg->ed->ike_sa->remote_port);

  auth_method = neg->ed->ike_ed->auth_method;

#ifdef SSHDIST_IKE_XAUTH
  if (neg->ike_sa->xauth_enabled)
    {
      switch (neg->ed->ike_ed->auth_method)
        {
        case SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES:
          auth_method = SSH_IKE_VALUES_AUTH_METH_XAUTH_I_DSS_SIGNATURES;
          break;
        case SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES:
          auth_method = SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_SIGNATURES;
          break;
        case SSH_IKE_VALUES_AUTH_METH_PRE_SHARED_KEY:
          auth_method = SSH_IKE_VALUES_AUTH_METH_XAUTH_I_PRE_SHARED;
          break;
        default:
          break;
        }
    }
#endif /* SSHDIST_IKE_XAUTH */

  if ((p1_proposal = ikev2_fb_sav2_to_sav1(neg->sav2,
                                           auth_method,
                                           neg->ed->ike_ed->sa_life_seconds,
                                           0L, FALSE, 0L, 0L,
                                           0, NULL, 0))
      == NULL)
    {
      neg->ike_error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
      return SSH_FSM_CONTINUE;
    }

  for (i = 0; i < neg->sav2->number_of_transforms_used; i++)
    {
      if (neg->sav2->transforms[i].type == SSH_IKEV2_TRANSFORM_TYPE_D_H)
        {
          neg->ed->ike_ed->group_number = neg->sav2->transforms[i].id;
          break;
        }
    }

  /* Free and zero it, QM will reuse this. */
  ssh_ikev2_sa_free(neg->server->sad_handle, neg->sav2);
  neg->sav2 = NULL;

  if (neg->ed->ike_ed->exchange_type == SSH_IKE_XCHG_TYPE_AGGR)
    connect_flags = SSH_IKE_IKE_FLAGS_AGGR_ENCRYPT_LAST_PACKET;
  else
    connect_flags = SSH_IKE_IKE_FLAGS_MAIN_ALLOW_CLEAR_TEXT_CERTS;

  if (neg->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_START_WITH_NAT_T)
    connect_flags |= SSH_IKE_FLAGS_START_WITH_NAT_T;

  /* Check for initial contact, but do not send it in aggressive mode */
  if (neg->initial_contact &&
      neg->ed->ike_ed->exchange_type !=  SSH_IKE_XCHG_TYPE_AGGR)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Sending Initial Contact notification"));
      connect_flags |= SSH_IKE_IKE_FLAGS_SEND_INITIAL_CONTACT;
    }

  /* Take a reference to fallback negotiation for the isakmp library.
     It will be freed in ikev2_fb_i_ike_negotiation_cb(). */
  IKEV2_FB_NEG_TAKE_REF(neg);

  /* Mark that isakmp library IKE SA has been allocated */
  neg->ikev1_sa_unallocated = 0;

  ret = ssh_ike_connect((SshIkeServerContext)neg->server,
                        &neg->ed->ike_sa->v1_sa,
                        p1_addr, p1_port,
                        neg->ikev1_id,
                        p1_proposal,
                        neg->ed->ike_ed->exchange_type,
                        neg->ed->ike_sa->ike_spi_i,
                        neg->ike_sa,
                        connect_flags,
                        ikev2_fb_i_ike_negotiation_cb,
                        neg);

  if (ret != SSH_IKE_ERROR_OK)
    {
      /* Free the reference to fallback negotiation. */
      ikev2_fallback_negotiation_free(neg->fb, neg);

      ssh_ike_free_sa_payload(p1_proposal);
      SSH_DEBUG(SSH_D_ERROR,
                ("IKE SA creation failed immediately: error %d", ret));

      /* If neg->ike_error was not already marked with correct error code
         despite the failure, update it now. */
      if (neg->ike_error == (int) SSH_IKE_ERROR_OK)
        {
          neg->ike_error
              = ikev2_fb_v1_notify_message_type_to_v2_error_code((int)ret);
        }

      return SSH_FSM_CONTINUE;
    }
  else
    {
      neg->ikev1_id = NULL;
      return SSH_FSM_SUSPENDED;
    }
}

SSH_FSM_STEP(ikev2_fb_i_p1_negotiation_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_DEBUG(SSH_D_MIDSTART, ("Phase I negotiation result"));

  if (neg->aborted)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Phase I negotiation was aborted (neg %p)",
                              neg));
      return SSH_FSM_FINISH;
    }

  if (neg->ike_sa)
    {
      /* Inform the policy manager the Phase-I negotiation is completed */
      SSH_IKEV2_FB_V2_NOTIFY(neg, ike_sa_done)(neg->server->sad_handle,
                                               neg->ed,
                                               neg->ike_error);
      SSH_IKEV2_FB_LOG_V1_ERROR(neg->v1_error);
    }

  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Phase I negotiation failed, error %s (neg %p)",
                 ssh_ike_error_code_to_string((int) neg->ike_error),
                 neg));

      (*neg->ed->callback)(neg->server->sad_handle,
                           neg->ike_sa,
                           neg->ed,
                           neg->ike_error);
      neg->ed->callback = NULL_FNPTR;

      /* The policy_manager_data is invalidated after this. */
      if (neg->p1_info)
        neg->p1_info->policy_manager_data = NULL;

      SSH_IKEV2_FB_V2_NOTIFY(neg, ike_sa_delete)
        (neg->server->sad_handle, neg->ike_sa, NULL_FNPTR, NULL);

      if (neg->ed->ipsec_ed &&
          (neg->ed->ipsec_ed->flags & SSH_IKEV2_IPSEC_OPERATION_REGISTERED))
        {
          ssh_operation_unregister_no_free(
                  neg->ed->ipsec_ed->operation_handle);
          neg->ed->ipsec_ed->flags &= ~SSH_IKEV2_IPSEC_OPERATION_REGISTERED;
        }
      if (neg->ed->info_ed &&
          (neg->ed->info_ed->flags & SSH_IKEV2_INFO_OPERATION_REGISTERED))
        {
          ssh_operation_unregister_no_free(neg->ed->info_ed->operation_handle);
          neg->ed->info_ed->flags &= ~SSH_IKEV2_INFO_OPERATION_REGISTERED;
        }

      return SSH_FSM_FINISH;
    }

#ifdef SSHDIST_ISAKMP_CFG_MODE
  SSH_FSM_SET_NEXT(ikev2_fb_i_p1_check_cfg);
#else /* !SSHDIST_ISAKMP_CFG_MODE */
  SSH_FSM_SET_NEXT(ikev2_fb_i_p1_finish);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  return SSH_FSM_CONTINUE;
}


#ifdef SSHDIST_ISAKMP_CFG_MODE
SSH_FSM_STEP(ikev2_fb_i_p1_check_cfg)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;
  SshIkev2Sa ike_sa = neg->ike_sa;

  SSH_DEBUG(SSH_D_MIDSTART, ("Phase I done : check XAUTH/CFGMODE"));

  if (neg->aborted)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Phase I XAUTH/CFGMODE negotiation was aborted (neg %p)",
                 neg));
      return SSH_FSM_FINISH;
    }

  SSH_ASSERT(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR);

  SSH_DEBUG(SSH_D_LOWOK, ("cfg_pending=%d, xauth=%d, xauth_done=%d",
                          ike_sa->server_cfg_pending,
                          ike_sa->xauth_enabled,
                          ike_sa->xauth_done));

  if (IKEV2_FB_CLIENT_WAITING_CFG(ike_sa))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Registering CFG mode poll timeout"));
      neg->cfgmode_ticks = 4;
      ssh_register_timeout(neg->cfgmode_timeout, 0L, 500000L,
                           ikev2_fb_i_p1_cfg_poll_timer,
                           neg);
      SSH_FSM_SET_NEXT(ikev2_fb_i_p1_wait_cfg);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ikev2_fb_i_p1_finish);
  return SSH_FSM_CONTINUE;
}

static void ikev2_fb_i_p1_cfg_poll_timer(void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;
  SshIkev2Sa ike_sa = neg->ike_sa;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("In CFG mode poll timeout (neg %p)", neg));

  /* Allow 120 seconds for Xauth to timeout if we have evidence that
     Xauth has begun. */
  if (neg->ike_sa->xauth_started && !neg->cfgmode_ticks_updated)
    {
      neg->cfgmode_ticks = 240;
      neg->cfgmode_ticks_updated = 1;
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Xauth started before timeout, "
                                   "increasing xauth ticks paramter to %d ",
                                   neg->cfgmode_ticks));
    }
  /* If XAUTH is done but we are still waiting for the server to initiate
     CFGmode then reduce the tick count to a low value, as it there is no
     point in waiting for an extended period once XAUTH is completed */
  if (neg->ike_sa->xauth_done && neg->cfgmode_ticks > 5)
    {
      neg->cfgmode_ticks = 5;
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Xauth done, reducing ticks to %d",
                                   neg->cfgmode_ticks));
    }

  SSH_ASSERT(neg->cfgmode_ticks > 0);
  neg->cfgmode_ticks--;

  SSH_DEBUG(SSH_D_LOWOK, ("cfg_pending=%d, xauth=%d, xauth_done=%d",
                          ike_sa->server_cfg_pending,
                          ike_sa->xauth_enabled,
                          ike_sa->xauth_done));

  if (IKEV2_FB_CLIENT_WAITING_CFG(ike_sa))
    {
      if (neg->cfgmode_ticks == 0)
        {
          ssh_fsm_continue(neg->thread);
          return;
        }

      SSH_DEBUG(SSH_D_LOWOK, ("XAUTH/CFGmode not done, %d ticks remaining, "
                              "scheduling another timeout",
                              neg->cfgmode_ticks));

      ssh_register_timeout(neg->cfgmode_timeout, 0L, 500000L,
                           ikev2_fb_i_p1_cfg_poll_timer,
                           neg);
    }
  ssh_fsm_continue(neg->thread);
  return;
}

SSH_FSM_STEP(ikev2_fb_i_p1_wait_cfg)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;
  SshIkev2Sa ike_sa = neg->ike_sa;

  SSH_DEBUG(SSH_D_LOWOK, ("cfg_pending=%d, xauth=%d, xauth_done=%d",
                          ike_sa->server_cfg_pending,
                          ike_sa->xauth_enabled,
                          ike_sa->xauth_done));

  if (IKEV2_FB_CLIENT_WAITING_CFG(ike_sa))
    {
      if (neg->cfgmode_ticks != 0)
        {
          SSH_DEBUG(SSH_D_HIGHOK,
                    ("Suspending thread until CFG mode is done (neg %p)",
                     neg));
          return SSH_FSM_SUSPENDED;
        }

      if (neg->ed->ipsec_ed && ike_sa->xauth_enabled && !ike_sa->xauth_done)
        {
          if (ike_sa->hybrid_enabled)
            {
              SSH_DEBUG(SSH_D_HIGHOK, ("XAUTH not done (neg %p), "
                                       "completing Phase-I with error",
                                       neg));
              neg->ike_error = SSH_IKEV2_ERROR_TIMEOUT;
              ikev2_fb_ipsec_complete(neg);
              return SSH_FSM_FINISH;
            }

          if (ike_sa->xauth_started)
            {
              SSH_DEBUG(SSH_D_HIGHOK, ("XAUTH not finished (neg %p), "
                                       "completing Phase-I with error",
                                       neg));
              neg->ike_error = SSH_IKEV2_ERROR_TIMEOUT;
              ikev2_fb_ipsec_complete(neg);
              return SSH_FSM_FINISH;
            }
        }

      SSH_DEBUG(SSH_D_HIGHOK, ("XAUTH/CFGmode was not initiated by the "
                               "server, finishing Phase-I thread"));
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("XAUTH/CFGmode negotiation completed, "
                               "finishing Phase-I thread"));
    }

  SSH_FSM_SET_NEXT(ikev2_fb_i_p1_finish);
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */

SSH_FSM_STEP(ikev2_fb_i_p1_finish)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

#ifdef SSHDIST_ISAKMP_CFG_MODE
  if (neg->ed->conf)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Phase I done, move to CFG start (neg %p)",
                                 neg));
      SSH_FSM_SET_NEXT(ikev2_fb_i_cfg_negotiation_start);
      return SSH_FSM_CONTINUE;
    }
  else
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    {
      if (neg->ed->info_ed)
        {
          /* is DPD ? */
          if (neg->ed->info_ed->del == NULL &&
              neg->ed->info_ed->notify == NULL &&
              neg->ed->info_ed->conf == NULL)
            {
              SSH_DEBUG(SSH_D_MIDSTART,
                        ("Phase I done, skip DPD info (neg %p)", neg));

              if (neg->ed->callback != NULL_FNPTR)
                (*neg->ed->callback)(neg->server->sad_handle,
                                     neg->ike_sa, neg->ed,
                                     neg->ike_error);
              neg->ed->callback = NULL_FNPTR;

              ssh_operation_unregister_no_free(
                      neg->ed->info_ed->operation_handle);
              neg->ed->info_ed->flags &= ~SSH_IKEV2_INFO_OPERATION_REGISTERED;

              ikev2_free_exchange_data(neg->ed->ike_sa, neg->ed);
              neg->ed = NULL;
              return SSH_FSM_FINISH;
            }
          else
            {
              SSH_DEBUG(SSH_D_MIDSTART,
                        ("Phase I done, move to info start (neg %p)", neg));
              SSH_FSM_SET_NEXT(ikev2_fb_i_info_negotiation_start);
              return SSH_FSM_CONTINUE;
            }
        }
      else if (neg->ed->ipsec_ed)
        {
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
          if (neg->ed->ipsec_ed->ts_local == NULL ||
              neg->ed->ipsec_ed->ts_remote == NULL)
            {
              /* Null traffic selectors indicate that no IPsec SA is
                 wanted. */
              SSH_DEBUG(SSH_D_MIDSTART,
                        ("Phase I done, completing without QM negotiation"));
              ikev2_fb_ipsec_complete(neg);
              return SSH_FSM_FINISH;
            }
          else
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
            {
              SSH_DEBUG(SSH_D_MIDSTART,
                        ("Phase I done, move to QM start (neg %p)", neg));
              SSH_FSM_SET_NEXT(ikev2_fb_i_qm_negotiation_start);
              return SSH_FSM_CONTINUE;
            }
        }
      else
        {
          SSH_NOTREACHED;
          return SSH_FSM_FINISH;
        }
    }
}
#endif /* SSHDIST_IKEV1 */
