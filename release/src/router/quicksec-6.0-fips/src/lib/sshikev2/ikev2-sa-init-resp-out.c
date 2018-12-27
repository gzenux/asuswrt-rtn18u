/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for IKE SA INIT responder out.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshadt_intmap.h"

#define SSH_DEBUG_MODULE "SshIkev2StateSaInitRespOut"

/* Responder side IKE SA INIT packet out. Initialize. */
SSH_FSM_STEP(ikev2_state_init_responder_out)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_responder_out_sa);

  packet->ed->next_payload_offset = -1;
  packet->ed->buffer = ssh_buffer_allocate();
  if (packet->ed->buffer == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating buffer"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }
  return SSH_FSM_CONTINUE;
}

/* Add SA payload. */
SSH_FSM_STEP(ikev2_state_init_responder_out_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2PayloadTransform trans;
  SshIkev2PayloadSA sa;
  SshIkev2Error err;
  int i;

  SSH_FSM_SET_NEXT(ikev2_state_init_responder_out_dh_setup);

  sa = ssh_ikev2_sa_allocate(ike_sa->server->sad_handle);
  if (sa == NULL)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);

  for(i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
    {
      trans = packet->ed->ike_ed->ike_sa_transforms[i];
      if (trans != NULL)
        {
          err = ssh_ikev2_sa_add(sa,
                                 (SshUInt8) 0,
                                 trans->type,
                                 trans->id,
                                 trans->transform_attribute);
          if (err != SSH_IKEV2_ERROR_OK)
            {
              ssh_ikev2_sa_free(ike_sa->server->sad_handle, sa);
              return ikev2_error(packet, err);
            }
        }
    }

  sa->proposal_number = packet->ed->sa->proposal_number;
  sa->protocol_id[0] = SSH_IKEV2_PROTOCOL_ID_IKE;

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_SA);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding SAr1"));
  if (ikev2_encode_sa(packet, packet->ed->buffer, sa,
                      &packet->ed->next_payload_offset) == 0)
    {
      ssh_ikev2_sa_free(ike_sa->server->sad_handle, sa);
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }
  ssh_ikev2_sa_free(ike_sa->server->sad_handle, sa);

  return SSH_FSM_CONTINUE;
}

void
ikev2_state_init_r_out_dh_setup_cb(SshCryptoStatus status,
                                   SshPkGroupDHSecret secret,
                                   const unsigned char *exchange_buffer,
                                   size_t exchange_buffer_len,
                                   void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  if (status != SSH_CRYPTO_OK)
    {
      /* Failure. */
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: Diffie-Hellman setup failed: %s",
                                   ssh_crypto_status_message(status)));
      ikev2_error(packet, SSH_IKEV2_ERROR_CRYPTO_FAIL);
    }
  else
    {
      /* Success, add the KE payload. */
      SshIkev2PayloadKEStruct ke[1];

      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Diffie-Hellman done using group = %d",
                                       packet->ed->ike_ed->group_number));
      /* First update the next payload pointer of the previous payload. */
      ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_KE);

      /* Create KE payload. */
      ke->dh_group = packet->ed->ike_ed->group_number;
      ke->key_exchange_len = exchange_buffer_len;
      ke->key_exchange_data = (unsigned char *) exchange_buffer;

      /* Encode and add it. */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding KEr"));
      if (ikev2_encode_ke(packet, packet->ed->buffer, ke,
                          &packet->ed->next_payload_offset) == 0)
        ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);

      /* Store the secret. */
      packet->ed->ike_ed->dh_secret = secret;
    }
}

/* Do the Diffie-Hellman setup. */
SSH_FSM_STEP(ikev2_state_init_responder_out_dh_setup)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_responder_out_nonce);

  packet->ed->ike_ed->group_number =
    packet->ed->ike_ed->ike_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H]->id;

  packet->ed->ike_ed->group =
    ssh_adt_intmap_get(packet->ike_sa->server->context->group_intmap,
                       (SshUInt32) packet->ed->ike_ed->group_number);
  if (packet->ed->ike_ed->group == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Unsupported group configured in "
                       "system group = %d",
                       packet->ed->ike_ed->group_number));
      return ikev2_error(packet, SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN);
    }
  ssh_ikev2_sa_free(packet->ike_sa->server->sad_handle, packet->ed->sa);
  packet->ed->sa = NULL;

  SSH_FSM_ASYNC_CALL(
     packet->operation =
     ssh_pk_group_dh_setup_async(packet->ed->ike_ed->group,
                                 ikev2_state_init_r_out_dh_setup_cb,
                                 packet);
     );
}

/* Add nonce payload. */
SSH_FSM_STEP(ikev2_state_init_responder_out_nonce)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_responder_out_notify);

  ikev2_create_nonce_and_add(packet, &(packet->ed->ike_ed->nr));
  return SSH_FSM_CONTINUE;
}

/* Request Notify payloads and add them. */
SSH_FSM_STEP(ikev2_state_init_responder_out_notify)
{
  SshIkev2Packet packet = thread_context;

#ifdef SSHDIST_IKE_CERT_AUTH
  SSH_FSM_SET_NEXT(ikev2_state_init_responder_out_certreq);
#else /* SSHDIST_IKE_CERT_AUTH */
  SSH_FSM_SET_NEXT(ikev2_state_init_responder_out_vid);
#endif /* SSHDIST_IKE_CERT_AUTH */

  if (!(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_DISABLED) &&
      !(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T))
    ikev2_add_nat_discovery_notify(packet);

  /*  This will call
      SSH_IKEV2_POLICY_CALL(packet, ike_sa, notify_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_notify(packet));
}

#ifdef SSHDIST_IKE_CERT_AUTH
/* Request CAs and add them. */
SSH_FSM_STEP(ikev2_state_init_responder_out_certreq)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_responder_out_vid);

  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, get_cas) */
  SSH_FSM_ASYNC_CALL(ikev2_add_certreq(packet));
}
#endif /* SSHDIST_IKE_CERT_AUTH */

/* Request vendor ID payloads and add them. */
SSH_FSM_STEP(ikev2_state_init_responder_out_vid)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_responder_out_dh_agree_start);

  /*  This will call
      SSH_IKEV2_POLICY_CALL(packet, ike_sa, vendor_id_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_vid(packet));
}

/* Start the Diffie-Hellman agree from the bottom of event
   loop, so it will not slow down the process here, but so
   that it should be ready when the packet comes back here. */
SSH_FSM_STEP(ikev2_state_init_responder_out_dh_agree_start)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2Error err;

  /* Note, we might want to make this configurable later,
     i.e. do we want to start this oppurtunistic calculation
     here, or simply postpone this to the phase when the
     next packet comes in. If we do nothing here, then the
     operation will be postponed. */

  /* We start the operation in the zero timeout. Note, that
     we do not care if this succeeded or not, as if it
     didn't succeed, then we will start it again when the
     packet comes in. Note also that the ike_sa cannot be
     deletede before this has had change to run, i.e. the
     ike_sa should also be deleted using zero timeout. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                  ("Starting Diffie-Hellman setup after timeout"));
  ssh_register_timeout(packet->ed->timeout, 0, 0, ikev2_skeyseed, ike_sa);

  /* Send packet next. */
  SSH_FSM_SET_NEXT(ikev2_state_send);

  /* Now we need to make the packet ready for to be sent. */
  err = ikev2_encode_header(packet, packet->ed->buffer);
  ssh_buffer_free(packet->ed->buffer);
  packet->ed->buffer = NULL;
  if (err == SSH_IKEV2_ERROR_OK)
    {
      /* Store last packet. */
      packet->ed->ike_ed->local_ike_sa_init =
        ssh_obstack_memdup(packet->ed->obstack,
                           (packet->use_natt ?
                            packet->encoded_packet + 4 :
                            packet->encoded_packet),
                           (packet->use_natt ?
                            packet->encoded_packet_len - 4 :
                            packet->encoded_packet_len));
      if (packet->ed->ike_ed->local_ike_sa_init == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR,
                          ("Error: Out of memory copying packet"));
          return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
        }
      packet->ed->ike_ed->local_ike_sa_init_len =
        (packet->use_natt ?
         packet->encoded_packet_len - 4 :
         packet->encoded_packet_len);
    }
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("State = AUTH_1ST"));
  packet->ed->state = SSH_IKEV2_STATE_IKE_AUTH_1ST;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  /* Moving to authentication round one */
  packet->ed->ike_ed->authentication_round = 1;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  /* This will call
     SSH_IKEV2_POLICY_NOTIFY(packet->ed->ike_sa, responder_exchange_done) */
  ikev2_responder_exchange_done(packet);

  /* The exchange data is stored in the ike_sa->initial_ed,
     so no need to keep it in the packet. */
  ikev2_free_exchange_data(ike_sa, packet->ed);
  packet->ed = NULL;
  return ikev2_error(packet, err);
}
