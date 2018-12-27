/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for IKE SA INIT initiator out.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshadt_intmap.h"

#define SSH_DEBUG_MODULE "SshIkev2StateSaInitInitOut"

SSH_FSM_STEP(ikev2_state_init_initiator_out)
{
  SshIkev2Packet packet = thread_context;

  ikev2_debug_exchange_begin(packet);

  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_out_cookie);

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

/* Check if we have cookie from other end, and if so, add it
   to the packet. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_cookie)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadNotify notify;

  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_out_fill_sa);

  notify = packet->ed->notify;
  while (notify != NULL)
    {
      if (notify->notify_message_type == SSH_IKEV2_NOTIFY_COOKIE &&
          notify->spi_size == 0 &&
          notify->spi_data == NULL &&
          notify->notification_size != 0)
        {
          /* Yes we do have cookie. */
          break;
        }
      notify = notify->next_notify;
    }
  if (notify != NULL)
    {
      /* First update the next payload pointer of the previous payload. */
      ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

      /* Add notify payload. */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N(COOKIE)"));
      if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                              &packet->ed->next_payload_offset) == 0)
        {
          return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
        }
    }
  return SSH_FSM_CONTINUE;
}


void ikev2_reply_cb_init_initiator_fill_ike_sa(SshIkev2Error error_code,
                                               SshIkev2PayloadSA sa,
                                               void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  /* Set the error code if error. */
  ikev2_error(packet, error_code);
  if (error_code == SSH_IKEV2_ERROR_OK)
    SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("IKE SA filled successfully"));
  else
    SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: IKE SA fill failed: %d",
                                 error_code));

  packet->ed->ike_ed->sa_i = sa;
}

/* Fill in the SA payload. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_fill_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_out_sa);
  if (packet->ed->ike_ed->sa_i == NULL)
    {
      SSH_FSM_ASYNC_CALL(
                         SSH_IKEV2_POLICY_CALL(packet, ike_sa, fill_ike_sa)
                         (ike_sa->server->sad_handle, packet->ed,
                          ikev2_reply_cb_init_initiator_fill_ike_sa,
                          packet));
    }
  return SSH_FSM_CONTINUE;
}

/* Add the SA payload. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_sa)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_out_dh_setup);

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_SA);

  /* So just add SA payload. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding SAi1"));
  if (ikev2_encode_sa(packet, packet->ed->buffer, packet->ed->ike_ed->sa_i,
                      &packet->ed->next_payload_offset) == 0)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
  return SSH_FSM_CONTINUE;
}

void
ikev2_state_init_i_out_dh_setup_cb(SshCryptoStatus status,
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
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding KEi"));
      if (ikev2_encode_ke(packet, packet->ed->buffer, ke,
                          &packet->ed->next_payload_offset) == 0)
        ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);

      /* Store the secret. */
      if (packet->ed->ike_ed->dh_secret == NULL)
        {
          /* Check that we have new secret, if we are simply
             reusing the old one, no need to store it again. */
          packet->ed->ike_ed->dh_secret = secret;
          packet->ed->ike_ed->exchange_buffer =
            ssh_obstack_memdup(packet->ed->obstack, exchange_buffer,
                               exchange_buffer_len);
          if (packet->ed->ike_ed->exchange_buffer == NULL)
            {
              SSH_IKEV2_DEBUG(SSH_D_ERROR,
                              ("Error: Out of memory allocating "
                               "exchange_buffer"));
              ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
            }
          packet->ed->ike_ed->exchange_buffer_len = exchange_buffer_len;
        }
    }
}

/* Do the Diffie-Hellman setup. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_dh_setup)
{
  SshIkev2Packet packet = thread_context;
  SshUInt16 group = 0;

  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_out_nonce);

  group = ikev2_find_group(packet, packet->ed->ike_ed->sa_i);

  if (group == 0)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("No IKE group configured in policy"));

      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_INVALID_PROPOSAL,
                  "Unsupported group configured by the system");
      return ikev2_error(packet, SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN);
    }

  /* Check if we have already done DH once. */
  if (packet->ed->ike_ed->dh_secret != NULL)
    {
      if (group == packet->ed->ike_ed->group_number)
        {
          /* We have same group already, so use the old KE payload. */
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Reusing old KE payload"));
          SSH_FSM_ASYNC_CALL(
             ikev2_state_init_i_out_dh_setup_cb(SSH_CRYPTO_OK,
                                                       packet->ed->ike_ed->
                                                       dh_secret,
                                                       packet->ed->ike_ed->
                                                       exchange_buffer,
                                                       packet->ed->ike_ed->
                                                       exchange_buffer_len,
                                                       packet);
             );
        }
      /* Free the previous secret. */
      ssh_pk_group_dh_return_randomizer(packet->ed->ike_ed->group,
                                      packet->ed->ike_ed->dh_secret,
                                      packet->ed->ike_ed->exchange_buffer,
                                      packet->ed->ike_ed->exchange_buffer_len);

      packet->ed->ike_ed->dh_secret = NULL;
      packet->ed->ike_ed->exchange_buffer = NULL;
      packet->ed->ike_ed->exchange_buffer_len = 0;

      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Freeing old KE payload"));
    }
  packet->ed->ike_ed->group =
    ssh_adt_intmap_get(packet->ike_sa->server->context->group_intmap,
                       (SshUInt32) group);

  if (packet->ed->ike_ed->group == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Unsupported group configured in "
                       "system group = %d",
                       group));
      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_INVALID_PROPOSAL,
                  "Unsupported group configured by the system");

      return ikev2_error(packet, SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN);
    }
  packet->ed->ike_ed->group_number = group;
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Starting Diffie-Hellman using group = %d",
                                   group));
  SSH_FSM_ASYNC_CALL(
     packet->operation =
     ssh_pk_group_dh_setup_async(packet->ed->ike_ed->group,
                                 ikev2_state_init_i_out_dh_setup_cb,
                                 packet);
     );

}

/* Add NONCE payload. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_nonce)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_out_notify);
  ikev2_create_nonce_and_add(packet, &(packet->ed->ike_ed->ni));
  return SSH_FSM_CONTINUE;
}

/* Request Notify payloads and add them. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_notify)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_out_vid);

  if (!(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T))
    ikev2_add_nat_discovery_notify(packet);
  /*  This will call
      SSH_IKEV2_POLICY_CALL(packet, ike_sa, notify_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_notify(packet));
}

/* Request vendor ID payloads and add them. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_vid)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_out_done);
  /*  This will call
      SSH_IKEV2_POLICY_CALL(packet, ike_sa, vendor_id_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_vid(packet));
}

/* Encode packet and sent it. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_done)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Error err;

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
  return ikev2_error(packet, err);
}

