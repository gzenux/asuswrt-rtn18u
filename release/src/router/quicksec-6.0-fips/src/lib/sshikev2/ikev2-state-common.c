/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine utility functions.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshadt_intmap.h"

#define SSH_DEBUG_MODULE "SshIkev2StateUtils"

/* Create nonce payload and add it. */
void
ikev2_create_nonce_and_add(SshIkev2Packet packet,
                           SshIkev2PayloadNonce *return_nonce)
{
  SshIkev2PayloadNonce nonce;
  int i;

  if (*return_nonce == NULL)
    {
      /* Create nonce payload. */
      nonce = ssh_obstack_alloc(packet->ed->obstack, sizeof(*nonce));
      if (nonce == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR,
                          ("Error: Out of memory allocating nonce"));
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return;
        }

      nonce->nonce_size = SSH_IKEV2_NONCE_SIZE;
      nonce->nonce_data =
        ssh_obstack_alloc_unaligned(packet->ed->obstack, nonce->nonce_size);
      if (nonce->nonce_data == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR,
                          ("Error: Out of memory allocating nonce_data"));
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return;
        }

      for(i = 0; i < nonce->nonce_size; i++)
        nonce->nonce_data[i] = ssh_random_get_byte();
      *return_nonce = nonce;
    }
  else
    {
      nonce = *return_nonce;
    }

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NONCE);

  /* Add the nonce payload. */
  /* Encode and add it. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding NONCE"));
  if (ikev2_encode_nonce(packet, packet->ed->buffer, nonce,
                         &packet->ed->next_payload_offset) == 0)
    {
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      return;
    }
  return;
}

/* Verifies nonce payload is ok and stores it given
   location. Sets thread to error state on error.  */
void ikev2_check_nonce(SshIkev2Packet packet,
                       SshIkev2PayloadNonce *nonce)
{
  if (*nonce != NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Duplicate NONCE"));

      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_INVALID_NEXT_PAYLOAD,
                  "Duplicate nonce in payload");

      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
      return;
    }
  *nonce = packet->ed->nonce;
  packet->ed->nonce = NULL;
}

/* Add the notifies to the packet. */
void ikev2_reply_cb_notify_request(SshIkev2Error error_code,
                                   SshIkev2ProtocolIdentifiers protocol_id,
                                   unsigned char *spi,
                                   size_t spi_size,
                                   SshIkev2NotifyMessageType
                                   notify_message_type,
                                   unsigned char *notification_data,
                                   size_t notification_data_size,
                                   void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2PayloadNotifyStruct notify[1];

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      packet->operation = NULL;
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: notify request failed: %d",
                                   error_code));
      SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
      ikev2_error(packet, error_code);
      return;
    }

  if (notify_message_type == 0)
    {
      packet->operation = NULL;
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("No more notifies"));
      SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
      return;
    }

  if (notify_message_type == SSH_IKEV2_NOTIFY_SET_WINDOW_SIZE)
    {
      if (ikev2_receive_window_set_size(
                  packet->ike_sa->receive_window,
                  SSH_GET_32BIT(notification_data))
          != SSH_IKEV2_ERROR_OK)
        {
          SSH_IKEV2_DEBUG(SSH_D_FAIL,
                          ("Can not configure receive window, "
                           "ignoring window size notification from client"));
          return;
        }
    }

#ifdef SSHDIST_IKE_MOBIKE
  if (notify_message_type == SSH_IKEV2_NOTIFY_MOBIKE_SUPPORTED &&
      packet->ed->state == SSH_IKEV2_STATE_IKE_AUTH_LAST &&
      !(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    {
      SshIkev2PayloadNotify peer_notify;

      /* Check if we received a MOBIKE enabled notify from the initiator */
      for (peer_notify = packet->ed->notify; peer_notify;
           peer_notify = peer_notify->next_notify)
        {
          if (peer_notify->notify_message_type ==
              SSH_IKEV2_NOTIFY_MOBIKE_SUPPORTED)
            {
              SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                              ("Enabling MOBIKE for responder IKE SA"));
              packet->ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED;
              break;
            }
        }
    }
#endif /* SSHDIST_IKE_MOBIKE */

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Notify from policymanager = %d",
                                   notify_message_type));
  /* Fill in the notify payload. */
  notify->protocol = protocol_id;
  notify->notify_message_type = notify_message_type;
  notify->spi_size = spi_size;
  notify->spi_data = spi;
  notify->notification_size = notification_data_size;
  notify->notification_data = notification_data;

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  /* Encode notify payload and add it. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N"));
  if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                          &packet->ed->next_payload_offset) == 0)
    {
      /* Note, that we do not yet continue the thread, as
         there will be more calls to this function, but we
         have already set the state to be error state. */
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }
}

/* Do async operation to request Notify payloads and add
   them to the outgoing packet. Moves to the error state in
   case of error, otherwise simply continues thread, and
   assumes the next state is already set. */
void ikev2_add_notify(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* OK, added to the {init,(second_)?auth,child,rekey}_{i,r}_out_notify */
  SSH_IKEV2_POLICY_CALL(packet, ike_sa, notify_request)
    (ike_sa->server->sad_handle, packet->ed,
     ikev2_reply_cb_notify_request, packet);
}

/* Add vendor ID payloads to the packet. */
void ikev2_reply_cb_vid_request(SshIkev2Error error_code,
                                const unsigned char *vendor_id,
                                size_t vendor_id_len,
                                void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2PayloadVendorIDStruct vid[1];

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      packet->operation = NULL;
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: VID request failed: %d",
                                   error_code));
      SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
      ikev2_error(packet, error_code);
      return;
    }

  if (vendor_id_len == 0)
    {
      packet->operation = NULL;
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("No more VIDs"));
      SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
      return;
    }

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Got VID"));
  /* Fill in the vid payload. */
  vid->vendorid_size = vendor_id_len;
  vid->vendorid_data = (unsigned char *) vendor_id;

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_VID);

  /* Encode notify payload and add it. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding VID"));
  if (ikev2_encode_vendor_id(packet, packet->ed->buffer, vid,
                             &packet->ed->next_payload_offset) == 0)
    {
      /* Note, that we do not yet continue the thread, as
         there will be more calls to this function, but we
         have already set the state to be error state. */
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }
}

/* Do async operation to request Vendor ID payloads and add
   them to the outgoing packet. Moves to the error state in
   case of error, otherwise simply continues thread, and
   assumes the next state is already set. */
void ikev2_add_vid(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* OK, added to {init,(second_?)auth,child,rekey,info,}_{i,r}_out_vid. */
  SSH_IKEV2_POLICY_CALL(packet, ike_sa, vendor_id_request)
    (ike_sa->server->sad_handle, packet->ed,
     ikev2_reply_cb_vid_request, packet);
}

/* Add the ID payload to the packet. */
void ikev2_reply_cb_id(SshIkev2Error error_code,
                       Boolean local,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                       Boolean another_auth_follows,
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                       const SshIkev2PayloadID id_payload,
                       void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2PayloadType type;
  SshIkev2PayloadID id_copy;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: id call failed: %d", error_code));
      ikev2_error(packet, error_code);
      return;
    }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (local && another_auth_follows)
    {
      /* Check if there is another authentication round after
         authenticating this ID. Responder will require this,
         but initiator initiates it only if needed. */
      if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                          ("Preparing to initiate another authentication with "
                           "responder."));
          packet->ed->ike_ed->init_another_auth_follows = TRUE;
        }
      else
        {
          packet->ed->ike_ed->init_another_auth_follows = FALSE;
        }

      if (!(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                          ("Preparing to require another authentication from "
                           "initiator."));
          packet->ed->ike_ed->resp_require_another_auth = TRUE;
        }
      else
        {
          packet->ed->ike_ed->resp_require_another_auth = FALSE;
        }
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */


  /* Check if we got ID payload. */
  if (id_payload == NULL)
    {
      /* Nope, check if this was local ID payload, then it
         is error, but it is ok if we do not get the IDr
         in the initiator. */
      if (local)
        {
          SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: No local ID"));
          ikev2_error(packet, SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN);
        }
      else
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("No remote ID"));
        }
      return;
    }

  id_copy = ssh_obstack_alloc(packet->ed->obstack, sizeof(*id_copy));

  if (id_copy == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating id"));
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      return;
    }

  id_copy->id_type = id_payload->id_type;
  id_copy->id_reserved = id_payload->id_reserved;
  id_copy->id_data_size = id_payload->id_data_size;
  id_copy->id_data =
    ssh_obstack_memdup(packet->ed->obstack,
                       id_payload->id_data,
                       id_payload->id_data_size);
  if (id_copy->id_data == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating id_data"));
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      return;
    }

  if (local && (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    {

      type = SSH_IKEV2_PAYLOAD_TYPE_ID_I;
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      if (packet->ed->ike_ed->authentication_round == 2)
        packet->ed->ike_ed->second_id_i = id_copy;
      else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
        packet->ed->ike_ed->id_i = id_copy;
    }
  else
    {
      type = SSH_IKEV2_PAYLOAD_TYPE_ID_R;
      if (!(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
        packet->ed->ike_ed->id_r = id_copy;
    }

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, type);

  /* Encode ID payload and add it. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding ID%s",
                                   type == SSH_IKEV2_PAYLOAD_TYPE_ID_I ?
                                   "i" : "r"));

  if (type == SSH_IKEV2_PAYLOAD_TYPE_ID_I)
    {
      if (ikev2_encode_idi(packet, packet->ed->buffer, id_payload,
                           &packet->ed->next_payload_offset) == 0)
        {
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return;
        }
    }
  else
    {
      if (ikev2_encode_idr(packet, packet->ed->buffer, id_payload,
                           &packet->ed->next_payload_offset) == 0)
        {
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return;
        }
    }
}

/* Do async operation to request ID and add it to the
   outgoing packet. Moves to the error state in case of
   error, otherwise simply continues thread, and assumes the
   next state is already set. */
void ikev2_add_id(SshIkev2Packet packet, Boolean local)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* OK, added to the _auth_{i,i}_out_id{i,r}, _second_auth_i_out_id. */
  SSH_IKEV2_POLICY_CALL(packet, ike_sa, id)
    (ike_sa->server->sad_handle, packet->ed, local,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
     packet->ed->ike_ed->authentication_round,
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
     ikev2_reply_cb_id, packet);
}

/* Add the auth payload to the packet. */
void ikev2_add_auth(SshIkev2Packet packet,
                    SshIkev2AuthMethod auth_method,
                    const unsigned char *auth_data,
                    size_t auth_size)
{
  SshIkev2PayloadAuthStruct auth[1];

  /* Fill in the auth payload. */
  auth->auth_method = auth_method;
  auth->authentication_data = (unsigned char *) auth_data;
  auth->authentication_size = auth_size;

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_AUTH);

  /* Encode auth payload and add it. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding AUTH"));
  if (ikev2_encode_auth(packet, packet->ed->buffer, auth,
                        &packet->ed->next_payload_offset) == 0)
    ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
}

/* Add the Conf payload to the packet. */
void ikev2_reply_cb_conf(SshIkev2Error error_code,
                         SshIkev2PayloadConf conf_payload,
                         void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: get conf failed: %d", error_code));
      ikev2_ipsec_error(packet, error_code);
      /* Make sure the conf payload is freed in case it was given to us, even
         when there was error code. */
      if (conf_payload != NULL)
        ssh_ikev2_conf_free(ike_sa->server->sad_handle, conf_payload);
      return;
    }
  /* Check if we got CONF payload. */
  if (conf_payload == NULL)
    {
      /* Nope, so no need to add anything. */
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("No Conf payload"));
      return;
    }
  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_CONF);

  /* Encode conf payload and add it. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding CONF"));
  if (ikev2_encode_conf(packet, packet->ed->buffer, conf_payload,
                        &packet->ed->next_payload_offset) == 0)
    {
      ssh_ikev2_conf_free(ike_sa->server->sad_handle, conf_payload);
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      return;
    }
  ssh_ikev2_conf_free(ike_sa->server->sad_handle, conf_payload);
}

/* Do async operation to request conf payload and add it to
   the outgoing packet. Moves to the error state in case of
   error, otherwise simply continues thread, and assumes the
   next state is already set. */
void ikev2_add_conf(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* OK, added to (second_)?auth_{i,r}_out_cp. */
  SSH_IKEV2_POLICY_CALL(packet, ike_sa, conf_request)
    (ike_sa->server->sad_handle, packet->ed,
     ikev2_reply_cb_conf, packet);
}

/* Fill in the algorithm names in the IKEv2 SA structure,
   based on the packet->ed->ike_ed->ike_sa_transforms. */
SshIkev2Error ikev2_fill_in_algorithms(SshIkev2Sa ike_sa,
                                       SshIkev2PayloadTransform *transforms)
{
  SshUInt32 code;

  code = transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR]->transform_attribute;
  if ((code >> 16) == 0x800e)
    {
      code = code & 0xffff;
      code <<= 16;
    }
  else
    {
      code = 0;
    }
  code |= transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR]->id;
  ike_sa->encrypt_algorithm = (unsigned char *)
    ssh_find_keyword_name(ssh_ikev2_encr_algorithms, code);

  if (ike_sa->encrypt_algorithm == NULL ||
      !ssh_cipher_supported(ssh_csstr(ike_sa->encrypt_algorithm)))
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Error: Selected unsupported encryption "
                 "algorithm 0x%x %s for SA %p",
                 (int) code, ike_sa->encrypt_algorithm, ike_sa));

      ikev2_audit(ike_sa,
                  SSH_AUDIT_IKE_INVALID_TRANSFORM,
                  "Unsupported encryption algorithm selected");
      return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
    }

  code = transforms[SSH_IKEV2_TRANSFORM_TYPE_PRF]->id;
  ike_sa->prf_algorithm = (unsigned char *)
    ssh_find_keyword_name(ssh_ikev2_prf_algorithms, code);

  if (ike_sa->prf_algorithm == NULL ||
      !ssh_mac_supported(ssh_csstr(ike_sa->prf_algorithm)))
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Error: Selected unsupported PRF algorithm %d %s for SA %p",
                 (int) code, ike_sa->prf_algorithm, ike_sa));

      ikev2_audit(ike_sa,
                  SSH_AUDIT_IKE_INVALID_TRANSFORM,
                  "Unsupported PRF algorithm selected");
      return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
    }

  /* Combined mode does not have separate integrity function */
  if (transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG] != NULL)
    {
      code = transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG]->id;
      ike_sa->mac_algorithm = (unsigned char *)
          ssh_find_keyword_name(ssh_ikev2_mac_algorithms, code);

      if (ssh_cipher_is_auth_cipher(ike_sa->encrypt_algorithm))
        {
          SSH_DEBUG(
                  SSH_D_ERROR,
                  ("Error: Selected MAC algorithm %d %s for SA %p "
                   "with authenticating cipher.",
                   (int) code, ike_sa->mac_algorithm, ike_sa));

          ikev2_audit(ike_sa,
                      SSH_AUDIT_IKE_INVALID_TRANSFORM,
                      "MAC algorithm with authenticating cipher.");
          return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
        }
    }
  else
    {
      if (ssh_cipher_is_auth_cipher(ike_sa->encrypt_algorithm))
        return SSH_IKEV2_ERROR_OK;

      ike_sa->mac_algorithm = NULL;
    }

  if (ike_sa->mac_algorithm == NULL ||
      !ssh_mac_supported(ssh_csstr(ike_sa->mac_algorithm)))
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Error: Selected unsupported MAC algorithm %d %s for SA %p",
                 (int) code, ike_sa->mac_algorithm, ike_sa));

      ikev2_audit(ike_sa,
                  SSH_AUDIT_IKE_INVALID_TRANSFORM,
                  "Unsupported MAC algorithm selected");
      return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
    }

  return SSH_IKEV2_ERROR_OK;
}


/* Verify the SA payload matches the payload we sent out.
   Return TRUE if successful, otherwise return FALSE, and
   move the thread to error state. */
Boolean ikev2_verify_sa(SshIkev2Packet packet,
                        SshIkev2PayloadSA sa_payload,
                        SshIkev2PayloadSA original_sa_payload,
                        SshIkev2PayloadTransform *transforms,
                        Boolean ike)
{
  int i, j, prop;

  for(i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
    transforms[i] = NULL;

  if ((ike && sa_payload->protocol_id[0] != SSH_IKEV2_PROTOCOL_ID_IKE) ||
      (!ike && (sa_payload->protocol_id[0] != SSH_IKEV2_PROTOCOL_ID_ESP &&
                sa_payload->protocol_id[0] != SSH_IKEV2_PROTOCOL_ID_AH)))
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Error: invalid protocol_id : %d",
                       sa_payload->protocol_id[0]));
      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_INVALID_PROTOCOL_ID,
                  "Invalid protocol ID selected");

      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
      return FALSE;
    }

  if (sa_payload->number_of_transforms[0] !=
      sa_payload->number_of_transforms_used)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Error: Multiple proposals"));
      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_INVALID_PROPOSAL,
                  "Multiple proposals selected");

      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
      return FALSE;
    }

  prop = sa_payload->proposal_number;

  if (prop == 0 ||
      (prop - 1) >= SSH_IKEV2_SA_MAX_PROPOSALS ||
      original_sa_payload->proposals[prop - 1] == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                ("Error: Proposal number is invalid: %d", prop));

      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_INVALID_PROPOSAL,
                  "Selected proposal number is invalid");
      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
      return FALSE;
    }
  prop--;

  if (!ike &&
      sa_payload->protocol_id[0] != original_sa_payload->protocol_id[prop])
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Error: invalid protocol_id : %d vs %d",
                       sa_payload->protocol_id[0],
                       original_sa_payload->protocol_id[prop]));

      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_INVALID_PROTOCOL_ID,
                  "Invalid protocol ID in the SA payload");
      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
      return FALSE;
    }

  /* First we need to fill in the transforms structure. */
  for (i = 0; i < sa_payload->number_of_transforms_used; i++)
    {
      if (sa_payload->transforms[i].type >= SSH_IKEV2_TRANSFORM_TYPE_MAX)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Error: transform type invalid: %d",
                                          sa_payload->transforms[i].type));

          ikev2_audit(packet->ike_sa,
                      SSH_AUDIT_IKE_INVALID_TRANSFORM_TYPE,
                      "IKE transform type is invalid");

          ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
          return FALSE;
        }
      if (transforms[sa_payload->transforms[i].type] != NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("Error: Duplicate transform type : %d",
                           sa_payload->transforms[i].type));

          ikev2_audit(packet->ike_sa,
                      SSH_AUDIT_IKE_INVALID_TRANSFORM_TYPE,
                      "Duplicate transform type in proposal");

          ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
          return FALSE;
        }
      transforms[sa_payload->transforms[i].type] =
        &(sa_payload->transforms[i]);
    }

  /* Next we need to check that it matches our proposal. */
  for (i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
    {
      int transform_id = 0;
      int transform_attribute = 0;
      int original_transform_type_count = 0;

      /* Check that the other end returned attribute
             too. */
      if (transforms[i] != NULL)
        {
          transform_id = transforms[i]->id;
          transform_attribute = transforms[i]->transform_attribute;
        }

      for (j = 0; j < original_sa_payload->number_of_transforms[prop]; j++)
        {
          SshIkev2PayloadTransform original_transform =
              &original_sa_payload->proposals[prop][j];

          if (original_transform->type != i)
            continue;

          original_transform_type_count++;

          /* Check if we have matching proposal. */
          if (original_transform->id == transform_id &&
              original_transform->transform_attribute == transform_attribute)
            {
              /* This is matching proposal, so break out. */
              break;
            }
        }

      if (j == original_sa_payload->number_of_transforms[prop])
        {
          /* No exact match found. */

          if (original_transform_type_count != 0 ||
              transform_id != 0)
            {
              SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                              ("Error: No matching proposal found for type: "
                               "%s (%d)",
                               ssh_ikev2_transform_type_to_string(i), i));
              ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
              return FALSE;
            }
        }
      /* We did find matching proposal, or we didn't send
         proposal and other end didnt reply with proposal,
         so everything is ok. */
    }
  return TRUE;
}

/* The SA select reply processing. Fill in the transforms
   table, and proposal number. Return TRUE if successful,
   otherwise return FALSE, and move the thread to error
   stete. */
Boolean ikev2_select_sa_reply(SshIkev2Packet packet,
                              SshIkev2Error error_code,
                              SshIkev2PayloadTransform *selected_transforms,
                              SshIkev2PayloadTransform *transforms)
{
  int i;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  /* Set the error code if error. */
  if (error_code == SSH_IKEV2_ERROR_OK)
    SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("SA selected successfully"));
  else
    {
      if (packet->ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST ||
#ifdef SSHDIST_IKE_EAP_AUTH
          packet->ed->state == SSH_IKEV2_STATE_IKE_AUTH_EAP ||
#endif /* SSHDIST_IKE_EAP_AUTH */
          packet->ed->state == SSH_IKEV2_STATE_IKE_AUTH_LAST)
        ikev2_ipsec_error(packet, error_code);
      else
        ikev2_error(packet, error_code);
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: SA select failed: %d",
                                   error_code));
      return FALSE;
    }

  /* Store return data. */
  if (selected_transforms != NULL)
    {
      for(i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
        {
          transforms[i] = selected_transforms[i];
        }
    }
  return TRUE;
}

/* Find group from policy, the input group is the preferred
   group from the previous notifications if available. */
SshUInt16 ikev2_find_policy_group(SshIkev2Packet packet,
                                  SshIkev2PayloadSA sa_payload,
                                  SshUInt16 group)
{
  int i;

  if (group != 0)
    {
      /* First we need to check that group is acceptable by
         policy. */
      for(i = 0; i < sa_payload->number_of_transforms_used; i++)
        {
          if (sa_payload->transforms[i].type == SSH_IKEV2_TRANSFORM_TYPE_D_H &&
              sa_payload->transforms[i].id == group)
            return group;
        }
      /* If we didn't find matching group from our policy,
         we simply ignore the INVALID_KE_PAYLOAD sent by the
         other end. */
      if (i == sa_payload->number_of_transforms_used)
        {
          SSH_IKEV2_DEBUG(SSH_D_UNCOMMON,
                          ("N(INVALID_KE_PAYLOAD) found, with "
                           "invalid group = %d",
                           group));
          group = 0;
        }
    }
  if (group == 0)
    {
      /* Search for first group. */
      for(i = 0; i < sa_payload->number_of_transforms_used; i++)
        {
          if (sa_payload->transforms[i].type == SSH_IKEV2_TRANSFORM_TYPE_D_H)
            {
              group = sa_payload->transforms[i].id;
              SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Using first group = %d",
                                               group));
              break;
            }
        }
    }
  return group;
}

/* Find group from notifications. Returns -1 if no
   notifiation found. */
int ikev2_find_notify_group(SshIkev2Packet packet)
{
  SshIkev2PayloadNotify notify;
  SshUInt16 group;

  /* First we search for the INVALID_KE_PAYLOAD from the
     other end, and use that as group (if it is allowed). */
  notify = packet->ed->notify;
  while (notify != NULL)
    {
      if (notify->notify_message_type == SSH_IKEV2_NOTIFY_INVALID_KE_PAYLOAD &&
          notify->spi_size == 0 &&
          notify->spi_data == NULL &&
          notify->notification_size == 2)
        {
          /* Yes we do have INVALID_KE_PAYLOAD. */
          group = SSH_GET_16BIT(notify->notification_data);
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                          ("N(INVALID_KE_PAYLOAD) found, group = %d",
                           group));
          return group;
        }
      notify = notify->next_notify;
    }
  return -1;
}

/* Find group. First check for the notifications, and if no
   INVALID_KE_PAYLOAD notification is found, then take the
   first group from the sa_payload. */
SshUInt16 ikev2_find_group(SshIkev2Packet packet,
                                  SshIkev2PayloadSA sa_payload)
{
  int group;
  group = ikev2_find_notify_group(packet);
  if (group < 0)
    group = 0;
  return ikev2_find_policy_group(packet, sa_payload, (SshUInt16) group);
}

void ikev2_add_ke_dh_setup_cb(SshCryptoStatus status,
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
                                       packet->ed->ipsec_ed->group_number));
      /* First update the next payload pointer of the previous payload. */
      ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_KE);

      /* Create KE payload. */
      ke->dh_group = packet->ed->ipsec_ed->group_number;
      ke->key_exchange_len = exchange_buffer_len;
      ke->key_exchange_data = (unsigned char *) exchange_buffer;

      /* Encode and add it. */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding KEi"));
      if (ikev2_encode_ke(packet, packet->ed->buffer, ke,
                          &packet->ed->next_payload_offset) == 0)
        ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);

      /* Store the secret. */
      packet->ed->ipsec_ed->dh_secret = secret;
      packet->ed->ipsec_ed->exchange_buffer =
        ssh_obstack_memdup(packet->ed->obstack, exchange_buffer,
                           exchange_buffer_len);
      if (packet->ed->ipsec_ed->exchange_buffer == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR,
                          ("Error: Out of memory allocating "
                           "exchange_buffer"));
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
        }
      packet->ed->ipsec_ed->exchange_buffer_len = exchange_buffer_len;
    }
}

/* Add KE payload. Do the Diffie-Hellman setup for the
   selected group and add KE payload. */
void ikev2_add_ke(SshIkev2Packet packet, SshUInt16 group)
{
  packet->ed->ipsec_ed->group =
    ssh_adt_intmap_get(packet->ike_sa->server->context->group_intmap,
                       (SshUInt32) group);

  if (packet->ed->ipsec_ed->group == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Unsupported group configured in "
                       "system group = %d",
                       group));
      SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
      ikev2_error(packet, SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN);
      return;
    }
  packet->ed->ipsec_ed->group_number = group;
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Starting Diffie-Hellman using group = %d",
                                   group));
  packet->operation =
    ssh_pk_group_dh_setup_async(packet->ed->ipsec_ed->group,
                                ikev2_add_ke_dh_setup_cb,
                                packet);
}

/* IKEv2 SA Diffie-Hellman Agree. */
void ikev2_child_agree_cb(SshCryptoStatus status,
                          const unsigned char *shared_secret_buffer,
                          size_t shared_secret_buffer_len,
                          void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  if (status != SSH_CRYPTO_OK)
    {
      /* Failure. */
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: Diffie-Hellman agree failed: %s",
                                   ssh_crypto_status_message(status)));
      ikev2_error(packet, SSH_IKEV2_ERROR_CRYPTO_FAIL);
    }
  else
    {
      packet->ed->ipsec_ed->shared_secret_buffer =
        ssh_obstack_memdup(packet->ed->obstack, shared_secret_buffer,
                           shared_secret_buffer_len);
      if (packet->ed->ipsec_ed->shared_secret_buffer == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR,
                          ("Error: Out of memory allocating "
                           "exchange_buffer"));
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
        }
      packet->ed->ipsec_ed->shared_secret_buffer_len =
        shared_secret_buffer_len;
    }
}

/* Calculate the Diffie-Hellman agree for child SA. */
void ikev2_child_agree(SshIkev2Packet packet)
{
  SshPkGroupDHSecret dh_secret;

  /* We need to mark that secret is already freed before calling the async
     callback, as it might be possible that the exchange is canceled during the
     async call and that will cancel the async operation (causing dh_secret to
     be freed), and set the next state to be some error state, i.e. the
     callback will never be called. */
  dh_secret = packet->ed->ipsec_ed->dh_secret;
  packet->ed->ipsec_ed->dh_secret = NULL;

  packet->operation =
    ssh_pk_group_dh_agree_async(packet->ed->ipsec_ed->group,
                                dh_secret,
                                packet->ed->ke->key_exchange_data,
                                packet->ed->ke->key_exchange_len,
                                ikev2_child_agree_cb,
                                packet);

}

/* Check if notify_type is unrecognized. */
Boolean ikev2_unrecognized_notify(SshIkev2NotifyMessageType notify_type)
{
  switch (notify_type)
    {
      /* Error notifies */
    case SSH_IKEV2_NOTIFY_RESERVED:
    case SSH_IKEV2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD:
    case SSH_IKEV2_NOTIFY_INVALID_IKE_SPI:
    case SSH_IKEV2_NOTIFY_INVALID_MAJOR_VERSION:
    case SSH_IKEV2_NOTIFY_INVALID_SYNTAX:
    case SSH_IKEV2_NOTIFY_INVALID_MESSAGE_ID:
    case SSH_IKEV2_NOTIFY_INVALID_SPI:
    case SSH_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN:
    case SSH_IKEV2_NOTIFY_INVALID_KE_PAYLOAD:
    case SSH_IKEV2_NOTIFY_AUTHENTICATION_FAILED:
    case SSH_IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED:
    case SSH_IKEV2_NOTIFY_NO_ADDITIONAL_SAS:
    case SSH_IKEV2_NOTIFY_INTERNAL_ADDRESS_FAILURE:
    case SSH_IKEV2_NOTIFY_FAILED_CP_REQUIRED:
    case SSH_IKEV2_NOTIFY_TS_UNACCEPTABLE:
    case SSH_IKEV2_NOTIFY_INVALID_SELECTORS:
    case SSH_IKEV2_NOTIFY_UNACCEPTABLE_ADDRESS:
    case SSH_IKEV2_NOTIFY_UNEXPECTED_NAT_DETECTED:
    case SSH_IKEV2_NOTIFY_TEMPORARY_FAILURE:
    case SSH_IKEV2_NOTIFY_CHILD_SA_NOT_FOUND:

      /* Status notifies */
    case SSH_IKEV2_NOTIFY_INITIAL_CONTACT:
    case SSH_IKEV2_NOTIFY_SET_WINDOW_SIZE:
    case SSH_IKEV2_NOTIFY_ADDITIONAL_TS_POSSIBLE:
    case SSH_IKEV2_NOTIFY_IPCOMP_SUPPORTED:
    case SSH_IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP:
    case SSH_IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP:
    case SSH_IKEV2_NOTIFY_COOKIE:
    case SSH_IKEV2_NOTIFY_USE_TRANSPORT_MODE:
    case SSH_IKEV2_NOTIFY_HTTP_CERT_LOOKUP_SUPPORTED:
    case SSH_IKEV2_NOTIFY_REKEY_SA:
    case SSH_IKEV2_NOTIFY_ESP_TFC_PADDING_NOT_SUPPORTED:
    case SSH_IKEV2_NOTIFY_NON_FIRST_FRAGMENTS_ALSO:
    case SSH_IKEV2_NOTIFY_MOBIKE_SUPPORTED:
    case SSH_IKEV2_NOTIFY_ADDITIONAL_IP4_ADDRESS:
    case SSH_IKEV2_NOTIFY_ADDITIONAL_IP6_ADDRESS:
    case SSH_IKEV2_NOTIFY_NO_ADDITIONAL_ADDRESSES:
    case SSH_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES:
    case SSH_IKEV2_NOTIFY_COOKIE2:
    case SSH_IKEV2_NOTIFY_NO_NATS_ALLOWED:
    case SSH_IKEV2_NOTIFY_MULTIPLE_AUTH_SUPPORTED:
    case SSH_IKEV2_NOTIFY_ANOTHER_AUTH_FOLLOWS:
    case SSH_IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION:
      return FALSE;

    default:
      return TRUE;
    }
}

/* Parse notifies from the packet. */
void ikev2_process_notify(SshIkev2Packet packet)
{
#ifdef SSHDIST_IKE_MOBIKE
  SshIpAddrStruct additional_ip[SSH_IKEV2_SA_MAX_ADDITIONAL_ADDRESSES];
  SshUInt32 num_additional_ip = 0;
  Boolean received_mobike_address_list = FALSE;
#endif /* SSHDIST_IKE_MOBIKE */
  SshIkev2PayloadNotify notify;
  SshIkev2Error error;
  int i;

#ifdef SSHDIST_IKE_MOBIKE
  /* Add the address from header */
  num_additional_ip = 1;
  additional_ip[0] = *packet->remote_ip;
#endif /* SSHDIST_IKE_MOBIKE */

  /* Do we have notification payloads we know here. */
  notify = packet->ed->notify;
  i = packet->ed->notify_count;
  while (notify != NULL && i > 0)
    {
      switch (notify->notify_message_type)
        {
        case SSH_IKEV2_NOTIFY_INVALID_MESSAGE_ID:
          if (notify->spi_size == 0 &&
              notify->spi_data == NULL &&
              notify->notification_size == 4 &&
              notify->notification_data != NULL)
            SSH_IKEV2_DEBUG(SSH_D_UNCOMMON,
                            ("Received invalid message id %ld notify",
                             (long) SSH_GET_32BIT(notify->notification_data)));
          else
            SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                            ("Received garbaged invalid message id"));
          break;
        case SSH_IKEV2_NOTIFY_SET_WINDOW_SIZE:
          if (notify->spi_size == 0 &&
              notify->spi_data == NULL &&
              notify->notification_size == 4 &&
              notify->notification_data != NULL)
            {
              SshUInt32 window;

              window = SSH_GET_32BIT(notify->notification_data);

              SSH_IKEV2_DEBUG(SSH_D_UNCOMMON,
                              ("Received set window size to %d notify",
                               (int) window));
              error =
                  ikev2_transmit_window_set_size(
                          packet->ed->ike_sa->transmit_window,
                          window);
              if (error != SSH_IKEV2_ERROR_OK)
                {
                  ikev2_error(packet, error);
                  return;
                }
            }
          else
            SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                            ("Received garbaged window size notify"));
          break;

        case SSH_IKEV2_NOTIFY_INVALID_KE_PAYLOAD:
          if (notify->spi_size == 0 &&
              notify->spi_data == NULL &&
              notify->notification_size == 2 &&
              notify->notification_data != NULL)
            {
              packet->ed->ike_sa->dh_group =
                SSH_GET_16BIT(notify->notification_data);
              SSH_IKEV2_DEBUG(SSH_D_UNCOMMON,
                              ("Received invalid KE notify, new group = %d",
                               packet->ed->ike_sa->dh_group));
              if (packet->ed->state == SSH_IKEV2_STATE_CREATE_CHILD ||
                  packet->ed->state == SSH_IKEV2_STATE_REKEY_IKE)
                {
                  ikev2_audit(packet->ike_sa,
                              SSH_AUDIT_IKE_INVALID_NEXT_PAYLOAD,
                              "Received Invalid KE payload in IKE rekey "
                              "or create Child exchange.");

                  ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_KE_PAYLOAD);
                  packet->error_from_notify = TRUE;
                }
            }
          else
            SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                            ("Received garbaged invalid KE notify"));
          break;

#ifdef SSHDIST_IKE_MOBIKE
        case SSH_IKEV2_NOTIFY_NO_ADDITIONAL_ADDRESSES:
          received_mobike_address_list = TRUE;
          break;

        case SSH_IKEV2_NOTIFY_ADDITIONAL_IP4_ADDRESS:
        case SSH_IKEV2_NOTIFY_ADDITIONAL_IP6_ADDRESS:
          if ((packet->exchange_type == SSH_IKEV2_EXCH_TYPE_INFORMATIONAL) ||
              (packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_AUTH))
            {
              if (notify->spi_size == 0 &&
                  notify->spi_data == NULL &&
                  notify->notification_data != NULL &&
                  (notify->notification_size == 4 ||
                   notify->notification_size == 16))
                {
                  if (num_additional_ip
                      >= SSH_IKEV2_SA_MAX_ADDITIONAL_ADDRESSES)
                    break;

                  SSH_IP_DECODE(&additional_ip[num_additional_ip],
                                notify->notification_data,
                                notify->notification_size);

                  /* Skip if it is same as in the current IP. */
                  if (SSH_IP_EQUAL(&additional_ip[num_additional_ip],
                                   &additional_ip[0]))
                    {
                      SSH_DEBUG(SSH_D_MIDSTART,
                                ("Skipped errorneous additional IP address "
                                 "notify for currently used address %@",
                                 ssh_ipaddr_render,
                                 &additional_ip[num_additional_ip]));
                      break;
                    }

                  SSH_DEBUG(SSH_D_MIDSTART,
                            ("Received additional IP address "
                             "notify for address %@",
                             ssh_ipaddr_render,
                             &additional_ip[num_additional_ip]));
                  num_additional_ip++;
                  received_mobike_address_list = TRUE;
                }
              else
                SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                                ("Received garbage additional address "
                                 "notify"));
            }
          break;
#endif /* SSHDIST_IKE_MOBIKE */

#ifdef SSH_IKEV2_MULTIPLE_AUTH
        case SSH_IKEV2_NOTIFY_MULTIPLE_AUTH_SUPPORTED:
          if (((packet->ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST) &&
               !(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)) ||
              ((packet->ed->state == SSH_IKEV2_STATE_IKE_INIT_SA) &&
               (packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)))
            {
              if (notify->notify_message_type ==
                  SSH_IKEV2_NOTIFY_MULTIPLE_AUTH_SUPPORTED &&
                  notify->spi_size == 0 &&
                  notify->spi_data == NULL &&
                  notify->notification_size == 0)
                {
                  /* Peer supports IKEv2 multiple authenticatiosn */
                  SSH_IKEV2_DEBUG(SSH_D_LOWOK,
                                  ("N(MULTIPLE_AUTH_SUPPORTED) found"));
                  packet->ed->ike_ed->peer_supports_multiple_auth = 1;
                }

            }
          break;

        case SSH_IKEV2_NOTIFY_ANOTHER_AUTH_FOLLOWS:
          if (!(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
            {
              if (notify->notify_message_type ==
                  SSH_IKEV2_NOTIFY_ANOTHER_AUTH_FOLLOWS &&
                  notify->spi_size == 0 &&
                  notify->spi_data == NULL &&
                  notify->notification_size == 0)
                {
                  /* Peer supports IKEv2 multiple authenticatiosn */
                  SSH_IKEV2_DEBUG(SSH_D_LOWOK,
                                  ("N(ANOTHER_AUTH_FOLLOWS) found"));
                  packet->ed->ike_ed->second_eap_auth = 1;
                }
            }

          break;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

#ifdef SSHDIST_IKE_REDIRECT
        /* TODO clean this up, if no handling is done here */
        case SSH_IKEV2_NOTIFY_REDIRECT_SUPPORTED:
          SSH_DEBUG(SSH_D_LOWOK, ("REDIRECT_SUPPORTED received"));
          break;
        case SSH_IKEV2_NOTIFY_REDIRECTED_FROM:
          SSH_DEBUG(SSH_D_LOWOK, ("REDIRECTED_FROM received"));
          break;
        case SSH_IKEV2_NOTIFY_REDIRECT:
          SSH_DEBUG(SSH_D_LOWOK, ("REDIRECTED received"));
          break;
#endif /* SSHDIST_IKE_REDIRECT */

        case SSH_IKEV2_NOTIFY_COOKIE:
        case SSH_IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP:
        case SSH_IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP:
          /* Silently ignore status notifications we process elsewhere. */
          break;
        case SSH_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN:
        case SSH_IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED:
        case SSH_IKEV2_NOTIFY_NO_ADDITIONAL_SAS:
        case SSH_IKEV2_NOTIFY_INTERNAL_ADDRESS_FAILURE:
        case SSH_IKEV2_NOTIFY_FAILED_CP_REQUIRED:
        case SSH_IKEV2_NOTIFY_TS_UNACCEPTABLE:
        case SSH_IKEV2_NOTIFY_UNACCEPTABLE_ADDRESS:
        case SSH_IKEV2_NOTIFY_UNEXPECTED_NAT_DETECTED:
        case SSH_IKEV2_NOTIFY_TEMPORARY_FAILURE:
        case SSH_IKEV2_NOTIFY_CHILD_SA_NOT_FOUND:
          if (packet->ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST ||
#ifdef SSHDIST_IKE_EAP_AUTH
              packet->ed->state == SSH_IKEV2_STATE_IKE_AUTH_EAP ||
#endif /* SSHDIST_IKE_EAP_AUTH */
              packet->ed->state == SSH_IKEV2_STATE_IKE_AUTH_LAST)
            {
              ikev2_debug_exchange_fail_remote(packet,
                                           (int) notify->notify_message_type);
              SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                              ("Received IPsec error notify %s (%d)",
                               ssh_ikev2_notify_to_string(
                                                          notify->
                                                          notify_message_type),
                               notify->notify_message_type));
              packet->ed->ipsec_ed->error = (int) notify->notify_message_type;
              break;
            }
          /*FALLTHROUGH*/
        default:
          if (notify->notify_message_type < SSH_IKEV2_NOTIFY_INITIAL_CONTACT)
            {
              if (packet->exchange_type == SSH_IKEV2_EXCH_TYPE_INFORMATIONAL)
                {
                  /* Make sure we do not delete IKE SA when we receive notify
                     concerning IPsec SA, i.e. something that is not fatal for
                     the IKE SA itself. */
                  if (notify->notify_message_type ==
                      SSH_IKEV2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD)
                    {
                      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                                      ("Received non fatal error %s for "
                                       "IKE SA (%d)",
                                       ssh_ikev2_notify_to_string(
                                                          notify->
                                                          notify_message_type),
                                       notify->notify_message_type));
                    }
                  if (notify->notify_message_type ==
                      SSH_IKEV2_NOTIFY_INVALID_SPI ||
                      notify->notify_message_type ==
                      SSH_IKEV2_NOTIFY_INVALID_SELECTORS)
                    {
                      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                                      ("Received error %s (%d) for IPsec SA",
                                       ssh_ikev2_notify_to_string(
                                                          notify->
                                                          notify_message_type),
                                       notify->notify_message_type));
                      break;
                    }
                }

              /* Check if this is an unrecognized notify type and ignore it
                 if this is a request.

                 RFC5996 says:

                 Types in the range 0 - 16383 are intended for reporting
                 errors.  An implementation receiving a Notify payload with
                 one of these types that it does not recognize in a response
                 MUST assume that the corresponding request has failed
                 entirely.  Unrecognized error types in a request and status
                 types in a request or response MUST be ignored except that
                 they SHOULD be logged.

              */
              if (ikev2_unrecognized_notify(notify->notify_message_type)
                  && !(packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE))
                {
                  SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                                  ("Ignored unrecognized error notify %s (%d) "
                                   "in a request message",
                                   ssh_ikev2_notify_to_string(
                                                          notify->
                                                          notify_message_type),
                                   notify->notify_message_type));
                  break;
                }

              SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                              ("Received error notify %s (%d)",
                               ssh_ikev2_notify_to_string(
                                                          notify->
                                                          notify_message_type),
                               notify->notify_message_type));

              if (notify->notify_message_type)
                ikev2_error_remote(packet, (int) notify->notify_message_type);
              else
                ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
              packet->error_from_notify = TRUE;
            }
          else
            {
              SSH_IKEV2_DEBUG(SSH_D_LOWOK,
                              ("Ignored status notify %s (%d)",
                               ssh_ikev2_notify_to_string(
                                                          notify->
                                                          notify_message_type),
                               notify->notify_message_type));
            }
          break;
        }
      notify = notify->next_notify;
      i--;
    }

#ifdef SSHDIST_IKE_MOBIKE
  /* Update the list of additional IP addresses in the IKE SA */
  if (received_mobike_address_list)
    {
      SSH_ASSERT(num_additional_ip <= SSH_IKEV2_SA_MAX_ADDITIONAL_ADDRESSES);

      packet->ed->ike_sa->num_additional_ip_addresses = num_additional_ip;
      memcpy(&packet->ed->ike_sa->additional_ip_addresses, additional_ip,
             num_additional_ip * sizeof(SshIpAddrStruct));
    }

#endif /* SSHDIST_IKE_MOBIKE */
  return;
}
