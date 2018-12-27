/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateAuthInitIn"

#ifdef SSHDIST_IKE_EAP_AUTH
#ifdef SSH_IKEV2_MULTIPLE_AUTH

/* Initiator side IKE AUTH packet in. */
SSH_FSM_STEP(ikev2_state_second_auth_initiator_in)
{
  SshIkev2Packet packet = thread_context;

  if (packet->ed->ike_ed->second_auth_remote == NULL)
    {
      /** No AUTH payload,  */
      SSH_FSM_SET_NEXT(ikev2_state_second_auth_initiator_in_eap);
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                      ("No AUTH-payload, this packet is part of"
                       "second EAP-authentication"));
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("State = AUTH_EAP"));
      packet->ed->state = SSH_IKEV2_STATE_IKE_AUTH_EAP;
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                      ("AUTH-payload found, this is the last packet"
                       "in the second EAP-authentication"));
      SSH_FSM_SET_NEXT(ikev2_state_second_auth_initiator_in_check_auth);
    }

  ikev2_process_notify(packet);
  return SSH_FSM_CONTINUE;
}

/* Initiator side IKE SA INIT packet, check if we have AUTH
   payload, and its type. */
SSH_FSM_STEP(ikev2_state_second_auth_initiator_in_check_auth)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;

  ed->data_to_signed =
    ikev2_auth_data(packet, FALSE, TRUE, FALSE, &ed->data_to_signed_len);
  if (ed->data_to_signed == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating data_to_signed"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  switch (packet->ed->ike_ed->second_auth_remote->auth_method)
    {
    case SSH_IKEV2_AUTH_METHOD_SHARED_KEY:
      /** Auth_method == SHARED_KEY. */
      SSH_FSM_SET_NEXT(ikev2_state_second_auth_initiator_in_shared_key);
      break;
    default:
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Error: Invalid second auth_method type : %d",
                       packet->ed->ike_ed->auth_remote->auth_method));
      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
      break;
    }
  return SSH_FSM_CONTINUE;
}

/* Verify shared key AUTH payload. */
SSH_FSM_STEP(ikev2_state_second_auth_initiator_in_shared_key)
{
  SshIkev2Packet packet = thread_context;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Verify second EAP AUTH payload"));
  SSH_FSM_SET_NEXT(ikev2_state_second_auth_initiator_in_eap);

  SSH_FSM_ASYNC_CALL(ikev2_check_auth_eap(packet));
}

/* Check for EAP payload. */
SSH_FSM_STEP(ikev2_state_second_auth_initiator_in_eap)
{
  SshIkev2Packet packet = thread_context;

  /* If we do not have mandatory payloads, then this must be
     EAP only packet, and we simply send return EAP packet
     to the other end. */
  if (packet->ed->sa == NULL ||
      packet->ed->ipsec_ed->ts_i == NULL ||
      packet->ed->ipsec_ed->ts_r == NULL)
    {
      if (packet->ed->ipsec_ed->error != SSH_IKEV2_ERROR_OK)
        {
          /* There was error when creating the IPsec SA. */
          /** There was error code for the IPsec SA */
          SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_finish);
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Freeing up IPsec SPI"));
          SSH_IKEV2_POLICY_NOTIFY(packet->ed->ike_sa, ipsec_spi_delete)
            (packet->ed->ike_sa->server->sad_handle,
             packet->ed->ipsec_ed->spi_inbound);
          return SSH_FSM_CONTINUE;
        }
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                      ("No SAr2, TSi, or TSr so must be EAP packet"));
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("State = AUTH_EAP"));
      packet->ed->state = SSH_IKEV2_STATE_IKE_AUTH_EAP;
      /** No SA, TSi and TSr, must be EAP only packet */
      SSH_FSM_SET_NEXT(ikev2_state_second_auth_initiator_in_end);
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("State = AUTH_LAST"));
      packet->ed->state = SSH_IKEV2_STATE_IKE_AUTH_LAST;

      /** We did have SA, TSi and TSr. */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                      ("SAr2, TSi, or TSr, so this is final packet"));

      SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_sa);
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_state_second_auth_initiator_in_end)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2Packet reply_packet;

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Sending second auth EAP packet"));

  if (ikev2_transmit_window_full(ike_sa->transmit_window))
    return ikev2_error(packet, SSH_IKEV2_ERROR_WINDOW_FULL);

  /** Send next EAP packet. */
  /* SSH_FSM_SET_NEXT(ikev2_state_second_auth_initiator_out_eap); */
  reply_packet =
    ikev2_reply_packet_allocate(packet,
                                ikev2_state_second_auth_initiator_out_eap);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;
  reply_packet->exchange_type = SSH_IKEV2_EXCH_TYPE_IKE_AUTH;
  reply_packet->flags = SSH_IKEV2_PACKET_FLAG_INITIATOR;

  ikev2_transmit_window_insert(ike_sa->transmit_window, reply_packet);

  return SSH_FSM_FINISH;
}


#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#endif /* SSHDIST_IKE_EAP_AUTH */
