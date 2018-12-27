/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for INFORMATIONAL responder out.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateInfoRespOut"

/* Start INFORMATIONAL state. */
SSH_FSM_STEP(ikev2_state_info_responder_out)
{
  SshIkev2Packet packet = thread_context;

  if (packet->ed->info_ed->flags & SSH_IKEV2_INFO_EMPTY_RESPONSE)
    {
      SSH_FSM_SET_NEXT(ikev2_state_info_responder_out_encrypt);
    }
  else
    {
      SSH_FSM_SET_NEXT(ikev2_state_info_responder_out_add_delete);
    }

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


/* Add delete payload. */
SSH_FSM_STEP(ikev2_state_info_responder_out_add_delete)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_info_responder_out_add_notify);
  ikev2_info_add_delete(packet);
  return SSH_FSM_CONTINUE;
}

/* Add notify payload. */
SSH_FSM_STEP(ikev2_state_info_responder_out_add_notify)
{
  SshIkev2Packet packet = thread_context;
  SSH_FSM_SET_NEXT(ikev2_state_info_responder_out_add_conf);
  ikev2_info_add_notify(packet);
  return SSH_FSM_CONTINUE;
}

/* Add conf payload. */
SSH_FSM_STEP(ikev2_state_info_responder_out_add_conf)
{
  SshIkev2Packet packet = thread_context;

#ifdef SSHDIST_IKE_MOBIKE
  if (packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)
    /** If MOBIKE */
    SSH_FSM_SET_NEXT(ikev2_state_info_responder_out_mobike);
  else
#endif /* SSHDIST_IKE_MOBIKE */
    /** No MOBIKE */
    SSH_FSM_SET_NEXT(ikev2_state_responder_notify_vid);

  ikev2_info_add_conf(packet);
  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_MOBIKE
/** Add MOBIKE related notifies */
SSH_FSM_STEP(ikev2_state_info_responder_out_mobike)
{
 SshIkev2Packet packet = thread_context;
 SshIkev2PayloadNotify recv_notify;
 Boolean nat_source_seen, nat_destination_seen;
 SshIkev2Error error_code;

 SSH_ASSERT(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED);

 SSH_FSM_SET_NEXT(ikev2_state_responder_notify_vid);

 SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Checking cookie2 for MOBIKE enabled SA"));

 nat_source_seen = nat_destination_seen = FALSE;

 recv_notify = packet->ed->notify;
 while (recv_notify != NULL)
   {
     if (recv_notify->notify_message_type == SSH_IKEV2_NOTIFY_COOKIE2)
       {
         SshIkev2PayloadNotifyStruct notify[1];

         SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Cookie2 notify received, "
                                          "constructing reply notify"));

         /* First update the next payload pointer of the
            previous payload. */
         ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

         notify->protocol = SSH_IKEV2_PROTOCOL_ID_NONE;
         notify->notify_message_type = SSH_IKEV2_NOTIFY_COOKIE2;
         notify->spi_size = 0;
         notify->spi_data = NULL;
         notify->notification_size = recv_notify->notification_size;
         notify->notification_data = recv_notify->notification_data;

         SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N(COOKIE2)"));
         if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                                 &packet->ed->next_payload_offset) == 0)
           return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
       }
     else if (recv_notify->notify_message_type ==
              SSH_IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP)
       nat_source_seen = TRUE;
     else if (recv_notify->notify_message_type ==
              SSH_IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP)
       nat_destination_seen = TRUE;

     recv_notify = recv_notify->next_notify;
   }

 error_code = ikev2_check_no_nats_notify(packet);

 if (error_code != SSH_IKEV2_ERROR_OK)
   {
     SshIkev2PayloadNotifyStruct notify[1];

     SSH_IKEV2_DEBUG(SSH_D_FAIL, ("NO NATS payload does not match "
                                  "addresses in packet"));

     /* First update the next payload pointer of the previous payload. */
     ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

     notify->protocol = SSH_IKEV2_PROTOCOL_ID_NONE;
     notify->notify_message_type = (int) error_code;
     notify->spi_size = 0;
     notify->spi_data = NULL;
     notify->notification_size = 0;
     notify->notification_data = NULL;

     SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                     ("Adding N(UNEXPECTED_NAT_DETECTED)"));
     if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                             &packet->ed->next_payload_offset) == 0)
       return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);

     packet->ed->info_ed->unexpected_nat_detected = 1;
   }

 /* Add NAT-T discovery to the response packet if one was present in
    the request. */
 if (nat_source_seen && nat_destination_seen)
   ikev2_add_nat_discovery_notify(packet);

 return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IKE_MOBIKE */


/* Encrypt packet. */
SSH_FSM_STEP(ikev2_state_info_responder_out_encrypt)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Error err;

  /* Send packet next. */
  SSH_FSM_SET_NEXT(ikev2_state_send);

  err = ikev2_encrypt_packet(packet, packet->ed->buffer);
  ssh_buffer_free(packet->ed->buffer);
  packet->ed->buffer = NULL;

  if (err == SSH_IKEV2_ERROR_OK)
    ikev2_debug_exchange_end(packet);

  if (!(packet->ed->info_ed->flags & SSH_IKEV2_INFO_EMPTY_RESPONSE))
    {
      /* This will call
         SSH_IKEV2_POLICY_NOTIFY(packet->ed->ike_sa, responder_exchange_done)*/
      ikev2_responder_exchange_done(packet);
    }

  /* Then we destroy the exchange */
  ikev2_free_exchange_data(packet->ed->ike_sa, packet->ed);
  packet->ed = NULL;
  return ikev2_error(packet, err);
}
