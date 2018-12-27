/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateAuthInitOut"

#ifdef SSH_IKEV2_MULTIPLE_AUTH

/* Start IKE AUTH state. */
SSH_FSM_STEP(ikev2_state_second_auth_initiator_out)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_second_auth_initiator_out_id);

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

/* Add the secondary identity to the packet */
SSH_FSM_STEP(ikev2_state_second_auth_initiator_out_id)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_notify_vid_encrypt_send);

  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, id) */
  SSH_FSM_ASYNC_CALL(ikev2_add_id(packet, TRUE));
}

/* Send out EAP payload. */
SSH_FSM_STEP(ikev2_state_second_auth_initiator_out_eap)
{
  SshIkev2Packet packet = thread_context;

  packet->ed->next_payload_offset = -1;
  packet->ed->buffer = ssh_buffer_allocate();
  if (packet->ed->buffer == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating buffer"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  packet->ed->ike_ed->second_auth_remote = NULL;
  SSH_FSM_SET_NEXT(ikev2_state_second_auth_initiator_out_eap_check);

  SSH_FSM_ASYNC_CALL(ikev2_add_eap(packet));
}

/* Check if eap is done. */
SSH_FSM_STEP(ikev2_state_second_auth_initiator_out_eap_check)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;

  if (packet->ed->ike_ed->eap_state == SSH_IKEV2_EAP_DONE)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                      ("EAP is finished, move to add second AUTH(EAP)"));

      ed->data_to_signed =
        ikev2_auth_data(packet, TRUE, FALSE, TRUE, &ed->data_to_signed_len);
      if (ed->data_to_signed == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR,
                          ("Error: Out of memory allocating data_to_signed"));
          return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
        }

      /** EAP finished */
      SSH_FSM_SET_NEXT(ikev2_state_second_auth_initiator_out_auth_eap);
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("EAP still in progress, send packet"));
      /** EAP still in progress. */
      SSH_FSM_SET_NEXT(ikev2_state_notify_vid_encrypt_send);
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_state_second_auth_initiator_out_auth_eap)
{
  SshIkev2Packet packet = thread_context;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding second EAP AUTH"));
  SSH_FSM_SET_NEXT(ikev2_state_notify_vid_encrypt_send);
  SSH_FSM_ASYNC_CALL(ikev2_add_auth_eap(packet));
}

#endif /*  SSH_IKEV2_MULTIPLE_AUTH */
