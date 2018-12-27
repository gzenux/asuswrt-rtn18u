/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine EAP auth utilities.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateEapAuth"

#ifdef SSHDIST_IKE_EAP_AUTH
void ikev2_reply_cb_eap_shared_key_local(SshIkev2Error error_code,
                                         const unsigned char *key_out,
                                         size_t key_out_len,
                                         void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: shared_key failed: %d",
                                   error_code));
      ikev2_error(packet, error_code);
      return;
    }

  if (key_out == NULL)
    {
      if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("EAP done, using sk_pi key"));
          key_out = ike_sa->sk_pi;
        }
      else
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("EAP done, using sk_pr key"));
          key_out = ike_sa->sk_pr;
        }
      key_out_len = ike_sa->sk_p_len;
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Shared key found"));
    }

  /* Compute the AUTH payload */
  ikev2_reply_cb_shared_key_auth_compute(key_out, key_out_len, packet);
}

/* Do the async operation and get the EAP shared key from
   the other end and add AUTH payload to packet. Moves to
   the error state in case of error, otherwise simply
   continues thread, and assumes the next state is already
   set. Sets the eap_enabled to true, if we cannot find key
   for the other end. */
void ikev2_add_auth_eap(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* OK, Added to the auth_{initiator,responder}_out_auth_eap */
  SSH_IKEV2_POLICY_CALL(packet, ike_sa, eap_shared_key)
    (ike_sa->server->sad_handle, packet->ed,
     ikev2_reply_cb_eap_shared_key_local, packet);
}

void ikev2_reply_cb_eap(SshIkev2Error error_code,
                        const unsigned char *eap_data,
                        size_t eap_size,
                        void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2PayloadEapStruct eap[1];

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: eap failed: %d", error_code));
      ikev2_error(packet, error_code);
      return;
    }

  if (eap_data == NULL)
    {
      /* This means that the EAP is ready, so we can continue
         the normal process. */
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("No more EAP packets, we are finished"));

      packet->ed->ike_ed->eap_state = SSH_IKEV2_EAP_DONE;
      return;
    }

  /* Fill in the eap payload. */
  eap->eap_data = (unsigned char *) eap_data;
  eap->eap_size = eap_size;

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_EAP);

  /* Encode eap payload and add it. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding EAP"));
  if (ikev2_encode_eap(packet, packet->ed->buffer, eap,
                       &packet->ed->next_payload_offset) == 0)
    ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
  return;
}

/* Do async operation to request EAP payload and add it to
   the outgoing packet. Moves to the error state in case of
   error, otherwise simply continues thread, and assumes the
   next state is already set. */
void ikev2_add_eap(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* OK, Added to the auth_{initiator,responder}_out_eap */
  SSH_IKEV2_POLICY_CALL(packet, ike_sa, eap_request)
    (ike_sa->server->sad_handle, packet->ed,
     ikev2_reply_cb_eap, packet);
}

void ikev2_reply_cb_eap_shared_key_remote(SshIkev2Error error_code,
                                          const unsigned char *key_out,
                                          size_t key_out_len,
                                          void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: shared_key failed: %d",
                                   error_code));
      ikev2_error(packet, error_code);
      return;
    }

  if (key_out == NULL)
    {
      if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
        {
          key_out = ike_sa->sk_pr;
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("EAP done, using sk_pr key"));
        }
      else
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("EAP done, using sk_pi key"));
          key_out = ike_sa->sk_pi;
        }
      key_out_len = ike_sa->sk_p_len;
    }

  /* Verify the remote AUTH payload */
  ikev2_reply_cb_shared_key_auth_verify(key_out, key_out_len, packet);
}

/* Check that the auth payload is valid. */
void ikev2_check_auth_eap(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* OK, Added to the auth_{initiator,responder}_in_shared_key */
  SSH_IKEV2_POLICY_CALL(packet, ike_sa, eap_shared_key)
    (ike_sa->server->sad_handle, packet->ed,
     ikev2_reply_cb_eap_shared_key_remote, packet);
}

#endif /* SSHDIST_IKE_EAP_AUTH */
