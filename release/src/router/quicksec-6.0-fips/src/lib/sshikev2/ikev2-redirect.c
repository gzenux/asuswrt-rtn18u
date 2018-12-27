/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 redirect utilities.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateRedirectOut"

#ifdef SSHDIST_IKE_REDIRECT

SshIkev2Error
ikev2_make_redirect_payload(SshIkev2Packet packet, SshBuffer buffer,
                            SshIkev2PayloadNonce nonce)
{
  SshIkev2PayloadNotifyStruct notify[1];
  size_t gw_payload_size;
  unsigned char *redirect_payload;
  size_t len;

  SSH_IKEV2_DEBUG(SSH_D_MY, ("Build REDIRECT Notify"));

  gw_payload_size = 2 + SSH_IP_ADDR_LEN(packet->ed->redirect_addr);
  redirect_payload = ssh_obstack_alloc(packet->ed->obstack,
                    gw_payload_size + (nonce != NULL ? nonce->nonce_size: 0));

  if (redirect_payload ==  NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error allocating redirect payload"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  /* GW Ident Type */
  redirect_payload[0] = SSH_IP_IS4(packet->ed->redirect_addr) ?
                                            SSH_IKEV2_REDIRECT_GW_IDENT_IPV4 :
                                            SSH_IKEV2_REDIRECT_GW_IDENT_IPV6;

  /* Add the GW Ident Len and the address */
  SSH_IP_ENCODE(packet->ed->redirect_addr, redirect_payload + 2,
                redirect_payload[1]);

  /* Add the NONCE */
  if (nonce != NULL)
    memcpy(redirect_payload + gw_payload_size,
           packet->ed->nonce->nonce_data,
           packet->ed->nonce->nonce_size);

  notify->protocol = 0;
  notify->notify_message_type = SSH_IKEV2_NOTIFY_REDIRECT;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size =
    gw_payload_size + (nonce != NULL ? nonce->nonce_size: 0);

  notify->notification_data = redirect_payload;

  SSH_IKEV2_DEBUG(SSH_D_MY, ("Adding N(REDIRECT) request"));
  len = ikev2_encode_notify(packet, buffer, notify, NULL);
  if (len == 0)
      return  SSH_IKEV2_ERROR_INVALID_SYNTAX;

  return SSH_IKEV2_ERROR_OK;
}

/* Send redirect notify out. */
SSH_FSM_STEP(ikev2_state_redirect_out)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Error err;
  SshBuffer buffer;


  buffer = ssh_buffer_allocate();
  if (buffer == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating buffer"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  err = ikev2_make_redirect_payload(packet, buffer, packet->ed->nonce);
  if (err != SSH_IKEV2_ERROR_OK)
    {
      ssh_buffer_free(buffer);
      return ikev2_error(packet, err);
    }

  packet->first_payload = SSH_IKEV2_PAYLOAD_TYPE_NOTIFY;

  /* Zero out responder SPI.*/
  memset(packet->ike_spi_r, 0, 8);

  err = ikev2_encode_header(packet, buffer);
  ssh_buffer_free(buffer);
  SSH_FSM_SET_NEXT(ikev2_state_send_and_destroy);
  SSH_IKEV2_DEBUG(SSH_D_MY,
      ("Build REDIRECT Notify finished, ikev2err %d", err));
  return ikev2_error(packet, err);
}

static void
ikev2_packet_ike_redirect_cb(SshIkev2Error error, SshIpAddr redirect_addr,
                             void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  packet->error = error;

  if (redirect_addr != NULL)
    {
      packet->ed->redirect = TRUE;
      memcpy(packet->ed->redirect_addr, redirect_addr,
             sizeof(*packet->ed->redirect_addr));
    }
}

void ikev2_check_redirect(SshIkev2Packet packet)
{

  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_IKEV2_POLICY_CALL(packet, ike_sa, ike_redirect)
    (ike_sa->server->sad_handle, packet->ed,
     ikev2_packet_ike_redirect_cb,
     packet);
}

static void ikev2_redirect_delete_old_sa(SshIkev2Error error,
                                         SshIpAddr redirect_addr,
                                         void *context)
{
  SshIkev2Packet packet = context;

  SSH_IKEV2_DEBUG(SSH_D_ERROR, ("redirect: deleting old SA..."));
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  if (error == SSH_IKEV2_ERROR_OK)
    ikev2_do_error_delete(packet, packet->ike_sa);
  else
    ikev2_error(packet, error);
}


void ikev2_redirected(SshIkev2Packet packet)
{
    /* we are letting PM handle this because we need a clean new IKE
     * negotioation which cannot be started from IKE lib */
    SSH_IKEV2_POLICY_CALL(packet, packet->ike_sa, ike_redirect)
        (packet->ike_sa->server->sad_handle, packet->ed,
         ikev2_redirect_delete_old_sa, packet);

}

#endif /* SSHDIST_IKE_REDIRECT */
