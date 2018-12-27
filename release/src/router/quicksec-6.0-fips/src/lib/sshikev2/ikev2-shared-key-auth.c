/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine shared key auth utilities.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateSharedKeyAuth"

/* Complete the preshared key callback for the local (preshared or EAP)
   key. This computes the local AUTH payload. */
void ikev2_reply_cb_shared_key_auth_compute(const unsigned char *key_out,
                                            size_t key_out_len,
                                            SshIkev2Packet packet)
{
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshCryptoStatus status;
  size_t mac_len;
  SshMac mac;

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Allocating PRF(%s) with key",
                                     ike_sa->prf_algorithm),
                    key_out, key_out_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */
  /* Allocate mac. */
  status = ssh_mac_allocate(ssh_csstr(ike_sa->prf_algorithm),
                            key_out, key_out_len, &mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: mac allocate failed: %s",
                                    ssh_crypto_status_message(status)));
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      return;
    }

  ssh_mac_reset(mac);
  ssh_mac_update(mac, ssh_ustr("Key Pad for IKEv2"), 17);
  status = ssh_mac_final(mac, digest);
  ssh_mac_free(mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: mac final failed: %s",
                                    ssh_crypto_status_message(status)));
      ikev2_error(packet,  SSH_IKEV2_ERROR_CRYPTO_FAIL);
      return;
    }

  mac_len = ssh_mac_length(ssh_csstr(ike_sa->prf_algorithm));

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Output of 1st PRF(%s)",
                                     ike_sa->prf_algorithm),
                    digest, mac_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Allocate second mac. */
  status = ssh_mac_allocate(ssh_csstr(ike_sa->prf_algorithm),
                            digest, mac_len, &mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: 2nd mac allocate failed: %s",
                                    ssh_crypto_status_message(status)));
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      return;
    }

  ssh_mac_reset(mac);
  ssh_mac_update(mac, ed->data_to_signed, ed->data_to_signed_len);
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Adding data to be MACed"),
                    ed->data_to_signed, ed->data_to_signed_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */
  ssh_free(ed->data_to_signed);
  ed->data_to_signed = NULL;

  status = ssh_mac_final(mac, digest);
  ssh_mac_free(mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: 2nd mac final failed: %s",
                                    ssh_crypto_status_message(status)));
      ikev2_error(packet,  SSH_IKEV2_ERROR_CRYPTO_FAIL);
      return;
    }
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Output of 2nd PRF(%s)",
                                     ike_sa->prf_algorithm),
                    digest, mac_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  ikev2_add_auth(packet, SSH_IKEV2_AUTH_METHOD_SHARED_KEY, digest, mac_len);
}


void ikev2_reply_cb_shared_key_local(SshIkev2Error error_code,
                                     const unsigned char *key_out,
                                     size_t key_out_len,
                                     void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;
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
      ssh_free(ed->data_to_signed);
      ed->data_to_signed = NULL;

#ifdef SSHDIST_IKE_EAP_AUTH
      if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWOK,
                          ("No shared key found for initiator, "
                           "enable EAP"));

          ed->eap_state = SSH_IKEV2_EAP_STARTED;
        }
      else
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWOK,
                          ("No shared key found for responder, "
                           "attempt EAP only auth"));
        }
#else /* SSHDIST_IKE_EAP_AUTH */
      ikev2_error(packet, SSH_IKEV2_ERROR_AUTHENTICATION_FAILED);
#endif /* SSHDIST_IKE_EAP_AUTH */

      return;
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Shared key found"));
    }

  /* Compute the AUTH payload */
  ikev2_reply_cb_shared_key_auth_compute(key_out, key_out_len, packet);
}


/* Do the async operation and get the shared key from the
   other end and add AUTH payload to packet. Moves to the
   error state in case of error, otherwise simply continues
   thread, and assumes the next state is already set. */
void ikev2_add_auth_shared_key(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* OK added to the *_auth_{initiator,responder}_out_auth_shared_key. */
  SSH_IKEV2_POLICY_CALL(packet, ike_sa, shared_key)
    (ike_sa->server->sad_handle, packet->ed, TRUE,
     ikev2_reply_cb_shared_key_local, packet);
}

/* Complete the preshared key callback for the remote (preshared or EAP)
   key. This verifies the remote AUTH payload. */
void ikev2_reply_cb_shared_key_auth_verify(const unsigned char *key_out,
                                           size_t key_out_len,
                                           SshIkev2Packet packet)
{
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshCryptoStatus status;
  size_t mac_len;
  SshMac mac;

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Allocating PRF(%s) with key",
                                     ike_sa->prf_algorithm),
                    key_out, key_out_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */
  /* Allocate mac. */
  status = ssh_mac_allocate(ssh_csstr(ike_sa->prf_algorithm),
                            key_out, key_out_len, &mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: mac allocate failed: %s",
                                    ssh_crypto_status_message(status)));
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      return;
    }

  ssh_mac_reset(mac);
  ssh_mac_update(mac, ssh_custr("Key Pad for IKEv2"), 17);
  status = ssh_mac_final(mac, digest);
  ssh_mac_free(mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: mac final failed: %s",
                                    ssh_crypto_status_message(status)));
      ikev2_error(packet,  SSH_IKEV2_ERROR_CRYPTO_FAIL);
      return;
    }

  mac_len = ssh_mac_length(ssh_csstr(ike_sa->prf_algorithm));

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Output of 1st PRF(%s)",
                                     ike_sa->prf_algorithm),
                    digest, mac_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Allocate second mac. */
  status = ssh_mac_allocate(ssh_csstr(ike_sa->prf_algorithm),
                            digest, mac_len, &mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: 2nd mac allocate failed: %s",
                              ssh_crypto_status_message(status)));
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      return;
    }

  ssh_mac_reset(mac);
  ssh_mac_update(mac, ed->data_to_signed, ed->data_to_signed_len);
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Adding data to be MACed"),
                    ed->data_to_signed, ed->data_to_signed_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */
  ssh_free(ed->data_to_signed);
  ed->data_to_signed = NULL;

  status = ssh_mac_final(mac, digest);
  ssh_mac_free(mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: 2nd mac final failed: %s",
                                    ssh_crypto_status_message(status)));
      ikev2_error(packet,  SSH_IKEV2_ERROR_CRYPTO_FAIL);
      return;
    }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Output of 2nd PRF(%s)",
                                     ike_sa->prf_algorithm),
                    digest, mac_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */


#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (packet->ed->ike_ed->first_auth_done)
    {
      if (mac_len != ed->second_auth_remote->authentication_size ||
          memcmp(digest,
                 ed->second_auth_remote->authentication_data,
                 mac_len) != 0)
        {
          SSH_IKEV2_DEBUG(SSH_D_FAIL,
                          ("Error: Second Auth payload contents does "
                           "not match"));
          ikev2_error(packet, SSH_IKEV2_ERROR_AUTHENTICATION_FAILED);
          return;
        }
    }
  else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
    {
      if (mac_len != ed->auth_remote->authentication_size ||
          memcmp(digest, ed->auth_remote->authentication_data, mac_len) != 0)
        {
          SSH_IKEV2_DEBUG(SSH_D_FAIL,
                          ("Error: Auth payload contents does not match"));
          ikev2_error(packet, SSH_IKEV2_ERROR_AUTHENTICATION_FAILED);
          return;
        }
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      packet->ed->ike_ed->first_auth_verified = 1;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
    }

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Auth payload ok"));
}

void ikev2_reply_cb_shared_key_remote(SshIkev2Error error_code,
                                      const unsigned char *key_out,
                                      size_t key_out_len,
                                      void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;

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
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Authentication failed, no key found "
                                   "when verifying AUTH payload "));
      ssh_free(ed->data_to_signed);
      ed->data_to_signed = NULL;
      ikev2_error(packet, SSH_IKEV2_ERROR_AUTHENTICATION_FAILED);
      return;
    }

  /* Verify the remote AUTH payload */
  ikev2_reply_cb_shared_key_auth_verify(key_out, key_out_len, packet);
}

/* Check that the auth payload is valid. */
void ikev2_check_auth_shared_key(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* OK added to the *_auth_{initiator,responder}_in_shared_key. */
  SSH_IKEV2_POLICY_CALL(packet, ike_sa, shared_key)
    (ike_sa->server->sad_handle, packet->ed, FALSE,
     ikev2_reply_cb_shared_key_remote, packet);
}
