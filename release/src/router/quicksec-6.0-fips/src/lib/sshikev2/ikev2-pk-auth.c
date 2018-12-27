/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine public key auth utilities.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StatePkAuth"

#ifdef SSHDIST_IKE_CERT_AUTH
/* Add the certificate requests to the packet. */
void ikev2_reply_cb_get_cas(SshIkev2Error error_code,
                            int number_of_cas,
                            SshIkev2CertEncoding *ca_encodings,
                            const unsigned char **ca_authority_data,
                            size_t *ca_authority_size,
                            void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2PayloadCertReqStruct certreq[1];
  int i;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: Get CAs failed: %d", error_code));
      ikev2_error(packet, error_code);
      return;
    }
  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Got %d CAs", number_of_cas));

  for(i = 0; i < number_of_cas; i++)
    {
      /* Fill in the certificate request payload. */
      certreq->cert_encoding = ca_encodings[i];
      certreq->authority_size = ca_authority_size[i];
      certreq->authority_data = (unsigned char *) ca_authority_data[i];

      /* First update the next payload pointer of the previous payload. */
      ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_CERT_REQ);

      /* Encode cert request payload and add it. */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding CERTREQ"));
      if (ikev2_encode_certreq(packet, packet->ed->buffer, certreq,
                               &packet->ed->next_payload_offset) == 0)
        {
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return;
        }
    }
}

/* Do async operation to request CAs and add them to the
   outgoing packet as certificate request payloads. Moves to
   the error state in case of error, otherwise simply
   continues thread, and assumes the next state is already
   set. */
void ikev2_add_certreq(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* OK, added to the ikev2_state_auth_{responder,initiator}_out_certreq */
  SSH_IKEV2_POLICY_CALL(packet, ike_sa, get_cas)
    (ike_sa->server->sad_handle, packet->ed,
     ikev2_reply_cb_get_cas, packet);
}

/* Add the certificate payloads to the packet. */
void ikev2_reply_cb_get_certs(SshIkev2Error error_code,
                              SshPrivateKey private_key_out,
                              int number_of_certificates,
                              SshIkev2CertEncoding *cert_encs,
                              const unsigned char **certs,
                              size_t *cert_lengths,
                              void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2PayloadCertStruct cert[1];
  int i;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: Get certs failed: %d",
                                   error_code));
      ikev2_error(packet, error_code);
      return;
    }

  if (private_key_out != NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Got private key"));
      if (ssh_private_key_copy(private_key_out,
                               &packet->ed->ike_ed->private_key)
          != SSH_CRYPTO_OK)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: While copying private key"));
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return;
        }
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("No private keys"));
      packet->ed->ike_ed->private_key = NULL;
    }
  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Got %d certificates",
                                number_of_certificates));

  for(i = 0; i < number_of_certificates; i++)
    {
      /* Fill in the certificate payload. */
      cert->cert_encoding = cert_encs[i];
      cert->cert_size = cert_lengths[i];
      cert->cert_data = (unsigned char *) certs[i];

      /* First update the next payload pointer of the previous payload. */
      ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_CERT);

      /* Encode cert payload and add it. */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding CERT"));
      if (ikev2_encode_cert(packet, packet->ed->buffer, cert,
                            &packet->ed->next_payload_offset) == 0)
        {
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return;
        }
    }
}

/* Do async operation to request certififcates. Moves to the
   error state in case of error, otherwise simply continues
   thread, and assumes the next state is already set. */
void ikev2_add_certs(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* OK, added to the ikev2_state_auth_{responder,initiator}_out_cert */
  SSH_IKEV2_POLICY_CALL(packet, ike_sa, get_certificates)
    (ike_sa->server->sad_handle, packet->ed,
     ikev2_reply_cb_get_certs, packet);
}

/* Signature is ready. */
void ikev2_state_auth_sign_cb(SshCryptoStatus status,
                              const unsigned char *signature_buffer,
                              size_t signature_buffer_len,
                              void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;
  const char *type;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  ssh_free(ed->data_to_signed);
  ed->data_to_signed = NULL;

  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: private key sign failed: %s",
                                   ssh_crypto_status_message(status)));
      ikev2_error(packet, SSH_IKEV2_ERROR_CRYPTO_FAIL);
      return;
    }

  if ((status = ssh_private_key_get_info(ed->private_key,
                                         SSH_PKF_KEY_TYPE, &type,
                                         SSH_PKF_END)) !=
      SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: private key get info failed: %s",
                                    ssh_crypto_status_message(status)));
      ikev2_error(packet, SSH_IKEV2_ERROR_CRYPTO_FAIL);
      return;
    }
  if (strcmp(type, "if-modn") == 0)
    ikev2_add_auth(context, SSH_IKEV2_AUTH_METHOD_RSA_SIG,
                   signature_buffer, signature_buffer_len);
  else if (strcmp(type, "dl-modp") == 0)
    ikev2_add_auth(context, SSH_IKEV2_AUTH_METHOD_DSS_SIG,
                   signature_buffer, signature_buffer_len);
#ifdef SSHDIST_CRYPT_ECP
  else if (strcmp(type, "ec-modp") == 0)
    {
      switch (ssh_private_key_max_signature_output_len(ed->private_key))
        {
        case 64:
          ikev2_add_auth(context, SSH_IKEV2_AUTH_METHOD_ECP_DSA_256,
                         signature_buffer, signature_buffer_len);
          break;
        case 96:
          ikev2_add_auth(context, SSH_IKEV2_AUTH_METHOD_ECP_DSA_384,
                         signature_buffer, signature_buffer_len);
          break;
        case 132:
          ikev2_add_auth(context, SSH_IKEV2_AUTH_METHOD_ECP_DSA_521,
                         signature_buffer, signature_buffer_len);
          break;
        default:
          SSH_IKEV2_DEBUG(SSH_D_FAIL,
                          ("Error: Invalid key private key signature len: %d",
                  ssh_private_key_max_signature_output_len(ed->private_key)));
          ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_ARGUMENT);
        }
    }
#endif /* SSHDIST_CRYPT_ECP  */
  else
    {
      ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_INVALID_KEY_TYPE,
                  "Invalid key type");

      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: Invalid key type %s", type));
      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_ARGUMENT);
    }
}

/* Do async operation and sign the data and add AUTH payload
   to packet. Moves to the error state in case of error,
   otherwise simply continues thread, and assumes the next
   state is already set. */
void ikev2_add_auth_public_key(SshIkev2Packet packet)
{
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;

  packet->operation =
    ssh_private_key_sign_async(ed->private_key,
                               ed->data_to_signed,
                               ed->data_to_signed_len,
                               ikev2_state_auth_sign_cb,
                               packet);
}

void ikev2_reply_cb_public_key(SshIkev2Error error_code,
                               SshPublicKey public_key_out,
                               void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: public_key failed: %d",
                                   error_code));
      ikev2_error(packet, error_code);
      return;
    }

  if (public_key_out == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: No public key found"));
      ikev2_error(packet, SSH_IKEV2_ERROR_AUTHENTICATION_FAILED);
      return;
    }
  if (ssh_public_key_copy(public_key_out, &(packet->ed->ike_ed->public_key))
      != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: public key copy failed"));
      ikev2_error(packet, SSH_IKEV2_ERROR_CRYPTO_FAIL);
      return;
    }
  return;
}

/* Check that the auth payload is valid. */
void ikev2_check_auth_public_key(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* OK, added to the ikev2_state_auth_{responder,initiator}_in_public_key */
  SSH_IKEV2_POLICY_CALL(packet, ike_sa, public_key)
    (ike_sa->server->sad_handle, packet->ed,
     ikev2_reply_cb_public_key, packet);
}

void ikev2_state_auth_verify_cb(SshCryptoStatus status,
                                void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  ssh_free(packet->ed->ike_ed->data_to_signed);
  packet->ed->ike_ed->data_to_signed = NULL;

  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: signature verification failed: %s",
                                   ssh_crypto_status_message(status)));
      ikev2_error(packet, SSH_IKEV2_ERROR_AUTHENTICATION_FAILED);
    }
  else
    {
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      packet->ed->ike_ed->first_auth_verified = 1;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Signature verification ok"));
    }
  return;
}

/* Verify the signature. */
void ikev2_check_auth_public_key_verify(SshIkev2Packet packet)
{
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;

  packet->operation =
    ssh_public_key_verify_async(ed->public_key,
                                ed->auth_remote->authentication_data,
                                ed->auth_remote->authentication_size,
                                ed->data_to_signed,
                                ed->data_to_signed_len,
                                ikev2_state_auth_verify_cb,
                                packet);
}
#endif /* SSHDIST_IKE_CERT_AUTH */
