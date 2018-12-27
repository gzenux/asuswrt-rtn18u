/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Packet Decode routine.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2PacketDecode"

/* This function decodes the header part of the input 'encoded_packet'
   to packet descriptor 'header', and stores copy of 'encoded_packet'
   to 'header->encoded_packet'. */
SshIkev2Error
ikev2_decode_header(SshIkev2Packet packet,
                    const unsigned char *encoded_packet,
                    size_t encoded_packet_len)
{
  int len, offset;

  if (packet->use_natt)
    {
      if (encoded_packet_len < 4)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Packet length(%d) < 4",
                                          encoded_packet_len));
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }
      if (SSH_GET_32BIT(encoded_packet) != 0)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("NAT-T enabled, but first 4 bytes not 0 = %08lx",
                           (unsigned long)
                           SSH_GET_32BIT(encoded_packet)));

          ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                      "Malformed packet, NAT-T enabled, but first 4 "
                      "bytes not 0");
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }
      offset = 4;
    }
  else
    {
      offset = 0;
    }

  if (encoded_packet_len < 28 + offset)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Packet length(%d) < %d",
                                      encoded_packet_len, 28 + offset));

      ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "Malformed packet received, length too short");
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  memcpy(packet->ike_spi_i, encoded_packet + offset, 8);
  memcpy(packet->ike_spi_r, encoded_packet + offset + 8, 8);
  packet->first_payload = SSH_GET_8BIT(encoded_packet + offset + 16);
  packet->major_version = SSH_GET_8BIT(encoded_packet + offset + 17) >> 4;
  packet->minor_version = SSH_GET_8BIT(encoded_packet + offset + 17) & 0x0f;
  packet->exchange_type = SSH_GET_8BIT(encoded_packet + offset + 18);
  packet->flags = SSH_GET_8BIT(encoded_packet + offset + 19);
  packet->message_id = SSH_GET_32BIT(encoded_packet + offset + 20);
  len = SSH_GET_32BIT(encoded_packet + offset + 24);

  /* Allow garbage at end of packet for IKEv1, due to Cisco
     implementation sending such packets. IKEv1 library will perform
     proper sanity checks for such packets. */
  if (((packet->major_version == 1)
       && (len + offset > encoded_packet_len))
      || ((packet->major_version > 1)
          && (len + offset != encoded_packet_len)))
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Length(%d) + %d != len from udp(%d)",
                                      len, offset, encoded_packet_len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  packet->encoded_packet = (unsigned char *) encoded_packet;
  packet->encoded_packet_len = encoded_packet_len;
  return SSH_IKEV2_ERROR_OK;
}

static SshIkev2Error
ikev2_verify_and_decrypt_packet(SshIkev2Packet packet,
                                SshIkev2Sa ike_sa,
                                size_t *header_len)
{
  SshCryptoStatus status;
  SshCipher cipher;
  SshMac mac;
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t len;

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Key for mac"),
                    (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
                    ike_sa->sk_ar : ike_sa->sk_ai, ike_sa->sk_a_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */
  /* Allocate mac. */
  status =
    ssh_mac_allocate(ssh_csstr(ike_sa->mac_algorithm),
                     (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
                     ike_sa->sk_ar : ike_sa->sk_ai, ike_sa->sk_a_len, &mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: mac(%s) allocate failed: %s",
                                    ike_sa->mac_algorithm,
                                    ssh_crypto_status_message(status)));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  len = ssh_mac_length(ssh_csstr(ike_sa->mac_algorithm));

  /* Remove the mac from the packet. */
  packet->encoded_packet_len -= len;

  /* Calculate the mac. Mac includes everything from the
     start of the header. */
  ssh_mac_reset(mac);
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Mac input"),
                    packet->encoded_packet + (packet->use_natt ? 4 : 0),
                    packet->encoded_packet_len - (packet->use_natt ? 4 : 0));
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */
  ssh_mac_update(mac, packet->encoded_packet + (packet->use_natt ? 4 : 0),
                 packet->encoded_packet_len - (packet->use_natt ? 4 : 0));
  status = ssh_mac_final(mac, digest);
  ssh_mac_free(mac);
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Mac output"), digest, len);

  /* Check the result of mac calculation. */
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: mac final failed: %s",
                                    ssh_crypto_status_message(status)));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Mac from the packet"),
                    packet->encoded_packet + packet->encoded_packet_len, len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Verify the mac. */
  if (memcmp(digest, packet->encoded_packet + packet->encoded_packet_len, len)
      != 0)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Error: mac check failed"));

      ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_INVALID_HASH_VALUE,
                  "MAC check failed on IKE packet");

      return SSH_IKEV2_ERROR_DISCARD_PACKET;
    }

  /* IMPORTANT: Now the packet is authentic.

     If we receive syntax/semantics error after this point they become
     fatal, and the SA will be destroyed. */

  /* Get the IV len. */
  if (!strcmp(ike_sa->encrypt_algorithm, "aes128-ctr") ||
      !strcmp(ike_sa->encrypt_algorithm, "aes192-ctr") ||
      !strcmp(ike_sa->encrypt_algorithm, "aes256-ctr"))
    len = 8;
  else
    len = ssh_cipher_get_iv_length(ssh_csstr(ike_sa->encrypt_algorithm));

  /* Check the length (IV + one byte). */
  if (len > packet->encoded_packet_len - *header_len)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("IV len(%zd) > payload len(%zd)",
                       len, packet->encoded_packet_len - *header_len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  /* Allocate cipher */
  status =
    ssh_cipher_allocate(ssh_csstr(ike_sa->encrypt_algorithm),
                        (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
                        ike_sa->sk_er : ike_sa->sk_ei, ike_sa->sk_e_len,
                        FALSE, &cipher);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: cipher allocate failed: %s",
                                    ssh_crypto_status_message(status)));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  /* Decrypt. */
  if (ike_sa->sk_n_len == 0)
    {
      /* CBC-mode cipher */
      status = ssh_cipher_set_iv(cipher, packet->encoded_packet + *header_len);

      if (status == SSH_CRYPTO_OK)
        {
          status = ssh_cipher_start(cipher);
        }

      if (status == SSH_CRYPTO_OK)
        {
          status =
            ssh_cipher_transform(cipher,
                                 packet->encoded_packet + *header_len + len,
                                 packet->encoded_packet + *header_len + len,
                                 packet->encoded_packet_len -
                                 *header_len - len);
        }
    }
  else
    {
      /* CTR-mode cipher */
      unsigned char iv[16];

      SSH_ASSERT(!strcmp(ike_sa->encrypt_algorithm, "aes128-ctr") ||
                 !strcmp(ike_sa->encrypt_algorithm, "aes192-ctr") ||
                 !strcmp(ike_sa->encrypt_algorithm, "aes256-ctr"));

      /* Setup IV */
      memset(iv, 0x00, 16);
      memcpy(iv, (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
             ike_sa->sk_nr : ike_sa->sk_ni,
             ike_sa->sk_n_len);
      memcpy(iv + 4, packet->encoded_packet + *header_len, 8);
      iv[15] = 0x01;

      status = ssh_cipher_set_iv(cipher, iv);

      if (status == SSH_CRYPTO_OK)
        {
          status = ssh_cipher_start(cipher);
        }

      if (status == SSH_CRYPTO_OK)
        {
          status =
            ssh_cipher_transform(cipher,
                                 packet->encoded_packet + *header_len + len,
                                 packet->encoded_packet + *header_len + len,
                                 packet->encoded_packet_len -
                                 *header_len - len);
        }
    }

  ssh_cipher_free(cipher);

  /* Check the result of decryption. */
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: cipher transform failed: %s",
                                    ssh_crypto_status_message(status)));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  /* Skip the IV. */
  *header_len += len;

  return SSH_IKEV2_ERROR_OK;
}

static SshIkev2Error
ikev2_combined_decrypt_packet(SshIkev2Packet packet,
                              SshIkev2Sa ike_sa,
                              size_t *header_len)
{
  SshCryptoStatus status;
  SshCipher cipher;
  unsigned char iv_buffer[SSH_CIPHER_MAX_IV_SIZE];
  size_t iv_len;
  size_t checksum_len;
  Boolean mac_check_failed = FALSE;

  /* Remove integrity checksum from packet len */
  checksum_len =
    ssh_cipher_auth_digest_length(ssh_csstr(ike_sa->encrypt_algorithm));
  packet->encoded_packet_len -= checksum_len;

  iv_len = ssh_cipher_get_iv_length(ssh_csstr(ike_sa->encrypt_algorithm));
  if (iv_len == 0)
    return SSH_IKEV2_ERROR_CRYPTO_FAIL;

  /* Allocate cipher */
  status =
    ssh_cipher_allocate(ssh_csstr(ike_sa->encrypt_algorithm),
                        (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
                        ike_sa->sk_er : ike_sa->sk_ei, ike_sa->sk_e_len,
                        FALSE, &cipher);

  if (status != SSH_CRYPTO_OK)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Using combined cipher %s with key",
                     ike_sa->encrypt_algorithm),
                    (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
                    ike_sa->sk_er : ike_sa->sk_ei,
                    ike_sa->sk_e_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Create IV buffer: nonce | IKEv2-IV | counter */
  memset(iv_buffer, 0x00, SSH_CIPHER_MAX_IV_SIZE);

  SSH_ASSERT(SSH_CIPHER_MAX_IV_SIZE >= ike_sa->sk_n_len + 8 + 4);

  memcpy(iv_buffer, (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
         ike_sa->sk_nr : ike_sa->sk_ni,
         ike_sa->sk_n_len);
  memcpy(iv_buffer + ike_sa->sk_n_len,
         packet->encoded_packet + *header_len, 8);

  /* Skip the IV-part from header  */
  *header_len += 8;

  /* Initialize the counter for counter mode (except CCM) as part of the iv */
  if (ike_sa->sk_n_len == 4)
    {
      iv_buffer[iv_len - 1] = 0x01;
    }

  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("IV"), iv_buffer, iv_len);

  status = ssh_cipher_set_iv(cipher, iv_buffer);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: cipher set iv failed: %s",
                                    ssh_crypto_status_message(status)));
      ssh_cipher_free(cipher);
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  /* Start cipher operation and input AAD. */
  status =
    ssh_cipher_auth_start(cipher,
                          packet->encoded_packet + (packet->use_natt ? 4 : 0),
                          28 + 4, packet->encoded_packet_len - *header_len);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: cipher auth start failed: %s",
                                    ssh_crypto_status_message(status)));
      ssh_cipher_free(cipher);
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("AAD"),
                    packet->encoded_packet + (packet->use_natt ? 4 : 0),
                    28 + 4);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Decrypt */
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Decrypting"),
                    packet->encoded_packet + *header_len,
                    packet->encoded_packet_len - *header_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  status =
    ssh_cipher_transform(cipher,
                         packet->encoded_packet + *header_len,
                         packet->encoded_packet + *header_len,
                         packet->encoded_packet_len - *header_len);

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Decrypted"),
                    packet->encoded_packet + *header_len,
                    packet->encoded_packet_len - *header_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Check the result of decryption. */
  if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: cipher transform failed: %s",
                                    ssh_crypto_status_message(status)));
      ssh_cipher_free(cipher);
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }


  status = ssh_cipher_auth_final_verify(cipher,
                                     packet->encoded_packet +
                                     packet->encoded_packet_len);

  if (status == SSH_CRYPTO_OPERATION_FAILED)
    {
      mac_check_failed = TRUE;
    }
  else if (status != SSH_CRYPTO_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                     ("Error: auth cipher final verify failed: %s",
                       ssh_crypto_status_message(status)));
      ssh_cipher_free(cipher);
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  ssh_cipher_free(cipher);

  if (mac_check_failed == TRUE)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Error: mac check failed"));

      ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_INVALID_HASH_VALUE,
                  "MAC check failed on IKE packet");

      return SSH_IKEV2_ERROR_DISCARD_PACKET;
    }

  return SSH_IKEV2_ERROR_OK;
}


/* Decode the encrypted packet, i.e check the mac and
   decrypt the packet. This will modify the
   packet->encoded_packet, packet->encoded_packet_len and
   the header_len. The header_len must have the length of
   headers before the encrypted packet when this is called,
   and it will be incremented to include the headers to be
   skipped from the encrypted payload. */
SshIkev2Error
ikev2_decode_encr(SshIkev2Packet packet,
                  size_t *header_len)
{
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2Error status;
  size_t len;

  /* Check the length. */
  if (packet->encoded_packet_len < *header_len + 4)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Packet length(%d) < header_len(%d) + 4",
                                      packet->encoded_packet_len,
                                      *header_len));

      ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "Malformed packet, length inconsistent with that "
                  "indicated in header");

      return SSH_IKEV2_ERROR_DISCARD_PACKET;
    }

  /* Get the payload type. */
  packet->first_payload = SSH_GET_8BIT(packet->encoded_packet + *header_len);

  /* Check the packet length, this must be last payload and
  consume everything up to the end of packet. */
  len = SSH_GET_16BIT(packet->encoded_packet + *header_len + 2);
  if (len != packet->encoded_packet_len - *header_len)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Encr payload len(%d) != packet_len(%d) - "
                       "header_len(%d)",
                       len, packet->encoded_packet_len, *header_len));

      ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "Malformed packet, length inconsistent with that "
                  "indicated in header");

      return SSH_IKEV2_ERROR_DISCARD_PACKET;
    }

  /* Get the MAC len. */
  if (ike_sa->mac_algorithm == NULL)
    len = ssh_cipher_auth_digest_length(ssh_csstr(ike_sa->mac_algorithm));
  else
    len = ssh_mac_length(ssh_csstr(ike_sa->mac_algorithm));

  /* Skip the generic encryption payload header. */
  *header_len += 4;

  /* Check the length. */
  if (len > packet->encoded_packet_len - *header_len)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("mac len(%zd) > payload len(%zd)",
                       len, packet->encoded_packet_len - *header_len));

      ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "Malformed packet, length inconsistent with that "
                  "indicated in header");
      return SSH_IKEV2_ERROR_DISCARD_PACKET;
    }

  ikev2_debug_packet_in(packet);

  /* Use combined mode or separate mac and cipher  */
  if (ike_sa->mac_algorithm == NULL)
    status = ikev2_combined_decrypt_packet(packet,
                                           packet->ike_sa,
                                           header_len);
  else
    status = ikev2_verify_and_decrypt_packet(packet,
                                             packet->ike_sa,
                                             header_len);

  if (status != SSH_IKEV2_ERROR_OK)
    return status;

  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                    ("Packet after decryption"),
                    packet->encoded_packet, packet->encoded_packet_len);
  /* Remove padding. */
  len = SSH_GET_8BIT(packet->encoded_packet + packet->encoded_packet_len - 1);
  if (len + 1 > packet->encoded_packet_len - *header_len)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("padding len(%d) > payload len(%d)",
                       len + 1, packet->encoded_packet_len - *header_len));

      ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "Malformed packet, invalid padding");

      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }
  SSH_DEBUG_HEXDUMP(SSH_D_MY1,
                    ("Padding of %d bytes", len),
                    packet->encoded_packet +
                    packet->encoded_packet_len - len - 1, len);

  /* Remove padding. */
  packet->encoded_packet_len -= len + 1;

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Packet decrypted successfully"));
  return SSH_IKEV2_ERROR_OK;
}

/* Decode the whole packet, i.e call the various decode
   payload functions to decode payloads. */
SshFSMStepStatus
ikev2_decode_packet(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2Error err;
  size_t header_len, len, payload_len;
  SshIkev2PayloadType curr_payload, next_payload;
  unsigned char *payload;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Decoding packet"));

  /* Check if IKE SA has already been aborted, i.e. if it was aborted between
     ikev2_udp_window_check and this call. */
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_ABORTED)
    {
      SSH_IKEV2_DEBUG(SSH_D_UNCOMMON,
                      ("Decoding packet, but IKE SA is already aborted"));
      return SSH_FSM_FINISH;
    }

  /* If we are doing the initial exchange, and we already
     have packet waiting to be processed, we simply ignore
     the packet. */
  if (ike_sa->initial_ed != NULL)
    {
      if (ike_sa->initial_ed->packet_to_process != NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_UNCOMMON,
                          ("We are already processing packet %p",
                           ike_sa->initial_ed->packet_to_process));
          return SSH_FSM_FINISH;
        }
    }

  if (packet->major_version != 2
      && (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) == 0)
    {
      /* Now we have enough information to send the
         SSH_IKEV2_NOTIFY_INVALID_MAJOR_VERSION. */

      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Major version number(%d) != 2",
                                      packet->major_version));

      ikev2_audit(ike_sa, SSH_AUDIT_IKE_INVALID_VERSION,
                  "Invalid major version number");

      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_MAJOR_VERSION);
    }

  header_len = 28;
  if (packet->use_natt)
    {
      header_len += 4;
    }

  /* First check if we have the encrypted payload, and if so
     we need to have the diffie-helman finished. */
  if (packet->first_payload == SSH_IKEV2_PAYLOAD_TYPE_ENCRYPTED)
    {
      SSH_IKEV2_DEBUG(SSH_D_MY1, ("Encrypted packet"));
      if (ike_sa->sk_d == NULL && ike_sa->initial_ed != NULL)
        {
          /* Need to wait for the crypto operations to finish. We
             simply store the packet, and then check if we have
             Diffie-Helman operation started. If so we simply wait for
             it to finish.  If not, we start new operation. */

          if (ike_sa->initial_ed->operation != NULL)
            {
              if (ike_sa->initial_ed->packet_to_process != NULL)
                {
                  SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                                  ("SKEYSEED calculation in progress, "
                                   "wait for it (packet dropped)"));
                  return SSH_FSM_FINISH;
                }
              else
                {
                  SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                                  ("SKEYSEED calculation in progress, "
                                   "wait for it (packet queued)"));
                  ike_sa->initial_ed->packet_to_process = packet;
                  return SSH_FSM_SUSPENDED;
                }
            }
          ike_sa->initial_ed->packet_to_process = packet;
          /* We do not have operation running, start it
             now. */
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Start calculating SKEYSEED"));

          /* Skeyseed computation will handle the anonymous encrypted
             packets by indicating failure (sk_d != NULL && sk_d_len
             == 0) */
          ikev2_skeyseed(ike_sa);
          if (ike_sa->initial_ed->operation != NULL)
            {
              SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Started calculating SKEYSEED"));
              /* We did start asyncronous operation, so
                 suspend the thread and wait for it to
                 finish. */
              return SSH_FSM_SUSPENDED;
            }
          ike_sa->initial_ed->packet_to_process = NULL;
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Finished calculating SKEYSEED"));

          /* We didn't start asyncronous operation, so the operation
             should now be done, continue the processing. */
          SSH_ASSERT(ike_sa->sk_d != NULL ||
                     (ike_sa->sk_d_len == 0 && ike_sa->sk_d == NULL));
        }

      /* Check if there was error in the async operation, or if this
         is an encrypted packet without D-H having been done (e.g
         packet without initial exchange having been done).  */
      if (ike_sa->sk_d_len == 0)
        {
          /* Yes, return error to the upper level. */
          SSH_IKEV2_DEBUG(SSH_D_UNCOMMON,
                          ("Error while calculating SKEYSEED"));
          return ikev2_error(packet, SSH_IKEV2_ERROR_DISCARD_PACKET);
        }
      err = ikev2_decode_encr(packet, &header_len);
      if (err != SSH_IKEV2_ERROR_OK)
        return ikev2_error(packet, err);

      /* Check IKE major version. Delete IKE SA if major version is not 2.*/
      if (packet->major_version != 2)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Major version number(%d) != 2",
                                          packet->major_version));

          ikev2_audit(ike_sa, SSH_AUDIT_IKE_INVALID_VERSION,
                      "Invalid major version number");

          /* Send SSH_IKEV2_NOTIFY_INVALID_MAJOR_VERSION. */
          return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_MAJOR_VERSION);
        }
    }
  else if (packet->exchange_type != SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT)
    {
      /* All packets after IKE_SA_INIT should be encrypted. If not, then
         we may display the notify payloads within the packet to the policy
         manager and discard the packet. We only display notifies to the
         policy manager when the exchange state is IKE_AUTH, in this state
         the notifies may be useful as an aid for diagnosing IKE negotiation
         failures. */
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Plain text packet which is not IKE_SA_INIT"));
      if (ike_sa->initial_ed == NULL ||
          packet->exchange_type != SSH_IKEV2_EXCH_TYPE_IKE_AUTH)
        return SSH_FSM_FINISH;

      SSH_IKEV2_DEBUG(SSH_D_MIDOK,
                      ("Plain text packet at IKE_SA_AUTH state "
                       "displayed to the application"));

      /* Use the exchange data from the initial_ed unless proper one
         available. */
      if (packet->ed == NULL)
        {
          ikev2_reference_exchange_data(ike_sa->initial_ed);
          packet->ed = ike_sa->initial_ed;
        }

      /* Extract any notify payloads and display them to the policy manager */
      curr_payload = packet->first_payload;
      payload = packet->encoded_packet + header_len;
      len = packet->encoded_packet_len - header_len;

      while (curr_payload != 0)
        {
          if (len < 4)
            return SSH_FSM_FINISH;

          next_payload = SSH_GET_8BIT(payload);
          payload_len = SSH_GET_16BIT(payload + 2);

          if (payload_len < 4)
            {
              SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                              ("Short packet payload_len(%d) < 4",
                               payload_len));

              ikev2_audit(packet->ike_sa,
                          SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                          "Malformed payload, less than 4 bytes");
              return SSH_FSM_FINISH;
            }

          if (len < payload_len)
            {
              SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                              ("Short packet left(%d) < payload_len(%d)",
                               len, payload_len));

              ikev2_audit(packet->ike_sa,
                          SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                          "Malformed payload, greater than packet size");
              return SSH_FSM_FINISH;
            }

          SSH_DEBUG_HEXDUMP(110, ("Payload of type %d", curr_payload),
                            payload, payload_len);

          payload += 4;
          payload_len -= 4;
          len -= 4;

          switch (curr_payload)
            {
            case SSH_IKEV2_PAYLOAD_TYPE_NOTIFY:
              err = ikev2_decode_notify(packet, FALSE, payload, payload_len);
              break;
            default:
              err = SSH_IKEV2_ERROR_OK;
              break;
            }
          if (err == SSH_IKEV2_ERROR_INVALID_SYNTAX)
            {
              ikev2_audit(packet->ike_sa,
                          SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                          "Malformed payload received");
            }
          if (err != SSH_IKEV2_ERROR_OK)
            return SSH_FSM_FINISH;

          /* Get next payload. */
          curr_payload = next_payload;
          payload += payload_len;
          len -= payload_len;
        }
      return SSH_FSM_FINISH;
    }
  else if (packet->message_id != 0)
    {
      /* All IKE_SA_INIT must have message id 0. */
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("IKE_SA_INIT packet with message id > 0"));
      SSH_ASSERT(packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT);

      ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "IKE_SA_INIT packet with message id larger than zero");

      return ikev2_error(packet, SSH_IKEV2_ERROR_DISCARD_PACKET);
    }
  else if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
    {
      /* As this must be first packet the IKE SA cannot be
         done yet. */
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("IKE_SA_INIT with message id to already existing SA"));

      ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "IKE_SA_INIT with message id to already existing SA");

      SSH_ASSERT(packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT);
      return ikev2_error(packet, SSH_IKEV2_ERROR_DISCARD_PACKET);
    }

  ikev2_list_packet_payloads(packet,
                             packet->encoded_packet + header_len,
                             packet->encoded_packet_len - header_len,
                             packet->first_payload,
                             FALSE);

  curr_payload = packet->first_payload;
  payload = packet->encoded_packet + header_len;
  len = packet->encoded_packet_len - header_len;

  if (packet->ed == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("No old context"));
      /* This is new exchange, as we do not have previous context. */
      if (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
        {
          /* This was response, but we do not know the
             context, so ignore the packet. */
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("No old context, and this is "
                                          "response, must be garbage"));
          return SSH_FSM_FINISH;
        }

      /* First see if we are doing initial exchange now. */
      if (ike_sa->initial_ed != NULL)
        {
          /* Yes, so this packet must be part of that
             exchange, and the exchange type must be IKE_AUTH.

             The RFC5996 states that CREATE_CHILD or INFORMATIONAL
             exchanges cannot be started before the initial exchange
             completes. If this end is the initiator and the IKE_AUTH
             response is lost, then the responder thinks that the
             initial exchange is completed and may start new
             CREATE_CHILD or INFORMATIONAL exchanges. In such case
             this end drops the request packets of this new exchange
             until it has received the IKE_AUTH response and
             successfully completed the initial exchange. */
          if (packet->exchange_type != SSH_IKEV2_EXCH_TYPE_IKE_AUTH)
            {
              SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Exchange type != IKE_AUTH"));
              return SSH_FSM_FINISH;
            }

          /* Use the exchange data from the initial_ed. */
          ikev2_reference_exchange_data(ike_sa->initial_ed);
          packet->ed = ike_sa->initial_ed;

          /* Allocate IPsec SA if we are creating child SA. */
          err = ikev2_allocate_exchange_data_ipsec(packet->ed);
          if (err != SSH_IKEV2_ERROR_OK)
            return ikev2_error(packet, err);
        }
      else
        {
          /* Allocate new exchange_data now. */
          packet->ed = ikev2_allocate_exchange_data(ike_sa);
          if (packet->ed == NULL)
            return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          packet->ed->ike_sa = ike_sa;

          switch (packet->exchange_type)
            {
            case SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT:
              /* Allocate IKE SA exchange data for IKE_SA_INIT. */
              /* Do we already have the IKE SA ready? If so
                 ignore this. */
              if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
                {
                  SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                                  ("IKE_SA_INIT packet to finished IKE SA"));
                  ikev2_free_exchange_data(ike_sa, packet->ed);
                  packet->ed = NULL;
                  return SSH_FSM_FINISH;
                }
              SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Starting new exchange"));

              /* Nope, so allocate new IKE SA exchange data. */
              err = ikev2_allocate_exchange_data_ike(packet->ed);
              if (err != SSH_IKEV2_ERROR_OK)
                return ikev2_error(packet, err);

              /* Store it to the initial_ed. */
              ikev2_reference_exchange_data(packet->ed);
              ike_sa->initial_ed = packet->ed;
              break;

            case SSH_IKEV2_EXCH_TYPE_IKE_AUTH:
              /* This cannot be IKE_AUTH, as we should have had
                 the initial_ed then. */
              SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("First packet was IKE_AUTH"));
              ikev2_free_exchange_data(ike_sa, packet->ed);
              packet->ed = NULL;
              return SSH_FSM_FINISH;

            case SSH_IKEV2_EXCH_TYPE_CREATE_CHILD_SA:
              /* Allocate IPsec SA if we are creating child SA. */
              err = ikev2_allocate_exchange_data_ipsec(packet->ed);
              if (err != SSH_IKEV2_ERROR_OK)
                return ikev2_error(packet, err);
              break;

            case SSH_IKEV2_EXCH_TYPE_INFORMATIONAL:
              /* Allocate Info exchange */
              err = ikev2_allocate_exchange_data_info(packet->ed);
              if (err != SSH_IKEV2_ERROR_OK)
                return ikev2_error(packet, err);

              break;

            default:
              /* Unknown exchange type. */
              SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Unknown exchange type %d",
                                              packet->exchange_type));

              ikev2_audit(packet->ike_sa,
                          SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                          "Unknown exchange type in payload");

              ikev2_free_exchange_data(ike_sa, packet->ed);
              packet->ed = NULL;
              return SSH_FSM_FINISH;
            }
        }
    }
  else
    {
      /* Ok, we had the context from previous run. */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("We have old context"));
      /* Check if we need to allocate IPsec SA context. */
      if (ike_sa->initial_ed != NULL &&
          packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_AUTH)
        {
          /* Allocate IPsec SA if we are creating IPsec. */
          err = ikev2_allocate_exchange_data_ipsec(packet->ed);
          if (err != SSH_IKEV2_ERROR_OK)
            return ikev2_error(packet, err);
        }
    }
  packet->ed->notify_count = 0;

#ifdef SSHDIST_IKE_MOBIKE
  *(packet->ed->remote_ip) = *(packet->remote_ip);
  packet->ed->remote_port = packet->remote_port;
  packet->ed->server = packet->server;
#endif /* SSHDIST_IKE_MOBIKE */

  /* Check if IKE SA is done and 1) port float is done and other end is behind
     NAT or 2) IKE SA is using TCP encapsulation, and the source ip or port
     has changed. */
  if ((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) &&
      (((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE) &&
        (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT) &&
#ifdef SSHDIST_IKE_MOBIKE
        /* RFC 4555 IKEv2 packets MUST NOT cause dynamic updates of IPsec
           SA's */
        (!(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)) &&
#endif /* SSHDIST_IKE_MOBIKE */
        packet->use_natt)
       || (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP))
      && (ike_sa->remote_port != packet->remote_port ||
          SSH_IP_CMP(ike_sa->remote_ip, packet->remote_ip) != 0))
    {
      /* OK, added to the ike_state_decode. */
      SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_sa_update)
        (ike_sa->server->sad_handle, packet->ed,
         packet->remote_ip, packet->remote_port);
    }

  ikev2_debug_decode_start(packet);

  while (curr_payload != 0)
    {
      int reserved_byte;

      if (len < 4)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Too short packet len(%d)", len));

          ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                      "Too short packet length");

          return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
        }

      next_payload = SSH_GET_8BIT(payload);
      reserved_byte = SSH_GET_8BIT(payload + 1);
      payload_len = SSH_GET_16BIT(payload + 2);

      if (payload_len < 4)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("Short packet payload_len(%d) < 4",
                           payload_len));

          ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                      "Too short payload length");

          return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
        }

      if (len < payload_len)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("Short packet left(%d) < payload_len(%d)",
                           len, payload_len));

          ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                      "Too short packet length, less than indicated "
                      "by payload length");

          return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
        }
      SSH_DEBUG_HEXDUMP(110,
                        ("Payload of type %d", curr_payload),
                        payload, payload_len);

      payload += 4;
      payload_len -= 4;
      len -= 4;
      switch (curr_payload)
        {
        case SSH_IKEV2_PAYLOAD_TYPE_SA:
          err = ikev2_decode_sa(packet, payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_KE:
          err = ikev2_decode_ke(packet, payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_ID_I:
          err = ikev2_decode_idi(packet, payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_ID_R:
          err = ikev2_decode_idr(packet, payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_CERT:
          err = ikev2_decode_cert(packet, payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_CERT_REQ:
          err = ikev2_decode_certreq(packet, payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_AUTH:
          err = ikev2_decode_auth(packet, payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_NONCE:
          err = ikev2_decode_nonce(packet, payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_NOTIFY:
          err = ikev2_decode_notify(packet,
                                    (ike_sa->flags &
                                     SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE),
                                    payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_DELETE:
          err = ikev2_decode_delete(packet, payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_VID:
          err = ikev2_decode_vendor_id(packet, payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_TS_I:
          err = ikev2_decode_tsi(packet, payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_TS_R:
          err = ikev2_decode_tsr(packet, payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_ENCRYPTED:
          err = SSH_IKEV2_ERROR_INVALID_SYNTAX;
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_CONF:
          err = ikev2_decode_conf(packet, payload, payload_len);
          break;
        case SSH_IKEV2_PAYLOAD_TYPE_EAP:
          err = ikev2_decode_eap(packet, payload, payload_len);
          break;
        default:
          /* Check for critical bit. */
          if (reserved_byte & 0x80)
            {
              err = SSH_IKEV2_ERROR_UNSUPPORTED_CRITICAL_PAYLOAD;
              SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                                ("Unsupported critical payload of type %d",
                                 curr_payload),
                                payload, payload_len);

              ikev2_audit(packet->ike_sa,
                          SSH_AUDIT_IKE_UNSUPPORTED_CRITICAL_PAYLOAD,
                          "Unsupported critical payload in packet");
            }
          else
            {
              /* Just ignore. */
              SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                                ("Unsupported payload of type %d",
                                 curr_payload),
                                payload, payload_len);
              err = SSH_IKEV2_ERROR_OK;
            }
          break;
        }

      if (err == SSH_IKEV2_ERROR_INVALID_SYNTAX)
        {
          ikev2_audit(packet->ike_sa,
                      SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                      "Malformed payload received");
        }

      if (err != SSH_IKEV2_ERROR_OK)
        return ikev2_error(packet, err);

      /* Get next payload. */
      curr_payload = next_payload;
      payload += payload_len;
      len -= payload_len;
    }
  if (len != 0)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Extra junk after packet len(%d)", len));

      ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "Extra junk after packet");
      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }

  if (packet->message_id == 0
      && !(packet->flags & SSH_IKEV2_PACKET_FLAG_INITIATOR)
      && (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
      && (packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT)
      && (packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
      && (packet->ike_sa->initial_ed != NULL)
      && (packet->ike_sa->initial_ed->state == SSH_IKEV2_STATE_IKE_INIT_SA))
    {
      if (memcmp(packet->ike_sa->ike_spi_r, "\0\0\0\0\0\0\0\0", 8) != 0)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("IKE SA %p has already responder IKE SPI set",
                           packet->ike_sa));
          ikev2_audit(ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                      "IKE_SA_INIT response packet with zero responder SPI");
          return SSH_FSM_FINISH;
        }

      /* Assert that initiator IKE SPI in packet matches the IKE SA.
         IKE SA lookup should not have succeeded otherwise. */
      SSH_ASSERT(memcmp(packet->ike_sa->ike_spi_i, packet->ike_spi_i,
                        sizeof(packet->ike_spi_i)) == 0);

      /* Copy responder IKE SPI to IKE SA if packet specifies it. */
      if (memcmp(packet->ike_spi_r, "\0\0\0\0\0\0\0\0", 8) != 0)
        {
          SSH_IKEV2_DEBUG(SSH_D_MIDOK,
                          ("Updating responder IKE SPI to IKE SA %p "
                           "I %08lx %08lx R %08lx %08lx ",
                           packet->ike_sa,
                           SSH_GET_32BIT(packet->ike_sa->ike_spi_i),
                           SSH_GET_32BIT(packet->ike_sa->ike_spi_i + 4),
                           SSH_GET_32BIT(packet->ike_spi_r),
                           SSH_GET_32BIT(packet->ike_spi_r + 4)));
          memcpy(packet->ike_sa->ike_spi_r, packet->ike_spi_r,
                 sizeof(packet->ike_spi_r));
        }
    }
  else
    {
      /* Assert that IKE SPIs in packet matches the IKE SA.
         IKE SA lookup should not have succeeded otherwise. */
      SSH_ASSERT(memcmp(packet->ike_sa->ike_spi_i, packet->ike_spi_i,
                        sizeof(packet->ike_spi_i)) == 0);
      SSH_ASSERT(memcmp(packet->ike_sa->ike_spi_r, packet->ike_spi_r,
                        sizeof(packet->ike_spi_r)) == 0);
    }

  return SSH_FSM_CONTINUE;
}
