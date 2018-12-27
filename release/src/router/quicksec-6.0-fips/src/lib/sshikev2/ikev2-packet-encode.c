/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Packet Encode routine.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshencode.h"

#define SSH_DEBUG_MODULE "SshIkev2PacketEncode"

/* This function encodes the header and the packet data
   (from `buffer') to the encoded_packet field inside
   `packet'. */
SshIkev2Error
ikev2_encode_header(SshIkev2Packet packet, SshBuffer buffer)
{
  size_t len;

  len = ssh_buffer_len(buffer);
  packet->encoded_packet_len = len + 28 + (packet->use_natt ? 4 : 0);
  packet->encoded_packet = ssh_malloc(packet->encoded_packet_len);
  if (packet->encoded_packet == NULL)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  len = ssh_encode_array(packet->encoded_packet,
                         packet->encoded_packet_len,
                         SSH_ENCODE_DATA(ssh_ustr("\0\0\0\0"),
                         (size_t) (packet->use_natt ? 4 : 0)),
                         SSH_ENCODE_DATA(packet->ike_spi_i, (size_t) 8),
                         SSH_ENCODE_DATA(packet->ike_spi_r, (size_t) 8),
                         SSH_ENCODE_CHAR(
                         (unsigned int) packet->first_payload),
                         SSH_ENCODE_CHAR(
                         (unsigned int) ((packet->major_version << 4) |
                                         packet->minor_version)),
                         SSH_ENCODE_CHAR((unsigned int) packet->exchange_type),
                         SSH_ENCODE_CHAR((unsigned int) packet->flags),
                         SSH_ENCODE_UINT32(packet->message_id),
                         SSH_ENCODE_UINT32(packet->encoded_packet_len -
                         (packet->use_natt ? 4 : 0)),
                         SSH_ENCODE_DATA(ssh_buffer_ptr(buffer), len),
                         SSH_FORMAT_END);
  if (len != packet->encoded_packet_len)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  ikev2_debug_packet_out(packet);

  ikev2_list_packet_payloads(packet,
                             packet->encoded_packet + 28,
                             packet->encoded_packet_len - 28,
                             packet->first_payload,
                             TRUE);

  return SSH_IKEV2_ERROR_OK;
}

/* Encrypt the packet and calculate MAC of it. This will
   also encode the packet to the packet->encoded_packet. */
SshIkev2Error ikev2_encrypt_packet(SshIkev2Packet packet,
                                   SshBuffer buffer)
{
  unsigned char temp_buffer[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned char iv_buffer[SSH_CIPHER_MAX_IV_SIZE], *p;
  size_t temp_len, mac_len, len, pad_len, iv_len;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshCryptoStatus status;
  SshCipher cipher;
  SshMac mac;
  Boolean combined_encryption;
  int i;

  ikev2_list_packet_payloads(packet,
                             ssh_buffer_ptr(buffer),
                             ssh_buffer_len(buffer),
                             packet->first_payload,
                             TRUE);

  /* Lets check that the max IV size is smaller than the max HASH digest
     length, so we can use the digest buffer as a placeholder. */
  SSH_ASSERT(SSH_CIPHER_MAX_IV_SIZE < SSH_MAX_HASH_DIGEST_LENGTH);

  /* Get the MAC len. */
  if (ike_sa->mac_algorithm == NULL)
    {
      mac_len =
        ssh_cipher_auth_digest_length(ssh_csstr(ike_sa->encrypt_algorithm));
      combined_encryption = TRUE;
    }
  else
    {
      mac_len = ssh_mac_length(ssh_csstr(ike_sa->mac_algorithm));
      combined_encryption = FALSE;
    }

  /* Lenght of the packet. */
  len = ssh_buffer_len(buffer);

  /* Add the pad length field. */
  len++;

  /* Get the block size. */
  temp_len = ssh_cipher_get_block_length(ssh_csstr(ike_sa->encrypt_algorithm));

  SSH_ASSERT(temp_len != 0);

  /* Calculate the padding length. */
  pad_len = temp_len - (len % temp_len);
  if (pad_len == temp_len)
    pad_len = 0;

  /* Get IV length. */
  if (ike_sa->sk_n_len == 0)
    {
      /* CBC mode cipher */
      iv_len = ssh_cipher_get_iv_length(ssh_csstr(ike_sa->encrypt_algorithm));

      for (i = 0; i < iv_len; i++)
        iv_buffer[i] = ssh_random_get_byte();
    }
  else
    {
      /* CTR and combined mode ciphers */
      SSH_ASSERT(!strcmp(ike_sa->encrypt_algorithm, "aes128-ctr") ||
                 !strcmp(ike_sa->encrypt_algorithm, "aes192-ctr") ||
                 !strcmp(ike_sa->encrypt_algorithm, "aes256-ctr") ||
                 (ike_sa->mac_algorithm == NULL));

      iv_len = 8;

      memset(iv_buffer, 0x00, SSH_CIPHER_MAX_IV_SIZE);

      memcpy(iv_buffer,
             (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
             ike_sa->sk_ni : ike_sa->sk_nr,
             ike_sa->sk_n_len);

      for (i = 0; i < iv_len; i++)
        iv_buffer[i + ike_sa->sk_n_len] = ssh_random_get_byte();

      /* Initialize counter for counter mode (except CCM) as part of the iv */
      if (ike_sa->sk_n_len == 4)
        {
          iv_buffer[15] = 0x01;
        }
    }

  /* The final length of the encrypted payload contents will be
     IV len + data len + padding len + mac len. */
  len = 4 + iv_len + len + pad_len + mac_len;

  /* Allocate the final packet. */
  packet->encoded_packet_len = 28 + len + (packet->use_natt ? 4 : 0);
  packet->encoded_packet = ssh_malloc(packet->encoded_packet_len);
  if (packet->encoded_packet == NULL)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  memset(temp_buffer, 0, sizeof(temp_buffer));

  temp_len =
    ssh_encode_array(packet->encoded_packet,
                     packet->encoded_packet_len,
                     SSH_ENCODE_DATA(ssh_ustr("\0\0\0\0"),
                     (size_t) (packet->use_natt ? 4 : 0)),
                     SSH_ENCODE_DATA(packet->ike_spi_i, (size_t) 8),
                     SSH_ENCODE_DATA(packet->ike_spi_r, (size_t) 8),
                     SSH_ENCODE_CHAR(
                     (unsigned int) SSH_IKEV2_PAYLOAD_TYPE_ENCRYPTED),
                     SSH_ENCODE_CHAR(
                     (unsigned int) ((packet->major_version << 4) |
                                     packet->minor_version)),
                     SSH_ENCODE_CHAR((unsigned int) packet->exchange_type),
                     SSH_ENCODE_CHAR((unsigned int) packet->flags),
                     SSH_ENCODE_UINT32(packet->message_id),
                     SSH_ENCODE_UINT32(packet->encoded_packet_len -
                     (packet->use_natt ? 4 : 0)),
                     /* Generic payload header. */
                     SSH_ENCODE_CHAR((unsigned int) packet->first_payload),
                     SSH_ENCODE_CHAR((unsigned int) 0),
                     SSH_ENCODE_UINT16((SshUInt16) len),
                     /* IV. */
                     SSH_ENCODE_DATA(temp_buffer, iv_len),
                     /* Data. */
                     SSH_ENCODE_DATA(
                     ssh_buffer_ptr(buffer), ssh_buffer_len(buffer)),
                     /* Padding. */
                     SSH_ENCODE_DATA(temp_buffer, pad_len),
                     /* Padding length. */
                     SSH_ENCODE_CHAR((unsigned int) pad_len),
                     /* Mac. */
                     SSH_ENCODE_DATA(temp_buffer, mac_len),
                     SSH_FORMAT_END);
  if (temp_len != packet->encoded_packet_len)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  ikev2_debug_packet_out(packet);

  p = packet->encoded_packet + (packet->use_natt ? 4 : 0);

  /* Copy IV value to packet. For CBC mode ciphers ike_sa->sk_n_len
     is zero. */
  for(i = 0; i < iv_len; i++)
    p[28 + 4 + i]  = iv_buffer[i + ike_sa->sk_n_len];


#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Using cipher %s with key: ",
                                     ike_sa->encrypt_algorithm),
                    (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
                    ike_sa->sk_ei : ike_sa->sk_er, ike_sa->sk_e_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Allocate cipher */
  status =
    ssh_cipher_allocate(ssh_csstr(ike_sa->encrypt_algorithm),
                        (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
                        ike_sa->sk_ei : ike_sa->sk_er, ike_sa->sk_e_len,
                        TRUE, &cipher);
  if (status != SSH_CRYPTO_OK)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("IV"), iv_buffer,
        ssh_cipher_get_iv_length(ssh_csstr(ike_sa->encrypt_algorithm)));

  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Encrypting %u bytes",
                     ssh_buffer_len(buffer) + pad_len + 1),
                    p + 28 + 4 + iv_len,
                    ssh_buffer_len(buffer) + pad_len + 1);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  status = ssh_cipher_set_iv(cipher, iv_buffer);
  if (status != SSH_CRYPTO_OK)
    {
      ssh_cipher_free(cipher);
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  if (combined_encryption == TRUE)
    {
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("AAD"), p, 28 + 4);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

      status = ssh_cipher_auth_start(cipher, p, 28 + 4,
                                     ssh_buffer_len(buffer) + pad_len + 1);
    }
  else
    {
      status = ssh_cipher_start(cipher);
    }

  if (status != SSH_CRYPTO_OK)
    {
      ssh_cipher_free(cipher);
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  status =
    ssh_cipher_transform(cipher,
                         p + 28 + 4 + iv_len,
                         p + 28 + 4 + iv_len,
                         ssh_buffer_len(buffer) + pad_len + 1);

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Encrypted %u bytes",
                     ssh_buffer_len(buffer) + pad_len + 1),
                    p + 28 + 4 + iv_len,
                    ssh_buffer_len(buffer) + pad_len + 1);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  if (status != SSH_CRYPTO_OK)
    {
      ssh_cipher_free(cipher);
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  if (combined_encryption)
    {
      /* Obtain the mac from combined cipher. */
      status = ssh_cipher_auth_final(cipher, temp_buffer);
      ssh_cipher_free(cipher);

      if (status != SSH_CRYPTO_OK)
        return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }
  else
    {
      ssh_cipher_free(cipher);

      /* Calculate the mac separately. */
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Using MAC %s with key: ",
                                         ike_sa->mac_algorithm),
                        (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
                        ike_sa->sk_ai : ike_sa->sk_ar, ike_sa->sk_a_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

      /* Allocate mac. */
      status =
        ssh_mac_allocate(ssh_csstr(ike_sa->mac_algorithm),
                         (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
                         ike_sa->sk_ai : ike_sa->sk_ar, ike_sa->sk_a_len,
                         &mac);
      if (status != SSH_CRYPTO_OK)
        return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("MACing"),
                        p, packet->encoded_packet_len - mac_len -
                        (packet->use_natt ? 4 : 0));
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

      /* Calculate the mac. Mac includes everything from the
         start of the header. */
      ssh_mac_reset(mac);
      ssh_mac_update(mac, p, packet->encoded_packet_len - mac_len -
                     (packet->use_natt ? 4 : 0));
      status = ssh_mac_final(mac, temp_buffer);
      ssh_mac_free(mac);


      /* Check the result of mac calculation. */
      if (status != SSH_CRYPTO_OK)
        return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Output of MAC"),
                    temp_buffer, mac_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Copy the mac to the place. */
  memcpy(packet->encoded_packet + packet->encoded_packet_len - mac_len,
         temp_buffer, mac_len);

  return SSH_IKEV2_ERROR_OK;
}
