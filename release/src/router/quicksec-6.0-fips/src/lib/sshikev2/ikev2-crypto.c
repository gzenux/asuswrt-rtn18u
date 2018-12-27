/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Core crypto routines.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2Crypto"

/** The length of IKEv2 cipher nonces */
#define IKEV2_CIPHER_AES_CTR_NONCE_LEN 4
#define IKEV2_CIPHER_AES_GCM_NONCE_LEN 4
#define IKEV2_CIPHER_AES_CCM_NONCE_LEN 3

/* Calculate IKE SA keying material. */
SshCryptoStatus ikev2_calculate_keys(SshIkev2Sa ike_sa,
                                     unsigned char *digest,
                                     size_t digest_len,
                                     SshIkev2PayloadNonce ni,
                                     SshIkev2PayloadNonce nr)
{
  unsigned char *buffer, *data;
  SshCryptoStatus status;
  size_t data_len;
  size_t mac_len;
  size_t len;

  mac_len = ssh_mac_length(ssh_csstr(ike_sa->prf_algorithm));

  /* Now we have SKEYSEED, calculate the full length needed
     for the output. */
  ike_sa->sk_d_len =
    ssh_mac_get_max_key_length(ssh_csstr(ike_sa->prf_algorithm));
  if (ike_sa->sk_d_len == 0)
    ike_sa->sk_d_len = mac_len;

  ike_sa->sk_p_len = ike_sa->sk_d_len;

  if (ike_sa->mac_algorithm == NULL)
    {
      /* Using combined mode cipher */
      SSH_ASSERT(ssh_cipher_is_auth_cipher(ike_sa->encrypt_algorithm));
      ike_sa->sk_a_len = 0;
    }
  else
    {
      /* Using separate mac algorithm */
      ike_sa->sk_a_len =
        ssh_mac_get_max_key_length(ssh_csstr(ike_sa->mac_algorithm));
      if (ike_sa->sk_a_len == 0)
        {
          int key_len;

          key_len =
            ssh_find_keyword_number(ssh_ikev2_mac_key_lengths,
                                    ssh_csstr(ike_sa->mac_algorithm));
          if (key_len == -1)
            ike_sa->sk_a_len =
              ssh_mac_length(ssh_csstr(ike_sa->mac_algorithm));
          else
            ike_sa->sk_a_len = key_len;
        }
    }

  ike_sa->sk_e_len =
    ssh_cipher_get_key_length(ssh_csstr(ike_sa->encrypt_algorithm));

  /* Only CTR, CCM and GCM mode algorithms use ike_sa->sk_n nonce */
  if (!strcmp(ike_sa->encrypt_algorithm, "aes128-ctr") ||
      !strcmp(ike_sa->encrypt_algorithm, "aes192-ctr") ||
      !strcmp(ike_sa->encrypt_algorithm, "aes256-ctr"))
    ike_sa->sk_n_len = IKEV2_CIPHER_AES_CTR_NONCE_LEN;
  /* Combined mode */
  else if (ike_sa->mac_algorithm == NULL)
    /* Check for CCM mode */
    if (strstr(ike_sa->encrypt_algorithm, "ccm") != NULL)
      {
        ike_sa->sk_n_len = IKEV2_CIPHER_AES_CCM_NONCE_LEN;
      }
    /* Else assume GCM mode */
    else
      {
        ike_sa->sk_n_len = IKEV2_CIPHER_AES_GCM_NONCE_LEN;
      }
  else
    ike_sa->sk_n_len = 0;

  len = ike_sa->sk_d_len + 2 * ike_sa->sk_a_len + 2 * ike_sa->sk_e_len +
    2 * ike_sa->sk_p_len + 2 * ike_sa->sk_n_len;

  data_len = ni->nonce_size + nr->nonce_size + 16;

  buffer = ssh_malloc(len);
  data = ssh_malloc(data_len);
  if (buffer == NULL || data == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Error: Out of memory allocating 2nd temp buffer"));
      /* Error. */
      ssh_free(buffer);
      ssh_free(data);
      return SSH_CRYPTO_NO_MEMORY;
    }
  memcpy(data, ni->nonce_data, ni->nonce_size);
  memcpy(data + ni->nonce_size, nr->nonce_data, nr->nonce_size);
  memcpy(data + ni->nonce_size + nr->nonce_size, ike_sa->ike_spi_i, 8);
  memcpy(data + ni->nonce_size + nr->nonce_size + 8, ike_sa->ike_spi_r, 8);

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("PRF+ data"), data, data_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  status = ssh_prf_plus(ike_sa->prf_algorithm, digest, digest_len,
                        data, data_len, buffer, len);
  memset(digest, 0, digest_len);
  memset(data, 0, data_len);
  ssh_free(data);

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("PRF+ output"), buffer, len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */





  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: ssh_prf_plus(%s) failed: %s",
                              ike_sa->prf_algorithm,
                              ssh_crypto_status_message(status)));
      memset(buffer, 0, len);
      ssh_free(buffer);
      return status;
    }

  ike_sa->sk_d = buffer;
  ike_sa->sk_ai = buffer + ike_sa->sk_d_len;
  ike_sa->sk_ar = ike_sa->sk_ai + ike_sa->sk_a_len;
  ike_sa->sk_ei = ike_sa->sk_ar + ike_sa->sk_a_len;
  ike_sa->sk_ni = ike_sa->sk_ei + ike_sa->sk_e_len;
  ike_sa->sk_er = ike_sa->sk_ni + ike_sa->sk_n_len;
  ike_sa->sk_nr = ike_sa->sk_er + ike_sa->sk_e_len;
  ike_sa->sk_pi = ike_sa->sk_nr + ike_sa->sk_n_len;
  ike_sa->sk_pr = ike_sa->sk_pi + ike_sa->sk_p_len;

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("SK_d"), ike_sa->sk_d, ike_sa->sk_d_len);
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("SK_ai"), ike_sa->sk_ai, ike_sa->sk_a_len);
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("SK_ar"), ike_sa->sk_ar, ike_sa->sk_a_len);
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("SK_ei"), ike_sa->sk_ei, ike_sa->sk_e_len);
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("SK_er"), ike_sa->sk_er, ike_sa->sk_e_len);
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("SK_ni"), ike_sa->sk_ni, ike_sa->sk_n_len);
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("SK_nr"), ike_sa->sk_nr, ike_sa->sk_n_len);
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("SK_pi"), ike_sa->sk_pi, ike_sa->sk_p_len);
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("SK_pr"), ike_sa->sk_pr, ike_sa->sk_p_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */
  return SSH_CRYPTO_OK;
}

/* IKEv2 SA Diffie-Hellman Agree. */
void ikev2_skeyseed_agree(SshCryptoStatus status,
                          const unsigned char *shared_secret_buffer,
                          size_t shared_secret_buffer_len,
                          void *context)
{
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned char *buffer;
  SshIkev2Sa ike_sa;
  Boolean truncate;
  size_t mac_len;
  SshMac mac;
  size_t len;

  ike_sa = context;

  if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_ABORTED)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("DH agree callback called for aborted SA %p",
                                 ike_sa));
      return;
    }

  ike_sa->initial_ed->operation = NULL;

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Error: DH agree for SA %p failed: %s",
                             ike_sa,
                             ssh_crypto_status_message(status)));
      goto error;
    }

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Shared secret from Diffie-Hellman"),
                    shared_secret_buffer,
                    shared_secret_buffer_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  len = ssh_mac_get_max_key_length(ssh_csstr(ike_sa->prf_algorithm));

  truncate = TRUE;

  if (len == 0 ||
      len > ike_sa->initial_ed->ike_ed->ni->nonce_size +
      ike_sa->initial_ed->ike_ed->nr->nonce_size)
    {
      len = ike_sa->initial_ed->ike_ed->ni->nonce_size +
        ike_sa->initial_ed->ike_ed->nr->nonce_size;
      truncate = FALSE;
    }

  buffer = ssh_malloc(len);
  if (buffer == NULL)
    {
      /* Error. */
      SSH_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating temp buffer"));
      goto error;
    }
  memset(buffer, 0, len);
  /* NOTE: What should we do if the nonce 1 is 128 bytes, and nonce 2 is 32
     bytes, and the mac only takes 128 bytes as input. Currently we take 64
     bytes from nonce 1 and 32 bytes from nonce 2. Perhaps we should take 96
     bytes from nonce 1 and 32 bytes of nonce 2. */
  if (truncate)
    {
      memcpy(buffer, ike_sa->initial_ed->ike_ed->ni->nonce_data,
             (len / 2) > ike_sa->initial_ed->ike_ed->ni->nonce_size ?
             ike_sa->initial_ed->ike_ed->ni->nonce_size : len / 2);
      memcpy(buffer + len / 2,
             ike_sa->initial_ed->ike_ed->nr->nonce_data,
             (len / 2) > ike_sa->initial_ed->ike_ed->nr->nonce_size ?
             ike_sa->initial_ed->ike_ed->nr->nonce_size : len / 2);
    }
  else
    {
      memcpy(buffer, ike_sa->initial_ed->ike_ed->ni->nonce_data,
             ike_sa->initial_ed->ike_ed->ni->nonce_size);
      memcpy(buffer + ike_sa->initial_ed->ike_ed->ni->nonce_size,
             ike_sa->initial_ed->ike_ed->nr->nonce_data,
             ike_sa->initial_ed->ike_ed->nr->nonce_size);
    }


#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Key for PRF (Ni | Nr)"), buffer, len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Allocate mac. */
  status = ssh_mac_allocate(ssh_csstr(ike_sa->prf_algorithm),
                            buffer, len, &mac);
  memset(buffer, 0, len);
  ssh_free(buffer);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: ssh_mac_allocate(%s) failed: %s",
                              ike_sa->prf_algorithm,
                              ssh_crypto_status_message(status)));
      goto error;
    }

  /* Calculate SKEYSEED. */
  ssh_mac_reset(mac);
  ssh_mac_update(mac, shared_secret_buffer, shared_secret_buffer_len);
  status = ssh_mac_final(mac, digest);
  ssh_mac_free(mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: ssh_mac_final(%s) failed: %s",
                              ike_sa->prf_algorithm,
                              ssh_crypto_status_message(status)));
      goto error;
    }

  mac_len = ssh_mac_length(ssh_csstr(ike_sa->prf_algorithm));
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("SKEYSEED"), digest, mac_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  status = ikev2_calculate_keys(ike_sa, digest, mac_len,
                                ike_sa->initial_ed->ike_ed->ni,
                                ike_sa->initial_ed->ike_ed->nr);
  memset(digest, 0, sizeof(digest));
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: ikev2_calculate_keys(%s) failed: %s",
                              ike_sa->prf_algorithm,
                              ssh_crypto_status_message(status)));
      goto error;
    }

  if (ike_sa->initial_ed->packet_to_process)
    ikev2_restart_packet(ike_sa->initial_ed->packet_to_process);
  SSH_DEBUG(SSH_D_LOWOK, ("SKEYSEED calculation done"));
  return;

 error:
  /* Mark the failure in the agree operation. The non NULL
     sk_d will indicate that we have finished the operation,
     but zero length sk_d_len will tell that it failed. The
     actual error code will be sent to the other end after
     the next packet comes in. */
  ike_sa->sk_d = (void *) 1;
  ike_sa->sk_d_len = 0;
  if (ike_sa->initial_ed->packet_to_process)
    ikev2_restart_packet(ike_sa->initial_ed->packet_to_process);
  return;
}

/* Calculate IKE SA rekey keymat. */
SshCryptoStatus
ikev2_calculate_rekey_skeyseed(SshIkev2ExchangeData ed)
{
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  SshCryptoStatus status;
  SshIkev2Sa new_ike_sa;
  size_t mac_len;
  SshMac mac;

  new_ike_sa = ed->ipsec_ed->new_ike_sa;
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Shared secret from Diffie-Hellman"),
                    ed->ipsec_ed->shared_secret_buffer,
                    ed->ipsec_ed->shared_secret_buffer_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Key for PRF (SK_d(old))"), ed->ike_sa->sk_d,
                    ed->ike_sa->sk_d_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Allocate mac. */
  status = ssh_mac_allocate(ssh_csstr(ed->ike_sa->prf_algorithm),
                            ed->ike_sa->sk_d,
                            ed->ike_sa->sk_d_len, &mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: ssh_mac_allocate(%s) failed: %s",
                              ed->ike_sa->prf_algorithm,
                              ssh_crypto_status_message(status)));
      return status;
    }

  /* Calculate SKEYSEED. */
  ssh_mac_reset(mac);
  if (ed->ipsec_ed->shared_secret_buffer_len != 0)
    ssh_mac_update(mac, ed->ipsec_ed->shared_secret_buffer,
                   ed->ipsec_ed->shared_secret_buffer_len);
  ssh_mac_update(mac, ed->ipsec_ed->ni->nonce_data,
                 ed->ipsec_ed->ni->nonce_size);
  ssh_mac_update(mac, ed->ipsec_ed->nr->nonce_data,
                 ed->ipsec_ed->nr->nonce_size);
  status = ssh_mac_final(mac, digest);
  ssh_mac_free(mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: ssh_mac_final(%s) failed: %s",
                              ed->ike_sa->prf_algorithm,
                              ssh_crypto_status_message(status)));
      return status;
    }

  mac_len = ssh_mac_length(ssh_csstr(ed->ike_sa->prf_algorithm));
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("SKEYSEED"), digest, mac_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  status = ikev2_calculate_keys(new_ike_sa, digest, mac_len,
                                ed->ipsec_ed->ni,
                                ed->ipsec_ed->nr);
  memset(digest, 0, sizeof(digest));
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: ikev2_calculate_keys(%s) failed: %s",
                              ed->ike_sa->prf_algorithm,
                              ssh_crypto_status_message(status)));
      return status;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("SKEYSEED calculation done"));
  return SSH_CRYPTO_OK;
}


/* Start calculating ikev2_skeyseed. When the operation is
   finished either restart the packet if we have or simply
   stop and wait for the packet. */
void ikev2_skeyseed(void *context)
{
  SshIkev2Sa ike_sa = context;
  SshPkGroupDHSecret dh_secret;

  /* Check that we do not start operation if there is
     already operation in progress, or if we have already
     finished the operation. */
  if (ike_sa->initial_ed->operation != NULL ||
      ike_sa->sk_d != NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("We already have SKEYSEED calculation for SA %p in progress",
                 ike_sa));
      return;
    }

  /* Check that we have all data, and if not so, indicate error. */
  if (ike_sa->initial_ed->ike_ed == NULL ||
      ike_sa->initial_ed->ike_ed->group == NULL ||
      ike_sa->initial_ed->ike_ed->dh_secret == NULL ||
      ike_sa->initial_ed->ke->key_exchange_data == NULL ||
      ike_sa->initial_ed->ke->key_exchange_len == 0)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Error: Some data missing when trying to generate SKEYSEED"));
      ike_sa->sk_d = (void *) 1;
      ike_sa->sk_d_len = 0;
      return;
    }

  /* We need to mark that secret is already freed before calling the async
     callback, as it might be possible that the exchange is canceled during the
     async call and that will cancel the async operation (causing dh_secret to
     be freed), and set the next state to be some error state, i.e. the
     callback will never be called. */
  dh_secret = ike_sa->initial_ed->ike_ed->dh_secret;
  ike_sa->initial_ed->ike_ed->dh_secret = NULL;

  SSH_DEBUG(SSH_D_LOWSTART, ("Starting SKEYSEED calculation for SA %p",
                             ike_sa));
  ike_sa->initial_ed->operation =
    ssh_pk_group_dh_agree_async(ike_sa->initial_ed->ike_ed->group,
                                dh_secret,
                                ike_sa->initial_ed->
                                ke->key_exchange_data,
                                ike_sa->initial_ed->
                                ke->key_exchange_len,
                                ikev2_skeyseed_agree,
                                ike_sa);
}

/* Generate stateless cookie based on the secret, nonce,
   spi_i and ip-address. */
SshIkev2Error ikev2_generate_cookie(SshIkev2Packet packet,
                                    SshIkev2Sa ike_sa,
                                    unsigned char *notify_data,
                                    size_t notify_len)
{
  SshCryptoStatus status;
  unsigned char buffer[16];
  SshMac mac;
  size_t len;

  SSH_DEBUG(SSH_D_LOWOK, ("Starting cookie generation for SA %p", ike_sa));
  packet->ed->ike_ed->cookie_len = 4 +
    ssh_mac_length(IKEV2_COOKIE_MAC_ALGORITHM);
  packet->ed->ike_ed->cookie =
    ssh_obstack_alloc(packet->ed->obstack,
                      packet->ed->ike_ed->cookie_len);
  if (packet->ed->ike_ed->cookie == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating cookie"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  if (notify_len > 4 && notify_data != NULL &&
      SSH_GET_32BIT(notify_data) ==
      ike_sa->server->context->cookie_version_number - 1)
    {
      ike_sa->server->context->cookie_secret_use_counter_prev++;
      SSH_PUT_32BIT(packet->ed->ike_ed->cookie,
                    ike_sa->server->context->cookie_version_number - 1);
      status = ssh_mac_allocate(IKEV2_COOKIE_MAC_ALGORITHM,
                                ike_sa->server->context->cookie_secret_prev,
                                IKEV2_COOKIE_SECRET_LEN, &mac);
    }
  else
    {
      ike_sa->server->context->cookie_secret_use_counter++;
      SSH_PUT_32BIT(packet->ed->ike_ed->cookie,
                    ike_sa->server->context->cookie_version_number);
      status = ssh_mac_allocate(IKEV2_COOKIE_MAC_ALGORITHM,
                                ike_sa->server->context->cookie_secret,
                                IKEV2_COOKIE_SECRET_LEN, &mac);
    }
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: ssh_mac_allocate(%s) failed: %s",
                              IKEV2_COOKIE_MAC_ALGORITHM,
                              ssh_crypto_status_message(status)));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  ssh_mac_reset(mac);
  ssh_mac_update(mac, packet->ed->nonce->nonce_data,
                 packet->ed->nonce->nonce_size);
  SSH_IP_ENCODE(packet->remote_ip, buffer, len);
  ssh_mac_update(mac, buffer, len);
  ssh_mac_update(mac, packet->ike_spi_i, 8);
  status = ssh_mac_final(mac, packet->ed->ike_ed->cookie + 4);
  ssh_mac_free(mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: ssh_mac_final(%s) failed: %s",
                              IKEV2_COOKIE_MAC_ALGORITHM,
                              ssh_crypto_status_message(status)));
      return SSH_IKEV2_ERROR_CRYPTO_FAIL;
    }
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Cookie generated"),
                    packet->ed->ike_ed->cookie,
                    packet->ed->ike_ed->cookie_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */
  return SSH_IKEV2_ERROR_OK;
}

/* Generate the AUTH data to be signed or MACed. It consist
   of either remote or local packet, either initiator or
   responder Nonce and either initiator or responder ID
   payload. Return NULL if failure, otherwise return
   mallocated string to be used. */
unsigned char *
ikev2_auth_data(SshIkev2Packet packet,
                Boolean local_packet,
                Boolean initiator_nonce,
                Boolean initiator_id,
                size_t *return_len)
{
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;
  SshIkev2Sa ike_sa = packet->ike_sa;
  unsigned char buffer[4], *ret;
  SshCryptoStatus status;
  unsigned char *p1, *p2;
  size_t len1, len2, len3;
  SshIkev2PayloadID id;
  unsigned char *sk_p;
  SshMac mac;

  if (ike_sa->sk_d_len == 0)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Diffie-Hellman failed before ike-auth-data computation"));
      *return_len = 0;
      return NULL;
    }

  if (local_packet)
    {
      p1 = ed->local_ike_sa_init;
      len1 = ed->local_ike_sa_init_len;
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Using local packet"));
    }
  else
    {
      p1 = ed->remote_ike_sa_init;
      len1 = ed->remote_ike_sa_init_len;
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Using remote packet"));
    }

  if (initiator_nonce)
    {
      p2 = ed->ni->nonce_data;
      len2 = ed->ni->nonce_size;
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Using initiator nonce"));
    }
  else
    {
      p2 = ed->nr->nonce_data;
      len2 = ed->nr->nonce_size;
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Using responder nonce"));
    }

  if (initiator_id)
    {
      sk_p = ike_sa->sk_pi;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
      if (ed->first_auth_done)
        {
          id = ed->second_id_i;
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Using second IDi and sk_pi"));
        }
      else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
        {
          id = ed->id_i;
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Using IDi and sk_pi"));
        }
    }
  else
    {
      id = ed->id_r;
      sk_p = ike_sa->sk_pr;
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Using IDr and sk_pr"));
    }

  len3 = ssh_mac_length(ssh_csstr(ike_sa->prf_algorithm));

  *return_len = len1 + len2 + len3;

#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Allocating sk_p_mac(%s) with key",
                     ike_sa->prf_algorithm),
                    sk_p, ike_sa->sk_p_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  /* Allocate mac. */
  status = ssh_mac_allocate(ssh_csstr(ike_sa->prf_algorithm),
                            sk_p, ike_sa->sk_p_len, &mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: ssh_mac_allocate(%s) failed: %s",
                              ike_sa->prf_algorithm,
                              ssh_crypto_status_message(status)));
      return NULL;
    }
  ssh_mac_reset(mac);
  buffer[0] = id->id_type;
  buffer[1] = (id->id_reserved >> 16) & 0xff;
  buffer[2] = (id->id_reserved >> 8) & 0xff;
  buffer[3] = id->id_reserved & 0xff;
  ssh_mac_update(mac, buffer, 4);
  ssh_mac_update(mac, id->id_data, id->id_data_size);
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Adding to sk_p_mac(%s)", ike_sa->prf_algorithm),
                    buffer, 4);
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Adding to sk_p_mac(%s)", ike_sa->prf_algorithm),
                    id->id_data, id->id_data_size);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */
  status = ssh_mac_final(mac, digest);
  ssh_mac_free(mac);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: ssh_mac_final(%s) failed: %s",
                              ike_sa->prf_algorithm,
                              ssh_crypto_status_message(status)));
      return NULL;
    }
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Output of sk_p_mac(%s)", ike_sa->prf_algorithm),
                    digest, len3);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  ret = ssh_malloc(len1 + len2 + len3);
  if (ret == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating auth_data"));
      return NULL;
    }

  memcpy(ret, p1, len1);
  memcpy(ret + len1, p2, len2);
  memcpy(ret + len1 + len2, digest, len3);
  memset(digest, 0, sizeof(digest));
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Output auth data"),
                    ret, len1 + len2 + len3);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */
  return ret;
}

/* Generate keying material for the IPsec SA. The keymat is
   filled with the keying material. */
SshIkev2Error ssh_ikev2_fill_keymat(SshIkev2ExchangeData ed,
                                    unsigned char *keymat,
                                    size_t keymat_len)
{
  SshIkev2Sa ike_sa = ed->ike_sa;
  SshIkev2PayloadNonce ni, nr;
  SshCryptoStatus status;
  unsigned char *buffer;
  size_t len;

#ifdef SSHDIST_IKEV1
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      if (keymat_len > ed->ipsec_ed->ikev1_keymat_len)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Insufficient keying material available, "
                                 "requested bytes %d, available bytes %d",
                                 keymat_len, ed->ipsec_ed->ikev1_keymat_len));
          return SSH_IKEV2_ERROR_CRYPTO_FAIL;
        }

      memcpy(keymat, ed->ipsec_ed->ikev1_keymat, keymat_len);
      return SSH_IKEV2_ERROR_OK;
    }
#endif /* SSHDIST_IKEV1 */

  if (ike_sa->initial_ed == ed)
    {
      ni = ed->ike_ed->ni;
      nr = ed->ike_ed->nr;
    }
  else if (ed->ipsec_ed != NULL)
    {
      ni = ed->ipsec_ed->ni;
      nr = ed->ipsec_ed->nr;
    }

  else
    {
      return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }
  len = ed->ipsec_ed->shared_secret_buffer_len +  ni->nonce_size +
    nr->nonce_size;

  buffer = ssh_malloc(len);
  if (buffer == NULL)
    {
      /* Error. */
      SSH_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating buffer"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }
  if (ed->ipsec_ed->shared_secret_buffer_len != 0)
    memcpy(buffer, ed->ipsec_ed->shared_secret_buffer,
           ed->ipsec_ed->shared_secret_buffer_len);
  memcpy(buffer + ed->ipsec_ed->shared_secret_buffer_len,
         ni->nonce_data, ni->nonce_size);
  memcpy(buffer + ed->ipsec_ed->shared_secret_buffer_len + ni->nonce_size,
         nr->nonce_data, nr->nonce_size);
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Using PRF+(%s) with key",
                                     ike_sa->prf_algorithm),
                    ike_sa->sk_d, ike_sa->sk_d_len);
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("With PRF+ data"),
                    buffer, len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */

  status = ssh_prf_plus(ike_sa->prf_algorithm,
                        ike_sa->sk_d, ike_sa->sk_d_len,
                        buffer, len, keymat, keymat_len);
  memset(buffer, 0, len);
  ssh_free(buffer);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: ssh_prf_plus(%s) failed: %s",
                              ike_sa->prf_algorithm,
                              ssh_crypto_status_message(status)));
      return SSH_IKEV2_ERROR_CRYPTO_FAIL;
    }
#ifdef SSH_IKEV2_CRYPTO_KEY_DEBUG
  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Output of PRF+"),
                    keymat, keymat_len);
#endif /* SSH_IKEV2_CRYPTO_KEY_DEBUG */
  return SSH_IKEV2_ERROR_OK;
}
