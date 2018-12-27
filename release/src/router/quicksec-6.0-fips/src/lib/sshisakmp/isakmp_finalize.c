/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Output finalize routines.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshIkeFinalize"


/*                                                              shade{0.9}
 * Finalize qm hash_1.                                          shade{1.0}
 */

SshIkeNotifyMessageType ike_finalize_qm_hash_1(SshIkeContext context,
                                               SshIkeSA sa,
                                               SshIkeNegotiation negotiation,
                                               SshIkePacket isakmp_packet,
                                               int payload_index,
                                               SshIkePayload payload)
{
  SshIkeNotifyMessageType ret;
  unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;

  if (payload_index != 0)
    ssh_fatal("Hash payload is not first in finalize_qm_hash_1 : %d",
              payload_index);

  ret = ike_calc_qm_hash(context, sa, negotiation,
                         isakmp_packet, hash, &hash_len,
                         FALSE);
  if (ret != 0)
    return ret;

  if (hash_len != payload->payload_length)
    ssh_fatal("Invalid payload_length in finalize_qm_hash_1 : %d != %d",
              payload->payload_length, hash_len);

  memmove(isakmp_packet->payloads[payload_index]->payload_start +
          SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN, hash, hash_len);
  SSH_DEBUG(5, ("Hash[0..%zd] = %08lx %08lx ...",
                hash_len, (unsigned long) SSH_IKE_GET32(hash),
                (unsigned long) SSH_IKE_GET32(hash + 4)));
  return 0;
}


/*                                                              shade{0.9}
 * Finalize qm hash_2.                                          shade{1.0}
 */

SshIkeNotifyMessageType ike_finalize_qm_hash_2(SshIkeContext context,
                                               SshIkeSA sa,
                                               SshIkeNegotiation negotiation,
                                               SshIkePacket isakmp_packet,
                                               int payload_index,
                                               SshIkePayload payload)
{
  SshIkeNotifyMessageType ret;
  unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;

  if (payload_index != 0)
    ssh_fatal("Hash payload is not first in finalize_qm_hash_2 : %d",
              payload_index);

  ret = ike_calc_qm_hash(context, sa, negotiation,
                         isakmp_packet, hash, &hash_len, TRUE);
  if (ret != 0)
    return ret;

  if (hash_len != payload->payload_length)
    ssh_fatal("Invalid payload_length in finalize_qm_hash_2 : %d != %d",
              payload->payload_length, hash_len);

  memmove(isakmp_packet->payloads[payload_index]->payload_start +
          SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN, hash, hash_len);
  return 0;
}



/*                                                              shade{0.9}
 * ike_finalize_mac
 * Finalize Phase 1 authentication hash.                        shade{1.0}
 */

SshIkeNotifyMessageType ike_finalize_mac(SshIkeContext isakmp_context,
                                         SshIkeSA isakmp_sa,
                                         SshIkeNegotiation negotiation,
                                         SshIkePacket isakmp_packet,
                                         int payload_index,
                                         SshIkePayload payload)
{
  SshIkeNotifyMessageType ret;
  unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;

  ret = ike_calc_mac(isakmp_context, isakmp_sa, negotiation,
                     hash, &hash_len, TRUE, NULL);
  if (ret != 0)
    return ret;

  if (hash_len != payload->payload_length)
    ssh_fatal("Invalid payload_length in finalize_mac : %d != %d",
              payload->payload_length, hash_len);

  memmove(isakmp_packet->payloads[payload_index]->payload_start +
          SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN, hash, hash_len);
  return 0;
}


#ifdef SSHDIST_IKE_CERT_AUTH
/*                                                              shade{0.9}
 * ike_finalize_sig
 * Finalize Phase 1 authentication sig.                         shade{1.0}
 */

SshIkeNotifyMessageType ike_finalize_sig(SshIkeContext isakmp_context,
                                         SshIkeSA isakmp_sa,
                                         SshIkeNegotiation negotiation,
                                         SshIkePacket isakmp_packet,
                                         int payload_index,
                                         SshIkePayload payload)
{
  unsigned char *hash;
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;
  SshIkeNotifyMessageType ret;
  SshOperationHandle handle;
  SshCryptoStatus cret;
  const unsigned char *mac_name;
  char *key_type;

  /* Check out if the previous call has finished. */
  if (negotiation->ike_ed->async_return_data_len != 0)
    {
      /* Yes, process data if we have it */
      if (negotiation->ike_ed->async_return_data)
        {
          /* Find the size of signature */
          if (payload->payload_length !=
              negotiation->ike_ed->async_return_data_len)
            ssh_fatal("Invalid payload_length in finalize_sig : %d != %d",
                      payload->payload_length, negotiation->ike_ed->
                      async_return_data_len);
          memmove(isakmp_packet->payloads[payload_index]->payload_start +
                  SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN,
                  negotiation->ike_ed->async_return_data,
                  negotiation->ike_ed->async_return_data_len);

          ssh_free(negotiation->ike_ed->async_return_data);
          negotiation->ike_ed->async_return_data = NULL;
          negotiation->ike_ed->async_return_data_len = 0;
          return 0;
        }
      /* Error occured during operation, return error */
      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 0;
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  /* Find hash context if it is defined for signature function */
  cret = ssh_private_key_get_info(negotiation->ike_ed->private_key,
                                  SSH_PKF_KEY_TYPE, &key_type, SSH_PKF_END);
  if (cret != SSH_CRYPTO_OK)
    {
      SSH_IKE_DEBUG(3, negotiation, ("private_key_get_info failed: %.200s",
                                     ssh_crypto_status_message(cret)));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }
  mac_name = NULL;
  if (strcmp(key_type, "dl-modp") == 0)
    mac_name = ssh_custr("hmac-sha1");

  hash = ike_register_new(isakmp_packet, hash_len);
  if (hash == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  ret = ike_calc_mac(isakmp_context, isakmp_sa, negotiation,
                     hash, &hash_len, TRUE, mac_name);
  if (ret != 0)
    return ret;

  /* Some sanity cheks */
  if (ssh_private_key_max_signature_input_len(negotiation->ike_ed->
                                              private_key) !=
      (size_t) -1 &&
      ssh_private_key_max_signature_input_len(negotiation->ike_ed->
                                              private_key) < hash_len)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Hash too large, private key cannot sign it, "
                     "hash_size = %d",
                     hash_len));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  /* Sign the digest */
  handle = ssh_private_key_sign_digest_async(negotiation->ike_ed->
                                             private_key,
                                             hash, hash_len,
                                             ike_st_o_sig_sign_cb,
                                             negotiation);

  /* Check if we started async operation, or if it is answered directly. */
  if (handle != NULL)
    {
      /* We started real async operation, go on wait.
         NOTE: This should never happen. */
      SSH_IKE_DEBUG(6, negotiation,
                    ("Asyncronous public key operation started"));
      ssh_fatal("Started async signing operation. Not supported for "
                "revised hash yet");
      /*       return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER; */
    }
  /* The result was retrieved immediately, process it now. */
  if (negotiation->ike_ed->async_return_data)
    {
      /* Find the size of signature */
      if (payload->payload_length !=
          negotiation->ike_ed->async_return_data_len)
        ssh_fatal("Invalid payload_length in finalize_sig : %d != %d",
                  payload->payload_length, negotiation->ike_ed->
                  async_return_data_len);
      memmove(isakmp_packet->payloads[payload_index]->payload_start +
              SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN,
              negotiation->ike_ed->async_return_data,
              negotiation->ike_ed->async_return_data_len);

      ssh_free(negotiation->ike_ed->async_return_data);
      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 0;
      return 0;
    }
  /* Error occured during operation, return error */
  negotiation->ike_ed->async_return_data = NULL;
  negotiation->ike_ed->async_return_data_len = 0;
  return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
}
#endif /* SSHDIST_IKE_CERT_AUTH */


/*                                                              shade{0.9}
 * ike_finalize_gen_hash
 * Finalize generic authentication hash.                         shade{1.0}
 */

SshIkeNotifyMessageType ike_finalize_gen_hash(SshIkeContext context,
                                              SshIkeSA sa,
                                              SshIkeNegotiation negotiation,
                                              SshIkePacket isakmp_packet,
                                              int payload_index,
                                              SshIkePayload payload)
{
  SshIkeNotifyMessageType ret;
  unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;

  if (payload_index != 0)
    ssh_fatal("Hash payload is not first in finalize_gen_hash : %d",
              payload_index);

  ret = ike_calc_gen_hash(context, sa, negotiation,
                          isakmp_packet, hash, &hash_len);
  if (ret != 0)
    return ret;

  if (hash_len != payload->payload_length)
    ssh_fatal("Invalid payload_length in finalize_gen_hash : %d != %d",
              payload->payload_length, hash_len);

  memmove(isakmp_packet->payloads[payload_index]->payload_start +
          SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN, hash, hash_len);
  return 0;
}
