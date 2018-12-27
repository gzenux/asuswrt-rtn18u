/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp encryption / decryption routines.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshIkeCrypt"

#ifdef SSHDIST_IKE_CERT_AUTH
/*                                                              shade{0.9}
 * ike_find_public_key
 * Find public_key for the connection. If the
 * hash_out_buffer is given then hash of the key is
 * stored there (only if multiple keys for host found).
 * The hash_out_buffer_len is in/out parameter, that will
 * contain the allocated length of hash_out_buffer (in) and
 * this function will set it to match used length of buffer.    shade{1.0}
 */

SshIkeNotifyMessageType ike_find_public_key(SshIkeContext isakmp_context,
                                            SshIkeSA isakmp_sa,
                                            SshIkeNegotiation negotiation,
                                            unsigned char *hash_out_buffer,
                                            size_t *hash_out_len,
                                            const unsigned char *hash_name)
{
  SshPolicyKeyType key_type = SSH_IKE_POLICY_KEY_TYPE_RSA_SIG;

  SSH_DEBUG(5, ("Find public key for %s:%s, id = %s -> %s:%s, id = %s",
                negotiation->ike_pm_info->local_ip,
                negotiation->ike_pm_info->local_port,
                negotiation->ike_pm_info->local_id_txt,
                negotiation->ike_pm_info->remote_ip,
                negotiation->ike_pm_info->remote_port,
                negotiation->ike_pm_info->remote_id_txt));

  if (negotiation->ike_ed->public_key != NULL)
    {
      if (hash_name != NULL)
        {
          if (*hash_out_len < negotiation->ike_ed->public_key_hash_len)
            ssh_fatal("Internal, ike_find_public_key gets "
                      "too small hash buffer");
          memcpy(hash_out_buffer, negotiation->ike_ed->public_key_hash,
                 negotiation->ike_ed->public_key_hash_len);
          *hash_out_len = negotiation->ike_ed->public_key_hash_len;
        }
      return 0;
    }

  switch (negotiation->ike_pm_info->auth_method)
    {
    case SSH_IKE_VALUES_AUTH_METH_PRE_SHARED_KEY:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_PRE_SHARED:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_PRE_SHARED:
#endif /* SSHDIST_IKE_XAUTH */
#ifdef REMOVED_BY_DOI_DRAFT_07
    case SSH_IKE_VALUES_AUTH_METH_GSSAPI:
#endif
      SSH_DEBUG(6, ("Isakmp_find_public_key called with invalid "
                    "auth_method : %d",
                    negotiation->ike_pm_info->auth_method));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
      break;
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_I_DSS_SIGNATURES:
      if (!negotiation->ike_pm_info->this_end_is_initiator)
        {
          SSH_DEBUG(6, ("Isakmp_find_public_key called with invalid "
                        "auth_method : %d",
                        negotiation->ike_pm_info->auth_method));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      key_type = SSH_IKE_POLICY_KEY_TYPE_DSS_SIG;
      break;
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_R_DSS_SIGNATURES:
      if (negotiation->ike_pm_info->this_end_is_initiator)
        {
          SSH_DEBUG(6, ("Isakmp_find_public_key called with invalid "
                        "auth_method : %d",
                        negotiation->ike_pm_info->auth_method));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      key_type = SSH_IKE_POLICY_KEY_TYPE_DSS_SIG;
      break;
#endif /* SSHDIST_IKE_XAUTH */
    case SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_DSS_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_DSS_SIGNATURES:
#endif /* SSHDIST_IKE_XAUTH */
      key_type = SSH_IKE_POLICY_KEY_TYPE_DSS_SIG;
      break;
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_I_RSA_SIGNATURES:
      if (!negotiation->ike_pm_info->this_end_is_initiator)
        {
          SSH_DEBUG(6, ("Isakmp_find_public_key called with invalid "
                        "auth_method : %d",
                        negotiation->ike_pm_info->auth_method));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      key_type = SSH_IKE_POLICY_KEY_TYPE_RSA_SIG;
      break;
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_R_RSA_SIGNATURES:
      if (negotiation->ike_pm_info->this_end_is_initiator)
        {
          SSH_DEBUG(6, ("Isakmp_find_public_key called with invalid "
                        "auth_method : %d",
                        negotiation->ike_pm_info->auth_method));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      key_type = SSH_IKE_POLICY_KEY_TYPE_RSA_SIG;
      break;
#endif /* SSHDIST_IKE_XAUTH */
    case SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_SIGNATURES:
#endif /* SSHDIST_IKE_XAUTH */
      key_type = SSH_IKE_POLICY_KEY_TYPE_RSA_SIG;
      break;
#ifdef SSHDIST_CRYPT_ECP
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_256:
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_384:
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_521:
      key_type = SSH_IKE_POLICY_KEY_TYPE_ECP_DSA_SIG;
      break;
#endif /* SSHDIST_CRYPT_ECP */
    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION_REVISED:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION_REVISED:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION_REVISED:
#endif /* SSHDIST_IKE_XAUTH */
      key_type = SSH_IKE_POLICY_KEY_TYPE_RSA_ENC;
      break;
    }

  /* Send query */
  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;

  ssh_policy_find_public_key(negotiation->ike_pm_info,
                             key_type, hash_name,
                             ike_policy_reply_find_public_key,
                             negotiation);

  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
    {
      /* Policy manager could not reply to query immediately. Return
         RETRY_LATER to state machine so it will postpone processing of the
         packet until the policy manager answers and calls
         callback function. Clear PROCESSING_PM_QUERY flag before returning to
         the state machine. Note that state machine will set the
         WAITING_PM_REPLY flag. */
      negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
    }

  if (negotiation->ike_ed->public_key == NULL)
    {
      SSH_DEBUG(7, ("Policy manager didn't find public key"));
      SSH_IKE_NOTIFY_TEXT(negotiation, "No public key found");
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }
  if (hash_name != NULL)
    {
      if (*hash_out_len < negotiation->ike_ed->public_key_hash_len)
        ssh_fatal("Internal, ike_find_public_key gets too small hash buffer");
      memcpy(hash_out_buffer, negotiation->ike_ed->public_key_hash,
             negotiation->ike_ed->public_key_hash_len);
      *hash_out_len = negotiation->ike_ed->public_key_hash_len;
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_find_private_key
 * Find private_key for the connection.                         shade{1.0}
 */

SshIkeNotifyMessageType ike_find_private_key(SshIkeContext isakmp_context,
                                             SshIkeSA isakmp_sa,
                                             SshIkeNegotiation negotiation,
                                             unsigned char *hash,
                                             size_t hash_len,
                                             const unsigned char *hash_name)
{
  SshPolicyKeyType key_type = SSH_IKE_POLICY_KEY_TYPE_RSA_SIG;

  SSH_DEBUG(5, ("Find private key for %s:%s, id = %s -> %s:%s, id = %s",
                negotiation->ike_pm_info->local_ip,
                negotiation->ike_pm_info->local_port,
                negotiation->ike_pm_info->local_id_txt,
                negotiation->ike_pm_info->remote_ip,
                negotiation->ike_pm_info->remote_port,
                negotiation->ike_pm_info->remote_id_txt));

  if (negotiation->ike_ed->private_key != NULL)
    return 0;

  switch (negotiation->ike_pm_info->auth_method)
    {
    case SSH_IKE_VALUES_AUTH_METH_PRE_SHARED_KEY:
#ifdef REMOVED_BY_DOI_DRAFT_07
    case SSH_IKE_VALUES_AUTH_METH_GSSAPI:
#endif
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_PRE_SHARED:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_PRE_SHARED:
#endif /* SSHDIST_IKE_XAUTH */
      SSH_DEBUG(6, ("Isakmp_find_private_key called with invalid "
                    "auth_method : %d",
                    negotiation->ike_pm_info->auth_method));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
      break;
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_I_DSS_SIGNATURES:
      if (negotiation->ike_pm_info->this_end_is_initiator)
        {
          SSH_DEBUG(6, ("Isakmp_find_public_key called with invalid "
                        "auth_method : %d",
                        negotiation->ike_pm_info->auth_method));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      key_type = SSH_IKE_POLICY_KEY_TYPE_DSS_SIG;
      break;
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_R_DSS_SIGNATURES:
      if (!negotiation->ike_pm_info->this_end_is_initiator)
        {
          SSH_DEBUG(6, ("Isakmp_find_public_key called with invalid "
                        "auth_method : %d",
                        negotiation->ike_pm_info->auth_method));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      key_type = SSH_IKE_POLICY_KEY_TYPE_DSS_SIG;
      break;
#endif /* SSHDIST_IKE_XAUTH */
    case SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_DSS_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_DSS_SIGNATURES:
#endif /* SSHDIST_IKE_XAUTH */
      key_type = SSH_IKE_POLICY_KEY_TYPE_DSS_SIG;
      break;
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_I_RSA_SIGNATURES:
      if (negotiation->ike_pm_info->this_end_is_initiator)
        {
          SSH_DEBUG(6, ("Isakmp_find_public_key called with invalid "
                        "auth_method : %d",
                        negotiation->ike_pm_info->auth_method));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      key_type = SSH_IKE_POLICY_KEY_TYPE_RSA_SIG;
      break;
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_R_RSA_SIGNATURES:
      if (!negotiation->ike_pm_info->this_end_is_initiator)
        {
          SSH_DEBUG(6, ("Isakmp_find_public_key called with invalid "
                        "auth_method : %d",
                        negotiation->ike_pm_info->auth_method));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      key_type = SSH_IKE_POLICY_KEY_TYPE_RSA_SIG;
      break;
#endif /* SSHDIST_IKE_XAUTH */
    case SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_SIGNATURES:
#endif /* SSHDIST_IKE_XAUTH */
      key_type = SSH_IKE_POLICY_KEY_TYPE_RSA_SIG;
      break;
#ifdef SSHDIST_CRYPT_ECP
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_256:
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_384:
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_521:
      key_type = SSH_IKE_POLICY_KEY_TYPE_ECP_DSA_SIG;
      break;
#endif /* SSHDIST_CRYPT_ECP */
    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION_REVISED:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION_REVISED:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION_REVISED:
#endif /* SSHDIST_IKE_XAUTH */
      key_type = SSH_IKE_POLICY_KEY_TYPE_RSA_ENC;
      break;
    }

  /* Send query */
  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;

  ssh_policy_find_private_key(negotiation->ike_pm_info,
                              key_type, hash_name, hash, hash_len,
                              ike_policy_reply_find_private_key,
                              negotiation);

  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
    {
      /* Policy manager could not reply to query immediately. Return
         RETRY_LATER to state machine so it will postpone processing of the
         packet until the policy manager answers and calls
         callback function. Clear PROCESSING_PM_QUERY flag before returning to
         the state machine. Note that state machine will set the
         WAITING_PM_REPLY flag. */
      negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
    }

  if (negotiation->ike_ed->private_key == NULL)
    {
      SSH_DEBUG(7, ("Policy manager didn't find private key"));
      SSH_IKE_NOTIFY_TEXT(negotiation, "No private key found");
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }
  return 0;
}
#endif /* SSHDIST_IKE_CERT_AUTH */


/*                                                              shade{0.9}
 * ike_find_pre_shared_key
 * Find pre-shared key for the connection.                      shade{1.0}
 */

SshIkeNotifyMessageType ike_find_pre_shared_key(SshIkeContext isakmp_context,
                                                SshIkeSA isakmp_sa,
                                                SshIkeNegotiation negotiation)
{
  SSH_DEBUG(5, ("Find pre shared key key for %s:%s, id = %s -> %s:%s, id = %s",
                negotiation->ike_pm_info->local_ip,
                negotiation->ike_pm_info->local_port,
                negotiation->ike_pm_info->local_id_txt,
                negotiation->ike_pm_info->remote_ip,
                negotiation->ike_pm_info->remote_port,
                negotiation->ike_pm_info->remote_id_txt));

  if (negotiation->ike_ed->pre_shared_key_len)
    goto end;

  /* Send query */
  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
  ssh_policy_find_pre_shared_key(negotiation->ike_pm_info,
                                 ike_policy_reply_find_pre_shared_key,
                                 negotiation);
  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
    {
      /* Policy manager could not reply to query immediately. Return
         RETRY_LATER to state machine so it will postpone processing of the
         packet until the policy manager answers and calls callback function.
         Clear PROCESSING_PM_QUERY flag before returning to the state machine.
         Note that state machine will set the WAITING_PM_REPLY flag. */
      negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
    }

 end:
  if (negotiation->ike_ed->pre_shared_key == NULL)
    {
      SSH_DEBUG(7, ("Policy manager didn't find pre shared key"));
      SSH_IKE_NOTIFY_TEXT(negotiation, "No pre shared key found");
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }
  return 0;
}


#ifdef SSHDIST_IKE_CERT_AUTH
/*                                                              shade{0.9}
 * ike_async_decrypt_done_cb
 * Callback to be call when async decrypt is done.              shade{1.0}
 */
void ike_async_decrypt_done_cb(SshCryptoStatus status,
                               const unsigned char *plaintext_buffer,
                               size_t plaintext_buffer_len,
                               void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;

  if (status == SSH_CRYPTO_OK)
    {
      negotiation->ike_ed->async_return_data_len = plaintext_buffer_len;
      negotiation->ike_ed->async_return_data =
        ssh_memdup(plaintext_buffer, plaintext_buffer_len);
      if (negotiation->ike_ed->async_return_data == NULL)
        {
          negotiation->ike_ed->async_return_data = NULL;
          negotiation->ike_ed->async_return_data_len = 1;
        }
    }
  else
    {
      /* Signal the error case */
      SSH_IKE_DEBUG(3, negotiation,
                    ("Error in ssh_private_key_decrypt_async: %.200s",
                     ssh_crypto_status_message(status)));
      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 1;
    }

  /* Check if we need to restart the state machine */
  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY)
    ike_state_restart_packet(negotiation);
}

/*                                                              shade{0.9}
 * ike_rsa_decrypt_data
 * Decrypt given data by private key.                           shade{1.0}
 */

SshIkeNotifyMessageType ike_rsa_decrypt_data(SshIkeContext isakmp_context,
                                             SshIkeSA isakmp_sa,
                                             SshIkeNegotiation negotiation,
                                             unsigned char *data,
                                             size_t len,
                                             unsigned char **return_data,
                                             size_t *return_len)
{
  SshIkeNotifyMessageType ret;
  SshCryptoStatus cret;
  SshOperationHandle handle;

  SSH_DEBUG(5, ("RSA decrypt: data[0..%zd] = %08lx %08lx ...",
                len, (unsigned long) SSH_IKE_GET32(data),
                (unsigned long) SSH_IKE_GET32(data + 4)));

  /* Check out if the previous call has finished. */
  if (negotiation->ike_ed->async_return_data_len != 0)
    {
      /* Yes, return data if we have it */
      if (negotiation->ike_ed->async_return_data)
        {
          *return_data = negotiation->ike_ed->async_return_data;
          *return_len = negotiation->ike_ed->async_return_data_len;
          negotiation->ike_ed->async_return_data = NULL;
          negotiation->ike_ed->async_return_data_len = 0;
          return 0;
        }
      /* Error occured during operation return error */
      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 0;
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  ret = ike_find_private_key(isakmp_context, isakmp_sa, negotiation,
                             NULL, 0, NULL);

  if (ret != 0)
    return ret;

  cret = ssh_private_key_select_scheme(negotiation->ike_ed->private_key,
                                       SSH_PKF_ENCRYPT, "rsa-pkcs1-none",
                                       SSH_PKF_END);

  if (cret != SSH_CRYPTO_OK)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Error in ssh_private_key_select_scheme: %.200s",
                     ssh_crypto_status_message(cret)));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  if (len > ssh_private_key_max_decrypt_input_len(negotiation->ike_ed->
                                                  private_key))
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Length too large for public key, max = %d bytes",
                     ssh_private_key_max_decrypt_input_len(negotiation->
                                                           ike_ed->
                                                           private_key)));
      SSH_IKE_NOTIFY_TEXT(negotiation, "Data length too large for private "
                          "key to decrypt");
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  /* Decrypt the buffer */
  handle = ssh_private_key_decrypt_async(negotiation->ike_ed->private_key,
                                         data, len,
                                         ike_async_decrypt_done_cb,
                                         negotiation);

  /* Check if we started async operation, or if it is answered directly. */
  if (handle != NULL)
    {
      /* We started real async operation, go on wait */
      SSH_IKE_DEBUG(6, negotiation,
                    ("Asyncronous private key operation started"));
      return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
    }
  /* The result was retrieved immediately, process it now. */
  if (negotiation->ike_ed->async_return_data)
    {
      *return_data = negotiation->ike_ed->async_return_data;
      *return_len = negotiation->ike_ed->async_return_data_len;
      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 0;
      return 0;
    }
  /* Error occured during operation, return error */
  negotiation->ike_ed->async_return_data = NULL;
  negotiation->ike_ed->async_return_data_len = 0;
  return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
}

/*                                                              shade{0.9}
 * ike_async_encrypt_done_cb
 * Callback to be call when async encrypt is done.              shade{1.0}
 */
void ike_async_encrypt_done_cb(SshCryptoStatus status,
                               const unsigned char *ciphertext_buffer,
                               size_t ciphertext_buffer_len,
                               void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;

  if (status == SSH_CRYPTO_OK)
    {
      negotiation->ike_ed->async_return_data_len = ciphertext_buffer_len;
      negotiation->ike_ed->async_return_data =
        ssh_memdup(ciphertext_buffer, ciphertext_buffer_len);
      if (negotiation->ike_ed->async_return_data == NULL)
        {
          negotiation->ike_ed->async_return_data = NULL;
          negotiation->ike_ed->async_return_data_len = 1;
        }
    }
  else
    {
      /* Signal the error case */
      SSH_IKE_DEBUG(3, negotiation,
                    ("Error in ssh_public_key_encrypt_async: %.200s",
                     ssh_crypto_status_message(status)));
      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 1;
    }

  /* Check if we need to restart the state machine */
  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY)
    ike_state_restart_packet(negotiation);
}

/*                                                              shade{0.9}
 * ike_rsa_encrypt_data
 * Encrypt given data by public key.                            shade{1.0}
 */

SshIkeNotifyMessageType ike_rsa_encrypt_data(SshIkeContext isakmp_context,
                                             SshIkeSA isakmp_sa,
                                             SshIkeNegotiation negotiation,
                                             unsigned char *data,
                                             size_t len,
                                             unsigned char **return_data,
                                             size_t *return_len)
{
  SshIkeNotifyMessageType ret;
  SshCryptoStatus cret;
  SshOperationHandle handle;

  SSH_DEBUG(5, ("RSA encrypt: data[0..%zd] = %08lx %08lx ...",
                len,
                (unsigned long) SSH_IKE_GET32(data),
                (unsigned long) SSH_IKE_GET32(data + 4)));

  /* Check out if the previous call has finished. */
  if (negotiation->ike_ed->async_return_data_len != 0)
    {
      /* Yes, return data if we have it */
      if (negotiation->ike_ed->async_return_data)
        {
          *return_data = negotiation->ike_ed->async_return_data;
          *return_len = negotiation->ike_ed->async_return_data_len;
          negotiation->ike_ed->async_return_data = NULL;
          negotiation->ike_ed->async_return_data_len = 0;
          return 0;
        }
      /* Error occured during operation, return error */
      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 0;
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  ret = ike_find_public_key(isakmp_context, isakmp_sa, negotiation,
                            NULL, 0, NULL);

  if (ret != 0)
    return ret;

  cret = ssh_public_key_select_scheme(negotiation->ike_ed->public_key,
                                      SSH_PKF_ENCRYPT, "rsa-pkcs1-none",
                                      SSH_PKF_END);

  if (cret != SSH_CRYPTO_OK)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Error in ssh_public_key_select_scheme: %.200s",
                     ssh_crypto_status_message(cret)));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  if (len > ssh_public_key_max_encrypt_input_len(negotiation->ike_ed->
                                                 public_key))
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Length too large for public key, max = %d bytes",
                     ssh_public_key_max_encrypt_input_len(negotiation->
                                                          ike_ed->
                                                          public_key)));
      SSH_IKE_NOTIFY_TEXT(negotiation, "Length too large for public "
                          "key to encrypt");
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  /* Encrypt the buffer */
  handle = ssh_public_key_encrypt_async(negotiation->ike_ed->public_key,
                                        data, len,
                                        ike_async_encrypt_done_cb,
                                        negotiation);

  /* Check if we started async operation, or if it is answered directly. */
  if (handle != NULL)
    {
      /* We started real async operation, go on wait */
      SSH_IKE_DEBUG(6, negotiation,
                    ("Asyncronous public key operation started"));
      return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
    }
  /* The result was retrieved immediately, process it now. */
  if (negotiation->ike_ed->async_return_data)
    {
      *return_data = negotiation->ike_ed->async_return_data;
      *return_len = negotiation->ike_ed->async_return_data_len;
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
 * ike_prf_key
 * Return prf key for this isakmp_sa.                           shade{1.0}
 */

SshIkeNotifyMessageType ike_prf_key(SshIkeContext isakmp_context,
                                    SshIkeSA isakmp_sa,
                                    SshIkeNegotiation negotiation,
                                    unsigned char **key,
                                    size_t *key_len)
{
  switch (negotiation->ed->auth_method_type)
    {
    case SSH_IKE_AUTH_METHOD_ANY:
    case SSH_IKE_AUTH_METHOD_PHASE_1:
      ssh_fatal("isakmp_prf_key: Invalid auth method for isakmp_sa: %d",
                negotiation->ed->auth_method_type);
      break;
#ifdef SSHDIST_IKE_CERT_AUTH
    case SSH_IKE_AUTH_METHOD_SIGNATURES:
    case SSH_IKE_AUTH_METHOD_PUBLIC_KEY_ENCRYPTION:
      /* PRF key is Ni | Nr or hash(Ni | Nr) */
      if (negotiation->ike_ed->nonce_i == NULL ||
          negotiation->ike_ed->nonce_r == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
      if (negotiation->ed->auth_method_type == SSH_IKE_AUTH_METHOD_SIGNATURES)
        {
          *key_len = negotiation->ike_ed->nonce_i->pl.nonce.nonce_data_len +
            negotiation->ike_ed->nonce_r->pl.nonce.nonce_data_len;
          *key = ssh_malloc(*key_len);
          if (*key == NULL)
            return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
          memmove(*key, negotiation->ike_ed->nonce_i->pl.nonce.nonce_data,
                  negotiation->ike_ed->nonce_i->pl.nonce.nonce_data_len);
          memmove(*key + negotiation->ike_ed->nonce_i->pl.nonce.nonce_data_len,
                  negotiation->ike_ed->nonce_r->pl.nonce.nonce_data,
                  negotiation->ike_ed->nonce_r->pl.nonce.nonce_data_len);
        }
      else
        {
          SshCryptoStatus cret;
          SshHash hash;

          cret = ssh_hash_allocate(ssh_csstr(isakmp_sa->hash_algorithm_name),
                                   &hash);
          if (cret != SSH_CRYPTO_OK)
            {
              SSH_IKE_DEBUG(3, negotiation,
                            ("ssh_hash_allocate failed: %.200s",
                             ssh_crypto_status_message(cret)));
              return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
            }

          *key_len = ssh_hash_digest_length(ssh_hash_name(hash));
          *key = ssh_malloc(*key_len);
          if (*key == NULL)
            {
              ssh_hash_free(hash);
              return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
            }
          ssh_hash_reset(hash);
          ssh_hash_update(hash, negotiation->ike_ed->nonce_i->
                          pl.nonce.nonce_data, negotiation->
                          ike_ed->nonce_i->pl.nonce.nonce_data_len);
          ssh_hash_update(hash, negotiation->ike_ed->
                          nonce_r->pl.nonce.nonce_data,
                          negotiation->ike_ed->nonce_r->
                          pl.nonce.nonce_data_len);
          ssh_hash_final(hash, *key);
          ssh_hash_free(hash);
        }
      break;
#endif /* SSHDIST_IKE_CERT_AUTH */
    case SSH_IKE_AUTH_METHOD_PRE_SHARED_KEY:
      {
        /* PRF key is pre shared secret from policy manager */
        SshIkeNotifyMessageType ret;

        ret = ike_find_pre_shared_key(isakmp_context, isakmp_sa, negotiation);
        if (ret != 0)
          return ret;
        *key = ssh_memdup(negotiation->ike_ed->pre_shared_key,
                          negotiation->ike_ed->pre_shared_key_len);
        if (*key == NULL)
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        *key_len = negotiation->ike_ed->pre_shared_key_len;
      }
    break;
    default:
      ssh_fatal("Unsupported authentication method in ike_prf_key");
      break;
    }
  return 0;
}

/*                                                              shade{0.9}
 * ike_expand_key_using_prf
 * Expand key material by using prf.                            shade{1.0}
 */
SshIkeNotifyMessageType ike_expand_key_using_prf(SshIkeNegotiation negotiation,
                                                 SshMac mac,
                                                 size_t key_len,
                                                 unsigned char **key)
{
  int i;
  size_t m;

  /* Expand K = K1 | K2 | K3, K1 = prf(key, 0), K2 = prf(key, K1), etc */

  /* Find the number of bytes produced by mac function */
  m = ssh_mac_length(ssh_mac_name(mac));
  SSH_ASSERT(m != 0);

  /* Allocate key storage, multiple of mac function output len */
  *key = ssh_malloc(((key_len / m) + 1) * m);
  if (*key == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* First round */
  ssh_mac_reset(mac);
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "K1 hash .= 0", 1,
                       (unsigned char *) "\0");
  ssh_mac_update(mac, (unsigned char *) "\0", 1);
  ssh_mac_final(mac, *key);
  SSH_IKE_DEBUG_BUFFER(11, negotiation, "Output of K1 hash", m, *key);
  /* Next rounds */
  for (i = m; i < key_len; i += m)
    {
      ssh_mac_reset(mac);
      SSH_IKE_DEBUG_PRINTF_BUFFER(9, negotiation,
                                  ("K%d hash .= K%d", (i / m) + 1, i / m),
                                  m, (*key) + i - m);
      ssh_mac_update(mac, (*key) + i - m, m);
      ssh_mac_final(mac, (*key) + i);
      SSH_IKE_DEBUG_PRINTF_BUFFER(11, negotiation,
                                  ("Output of K%d hash",
                                   (i / m) + 1), m, (*key) + i);
    }
  /* Done */
  return 0;
}


/*                                                              shade{0.9}
 * ike_calc_skeyid_ph1_dh_cb
 * Process Diffie-Hellman agree after async operation is
 * finished.                                                    shade{1.0}
 */

void ike_calc_skeyid_ph1_dh_cb(SshCryptoStatus status,
                               const unsigned char *shared_secret_buffer,
                               size_t shared_secret_buffer_len,
                               void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;

  if (status == SSH_CRYPTO_OK)
    {
      negotiation->ike_ed->async_return_data_len = shared_secret_buffer_len;
      negotiation->ike_ed->async_return_data =
        ssh_memdup(shared_secret_buffer, shared_secret_buffer_len);
      if (negotiation->ike_ed->async_return_data == NULL)
        {
          negotiation->ike_ed->async_return_data = NULL;
          negotiation->ike_ed->async_return_data_len = 1;
        }
      SSH_ASSERT(shared_secret_buffer_len > 0);
    }
  else
    {
      /* Signal the error case */
      SSH_IKE_DEBUG(3, negotiation,
                    ("Error in ssh_pk_group_dh_agree_async: %.200s",
                     ssh_crypto_status_message(status)));
      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 1;
    }

  /* Check if we need to restart the state machine */
  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY)
    ike_state_restart_packet(negotiation);
}

/*                                                              shade{0.9}
 * ike_calc_skeyid_phase_1
 * Calculate phase 1skeyid data if not already done.            shade{1.0}
 */

SshIkeNotifyMessageType ike_calc_skeyid_phase_1(SshIkeContext isakmp_context,
                                                SshIkeSA isakmp_sa,
                                                SshIkeNegotiation negotiation)
{
  SshCryptoStatus cret;
  SshIkeNotifyMessageType ret;
  SshMac prf_mac;
  unsigned char c;
  unsigned char *key;
  size_t key_len, bl;
  int i;
  SshOperationHandle handle;

  /* Check we have enough material */
  if (negotiation->ike_ed->ke_i == NULL ||
      negotiation->ike_ed->ke_r == NULL ||
      negotiation->ike_ed->nonce_i == NULL ||
      negotiation->ike_ed->nonce_r == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;

  negotiation->ed->cipher_block_length =
    ssh_cipher_get_block_length(ssh_csstr(isakmp_sa->
                                          encryption_algorithm_name));

  /* Calculate g^xy */
  isakmp_sa->skeyid.dh_size =
    ssh_pk_group_dh_agree_max_output_length(negotiation->
                                            ike_ed->group->group);
  if (isakmp_sa->skeyid.dh_size == 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No Diffie-Hellman defined for group"));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  if (!negotiation->ike_ed->async_return_done &&
      negotiation->ike_ed->async_return_data_len == 0)
    {




      handle =
        ssh_pk_group_dh_agree_async(negotiation->ike_ed->group->group,
                                    negotiation->ike_ed->secret,
                                    (negotiation->ike_pm_info->
                                     this_end_is_initiator ?
                                     negotiation->ike_ed->ke_r->
                                     pl.ke.key_exchange_data :
                                     negotiation->ike_ed->ke_i->
                                     pl.ke.key_exchange_data),
                                    (negotiation->ike_pm_info->
                                     this_end_is_initiator ?
                                     negotiation->ike_ed->ke_r->
                                     pl.ke.key_exchange_data_len:
                                     negotiation->ike_ed->ke_i->
                                     pl.ke.key_exchange_data_len),
                                    ike_calc_skeyid_ph1_dh_cb,
                                    negotiation);
      /* This is freed by the agree function no matter what */
      negotiation->ike_ed->secret = NULL;

      /* Check if we started async operation, or if it is answered directly. */
      if (handle != NULL)
        {
          /* We started real async operation, go on wait */
          SSH_IKE_DEBUG(6, negotiation,
                        ("Asyncronous Diffie-Hellman agree "
                         "operation started"));
          return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
        }
    }
  if (!negotiation->ike_ed->async_return_done)
    {
      if (negotiation->ike_ed->async_return_data == NULL)
        {
          /* Error occurred during operation, return error */
          negotiation->ike_ed->async_return_data = NULL;
          negotiation->ike_ed->async_return_data_len = 0;
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      isakmp_sa->skeyid.dh = negotiation->ike_ed->async_return_data;
      isakmp_sa->skeyid.dh_size = negotiation->ike_ed->async_return_data_len;
      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 0;
      negotiation->ike_ed->async_return_done = TRUE;

      SSH_IKE_DEBUG_BUFFER(6, negotiation, "Diffie-hellman secret g^xy",
                           isakmp_sa->skeyid.dh_size,
                           isakmp_sa->skeyid.dh);

    }

  /* Get the secret key for prf */
  ret = ike_prf_key(isakmp_context, isakmp_sa, negotiation,
                    &key, &key_len);
  if (ret != 0)
    return ret;

  SSH_IKE_DEBUG(7, negotiation, ("Hash algorithm = %s",
                                 isakmp_sa->prf_algorithm_name));

  SSH_IKE_DEBUG_BUFFER(6, negotiation, "Prf key", key_len, key);
  /* Allocate mac */
  cret = ssh_mac_allocate(ssh_csstr(isakmp_sa->prf_algorithm_name),
                          key, key_len, &prf_mac);

  /* Free key */
  memset(key, 0, key_len);
  ssh_free(key);
  if (cret != SSH_CRYPTO_OK)
    {
      SSH_IKE_DEBUG(3, negotiation, ("ssh_mac_allocate(1) failed: %.200s",
                                     ssh_crypto_status_message(cret)));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }





  key_len = bl = ssh_mac_length(ssh_mac_name(prf_mac));
  isakmp_sa->skeyid.skeyid_size = bl;
  isakmp_sa->skeyid.skeyid = ssh_malloc(isakmp_sa->skeyid.skeyid_size);
  if (isakmp_sa->skeyid.skeyid == NULL)
    {
      ssh_mac_free(prf_mac);
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }


  SSH_IKE_DEBUG(7, negotiation, ("Calculating SKEYID"));
  for (i = 0; i < key_len; i += bl)
    {
      /* Calculate skeyid. */
      ssh_mac_reset(prf_mac);

      /* Add previous block if not first block */
      if (i != 0)
        {
          SSH_IKE_DEBUG_BUFFER(9, negotiation,
                               "SKEYID hash .= prev round output",
                               bl, isakmp_sa->skeyid.skeyid + i - bl);
          ssh_mac_update(prf_mac,
                         isakmp_sa->skeyid.skeyid + i - bl,
                         bl);
        }
      switch (negotiation->ed->auth_method_type)
        {
        case SSH_IKE_AUTH_METHOD_ANY:
        case SSH_IKE_AUTH_METHOD_PHASE_1:
          ssh_fatal("isakmp_calc_skeyid: Invalid auth method "
                    "for isakmp_sa: %d",
                    negotiation->ed->auth_method_type);
          break;
#ifdef SSHDIST_IKE_CERT_AUTH
        case SSH_IKE_AUTH_METHOD_SIGNATURES:
          /* SKEYID = PRF(Ni | Nr, g^xy) */
          SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID hash .= g^xy",
                               isakmp_sa->skeyid.dh_size,
                               isakmp_sa->skeyid.dh);
          ssh_mac_update(prf_mac, isakmp_sa->skeyid.dh,
                         isakmp_sa->skeyid.dh_size);
          break;
        case SSH_IKE_AUTH_METHOD_PUBLIC_KEY_ENCRYPTION:
          /* SKEYID = PRF(Ni | Nr, CKY-I | CKY-R) or
             SKEYID = PRF(hash(Ni | Nr), CKY-I | CKY-R) */
          SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID hash .= CKY-I",
                               SSH_IKE_COOKIE_LENGTH,
                               isakmp_sa->cookies.initiator_cookie);
          ssh_mac_update(prf_mac, isakmp_sa->cookies.initiator_cookie,
                         SSH_IKE_COOKIE_LENGTH);
          SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID hash .= CKY-R",
                               SSH_IKE_COOKIE_LENGTH,
                               isakmp_sa->cookies.responder_cookie);
          ssh_mac_update(prf_mac, isakmp_sa->cookies.responder_cookie,
                         SSH_IKE_COOKIE_LENGTH);
          break;
#endif /* SSHDIST_IKE_CERT_AUTH */
        case SSH_IKE_AUTH_METHOD_PRE_SHARED_KEY:
          /* SKEYID = PRF(pre_shared_key, Ni | Nr) */
          SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID hash .= Ni",
                               negotiation->ike_ed->nonce_i->
                               pl.nonce.nonce_data_len,
                               negotiation->ike_ed->nonce_i->
                               pl.nonce.nonce_data);
          ssh_mac_update(prf_mac,
                         negotiation->ike_ed->nonce_i->
                         pl.nonce.nonce_data,
                         negotiation->ike_ed->nonce_i->
                         pl.nonce.nonce_data_len);
          SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID hash .= Nr",
                               negotiation->ike_ed->nonce_r->
                               pl.nonce.nonce_data_len,
                               negotiation->ike_ed->nonce_r->
                               pl.nonce.nonce_data);
          ssh_mac_update(prf_mac,
                         negotiation->ike_ed->nonce_r->
                         pl.nonce.nonce_data,
                         negotiation->ike_ed->nonce_r->
                         pl.nonce.nonce_data_len);
          break;
        default:
          ssh_fatal("Unsupported authentication method in ike_calc_skeyid");
          break;
        }
      ssh_mac_final(prf_mac, isakmp_sa->skeyid.skeyid + i);
    }
  ssh_mac_free(prf_mac);

  SSH_IKE_DEBUG_BUFFER(6, negotiation, "Output of SKEYID hash",
                       isakmp_sa->skeyid.skeyid_size,
                       isakmp_sa->skeyid.skeyid);

  cret = ssh_mac_allocate(ssh_csstr(isakmp_sa->prf_algorithm_name),
                          isakmp_sa->skeyid.skeyid,
                          isakmp_sa->skeyid.skeyid_size,
                          &isakmp_sa->skeyid.skeyid_mac);
  if (cret != SSH_CRYPTO_OK)
    {
      SSH_IKE_DEBUG(3, negotiation, ("ssh_mac_allocate failed: %.200s",
                                     ssh_crypto_status_message(cret)));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  /* Generate SKEYID_{d,a,e} */
  /* SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0) */
  isakmp_sa->skeyid.skeyid_d_size =
    ssh_mac_length(ssh_mac_name(isakmp_sa->skeyid.skeyid_mac));
  isakmp_sa->skeyid.skeyid_d =
    ssh_malloc(isakmp_sa->skeyid.skeyid_d_size);
  if (isakmp_sa->skeyid.skeyid_d == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  ssh_mac_reset(isakmp_sa->skeyid.skeyid_mac);
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_d hash .= g^xy",
                       isakmp_sa->skeyid.dh_size,
                       isakmp_sa->skeyid.dh);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac,
                 isakmp_sa->skeyid.dh,
                 isakmp_sa->skeyid.dh_size);
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_d hash .= CKY-I",
                       SSH_IKE_COOKIE_LENGTH,
                       isakmp_sa->cookies.initiator_cookie);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac,
                 isakmp_sa->cookies.initiator_cookie,
                 SSH_IKE_COOKIE_LENGTH);
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_d hash .= CKY-R",
                       SSH_IKE_COOKIE_LENGTH,
                       isakmp_sa->cookies.responder_cookie);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac,
                 isakmp_sa->cookies.responder_cookie,
                 SSH_IKE_COOKIE_LENGTH);
  c = 0;
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_d hash .= 0", 1, &c);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac, &c, 1);
  ssh_mac_final(isakmp_sa->skeyid.skeyid_mac,
                isakmp_sa->skeyid.skeyid_d);

  SSH_IKE_DEBUG_BUFFER(6, negotiation, "Output of SKEYID_d hash",
                       isakmp_sa->skeyid.skeyid_d_size,
                       isakmp_sa->skeyid.skeyid_d);

  /* SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1) */
  isakmp_sa->skeyid.skeyid_a_size =
    ssh_mac_length(ssh_mac_name(isakmp_sa->skeyid.skeyid_mac));
  isakmp_sa->skeyid.skeyid_a =
    ssh_malloc(isakmp_sa->skeyid.skeyid_a_size);
  if (isakmp_sa->skeyid.skeyid_a == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  ssh_mac_reset(isakmp_sa->skeyid.skeyid_mac);
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_a hash .= SKEYID_d",
                       isakmp_sa->skeyid.skeyid_d_size,
                       isakmp_sa->skeyid.skeyid_d);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac,
                 isakmp_sa->skeyid.skeyid_d,
                 isakmp_sa->skeyid.skeyid_d_size);
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_a hash .= g^xy",
                       isakmp_sa->skeyid.dh_size,
                       isakmp_sa->skeyid.dh);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac,
                 isakmp_sa->skeyid.dh,
                 isakmp_sa->skeyid.dh_size);
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_a hash .= CKY-I",
                       SSH_IKE_COOKIE_LENGTH,
                       isakmp_sa->cookies.initiator_cookie);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac,
                 isakmp_sa->cookies.initiator_cookie,
                 SSH_IKE_COOKIE_LENGTH);
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_a hash .= CKY-R",
                       SSH_IKE_COOKIE_LENGTH,
                       isakmp_sa->cookies.responder_cookie);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac,
                 isakmp_sa->cookies.responder_cookie,
                 SSH_IKE_COOKIE_LENGTH);
  c = 1;
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_a hash .= 1", 1, &c);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac, &c, 1);
  ssh_mac_final(isakmp_sa->skeyid.skeyid_mac,
                isakmp_sa->skeyid.skeyid_a);

  SSH_IKE_DEBUG_BUFFER(6, negotiation, "Output of SKEYID_a hash",
                       isakmp_sa->skeyid.skeyid_a_size,
                       isakmp_sa->skeyid.skeyid_a);

  cret = ssh_mac_allocate(ssh_csstr(isakmp_sa->prf_algorithm_name),
                          isakmp_sa->skeyid.skeyid_a,
                          isakmp_sa->skeyid.skeyid_a_size,
                          &isakmp_sa->skeyid.skeyid_a_mac);
  if (cret != SSH_CRYPTO_OK)
    {
      SSH_IKE_DEBUG(3, negotiation, ("ssh_mac_allocate(a) failed: %.200s",
                                     ssh_crypto_status_message(cret)));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  /* SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2) */
  isakmp_sa->skeyid.skeyid_e_size =
    ssh_mac_length(ssh_mac_name(isakmp_sa->skeyid.skeyid_mac));
  isakmp_sa->skeyid.skeyid_e =
    ssh_malloc(isakmp_sa->skeyid.skeyid_e_size);
  if (isakmp_sa->skeyid.skeyid_e == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  ssh_mac_reset(isakmp_sa->skeyid.skeyid_mac);
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_e hash .= SKEYID_a",
                       isakmp_sa->skeyid.skeyid_a_size,
                       isakmp_sa->skeyid.skeyid_a);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac,
                 isakmp_sa->skeyid.skeyid_a,
                 isakmp_sa->skeyid.skeyid_a_size);
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_e hash .= g^xy",
                       isakmp_sa->skeyid.dh_size,
                       isakmp_sa->skeyid.dh);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac,
                 isakmp_sa->skeyid.dh,
                 isakmp_sa->skeyid.dh_size);
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_e hash .= CKY-I",
                       SSH_IKE_COOKIE_LENGTH,
                       isakmp_sa->cookies.initiator_cookie);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac,
                 isakmp_sa->cookies.initiator_cookie,
                 SSH_IKE_COOKIE_LENGTH);
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_e hash .= CKY-R",
                       SSH_IKE_COOKIE_LENGTH,
                       isakmp_sa->cookies.responder_cookie);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac,
                 isakmp_sa->cookies.responder_cookie,
                 SSH_IKE_COOKIE_LENGTH);
  c = 2;
  SSH_IKE_DEBUG_BUFFER(9, negotiation, "SKEYID_e hash .= 2", 1, &c);
  ssh_mac_update(isakmp_sa->skeyid.skeyid_mac, &c, 1);
  ssh_mac_final(isakmp_sa->skeyid.skeyid_mac,
                isakmp_sa->skeyid.skeyid_e);

  SSH_IKE_DEBUG_BUFFER(6, negotiation, "Output SKEYID_e hash",
                       isakmp_sa->skeyid.skeyid_e_size,
                       isakmp_sa->skeyid.skeyid_e);

  cret = ssh_mac_allocate(ssh_csstr(isakmp_sa->prf_algorithm_name),
                          isakmp_sa->skeyid.skeyid_e,
                          isakmp_sa->skeyid.skeyid_e_size,
                          &isakmp_sa->skeyid.skeyid_e_mac);
  if (cret != SSH_CRYPTO_OK)
    {
      SSH_IKE_DEBUG(3, negotiation, ("ssh_mac_allocate(e) failed: %.200s",
                                     ssh_crypto_status_message(cret)));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  /* Initialize encryption / decryption contexts */

  /* Check if skeyid_e has enough key material for key */

  /* Check for variable length keys */
  if (ssh_cipher_has_fixed_key_length(
                             ssh_csstr(isakmp_sa->encryption_algorithm_name)))
    key_len = ssh_cipher_get_key_length(
                             ssh_csstr(isakmp_sa->encryption_algorithm_name));
  else
    {
      if (negotiation->ike_ed->attributes.key_length != 0)
        {
          key_len = (negotiation->ike_ed->attributes.key_length + 7) / 8;
          /* limit the key_len to fixed bytes */
          if (key_len * 8 > isakmp_context->max_key_length)
            key_len = isakmp_context->max_key_length;
        }
      else
        {
          key_len =
            ssh_find_keyword_number(ssh_ike_encryption_key_lengths_keywords,
                                    ssh_csstr(isakmp_sa->
                                              encryption_algorithm_name));
          if (key_len == (size_t) -1)
            return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
    }

  /* Do we have enough material */
  if (isakmp_sa->skeyid.skeyid_e_size < key_len)
    {
      /* No, expand Ka = K1 | K2 | K3, K1 = prf(SKEYID_e, 0),
         K2 = prf(SKEYID_e, K1), etc */
      ret = ike_expand_key_using_prf(negotiation,
                                     isakmp_sa->skeyid.skeyid_e_mac,
                                     key_len, &key);
      if (ret != 0)
        return ret;
    }
  else
    {
      /* Copy data from SKEYID_e. Copy everything, in case we need it in
         the weak key check case */
      key = ssh_memdup(isakmp_sa->skeyid.skeyid_e,
                        isakmp_sa->skeyid.skeyid_e_size);
      if (key == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

    }

  if (ssh_find_keyword_number(ssh_ike_encryption_weak_key_check_keywords,
                              ssh_csstr(isakmp_sa->encryption_algorithm_name))
      == TRUE)
    {
      int key_start;

      /* Allocate encryption cipher */
      for (key_start = 0;
          key_start + key_len < isakmp_sa->skeyid.skeyid_e_size;
          key_start++)
        {
          cret =
            ssh_cipher_allocate(ssh_csstr(isakmp_sa->
                                          encryption_algorithm_name),
                                key + key_start,
                                key_len, TRUE,
                                &negotiation->ed->
                                encryption_cipher);
          if (cret == SSH_CRYPTO_OK)
            break;
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_cipher_allocate_and_test_weak_key, "
                         "key is weak, retrying: %.200s",
                         ssh_crypto_status_message(cret)));
        }

      if (cret != SSH_CRYPTO_OK)
        {
          ssh_free(key);
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_cipher_allocate failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }

      isakmp_sa->cipher_key = ssh_memdup(key + key_start, key_len);
      ssh_free(key);
      if (isakmp_sa->cipher_key == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
      isakmp_sa->cipher_key_len = key_len;

      SSH_IKE_DEBUG_BUFFER(6, negotiation, "Final encryption key",
                           isakmp_sa->cipher_key_len,
                           isakmp_sa->cipher_key);

      /* Allocate decryption cipher */
      cret =
        ssh_cipher_allocate(ssh_csstr(isakmp_sa->encryption_algorithm_name),
                            isakmp_sa->cipher_key, key_len, FALSE,
                            &negotiation->ed->decryption_cipher);

      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_cipher_allocate failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
    }
  else
    {
      isakmp_sa->cipher_key = key;
      isakmp_sa->cipher_key_len = key_len;

      SSH_IKE_DEBUG_BUFFER(6, negotiation, "Final encryption key",
                           isakmp_sa->cipher_key_len,
                           isakmp_sa->cipher_key);

      /* Allocate encryption cipher */
      cret =
        ssh_cipher_allocate(ssh_csstr(isakmp_sa->encryption_algorithm_name),
                            key, key_len, TRUE,
                            &negotiation->ed->encryption_cipher);

      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_cipher_allocate failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }

      /* Allocate decryption cipher */
      cret =
        ssh_cipher_allocate(ssh_csstr(isakmp_sa->encryption_algorithm_name),
                            key, key_len, FALSE,
                            &negotiation->ed->decryption_cipher);

      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_cipher_allocate failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
    }
  bl = negotiation->ed->cipher_block_length;

  /* Set the IV for cipher, if using block cipher */
  if (bl != 1)
    {
      /* Block cipher */
      SshHash hash_ctx;

      cret = ssh_hash_allocate(ssh_csstr(isakmp_sa->hash_algorithm_name),
                               &hash_ctx);

      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation, ("ssh_hash_allocate failed: %.200s",
                                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }

      /* Find the number of bytes produced by mac function */
      key_len = ssh_hash_digest_length(ssh_hash_name(hash_ctx));

      if (bl > key_len)
        {
          SSH_IKE_DEBUG(3, negotiation, ("block_size > hash_len"));
          ssh_hash_free(hash_ctx);
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }

      /* Allocate iv */
      key = ssh_malloc(key_len);
      if (key == NULL)
        {
          ssh_hash_free(hash_ctx);
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }

      /* Calc hash */
      ssh_hash_reset(hash_ctx);
      /* g^xi */
      SSH_IKE_DEBUG_BUFFER(9, negotiation, "IV hash .= g^xi",
                           negotiation->ike_ed->ke_i->
                           pl.ke.key_exchange_data_len,
                           negotiation->ike_ed->ke_i->
                           pl.ke.key_exchange_data);
      ssh_hash_update(hash_ctx, negotiation->ike_ed->ke_i->
                      pl.ke.key_exchange_data,
                      negotiation->ike_ed->ke_i->
                      pl.ke.key_exchange_data_len);
      /* g^xr */
      SSH_IKE_DEBUG_BUFFER(9, negotiation, "IV hash .= g^xr",
                           negotiation->ike_ed->ke_r->
                           pl.ke.key_exchange_data_len,
                           negotiation->ike_ed->ke_r->
                           pl.ke.key_exchange_data);
      ssh_hash_update(hash_ctx, negotiation->ike_ed->ke_r->
                      pl.ke.key_exchange_data,
                      negotiation->ike_ed->ke_r->
                      pl.ke.key_exchange_data_len);
      /* Get result */
      ssh_hash_final(hash_ctx, key);

      ssh_hash_free(hash_ctx);

      /* Set IVs */
      cret = ssh_cipher_set_iv(negotiation->ed->encryption_cipher, key);

      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_cipher_set_iv(e) failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }

      cret = ssh_cipher_set_iv(negotiation->ed->decryption_cipher, key);

      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation, ("ssh_cipher_set_iv(d) failed: %.200s",
                                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      SSH_IKE_DEBUG_BUFFER(9, negotiation, "Output of IV hash", bl, key);
      negotiation->ed->cipher_iv = key;
      isakmp_sa->cipher_iv_len = bl;
    }

  /* Mark skeyid initialized */
  isakmp_sa->skeyid.initialized = TRUE;
  negotiation->ike_ed->async_return_done = FALSE;
  return 0;
}

/*                                                              shade{0.9}
 * ike_calc_skeyid_phase_q2
 * Calculate phase 2 skeyid data if not already done.           shade{1.0}
 */

SshIkeNotifyMessageType ike_calc_skeyid_phase_2(SshIkeContext isakmp_context,
                                                SshIkeSA isakmp_sa,
                                                SshIkeNegotiation negotiation)
{
  SshCryptoStatus cret;
  size_t bl;

  negotiation->ed->cipher_block_length =
    ssh_cipher_get_block_length(ssh_csstr(isakmp_sa->
                                          encryption_algorithm_name));

  /* Allocate encryption cipher */
  cret = ssh_cipher_allocate(ssh_csstr(isakmp_sa->encryption_algorithm_name),
                             isakmp_sa->cipher_key,
                             isakmp_sa->cipher_key_len, TRUE,
                             &negotiation->ed->encryption_cipher);

  if (cret != SSH_CRYPTO_OK)
    {
      SSH_IKE_DEBUG(3, negotiation, ("ssh_cipher_allocate failed: %.200s",
                                     ssh_crypto_status_message(cret)));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  /* Allocate decryption cipher */
  cret = ssh_cipher_allocate(ssh_csstr(isakmp_sa->encryption_algorithm_name),
                             isakmp_sa->cipher_key,
                             isakmp_sa->cipher_key_len, FALSE,
                             &negotiation->ed->decryption_cipher);

  if (cret != SSH_CRYPTO_OK)
    {
      SSH_IKE_DEBUG(3, negotiation, ("ssh_cipher_allocate failed: %.200s",
                                     ssh_crypto_status_message(cret)));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  bl = negotiation->ed->cipher_block_length;

  /* Set the IV for cipher, if using block cipher */
  if (bl != 1)
    {
      /* Block cipher */
      SshHash hash_ctx;
      size_t hash_len;
      unsigned char *iv;
      unsigned char message_id[4];

      if (isakmp_sa->cipher_iv == NULL)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("No encryption iv found in isakmp_calc_skeyid"));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }

      cret = ssh_hash_allocate(ssh_csstr(isakmp_sa->hash_algorithm_name),
                               &hash_ctx);

      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_hash_allocate failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }

      /* Find the number of bytes produced by mac function */
      hash_len = ssh_hash_digest_length(ssh_hash_name(hash_ctx));

      if (bl > hash_len)
        {
          SSH_IKE_DEBUG(3, negotiation, ("block_size > hash_len"));
          ssh_hash_free(hash_ctx);
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }

      /* Allocate iv */
      iv = ssh_malloc(hash_len);
      if (iv == NULL)
        {
          ssh_hash_free(hash_ctx);
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }

      /* Calc encryption iv hash */
      ssh_hash_reset(hash_ctx);
      /* Phase 1 last iv */
      SSH_IKE_DEBUG_BUFFER(9, negotiation, "IV hash .= Final Phase 1 IV",
                           isakmp_sa->cipher_iv_len, isakmp_sa->cipher_iv);
      ssh_hash_update(hash_ctx, isakmp_sa->cipher_iv,
                      isakmp_sa->cipher_iv_len);
      /* Message-id */
      SSH_IKE_PUT32(message_id, negotiation->ed->message_id);
      SSH_IKE_DEBUG_BUFFER(9, negotiation, "IV hash .= Message id",
                           4, message_id);
      ssh_hash_update(hash_ctx, message_id, 4);
      /* Get result */
      ssh_hash_final(hash_ctx, iv);
      ssh_hash_free(hash_ctx);

      /* Set IVs */
      cret = ssh_cipher_set_iv(negotiation->ed->encryption_cipher, iv);

      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_cipher_set_iv(e) failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }

      cret = ssh_cipher_set_iv(negotiation->ed->decryption_cipher, iv);

      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_cipher_set_iv(d) failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }

      SSH_IKE_DEBUG_BUFFER(6, negotiation, "Output of phase 2 IV hash",
                           bl, iv);
      negotiation->ed->cipher_iv = iv;
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_calc_skeyid
 * Calculate skeyid data if not already done.                   shade{1.0}
 */

SshIkeNotifyMessageType ike_calc_skeyid(SshIkeContext isakmp_context,
                                        SshIkeSA isakmp_sa,
                                        SshIkeNegotiation negotiation)
{
  if ((negotiation->exchange_type == SSH_IKE_XCHG_TYPE_IP ||
       negotiation->exchange_type == SSH_IKE_XCHG_TYPE_AGGR) &&
      isakmp_sa->skeyid.initialized)
    {
      return 0;
    }
  else if ((negotiation->exchange_type == SSH_IKE_XCHG_TYPE_IP ||
       negotiation->exchange_type == SSH_IKE_XCHG_TYPE_AGGR) &&
      !isakmp_sa->skeyid.initialized)
    {
      return ike_calc_skeyid_phase_1(isakmp_context, isakmp_sa,
                                     negotiation);
    }
  else if ((negotiation->exchange_type == SSH_IKE_XCHG_TYPE_NGM ||
            negotiation->exchange_type == SSH_IKE_XCHG_TYPE_QM ||
#ifdef SSHDIST_ISAKMP_CFG_MODE
            negotiation->exchange_type == SSH_IKE_XCHG_TYPE_CFG ||
#endif /* SSHDIST_ISAKMP_CFG_MODE */
            negotiation->exchange_type == SSH_IKE_XCHG_TYPE_INFO)
           && negotiation->ed->encryption_cipher != NULL)
    {
      return 0;
    }
  else if ((negotiation->exchange_type == SSH_IKE_XCHG_TYPE_NGM ||
            negotiation->exchange_type == SSH_IKE_XCHG_TYPE_QM ||
#ifdef SSHDIST_ISAKMP_CFG_MODE
            negotiation->exchange_type == SSH_IKE_XCHG_TYPE_CFG ||
#endif /* SSHDIST_ISAKMP_CFG_MODE */
            negotiation->exchange_type == SSH_IKE_XCHG_TYPE_INFO)
           && negotiation->ed->encryption_cipher == NULL &&
           isakmp_sa->skeyid.initialized)
    {
      return ike_calc_skeyid_phase_2(isakmp_context, isakmp_sa,
                                     negotiation);
    }
  return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
}

/*                                                              shade{0.9}
 * ike_check_prime
 * Check if number is prime, keep local cache.                  shade{1.0}
 */

Boolean ike_check_prime(SshIkeContext ctx, SshMPInteger number)
{
  size_t size;
  unsigned char *buffer;
  void *pointer;
  SshADTHandle h;

  size = ssh_mprz_byte_size(number);
  buffer = ssh_malloc(size + 1);
  if (buffer == NULL)
    return FALSE;
  buffer[size] = '\0';
  ssh_mprz_get_buf(buffer, size, number);
  /* Search from the mapping */
  h = ssh_adt_get_handle_to_equal(ctx->prime_mapping, (void *) buffer);
  if (h == NULL)
    {
      if (ssh_mprz_is_probable_prime(number, 2))
        {
          SSH_DEBUG(4, ("New prime adding it to table"));
          pointer = (void *) 1;
        }
      else
        {
          SSH_DEBUG(4, ("New non prime adding it to table"));
          pointer = NULL;
        }

      ctx->number_of_primes_in_table++;
      if (ctx->number_of_primes_in_table > 2000)
        {
          SSH_DEBUG(3, ("Clearing prime table, more than 2000 primes in it"));

          ssh_adt_clear(ctx->prime_mapping);
          ctx->number_of_primes_in_table = 0;
        }
      ssh_adt_duplicate(ctx->prime_mapping, buffer);
      h = ssh_adt_get_handle_to_equal(ctx->prime_mapping, buffer);
      SSH_ASSERT(h != NULL);
      ssh_adt_map_attach(ctx->prime_mapping, h, pointer);
    }
  else
    {
      pointer = ssh_adt_map_lookup(ctx->prime_mapping, h);
    }
  ssh_free(buffer);

  /* Return result */
  if (pointer == NULL)
    return FALSE;
  return TRUE;
}

/*                                                              shade{0.9}
 * ike_calc_mac
 * Calculate HASH_I or HASH_R.                                  shade{1.0}
 */

SshIkeNotifyMessageType ike_calc_mac(SshIkeContext isakmp_context,
                                     SshIkeSA isakmp_sa,
                                     SshIkeNegotiation negotiation,
                                     unsigned char *hash,
                                     size_t *hash_len,
                                     Boolean local,
                                     const unsigned char *mac_name)
{
  SshIkeNotifyMessageType ret;
  Boolean initiator_first;
  SshMac mac;

  SSH_DEBUG(5, ("Start, initiator = %s, local = %s",
                (negotiation->ike_pm_info->this_end_is_initiator ?
                 "true" : "false"),
                (local ? "true" : "false")));

  ret = ike_calc_skeyid(isakmp_context, isakmp_sa, negotiation);
  if (ret != 0)
    return ret;

  if (local)
    initiator_first = negotiation->ike_pm_info->this_end_is_initiator;
  else
    initiator_first = !negotiation->ike_pm_info->this_end_is_initiator;

  if (mac_name != NULL)
    {
      SshCryptoStatus cret;

      cret = ssh_mac_allocate(ssh_csstr(mac_name),
                              isakmp_sa->skeyid.skeyid,
                              isakmp_sa->skeyid.skeyid_size,
                              &mac);
      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_mac_allocate failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
    }
  else
    {
      mac = isakmp_sa->skeyid.skeyid_mac;
    }

  ssh_mac_reset(mac);
  *hash_len = 0;

  {
    struct SshIkePayloadRec id;
    SshIkePayload g_xi, g_xr;
    unsigned char *p;
    size_t len;

    if (negotiation->ike_ed->ke_i == NULL ||
        negotiation->ike_ed->ke_r == NULL ||
        negotiation->ike_ed->sa_i == NULL)
      {
        SSH_IKE_DEBUG(3, negotiation, ("Exchange data missing"));
        if (mac_name != NULL)
          ssh_mac_free(mac);
        return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
      }

    if (local)
      id.pl.id = *(negotiation->ike_pm_info->local_id);
    else
      id.pl.id = *(negotiation->ike_pm_info->remote_id);

    if (initiator_first)
      {
        g_xi = negotiation->ike_ed->ke_i;
        g_xr = negotiation->ike_ed->ke_r;
      }
    else
      {
        g_xi = negotiation->ike_ed->ke_r;
        g_xr = negotiation->ike_ed->ke_i;
      }

    /* g^xi */
    SSH_IKE_DEBUG_PRINTF_BUFFER(9, negotiation,
                                ("HASH_%s hash .= g^x%s",
                                 initiator_first ? "I" : "R",
                                 initiator_first ? "i" : "r"),
                                g_xi->pl.ke.key_exchange_data_len,
                                g_xi->pl.ke.key_exchange_data);
    ssh_mac_update(mac, g_xi->pl.ke.key_exchange_data,
                   g_xi->pl.ke.key_exchange_data_len);
    /* g^xr */
    SSH_IKE_DEBUG_PRINTF_BUFFER(9, negotiation,
                                ("HASH_%s hash .= g^x%s",
                                 initiator_first ? "I" : "R",
                                 initiator_first ? "r" : "i"),
                                g_xr->pl.ke.key_exchange_data_len,
                                g_xr->pl.ke.key_exchange_data);
    ssh_mac_update(mac, g_xr->pl.ke.key_exchange_data,
                   g_xr->pl.ke.key_exchange_data_len);
    if (initiator_first)
      {
        /* CKY-I, CKY-R */
        SSH_IKE_DEBUG_BUFFER(9, negotiation, "HASH_I hash .= CKY-I",
                             SSH_IKE_COOKIE_LENGTH,
                             isakmp_sa->cookies.initiator_cookie);
        ssh_mac_update(mac, isakmp_sa->cookies.initiator_cookie,
                       SSH_IKE_COOKIE_LENGTH);
        SSH_IKE_DEBUG_BUFFER(9, negotiation, "HASH_I hash .= CKY-R",
                             SSH_IKE_COOKIE_LENGTH,
                             isakmp_sa->cookies.responder_cookie);
        ssh_mac_update(mac, isakmp_sa->cookies.responder_cookie,
                       SSH_IKE_COOKIE_LENGTH);
      }
    else
      {
        /* CKY-R, CKY-I */
        SSH_IKE_DEBUG_BUFFER(9, negotiation, "HASH_R hash .= CKY-R",
                             SSH_IKE_COOKIE_LENGTH,
                             isakmp_sa->cookies.responder_cookie);
        ssh_mac_update(mac, isakmp_sa->cookies.responder_cookie,
                       SSH_IKE_COOKIE_LENGTH);
        SSH_IKE_DEBUG_BUFFER(9, negotiation, "HASH_R hash .= CKY-I",
                             SSH_IKE_COOKIE_LENGTH,
                             isakmp_sa->cookies.initiator_cookie);
        ssh_mac_update(mac, isakmp_sa->cookies.initiator_cookie,
                       SSH_IKE_COOKIE_LENGTH);
      }
    /* SAp */
    SSH_IKE_DEBUG_PRINTF_BUFFER(9, negotiation,
                                ("HASH_%s hash .= SAi_b",
                                 initiator_first ? "I" : "R"),
                                negotiation->ike_ed->sa_i->payload_length,
                                negotiation->ike_ed->sa_i->payload_start
                                + 4);
    ssh_mac_update(mac, negotiation->ike_ed->sa_i->payload_start + 4,
                   negotiation->ike_ed->sa_i->payload_length);
    /* Local ID, we have to encode it here, because it might not yet
       be encoded, or it might be encrypted in payload. */
    ret = ike_encode_id(isakmp_context, negotiation, &id, &p, &len);
    if (ret != 0)
      {
        ssh_free(p);
        if (mac_name != NULL)
          ssh_mac_free(mac);
        return ret;
      }
    SSH_IKE_DEBUG_PRINTF_BUFFER(9, negotiation,
                                ("HASH_%s hash .= IDi%s_b",
                                 initiator_first ? "I" : "R",
                                 initiator_first ? "i" : "r"),
                                len, p);
    ssh_mac_update(mac, p, len);
    ssh_free(p);
  }

  *hash_len = ssh_mac_length(ssh_mac_name(mac));
  ssh_mac_final(mac, hash);

  if (mac_name != NULL)
    ssh_mac_free(mac);

  SSH_IKE_DEBUG_PRINTF_BUFFER(6, negotiation,
                              ("Output of HASH_%s hash",
                               local ?
                               (negotiation->ike_pm_info->
                                this_end_is_initiator ? "I" : "R") :
                               (negotiation->ike_pm_info->
                                this_end_is_initiator ? "R" : "I")),
                              *hash_len, hash);

  return 0;
}


/*                                                              shade{0.9}
 * ike_calc_qm_hash
 * Calculate quick mode authentication hash. Hash payload
 * must be the first payload.                                   shade{1.0}
 */
SshIkeNotifyMessageType ike_calc_qm_hash(SshIkeContext isakmp_context,
                                         SshIkeSA isakmp_sa,
                                         SshIkeNegotiation negotiation,
                                         SshIkePacket isakmp_packet,
                                         unsigned char *hash,
                                         size_t *hash_len,
                                         Boolean include_ni)
{
  SshMac mac;
  unsigned char buffer[4];

  mac = isakmp_sa->skeyid.skeyid_a_mac;

  /* Check that hash payload is first payload */
  if (isakmp_packet->payloads[0]->type != SSH_IKE_PAYLOAD_TYPE_HASH)
    {
      SSH_IKE_NOTIFY_TEXT(negotiation, "Hash payload must be first "
                          "payload in the packet");
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_HASH_INFORMATION;
    }

  *hash_len = ssh_mac_length(ssh_mac_name(mac));
  ssh_mac_reset(mac);

  /* HASH = prf(SKEYID_a, M-ID | [ Ni ] | Rest of packet) */
  /* M-ID */
  SSH_IKE_PUT32(buffer, isakmp_packet->message_id);
  SSH_IKE_DEBUG_BUFFER(8, negotiation, "HASH hash .= M-ID", 4, buffer);
  ssh_mac_update(mac, buffer, 4);
  if (include_ni)
    {
      /* [ Ni ] */
      if (negotiation->qm_ed->nonce_i == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_INVALID_HASH_INFORMATION;
      SSH_IKE_DEBUG_BUFFER(8, negotiation, "HASH hash .= Ni",
                           negotiation->qm_ed->nonce_i->
                           pl.nonce.nonce_data_len,
                           negotiation->qm_ed->nonce_i->
                           pl.nonce.nonce_data);
      ssh_mac_update(mac, negotiation->qm_ed->nonce_i->pl.nonce.nonce_data,
                     negotiation->qm_ed->nonce_i->pl.nonce.nonce_data_len);
    }
  /* Rest of packet */
  SSH_IKE_DEBUG_BUFFER(8, negotiation, "HASH hash .= rest of packet",
                       isakmp_packet->length -
                       isakmp_packet->payloads[1]->payload_offset -
                       SSH_IKE_PACKET_GENERIC_HEADER_LEN,
                       isakmp_packet->payloads[1]->payload_start);
  ssh_mac_update(mac,
                 isakmp_packet->payloads[1]->payload_start,
                 isakmp_packet->length -
                 isakmp_packet->payloads[1]->payload_offset -
                 SSH_IKE_PACKET_GENERIC_HEADER_LEN);
  /* Store hash */
  ssh_mac_final(mac, hash);
  SSH_IKE_DEBUG_BUFFER(8, negotiation, "Output of HASH hash", *hash_len, hash);
  return 0;
}


/*                                                              shade{0.9}
 * ike_calc_qm_hash_3
 * Calculate quick mode authentication hash 3.                  shade{1.0}
 */
SshIkeNotifyMessageType ike_calc_qm_hash_3(SshIkeContext isakmp_context,
                                           SshIkeSA isakmp_sa,
                                           SshIkeNegotiation negotiation,
                                           SshIkePacket isakmp_packet,
                                           unsigned char *hash,
                                           size_t *hash_len)
{
  SshMac mac;
  unsigned char buffer[4];

  mac = isakmp_sa->skeyid.skeyid_a_mac;

  *hash_len = ssh_mac_length(ssh_mac_name(mac));

  ssh_mac_reset(mac);
  /* HASH = prf(SKEYID_a, 0 | M-ID | Ni | Nr) */
  /* 0 */
  SSH_IKE_PUT32(buffer, 0);
  SSH_IKE_DEBUG_BUFFER(8, negotiation, "HASH hash .= 0", 1, buffer);
  ssh_mac_update(mac, buffer, 1);
  /* M-ID */
  SSH_IKE_PUT32(buffer, negotiation->ed->message_id);
  SSH_IKE_DEBUG_BUFFER(8, negotiation, "HASH hash .= M-ID", 4, buffer);
  ssh_mac_update(mac, buffer, 4);
  /* Ni */
  SSH_IKE_DEBUG_BUFFER(8, negotiation, "HASH hash .= Ni",
                       negotiation->qm_ed->nonce_i->pl.nonce.nonce_data_len,
                       negotiation->qm_ed->nonce_i->pl.nonce.nonce_data);
  ssh_mac_update(mac, negotiation->qm_ed->nonce_i->pl.nonce.nonce_data,
                 negotiation->qm_ed->nonce_i->pl.nonce.nonce_data_len);
  /* Nr */
  SSH_IKE_DEBUG_BUFFER(8, negotiation, "HASH hash .= Nr",
                       negotiation->qm_ed->nonce_r->pl.nonce.nonce_data_len,
                       negotiation->qm_ed->nonce_r->pl.nonce.nonce_data);
  ssh_mac_update(mac, negotiation->qm_ed->nonce_r->pl.nonce.nonce_data,
                 negotiation->qm_ed->nonce_r->pl.nonce.nonce_data_len);
  /* Store hash */
  ssh_mac_final(mac, hash);
  SSH_IKE_DEBUG_BUFFER(8, negotiation, "Output of HASH hash", *hash_len, hash);
  return 0;
}


/*                                                              shade{0.9}
 * ike_calc_gen_hash
 * Calculate genric authentication hash. Hash
 * payload must be the first payload.                           shade{1.0}
 */
SshIkeNotifyMessageType ike_calc_gen_hash(SshIkeContext isakmp_context,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkePacket isakmp_packet,
                                          unsigned char *hash,
                                          size_t *hash_len)
{
  SshMac mac;
  unsigned char buffer[4];

  mac = isakmp_sa->skeyid.skeyid_a_mac;

  /* Check that hash payload is first payload */
  if (isakmp_packet->payloads[0]->type != SSH_IKE_PAYLOAD_TYPE_HASH)
    {
      SSH_IKE_NOTIFY_TEXT(negotiation, "Hash payload must be first "
                          "payload in the packet");
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_HASH_INFORMATION;
    }

  *hash_len = ssh_mac_length(ssh_mac_name(mac));
  ssh_mac_reset(mac);

  /* HASH = prf(SKEYID_a, M-ID | Rest of packet) */
  /* M-ID */
  SSH_IKE_PUT32(buffer, isakmp_packet->message_id);
  SSH_IKE_DEBUG_BUFFER(8, negotiation, "HASH hash .= M-ID", 4, buffer);
  ssh_mac_update(mac, buffer, 4);
  /* Rest of packet */
  if (isakmp_packet->number_of_payload_packets > 1)
    {
      SSH_IKE_DEBUG_BUFFER(8, negotiation, "HASH hash .= rest of packet",
                           isakmp_packet->length -
                           isakmp_packet->payloads[1]->payload_offset -
                           SSH_IKE_PACKET_GENERIC_HEADER_LEN,
                           isakmp_packet->payloads[1]->payload_start);
      ssh_mac_update(mac,
                     isakmp_packet->payloads[1]->payload_start,
                     isakmp_packet->length -
                     isakmp_packet->payloads[1]->payload_offset -
                     SSH_IKE_PACKET_GENERIC_HEADER_LEN);
    }

  /* Store hash */
  ssh_mac_final(mac, hash);
  SSH_IKE_DEBUG_BUFFER(8, negotiation, "Output of HASH hash", *hash_len, hash);
  return 0;
}

SshIkeNotifyMessageType ike_calc_psk_hash(SshIkeContext isakmp_context,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          unsigned char *hash,
                                          size_t *hash_len)
{
  SshIkeNotifyMessageType ret;
  SshMac mac;

  ret = ike_calc_skeyid(isakmp_context, isakmp_sa, negotiation);
  if (ret != 0)
    return ret;

  ret = ike_find_pre_shared_key(isakmp_context, isakmp_sa, negotiation);
  if (ret != 0)
    return ret;

  mac = isakmp_sa->skeyid.skeyid_mac;
  ssh_mac_reset(mac);
  *hash_len = 0;

  ssh_mac_update(mac, negotiation->ike_ed->pre_shared_key,
                 negotiation->ike_ed->pre_shared_key_len);

  *hash_len = ssh_mac_length(ssh_mac_name(mac));
  ssh_mac_final(mac, hash);
  return 0;
}
