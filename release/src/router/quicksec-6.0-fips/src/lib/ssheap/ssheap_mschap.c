/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshgetput.h"
#include "sshbuffer.h"
#include "sshcrypt.h"
#include "singledes.h"
#include "md4.h"

#include "ssheap.h"
#include "ssheapi.h"

#include "ssheap_packet.h"
#include "ssheap_mschap.h"


#define SSH_DEBUG_MODULE "SshEapMschapV2"

#ifdef SSHDIST_EAP_MSCHAPV2
static const SshUInt8 mschap_v2_magic1[] = {
  0x4d, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
  0x65, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x6c, 0x69, 0x65,
  0x6e, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
  0x20, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74
};

static const SshUInt8 mschap_v2_magic2[] = {
  0x50, 0x61, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x6d, 0x61, 0x6b,
  0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x6d, 0x6f,
  0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x6f, 0x6e,
  0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f,
  0x6e
};

static const SshUInt8 bitmask[] = { 0x00, 0x01, 0x03, 0x07, 0x0f,
                              0x1f, 0x03f, 0x7f, 0xff };


/*
 * "Magic" constants used in master key derivations
 */
static const SshUInt8 mschap_v2_pad_1[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const SshUInt8 mschap_v2_pad_2[] = {
  0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
  0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
  0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
  0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2
};

static const SshUInt8 mschap_v2_key_magic_1[] = {
  0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
  0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
  0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79
};

static const SshUInt8 mschap_v2_key_magic_2[] = {
  0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
  0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
  0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
  0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
  0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
  0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
  0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
  0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
  0x6b, 0x65, 0x79, 0x2e
};

static const SshUInt8 mschap_v2_key_magic_3[] = {
  0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
  0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
  0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
  0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
  0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
  0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
  0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
  0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
  0x6b, 0x65, 0x79, 0x2e
};


static SshUInt8 *
ssh_eap_mschap_v2_string_tounicode(SshUInt8 *src, SshUInt16 srclen)
{
  SshUInt8 *tmpbuf;
  int i;

  tmpbuf = ssh_malloc(srclen * 2);
  if (tmpbuf == NULL)
    return NULL;

  for (i = 0; i < srclen; i++)
    {
      tmpbuf[2 * i] = src[i];
      tmpbuf[2 * i + 1] = '\0';
    }

  return tmpbuf;
}

static void
ssh_eap_mschap_v2_tohexstring(SshUInt8 *dst, SshUInt8 *src, SshUInt16 srclen)
{
  int i;
  SshUInt8 hex;

  for (i = 0; i < srclen; i++)
    {
      hex = (src[i] >> 4) & 0x0F;
      hex = (hex >= 10 ? (hex - 10 + 'A') : (hex + '0'));
      *dst++ = hex;

      hex = src[i] & 0x0F;
      hex = (hex >= 10 ? (hex - 10 + 'A') : (hex + '0'));
      *dst++ = hex;
    }
}

static void
ssh_eap_mschap_v2_init_peer_challenge(SshUInt8 *peer_challenge)
{
  int i;

  for (i = 0; i < SSH_EAP_MSCHAPV2_CHALLENGE_LENGTH; i++)
    peer_challenge[i] = ssh_random_get_byte();
}

static Boolean
ssh_eap_mschap_v2_md4(SshUInt8 *input,
                      SshUInt16 input_length,
                      SshUInt8 *dst,
                      SshUInt16 dstlen)
{
  SSH_ASSERT(dstlen >= 16);

  ssh_md4_of_buffer(dst,
                    input,
                    input_length);

  return TRUE;
}

static void
ssh_eap_mschap_v2_expand_des_key(SshUInt8 *out, SshUInt8 *in)
{
  SshUInt8 i = 0;
  SshUInt8 i2 = 0;
  SshUInt8 bits = 0;
  SshUInt8 tmp = 0;

  for (i = 0; i < 7; i++)
    {
      tmp = (tmp << (8 - bits)) | ((in[i] >> bits) & 0xFE);
      out[i2++] = tmp;
      tmp = in[i] & bitmask[bits + 1];
      bits++;
    }

  SSH_ASSERT(bits == 7);
  out[i2++] = (tmp << 1) & 0xFE;
}

static Boolean
ssh_eap_mschap_v2_parse_failure(SshUInt8 *buf,
                                SshUInt8 buflen,
                                SshUInt16 *error_code_return,
                                SshUInt8 *retry_code_return,
                                SshUInt8 **challenge_return,
                                SshUInt8 *challenge_return_len,
                                SshUInt8 *version_code_return)
{
  SshUInt8 *resp = NULL;
  SshUInt8 *error_code = NULL;
  SshUInt8 *version_code = NULL;
  SshUInt8 *challenge = NULL;
  SshUInt8 *retry = NULL;
  SshUInt8 *ptr = NULL;
  SshUInt16 error_value = 0;
  SshUInt16 version_value = 0;
  SshUInt16 retry_value = 0;

  *error_code_return = 0;
  *retry_code_return = 0;
  *challenge_return = NULL;
  *version_code_return = 0;

  if (buflen < 3 || buf == NULL)
    goto fail;

  resp = ssh_malloc(buflen + 1);
  if (resp == NULL)
    goto fail;

  memcpy(resp, buf, buflen);
  resp[buflen] = '\0';

  SSH_DEBUG(SSH_D_MY,("failure string: '%s'", resp));

  /* Extract the relevant fields from the failure packet */
  error_code = resp;

  retry = strchr(error_code, ' ');
  if (retry != NULL)
    *retry++ = '\0';

  while (retry != NULL && *retry != '\0' && *retry == ' ')
    retry++;

  ptr = retry;
  if (ptr != NULL && *ptr != '\0')
    {
      ptr = strchr(ptr,' ');
      challenge = ptr;

      if (challenge != NULL)
        {
          challenge++;

          while (*challenge != '\0' && *challenge == ' ')
            challenge++;

          if (strlen(challenge) > 2 && memcmp(challenge, "C=", 2) == 0)
            {
              *ptr = '\0';
              ptr = challenge;
            }
          else
            {
              challenge = NULL;
            }
        }
    }

  if (ptr != NULL && *ptr != '\0')
    {
      version_code = strchr(ptr, ' ');
      if (version_code != NULL)
        {
          *version_code++ = '\0';

          while (*version_code != '\0' && *version_code == ' ')
            version_code++;

          if (strlen(version_code) < 3 || memcmp(version_code, "V=", 2) != 0)
            version_code = NULL;
        }
    }

  /* Require that the "E=xxx" field is present */
  if (strlen(error_code) < 3 || memcmp(error_code, "E=", 2) != 0)
    goto fail;

  error_value = (SshUInt16)strtol(error_code + 2, NULL, 10);

  if (version_code != NULL && strlen(version_code) >= 3
      && memcmp(version_code, "V=", 2) == 0)
    version_value = (SshUInt16)strtol(version_code + 2, NULL, 10);

  if (retry != NULL && strlen(retry) >= 3 && memcmp(retry, "R=", 2) ==  0)
    retry_value = (SshUInt16)strtol(retry + 2, NULL, 10);

  /* Return parsed parameters */
  *error_code_return = error_value;
  *version_code_return = (SshUInt8)version_value;
  *retry_code_return = (SshUInt8)retry_value;

  if (challenge != NULL)
    {
      if ((strlen(challenge) - 2) !=
          SSH_EAP_MSCHAPV2_FAILURE_CHALLENGE_LENGTH)
        goto fail;

      *challenge_return = ssh_malloc(strlen(challenge) - 1);
      if (*challenge_return == NULL)
        goto fail;

      /* Skip C= */
      memcpy(*challenge_return, challenge + 2, strlen(challenge) - 1);
      *challenge_return_len = SSH_EAP_MSCHAPV2_FAILURE_CHALLENGE_LENGTH;
    }

  ssh_free(resp);
  return TRUE;

 fail:
  ssh_free(resp);
  return FALSE;
}

static Boolean
ssh_eap_mschap_v2_generate_generate_keys(SshUInt8 *secret,
                                         SshUInt8 secret_length,
                                         SshUInt8 *nt_response,
                                         SshUInt8 *master_send_key,
                                         SshUInt8 *master_receive_key)
{
  SshUInt8 md4_out[32] = {'\0'};
  SshUInt8 master_key[32] = {'\0'};
  SshUInt8 *tmpbuf;
  SshHash sha1 = NULL;
  SshCryptoStatus hash_status = SSH_CRYPTO_OK;

  tmpbuf = ssh_eap_mschap_v2_string_tounicode(secret, secret_length);
  if (tmpbuf == NULL)
    return FALSE;

  /* Compute HashNTPasswordHash() into md4_out */
  if (ssh_eap_mschap_v2_md4(tmpbuf, 2 * secret_length, md4_out, 32) == FALSE)
    goto fail;

  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("PasswordHash:"), md4_out, 16);

  if (ssh_eap_mschap_v2_md4(md4_out, 16, md4_out, 16) == FALSE)
    goto fail;

  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("PasswordHashHash:"), md4_out, 16);

  hash_status = ssh_hash_allocate("sha1", &sha1);
  if (hash_status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not instantiate SHA1 algorithm when generating "
                 "authenticator response"));
      goto fail;
    }

  ssh_hash_digest_length(ssh_hash_name(sha1));
  ssh_hash_reset(sha1);
  ssh_hash_update(sha1, md4_out, 16);
  ssh_hash_update(sha1, nt_response, 24);
  ssh_hash_update(sha1, mschap_v2_key_magic_1, 27);
  ssh_hash_final(sha1, master_key);
  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("MasterKey:"), master_key, 16);

  ssh_hash_reset(sha1);
  ssh_hash_update(sha1, master_key, 16);
  ssh_hash_update(sha1, mschap_v2_pad_1, 40);
  ssh_hash_update(sha1, mschap_v2_key_magic_2, 84);
  ssh_hash_update(sha1, mschap_v2_pad_2, 40);
  ssh_hash_final(sha1, master_receive_key);
  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("MasterReceiveKey:"), master_receive_key, 16);

  ssh_hash_reset(sha1);
  ssh_hash_update(sha1, master_key, 16);
  ssh_hash_update(sha1, mschap_v2_pad_1, 40);
  ssh_hash_update(sha1, mschap_v2_key_magic_3, 84);
  ssh_hash_update(sha1, mschap_v2_pad_2, 40);
  ssh_hash_final(sha1, master_send_key);
  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("MasterSendKey:"), master_send_key, 16);

  ssh_hash_free(sha1);
  ssh_free(tmpbuf);
  return TRUE;

 fail:
  ssh_free(tmpbuf);
  return FALSE;
}

static Boolean
ssh_eap_mschap_v2_generate_authenticator_response(
                                             SshUInt8 *secret,
                                             SshUInt16 secret_length,
                                             SshUInt8 *peer_challenge,
                                             SshUInt16 peer_challenge_length,
                                             SshUInt8 *auth_challenge,
                                             SshUInt16 auth_challenge_length,
                                             SshUInt8 *user_name,
                                             SshUInt16 user_name_length,
                                             SshUInt8 *ntresponse,
                                             SshUInt16 ntresponse_length,
                                             SshUInt8 *dst,
                                             SshUInt16 dstlen)
{
  SshUInt8 *tmpbuf;
  SshHash sha1 = NULL;
  SshCryptoStatus hash_status   = SSH_CRYPTO_OK;
  SshUInt16 sha1_len = 0;
  SshUInt8 md4_out[32] = {'\0'};
  SshUInt8 challenge[32] = {'\0'};
  SshUInt8 sha1_out[32] = {'\0'};

  tmpbuf = ssh_eap_mschap_v2_string_tounicode(secret, secret_length);
  if (tmpbuf == NULL)
    return FALSE;

  memset(dst, 0, dstlen);

  /* Compute HashNTPasswordHash() into md4_out */
  if (ssh_eap_mschap_v2_md4(tmpbuf, 2 * secret_length, md4_out, 32) == FALSE)
    goto fail;

  if (ssh_eap_mschap_v2_md4(md4_out, 16, md4_out, 16) == FALSE)
    goto fail;

  /* Compute "ChallengeHash" into 8 first bytes of sha1_out */
  hash_status = ssh_hash_allocate("sha1", &sha1);
  if (hash_status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not instantiate SHA1 algorithm when generating "
                 "authenticator response"));
      goto fail;
    }

  sha1_len = ssh_hash_digest_length(ssh_hash_name(sha1));
  ssh_hash_reset(sha1);
  ssh_hash_update(sha1, peer_challenge, peer_challenge_length);
  ssh_hash_update(sha1, auth_challenge, auth_challenge_length);




  if (user_name != NULL && user_name_length > 0)
    ssh_hash_update(sha1, user_name, user_name_length);

  if (sha1_len <= 32)
    ssh_hash_final(sha1, challenge);
  else
    memset(challenge, 0, 32);

  /* Compute the main skeleton of GenerateAuthenticatorResponse() */
  ssh_hash_reset(sha1);
  ssh_hash_update(sha1, md4_out, 16);
  ssh_hash_update(sha1, ntresponse, ntresponse_length);
  ssh_hash_update(sha1, mschap_v2_magic1, 39);

  if (sha1_len <= 32)
    ssh_hash_final(sha1,sha1_out);
  else
    memset(sha1_out,0,32);

  ssh_hash_reset(sha1);
  ssh_hash_update(sha1, sha1_out, sha1_len);
  ssh_hash_update(sha1, challenge, 8);
  ssh_hash_update(sha1, mschap_v2_magic2, 41);

  if (sha1_len <= dstlen)
    ssh_hash_final(sha1, dst);

  ssh_hash_free(sha1);
  ssh_free(tmpbuf);

  return TRUE;

 fail:
  ssh_free(tmpbuf);
  return FALSE;
}

static Boolean
ssh_eap_mschap_v2_generate_ntresponse(SshUInt8 *secret,
                                      SshUInt16 secret_length,
                                      SshUInt8 *peer_challenge,
                                      SshUInt16 peer_challenge_length,
                                      SshUInt8 *challenge,
                                      SshUInt16 challenge_length,
                                      SshUInt8 *user_name,
                                      SshUInt16 user_name_length,
                                      SshUInt8 *dst,
                                      SshUInt16 dstlen)
{
  SshHash sha1 = NULL;
  SshCryptoStatus hash_status   = SSH_CRYPTO_OK;
  SshUInt8 sha1_out[32] = {'\0'};
  SshUInt8 md4_out[32] = {'\0'};
  SshUInt8 des_key[8] = {'\0'};
  SshUInt8 in_idx = 0;
  SshUInt8 out_idx = 0;


  /* Compute "ChallengeHash" into 8 first bytes of sha1_out */
  memset(dst, 0, dstlen);
  if (dstlen < 24)
    return FALSE;

  hash_status = ssh_hash_allocate("sha1", &sha1);
  if (hash_status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not instantiate SHA1 algorithm when generating "
                 "NTresponse"));
      return FALSE;
    }

  ssh_eap_mschap_v2_init_peer_challenge(peer_challenge);
  ssh_hash_reset(sha1);
  ssh_hash_update(sha1, peer_challenge, peer_challenge_length);
  ssh_hash_update(sha1, challenge, challenge_length);

  if (user_name != NULL && user_name_length > 0)
    ssh_hash_update(sha1, user_name, user_name_length);

  if (ssh_hash_digest_length(ssh_hash_name(sha1)) <= 32)
    ssh_hash_final(sha1, sha1_out);
  else
    memset(sha1_out, 0, 32);

  ssh_hash_free(sha1);
  sha1 = NULL;

  memset(md4_out, 0, 32);
  if (ssh_eap_mschap_v2_md4(secret, secret_length, md4_out, 32) == FALSE)
    return FALSE;

  /* Compute ChallengeResponse */
  in_idx = 0;
  out_idx = 0;
  do {
    ssh_eap_mschap_v2_expand_des_key(des_key, md4_out + in_idx);

    if (ssh_single_des_cbc(des_key,
                           8,
                           dst + out_idx,
                           sha1_out,
                           8) == FALSE)
      {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Failed DES-CBC while creating NTresponse"));
        return FALSE;
      }

    out_idx += 8;
    in_idx += 7;
  } while (in_idx < 21);

  return TRUE;
}

static void
ssh_eap_mschap_v2_reset(SshEapProtocol protocol, SshEap eap)
{
  SshEapMschapv2State state;

  state = ssh_eap_protocol_get_state(protocol);

  if (state == NULL)
    return;

  if (state->peer_name != NULL)
    ssh_free(state->peer_name);

  if (state->secret_buf != NULL)
    ssh_free(state->secret_buf);

  if (state->new_secret_buf != NULL)
    ssh_free(state->new_secret_buf);

  if (state->challenge_buffer != NULL)
    ssh_free(state->challenge_buffer);

  memset(state, 0, sizeof(SshEapMschapv2StateStruct));

  SSH_DEBUG(SSH_D_MIDOK,("eap mschapv2 state reset"));
}
#endif /* SSHDIST_EAP_MSCHAPV2 */


void*
ssh_eap_mschap_v2_create(SshEapProtocol protocol, SshEap eap, SshUInt8 type)
{
#ifdef SSHDIST_EAP_MSCHAPV2
  SshEapMschapv2State state;

  state = ssh_malloc(sizeof(*state));

  if (state == NULL)
    return NULL;

  memset(state, 0, sizeof(SshEapMschapv2StateStruct));

  SSH_DEBUG(SSH_D_LOWOK,("created eap mschapv2 auth state"));

  return state;
#else /* SSHDIST_EAP_MSCHAPV2 */
  return NULL;
#endif /* SSHDIST_EAP_MSCHAPV2 */
}

void
ssh_eap_mschap_v2_destroy(SshEapProtocol protocol, SshUInt8 type, void *ctx)
{
#ifdef SSHDIST_EAP_MSCHAPV2
  SshEapMschapv2State state = NULL;

  state = (SshEapMschapv2State)ctx;

  if (state != NULL)
    {
      if (state->peer_name != NULL)
        ssh_free(state->peer_name);

      if (state->secret_buf != NULL)
        ssh_free(state->secret_buf);

      if (state->new_secret_buf != NULL)
        ssh_free(state->new_secret_buf);

      if (state->challenge_buffer != NULL)
        ssh_free(state->challenge_buffer);

      ssh_free(state);
    }
#endif /* SSHDIST_EAP_MSCHAPV2 */
}

#ifdef SSHDIST_EAP_MSCHAPV2
static void
ssh_eap_mschapv2_client_recv_challenge(SshEapProtocol protocol,
                                       SshEap eap,
                                       SshBuffer buf)
{
  SshEapMschapv2State state = NULL;

  state = ssh_eap_protocol_get_state(protocol);
  if ((state->flags & SSH_EAP_MSCHAPV2_CHALLENGE_REQUEST_RECEIVED)
      && !(state->flags & SSH_EAP_MSCHAPV2_CHALLENGE_RESPONSE_SENT))
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "EAP-MSCHAPV2: waiting for user input, silently "
                             "discard duplicate challenge request");
      return;
    }

  state->flags |= SSH_EAP_MSCHAPV2_CHALLENGE_REQUEST_RECEIVED;
  if (state->challenge_buffer != NULL)
    {
      ssh_free(state->challenge_buffer);
      state->challenge_buffer =  NULL;
    }

  if (ssh_buffer_ptr(buf) == NULL || (ssh_buffer_len(buf) < 6))
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "packet length incorrect for EAP-MSCHAPV2 "
                             "packet");
      return;
    }
  state->challenge_length  = ssh_buffer_ptr(buf)[9];

  /* MS-CHAPv2 challenge size always 16 bytes */
  if (state->challenge_length != SSH_EAP_MSCHAPV2_CHALLENGE_LENGTH
      || (state->challenge_length + 10) > ssh_buffer_len(buf))
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "EAP-MSCHAPV2 incorrect challenge length");
      return;
    }

  state->challenge_buffer = ssh_malloc(state->challenge_length);
  if (state->challenge_buffer == NULL)
    {
      ssh_eap_fatal(eap, protocol,
                    "Could not allocate buffer for challenge");
      return;
    }

  memcpy(state->challenge_buffer, ssh_buffer_ptr(buf) + 10,
         state->challenge_length);
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Challenge packet:"),
                    state->challenge_buffer, state->challenge_length);
  state->identifier = *(ssh_buffer_ptr(buf) + 6);

  /* We might already have the username, if this is resend */
  if (state->peer_name)
    ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                   SSH_EAP_TOKEN_SHARED_SECRET);
  else
    ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                   SSH_EAP_TOKEN_USERNAME);
}

static void
ssh_eap_mschapv2_client_recv_success(SshEapProtocol protocol,
                                     SshEap eap,
                                     SshBuffer buf)
{
  SshEapMschapv2State state = NULL;
  SshUInt8 *ucp = NULL;
  SshUInt16 len = 0;
  SshUInt8 *secret = NULL;
  SshUInt16 secretlen = 0;
  SshUInt8 *authresp = NULL;
  SshBuffer pkt = NULL;
  SshUInt8 b = 0;
  SshUInt8 hexbuf[SSH_EAP_MSCHAPV2_AUTHRESP_LENGTH*2 + 2] = {'\0'};
  SshUInt8 tmp_response[SSH_EAP_MSCHAPV2_AUTHRESP_LENGTH] = {'\0'};
  SshUInt8 send_key[SSH_EAP_MSCHAPV2_KEY_LEN + 2] = {'\0'};
  SshUInt8 recv_key[SSH_EAP_MSCHAPV2_KEY_LEN + 2] = {'\0'};

  SSH_DEBUG(SSH_D_MY, ("Received success request."));
  state = ssh_eap_protocol_get_state(protocol);
  if (!(state->flags & SSH_EAP_MSCHAPV2_CHALLENGE_RESPONSE_SENT))
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "EAP-MSCHAPV2 received unexpected success"
                             " request");
      return;
    }

  len = ssh_eap_packet_get_length(buf);
  if (len > ssh_buffer_len(buf))
    /* invalid packet, silently drop */
    goto fail_auth;

  if (len < (2 * SSH_EAP_MSCHAPV2_AUTHRESP_LENGTH + 6))
    goto fail_auth;

  ucp = ssh_buffer_ptr(buf);
  /* get the authenticator response */
  authresp = ucp + 9;

  if (memcmp(authresp, "S=", 2) != 0)
    goto fail_auth;

  if (state->is_secret_newpw == 1)
    {
      secret = state->new_secret_buf;
      secretlen = state->new_secret_length;
    }
  else
    {
      secret = state->secret_buf;
      secretlen = state->secret_length;
    }

  /* claculated authenticator response */
  if (ssh_eap_mschap_v2_generate_authenticator_response(
                                      secret,
                                      secretlen,
                                      state->peer_challenge_buffer,
                                      SSH_EAP_MSCHAPV2_CHALLENGE_LENGTH,
                                      state->challenge_buffer,
                                      state->challenge_length,
                                      state->peer_name,
                                      state->peer_name_length,
                                      state->nt_response_buffer,
                                      SSH_EAP_MSCHAPV2_NTRESPONSE_LENGTH,
                                      tmp_response,
                                      SSH_EAP_MSCHAPV2_AUTHRESP_LENGTH)
      == FALSE)
    {
      ssh_eap_fatal(eap, protocol, "Creating auth response failed");
      return;
    }

  ssh_eap_mschap_v2_tohexstring(hexbuf, tmp_response,
                                SSH_EAP_MSCHAPV2_AUTHRESP_LENGTH);
  SSH_DEBUG(SSH_D_MY, ("Authenticator Response: %s", hexbuf));
  if (memcmp(authresp + 2, hexbuf, SSH_EAP_MSCHAPV2_AUTHRESP_LENGTH * 2)
      != 0)
    /* Authentication failed */
    goto fail_auth;

  /* generate master session key */
  if (ssh_eap_mschap_v2_generate_generate_keys(
                                 secret,
                                 (SshUInt8) secretlen,
                                 state->nt_response_buffer,
                                 send_key,
                                 recv_key) != FALSE)
    {
      eap->msk = ssh_malloc(64);
      if (eap->msk != NULL)
        {
          eap->msk_len = 64;
          memset(eap->msk, 0, 64);
          memcpy(eap->msk, recv_key, 16);
          memcpy(eap->msk + 16, send_key, 16);
          /* plus 32 bytes of 0 padding */
          SSH_DEBUG_HEXDUMP(SSH_D_MY, ("EAP-MSCHAPv2 MSK:"),
                            eap->msk, 64);
        }
    }

  /* generate response packet */
  pkt = ssh_eap_create_reply(eap, 1,protocol->impl->id);
  if (pkt == NULL)
    {
      ssh_eap_fatal(eap, protocol,
                    "Out of memory. Could not allocate reply packet.");
      return;
    }

  b = (SshUInt8)(3);
  ssh_buffer_append(pkt, &b, 1);
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Success response:"),
                    ssh_buffer_ptr(pkt), ssh_buffer_len(pkt));

  ssh_eap_protocol_send_response(protocol, eap, pkt);
  state->flags |= SSH_EAP_MSCHAPV2_SUCCESS_STATUS;
  ssh_eap_protocol_auth_ok(protocol, eap, SSH_EAP_SIGNAL_NONE, NULL);
  return;

 fail_auth:
  state->flags |= SSH_EAP_MSCHAPV2_FAILURE_STATUS;
  ssh_eap_protocol_auth_fail(protocol, eap,
                             SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION, NULL);
  return;
}

static void
ssh_eap_mschapv2_client_recv_failure(SshEapProtocol protocol,
                                     SshEap eap,
                                     SshBuffer buf)
{
  SshUInt8 *ucp = NULL;
  SshUInt8 *challenge = NULL;
  SshUInt8 challenge_length = 0;
  SshUInt16 error_value = 0;
  SshUInt8 version_value = 0;
  SshUInt8 retry_value = 0;
  SshUInt16 len = 0;
  SshBuffer pkt = NULL;
  SshUInt8 b = 0;
  SshEapMschapv2State state = NULL;

  state = ssh_eap_protocol_get_state(protocol);
  if (!(state->flags & SSH_EAP_MSCHAPV2_CHALLENGE_RESPONSE_SENT))
    {
     ssh_eap_discard_packet(eap, protocol, buf,
                            "EAP-MSCHAPV2 received unexpected failure "
                            "request");
      return;
    }

  ucp = ssh_buffer_ptr(buf) + 9;
  len = ssh_buffer_len(buf) - 9;
  if (ssh_eap_mschap_v2_parse_failure(ucp, (SshUInt8) len,
                                      &error_value,
                                      &retry_value,
                                      &challenge,
                                      &challenge_length,
                                      &version_value) == FALSE)
    {
      ssh_free(challenge);
      ssh_eap_fatal(eap, protocol,
                    "eap mschapv2 failure packet parsing failed");
      return;
    }

  /* The failure is not retryable, send failure response */



  if (retry_value == 0)
    {
      ssh_free(challenge);

      pkt = ssh_eap_create_reply(eap, 1, protocol->impl->id);
      if (pkt == NULL)
        {
          ssh_eap_fatal(eap, protocol,
                        "Out of memory. Could not allocate reply packet.");
          return;
        }
      b = (SshUInt8)(4);
      ssh_buffer_append(pkt, &b, 1);
      ssh_eap_protocol_send_response(protocol, eap, pkt);
      ssh_eap_protocol_auth_fail(protocol, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION,
                                 NULL);
      return;
    }
  else /* try again with response packet */
    {
      /* Throw away old challenge */
      if (state->challenge_buffer != NULL)
        {
          ssh_free(state->challenge_buffer);
          state->challenge_buffer =  NULL;
        }

      state->challenge_buffer = challenge;
      state->challenge_length =
        SSH_EAP_MSCHAPV2_FAILURE_CHALLENGE_LENGTH;

      /* Request a new secret */
      if (state->secret_buf != NULL)
        ssh_free(state->secret_buf);
      state->secret_buf = NULL;

      if (state->new_secret_buf != NULL)
        ssh_free(state->new_secret_buf);
      state->new_secret_buf = NULL;

      ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                     SSH_EAP_TOKEN_SHARED_SECRET);
    }
  SSH_DEBUG(SSH_D_NICETOKNOW,("MS-CHAP failure: E=%u R=%u",
                              error_value,retry_value));
  return;
}

static void
ssh_eap_mschap_v2_client_recv_msg(SshEapProtocol protocol,
                                  SshEap eap,
                                  SshBuffer buf)
{
  SshEapMschapv2State state = NULL;
  unsigned char *ucp = NULL;

  state = ssh_eap_protocol_get_state(protocol);
  if (state == NULL)
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "EAP-MSCHAPV2 state uninitialized");
      return;
    }

  ucp = ssh_buffer_ptr(buf);
  if (ucp == NULL || (ssh_buffer_len(buf) < 6))
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "packet length incorrect for EAP-MSCHAPV2 "
                             "packet");
      return;
    }

  switch (ssh_buffer_ptr(buf)[5])
    {
    case SSH_EAP_MSCHAPV2_CHALLENGE:
      ssh_eap_mschapv2_client_recv_challenge(protocol, eap, buf);
      break;
    case SSH_EAP_MSCHAPV2_SUCCESS:
      ssh_eap_mschapv2_client_recv_success(protocol, eap, buf);
      break;
    case SSH_EAP_MSCHAPV2_FAILURE:
      ssh_eap_mschapv2_client_recv_failure(protocol, eap, buf);
      break;
    default:
      break;
    }
}

static void
ssh_eap_mschap_v2_client_recv_username(SshEapProtocol protocol,
                                       SshEap eap,
                                       SshBuffer buf)
{
  SshEapMschapv2State state = NULL;
  SshEapToken token = NULL;

  SSH_DEBUG(SSH_D_MY, ("Received username token"));
  state = ssh_eap_protocol_get_state(protocol);
  /* Wipe out the old stuff if required. */
  if (state->peer_name)
    {
      ssh_free(state->peer_name);
      state->peer_name = NULL;
    }

  token = (SshEapToken)ssh_buffer_ptr(buf);

  if (!token->token.buffer.dptr || token->token.buffer.len <= 0)
    {
      ssh_eap_discard_token(eap, protocol, buf,
                            ("eap mschapv2 did not receive"
                             " valid username"));
      ssh_eap_protocol_auth_fail(protocol, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION,
                                 NULL);
      return;
    }

  state->peer_name = ssh_calloc(1, token->token.buffer.len + 1);
  if (!state->peer_name)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap mschapv2 buffer"
                                                 " allocation failed"));
      return;
    }

  memcpy(state->peer_name, token->token.buffer.dptr,
         token->token.buffer.len);
  state->peer_name_length = (SshUInt8)token->token.buffer.len;
  SSH_DEBUG(SSH_D_MY, ("Received username %s.", state->peer_name));
  /* both name and password needed */
  SSH_DEBUG(SSH_D_MY, ("Requesting shared secret."));
  ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                 SSH_EAP_TOKEN_SHARED_SECRET);
}

static void
ssh_eap_mschap_v2_client_recv_secret(SshEapProtocol protocol,
                                     SshEap eap,
                                     SshBuffer buf)
{
  SshEapMschapv2State state = NULL;
  SshEapToken token = NULL;
  SshUInt16 secret_len = 0;
  SshUInt8 *secret_ptr = NULL;
  SshUInt8 *secret = NULL;
  SshUInt8 b = 0;
  SshUInt16 name_len = 0;
  SshBuffer pkt = NULL;
  int i = 0;
  SshUInt8 hdr[2];

  SSH_DEBUG(SSH_D_MY, ("Received shared secret token"));
  token = (SshEapTokenStruct *)ssh_buffer_ptr(buf);
  if (token == NULL)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("invalid token"));
      return;
    }

  secret_ptr = ssh_eap_get_token_secret_ptr(token);
  secret_len = (SshUInt16) ssh_eap_get_token_secret_len(token);
  if (secret_ptr == NULL || secret_len == 0)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap mschapv2 did not receive"
                                                 " valid secret"));
      ssh_eap_protocol_auth_fail(protocol, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION,
                                 NULL);
      return;
    }
  secret = ssh_eap_mschap_v2_string_tounicode(secret_ptr, secret_len);
  state = ssh_eap_protocol_get_state(protocol);

  name_len = 0;
  if (state != NULL && state->peer_name != NULL)
    name_len = state->peer_name_length;

  if (state == NULL || state->challenge_buffer == NULL)
    {
      ssh_eap_discard_token(eap, protocol, buf,
                            "EAP-MSCHAPV2 state lacks authenticator "
                            "challenge");
      goto fail;
    }

  /* Do not include common eap headers to length */
  pkt = ssh_eap_create_reply(
                 eap,
                 (SshUInt16)(5 + SSH_EAP_MSCHAPV2_RESPONSE_LENGTH + name_len),
                 protocol->impl->id);
  if (pkt == NULL)
    {
      ssh_eap_fatal(eap, protocol,
                    "Out of memory. Could not allocate reply packet.");
      goto fail;
    }

/* Based on the above, fill in the NTresponse field */
  if (ssh_eap_mschap_v2_generate_ntresponse(
                                    secret,
                                    2 * secret_len,
                                    state->peer_challenge_buffer,
                                    SSH_EAP_MSCHAPV2_CHALLENGE_LENGTH,
                                    state->challenge_buffer,
                                    state->challenge_length,
                                    state->peer_name,
                                    name_len,
                                    state->nt_response_buffer,
                                    SSH_EAP_MSCHAPV2_NTRESPONSE_LENGTH)
           == FALSE)
    {

      goto fail;
    }
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("NT Response:"),
                    state->nt_response_buffer,
                    SSH_EAP_MSCHAPV2_NTRESPONSE_LENGTH);
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Peer challenge:"),
                    state->peer_challenge_buffer,
                    SSH_EAP_MSCHAPV2_CHALLENGE_LENGTH);
  /* Build the packet buffer */
  b = (SshUInt8)(SSH_EAP_MSCHAPV2_RESPONSE);
  ssh_buffer_append(pkt, &b, 1);

  b = (SshUInt8)(state->identifier & 0xFF);
  ssh_buffer_append(pkt, &b, 1);

  hdr[0] = ((5 + SSH_EAP_MSCHAPV2_RESPONSE_LENGTH + name_len) >> 8);
  hdr[1] = (5 + SSH_EAP_MSCHAPV2_RESPONSE_LENGTH + name_len) & 0xFF;
  ssh_buffer_append(pkt, hdr, 2);

  b = (SshUInt8)(SSH_EAP_MSCHAPV2_RESPONSE_LENGTH);
  ssh_buffer_append(pkt, &b, 1);
  ssh_buffer_append(pkt, state->peer_challenge_buffer,
                    SSH_EAP_MSCHAPV2_CHALLENGE_LENGTH);
  b = (SshUInt8)(0x00);
  for (i = 0; i < SSH_EAP_MSCHAPV2_RESERVED_LENGTH; i++)
    ssh_buffer_append(pkt, &b, 1);
  ssh_buffer_append(pkt, state->nt_response_buffer,
                    SSH_EAP_MSCHAPV2_NTRESPONSE_LENGTH);
  ssh_buffer_append(pkt, &b, 1);
  ssh_buffer_append(pkt, state->peer_name, state->peer_name_length);

  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("Sending packet:"), ssh_buffer_ptr(pkt),
                    ssh_buffer_len(pkt));
  ssh_eap_protocol_send_response(protocol, eap, pkt);

  state->flags |= SSH_EAP_MSCHAPV2_CHALLENGE_RESPONSE_SENT;
  pkt = NULL;

  /* Store the secret for rechallenge in success packet */
  ssh_free(secret);
  secret = NULL;
  if (secret_ptr != NULL)
    {
      secret = ssh_malloc(secret_len);
      if (secret == NULL)
        {
          ssh_eap_fatal(eap, protocol,
                        "Out of memory.");
          goto fail;
        }

      memcpy(secret, secret_ptr, secret_len);
      if (state->is_secret_newpw == 1)
        {
          state->new_secret_buf = secret;
          state->new_secret_length = secret_len;
        }
      else
        {
          state->secret_buf = secret;
          state->secret_length = secret_len;
        }
      secret = NULL;
   }
  return;

 fail:
  if (pkt != NULL)
    ssh_buffer_free(pkt);

  if (secret != NULL)
    ssh_free(secret);

  ssh_eap_fatal(eap, protocol, "eap mschapv2 could not create NT response");
  return;
}

static void
ssh_eap_mschap_v2_client_recv_token(SshEapProtocol protocol,
                                    SshEap eap,
                                    SshBuffer buf)
{
  SshEapToken t = NULL;
  SshUInt8 token_type = 0;

  t = (SshEapToken)ssh_buffer_ptr(buf);
  if (t == NULL)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("invalid token"));
      return;
    }

  token_type = ssh_eap_get_token_type_from_buf(buf);
  switch (token_type)
    {
    case SSH_EAP_TOKEN_USERNAME:
      ssh_eap_mschap_v2_client_recv_username(protocol, eap, buf);
      break;
    case SSH_EAP_TOKEN_SHARED_SECRET:
      ssh_eap_mschap_v2_client_recv_secret(protocol, eap, buf);
      break;
    default:
      ssh_eap_discard_token(eap, protocol, buf, ("unexpected token type"));
      return;
    }
}
#endif /* SSHDIST_EAP_MSCHAPV2 */

SshEapOpStatus
ssh_eap_mschap_v2_signal(SshEapProtocolSignalEnum sig,
                         SshEap eap,
                         SshEapProtocol protocol,
                         SshBuffer buf)
{
#ifdef SSHDIST_EAP_MSCHAPV2
  SshEapMschapv2State state = NULL;

  if (ssh_eap_isauthenticator(eap) == TRUE)
    {
      switch (sig)
        {
        case SSH_EAP_PROTOCOL_RESET:
          SSH_ASSERT(buf == NULL);
          break;

        case SSH_EAP_PROTOCOL_BEGIN:
          SSH_ASSERT(buf == NULL);
          break;

        case SSH_EAP_PROTOCOL_RECV_MSG:
          SSH_ASSERT(buf != NULL);
          break;

        case SSH_EAP_PROTOCOL_RECV_TOKEN:
          SSH_ASSERT(buf != NULL);
          break;

        default:
          SSH_NOTREACHED;
        }
    }
  else
    {
      switch (sig)
        {
        case SSH_EAP_PROTOCOL_RESET:
          SSH_ASSERT(buf == NULL);
          ssh_eap_mschap_v2_reset(protocol,eap);
          break;

        case SSH_EAP_PROTOCOL_BEGIN:
          SSH_ASSERT(buf == NULL);
          state = ssh_eap_protocol_get_state(protocol);
          state->flags |= SSH_EAP_MSCHAPV2_BEGIN;
          break;

        case SSH_EAP_PROTOCOL_RECV_MSG:
          SSH_ASSERT(buf != NULL);
          ssh_eap_mschap_v2_client_recv_msg(protocol, eap, buf);
          break;

        case SSH_EAP_PROTOCOL_RECV_TOKEN:
          ssh_eap_mschap_v2_client_recv_token(protocol, eap, buf);
          break;

        default:
          SSH_NOTREACHED;
        }
    }
#endif /* SSHDIST_EAP_MSCHAPV2 */
  return SSH_EAP_OPSTATUS_SUCCESS;
}

SshEapOpStatus
ssh_eap_mschap_v2_key(SshEapProtocol protocol,
                      SshEap eap,
                      SshUInt8 type)
{
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(eap->is_authenticator == TRUE);

  if (eap->mppe_send_keylen < 16 || eap->mppe_recv_keylen < 16)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Keys too short %d %d",
                             eap->mppe_send_keylen,
                             eap->mppe_recv_keylen));
      return SSH_EAP_OPSTATUS_FAILURE;
    }

  eap->msk = ssh_malloc(64);
  if (eap->msk == NULL)
    return SSH_EAP_OPSTATUS_FAILURE;

  eap->msk_len = 64;
  memset(eap->msk, 0, 64);

  memcpy(eap->msk, eap->mppe_recv_key, 16);
  memcpy(eap->msk + 16, eap->mppe_send_key, 16);
  /* Plus 32 bytes of 0 padding */

  SSH_DEBUG_HEXDUMP(SSH_D_MIDOK, ("64 byte EAP-MSCHAPv2 MSK"),
                    eap->msk, eap->msk_len);

  return SSH_EAP_OPSTATUS_SUCCESS;
}

