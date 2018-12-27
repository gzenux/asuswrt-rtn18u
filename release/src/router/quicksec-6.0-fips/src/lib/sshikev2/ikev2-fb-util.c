/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-payloads.h"
#include "ikev2-internal.h"

#ifdef SSHDIST_IKEV1
#include "isakmp.h"
#include "isakmp_doi.h"
#include "isakmp_util.h"

#include "ikev2-fb.h"

#define SSH_DEBUG_MODULE "SshIkev2FallbackUtil"

SshIkev2FbNegotiation
ssh_ikev2_fb_p1_get_p1_negotiation(SshIkePMPhaseI pm_info)
{
  SshIkev2FbNegotiation neg;
  SshIkev2Sa ike_sa;

  if (pm_info == NULL)
    return NULL;

  ike_sa = (SshIkev2Sa)pm_info->policy_manager_data;
  if (ike_sa == NULL)
    return NULL;

  /* If IKE SA negotiation is done, then the fallback negotiation
     freeing is pending. Return NULL to signal that negotiation is
     finished. */
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
    return NULL;

  /* Check if fallback negotiation is already freed or negotiation
     is aborted. */
  neg = (SshIkev2FbNegotiation)ike_sa->p1_negotiation_context;
  if (neg == NULL || neg->aborted)
    return NULL;
  return neg;
}

/*--------------------------------------------------------------------*/
/* Miscallaneuous utility functions                                   */
/*--------------------------------------------------------------------*/

/* Returns the default key size in bits for the given algorithm. */
size_t ikev2_fb_ikev1_ah_key_len(SshIkeIpsecAHTransformIdentifiers ah_id)
{
  switch (ah_id)
    {
#ifdef SSHDIST_CRYPT_MODE_GCM
    case SSH_IKE_IPSEC_AH_TRANSFORM_AH_AES_128_GMAC:
      return 160;
    case SSH_IKE_IPSEC_AH_TRANSFORM_AH_AES_192_GMAC:
      return 224;
    case SSH_IKE_IPSEC_AH_TRANSFORM_AH_AES_256_GMAC:
      return 288;
#endif /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_XCBCMAC
    case SSH_IKE_IPSEC_AH_TRANSFORM_AH_XCBC_AES:
#endif /* SSHDIST_CRYPT_XCBCMAC */
    case SSH_IKE_IPSEC_AH_TRANSFORM_AH_MD5:
      return 128;
    case SSH_IKE_IPSEC_AH_TRANSFORM_AH_SHA:
      return 160;
    case SSH_IKE_IPSEC_AH_TRANSFORM_AH_SHA2_256:
      return 256;
    case SSH_IKE_IPSEC_AH_TRANSFORM_AH_SHA2_384:
      return 384;
    case SSH_IKE_IPSEC_AH_TRANSFORM_AH_SHA2_512:
      return 512;
    default:
      return 0;
    }
}

/* Returns the default key size in bits for the given algorithm. */
size_t
ikev2_fb_ikev1_auth_key_len(SshIkeIpsecAttributeAuthAlgorithmValues auth_id)
{
  switch (auth_id)
    {
    case IPSEC_VALUES_AUTH_ALGORITHM_HMAC_MD5:
#ifdef SSHDIST_CRYPT_XCBCMAC
    case IPSEC_VALUES_AUTH_ALGORITHM_XCBC_AES:
#endif /* SSHDIST_CRYPT_XCBCMAC */
      return 128;
#ifdef SSHDIST_CRYPT_MODE_GCM
    case IPSEC_VALUES_AUTH_ALGORITHM_AES_128_GMAC:
      return 160;
    case IPSEC_VALUES_AUTH_ALGORITHM_AES_192_GMAC:
      return 224;
    case IPSEC_VALUES_AUTH_ALGORITHM_AES_256_GMAC:
      return 288;
#endif /* SSHDIST_CRYPT_MODE_GCM */
    case IPSEC_VALUES_AUTH_ALGORITHM_HMAC_SHA_1:
      return 160;
    case IPSEC_VALUES_AUTH_ALGORITHM_HMAC_SHA2_256:
      return 256;
    case IPSEC_VALUES_AUTH_ALGORITHM_HMAC_SHA2_384:
      return 384;
    case IPSEC_VALUES_AUTH_ALGORITHM_HMAC_SHA2_512:
      return 512;
    default:
      return 0;
    }
}

/* Returns the default key size in bits for the given algorithm. */
size_t
ikev2_fb_ikev1_esp_key_len(SshIkeIpsecESPTransformIdentifiers esp_id)
{
  switch (esp_id)
    {
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_NULL:
      return 0;
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_DES_IV64:
      return 64;
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_DES:
      return 64;
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_3DES:
        return 192;
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_BLOWFISH:
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_CAMELLIA:
      return 128;
    case SSH_IKE_VALUES_ENCR_ALG_CAST_CBC:
      return 128;
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_IDEA:
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_3IDEA:
      return 128;
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES:
        return 128;
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CTR:
      return 128;
#ifdef SSHDIST_CRYPT_MODE_GCM
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_GCM_8:
      return 128;
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_GCM_12:
      return 128;
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_GCM_16:
      return 128;
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_NULL_AUTH_AES_GMAC:
      return 128;
#endif /*  SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_MODE_CCM
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CCM_8:
      return 128;
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CCM_12:
      return 128;
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CCM_16:
      return 128;
#endif /*  SSHDIST_CRYPT_MODE_CCM */
    default:
      return 0;
    }
}

size_t
ikev2_fb_ikev1_esp_nonce_len(SshIkeIpsecESPTransformIdentifiers esp_id)
{
  switch (esp_id)
    {
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CTR:
#ifdef SSHDIST_CRYPT_MODE_GCM
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_GCM_8:
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_GCM_12:
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_GCM_16:
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_NULL_AUTH_AES_GMAC:
#endif /*  SSHDIST_CRYPT_MODE_GCM */
      return 32;
#ifdef SSHDIST_CRYPT_MODE_CCM
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CCM_8:
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CCM_12:
    case SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CCM_16:
#endif /*  SSHDIST_CRYPT_MODE_CCM */
      return 24;
    default:
      return 0;
    }
}

Boolean
ikev2_fb_cipher_is_fixed_key_length(const unsigned char *algorithm_name)
{
  if (!ssh_usstrcmp(algorithm_name, "aes-cbc"))
    return FALSE;

  if (!ssh_usstrcmp(algorithm_name, "camellia-cbc"))
    return FALSE;

#ifdef SSHDIST_CRYPT_MODE_GCM
  if (!ssh_usstrcmp(algorithm_name, "aes-gcm"))
    return FALSE;

  if (!ssh_usstrcmp(algorithm_name, "aes-gcm-64"))
    return FALSE;

  if (!ssh_usstrcmp(algorithm_name, "aes-gcm-96"))
    return FALSE;
#endif /*  SSHDIST_CRYPT_MODE_GCM */

#ifdef SSHDIST_CRYPT_MODE_CCM
  if (!ssh_usstrcmp(algorithm_name, "aes-ccm"))
    return FALSE;

  if (!ssh_usstrcmp(algorithm_name, "aes-ccm-64"))
    return FALSE;

  if (!ssh_usstrcmp(algorithm_name, "aes-ccm-96"))
    return FALSE;
#endif /*  SSHDIST_CRYPT_MODE_CCM */










  return TRUE;
}

int
ikev2_fb_render_ike_cookie(unsigned char *buf, int buf_size,
                           int precision, void *datum)
{
  int i, len, total_len;
  unsigned char *ptr = (unsigned char *)datum;
  const unsigned char *delim;

  total_len = 0;

  for (i = 0; i < SSH_IKE_COOKIE_LENGTH; i++)
    {
      delim = ((i % 4) == 0 && i != 0) ? ssh_custr(" ") : ssh_custr("");
      len = ssh_snprintf(buf, buf_size, "%s%02x", delim, *ptr);
      if (len < 0)
        return 0;
      ptr++;

      total_len += len;
      buf += len;
      buf_size -= len;
    }
  return total_len;
}

int
ikev2_fb_ike_port_render(unsigned char *buf, int buf_size,
                         int precision, void *datum)
{
  char *port = (char *) datum;
  int wrote;

  SSH_ASSERT(port != NULL);

  if (port[0] == '5' && port[1] == '0' && port[2] == '0' && port[3] == '\0')
    return 0;

  wrote = ssh_snprintf(buf, buf_size, ":%s", port);
  if (wrote >= buf_size - 1)
    return buf_size + 1;

  if (precision >= 0)
    if (wrote > precision)
      wrote = precision;

  return wrote;
}

char *
ikev2_fb_util_data_to_hex(char *buf, size_t buflen,
                          const unsigned char *data, size_t datalen)
{
  int i, nprint;

  nprint = datalen;
  if (buflen / 3 < nprint)
    nprint = buflen / 3;

  if (nprint)
    {
      for (i = 0; i < nprint; i++)
        ssh_snprintf(buf + i * 3, buflen - i * 3, "%02x ", data[i]);
      buf[nprint * 3 - 1] = '\000';
    }
  else
    {
      SSH_ASSERT(buflen >= 1);
      buf[0] = '\000';
    }

  return buf;
}

#define SSH_IKEV2_MAX_KEYMAT_LEN 256

/* Generate keying material for the IPsec SA. The keymat is
   filled with the keying material. */
Boolean ikev2_fb_fill_keymat(SshIkev2ExchangeData ed,
                             SshIkeNegotiation negotiation,
                             SshIkeIpsecSelectedSA sas,
                             SshIkeIpsecKeymat keymat)

{
  SshIkeIpsecAttributeAuthAlgorithmValues auth_algorithm;
  SshCryptoStatus status;
  unsigned char *buffer = NULL;
  size_t keylen, offset;
  int i;

  if ((buffer = ssh_calloc(1, SSH_IKEV2_MAX_KEYMAT_LEN)) == NULL)
    return FALSE;

  SSH_ASSERT(ed->ipsec_ed->ikev1_keymat == NULL);
  offset = 0;

  /* Generate keying material for inbound transforms */
  for (i = 0; i < sas->number_of_protocols; i++)
    {
      SshIkeIpsecSelectedProtocol proto = &sas->protocols[i];

      switch (proto->protocol_id)
        {
        case SSH_IKE_PROTOCOL_IPSEC_AH:
          {
            if (proto->attributes.key_length)
              keylen = proto->attributes.key_length / 8;
            else
              keylen =
                ikev2_fb_ikev1_ah_key_len(proto->transform_id.ipsec_ah) / 8;

            if (keylen == 0 || offset + keylen > SSH_IKEV2_MAX_KEYMAT_LEN)
              goto error;

            SSH_DEBUG(SSH_D_LOWOK, ("Generate keys for inbound AH transform, "
                                    "SPI %lx, key length %zd",
                                    (unsigned long)
                                    SSH_GET_32BIT(proto->spi_in),
                                    keylen));

            /* Get inbound key */
            status = ssh_ike_ipsec_keys(negotiation, keymat,
                                        proto->spi_size_in,
                                        proto->spi_in,
                                        SSH_IKE_PROTOCOL_IPSEC_AH,
                                        keylen * 8,
                                        buffer + offset);
            if (status != SSH_CRYPTO_OK)
              goto error;

            SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Inbound AH key:"),
                              buffer + offset, keylen);

            offset += keylen;
          }
          break;

        case SSH_IKE_PROTOCOL_IPSEC_ESP:
          {
            auth_algorithm = proto->attributes.auth_algorithm;

            /* Do we have an authentication algorithm? */
            if (auth_algorithm)
              {
                keylen = ikev2_fb_ikev1_auth_key_len(auth_algorithm) / 8;
                if (keylen == 0)
                  goto error;
              }
            else
              keylen = 0;

            if (proto->attributes.key_length)
              keylen += proto->attributes.key_length / 8;
            else
              keylen +=
                ikev2_fb_ikev1_esp_key_len(proto->transform_id.ipsec_esp) / 8;

            keylen +=
              ikev2_fb_ikev1_esp_nonce_len(proto->transform_id.ipsec_esp) / 8;

            if (offset + keylen > SSH_IKEV2_MAX_KEYMAT_LEN)
              goto error;

            SSH_DEBUG(SSH_D_LOWOK, ("Generate keys for inbound ESP transform, "
                                    "SPI %lx, key length %zd",
                                    (unsigned long)
                                    SSH_GET_32BIT(proto->spi_in),
                                    keylen));

            status = ssh_ike_ipsec_keys(negotiation, keymat,
                                        proto->spi_size_in,
                                        proto->spi_in,
                                        SSH_IKE_PROTOCOL_IPSEC_ESP,
                                        keylen * 8,
                                        buffer + offset);
            if (status != SSH_CRYPTO_OK)
              goto error;

            SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Inbound ESP key:"),
                              buffer + offset, keylen);

            offset += keylen;
          }
          break;

        default:
          /* No key material for other protocols */
          break;
        }
    }

  /* Generate keying material for outbound transforms */
  for (i = 0; i < sas->number_of_protocols; i++)
    {
      SshIkeIpsecSelectedProtocol proto = &sas->protocols[i];

      switch (proto->protocol_id)
        {
        case SSH_IKE_PROTOCOL_IPSEC_AH:
          {
            if (proto->attributes.key_length)
              keylen = proto->attributes.key_length / 8;
            else
              keylen =
                ikev2_fb_ikev1_ah_key_len(proto->transform_id.ipsec_ah) / 8;

            if (keylen == 0 || offset + keylen > SSH_IKEV2_MAX_KEYMAT_LEN)
              goto error;

            SSH_DEBUG(SSH_D_LOWOK, ("Generate keys for outbound AH, "
                                    "SPI %lx, key length %zd",
                                    (unsigned long)
                                    SSH_GET_32BIT(proto->spi_out),
                                    keylen));

            /* Get outbound key */
            status = ssh_ike_ipsec_keys(negotiation, keymat,
                                        proto->spi_size_out,
                                        proto->spi_out,
                                        SSH_IKE_PROTOCOL_IPSEC_AH,
                                        keylen * 8,
                                        buffer + offset);
            if (status != SSH_CRYPTO_OK)
              goto error;

            SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Outbound AH key:"),
                              buffer + offset, keylen);

            offset += keylen;
          }
          break;

        case SSH_IKE_PROTOCOL_IPSEC_ESP:
          {
            auth_algorithm = proto->attributes.auth_algorithm;

            /* Do we have authentication algorithm? */
            if (auth_algorithm)
              {
                keylen = ikev2_fb_ikev1_auth_key_len(auth_algorithm) / 8;
                if (keylen == 0)
                  goto error;
              }
            else
              keylen = 0;

            if (proto->attributes.key_length)
              keylen += proto->attributes.key_length / 8;
            else
              keylen +=
                ikev2_fb_ikev1_esp_key_len(proto->transform_id.ipsec_esp) / 8;

            keylen +=
              ikev2_fb_ikev1_esp_nonce_len(proto->transform_id.ipsec_esp) / 8;

            if (offset + keylen > SSH_IKEV2_MAX_KEYMAT_LEN)
              goto error;

            SSH_DEBUG(SSH_D_LOWOK, ("Generate keys for outbound ESP "
                                    "transform, SPI %lx, key length %zd",
                                    (unsigned long)
                                    SSH_GET_32BIT(proto->spi_out),
                                    keylen));

            status = ssh_ike_ipsec_keys(negotiation, keymat,
                                        proto->spi_size_out,
                                        proto->spi_out,
                                        SSH_IKE_PROTOCOL_IPSEC_ESP,
                                        keylen * 8,
                                        buffer + offset);
            if (status != SSH_CRYPTO_OK)
              goto error;

            SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Outbound ESP key:"),
                              buffer + offset, keylen);

            offset += keylen;
          }
          break;

        default:
          /* No key material for other protocols */
          break;
        }
    }

  /* Store the key material to the exchange data */
  ed->ipsec_ed->ikev1_keymat = buffer;
  ed->ipsec_ed->ikev1_keymat_len = offset;

  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Keymat, length %d", offset),
                    buffer, offset);
  return TRUE;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("Could not generate IKEv1 IPSec SA keying material"));
  ssh_free(buffer);
  return FALSE;
}


Boolean
ikev2_fb_check_ipsec_responder_lifetimes(SshIkev2ExchangeData ed,
                                         SshUInt32 proposed_life_sec,
                                         SshUInt32 proposed_life_kb)
{
  SshUInt32 lifesec, lifekb;

  /* As a default, use what was proposed. */
  lifesec = proposed_life_sec;
  lifekb = proposed_life_kb;

  /* We use the minimum lifetime specified, or if the initiator's
     proposal did not contain any lifetimes, we use our end's
     lifetimes.  If both ends do not specify lifetime, we fallback to
     our default values. */

  if (proposed_life_kb && ed->ipsec_ed->sa_life_kbytes)
    {
      /* Use the minimum. */
      SSH_DEBUG(SSH_D_MIDOK, ("life (prop=%d, req=%d)kB",
                              (int) proposed_life_kb,
                              (int) ed->ipsec_ed->sa_life_kbytes));
      if (ed->ipsec_ed->sa_life_kbytes < proposed_life_kb)
        lifekb = ed->ipsec_ed->sa_life_kbytes;
    }
  else if (ed->ipsec_ed->sa_life_kbytes)
    {
      /* Use our lifetime. */
      lifekb = ed->ipsec_ed->sa_life_kbytes;
    }

  if (proposed_life_sec && ed->ipsec_ed->sa_life_seconds)
    {
      /* Use the minimum. */
      SSH_DEBUG(SSH_D_MIDOK, ("life (prop=%d, req=%d)s",
                              (int) proposed_life_sec,
                              (int) ed->ipsec_ed->sa_life_seconds));
      if (ed->ipsec_ed->sa_life_seconds < proposed_life_sec)
        lifesec = ed->ipsec_ed->sa_life_seconds;
    }
  else if (ed->ipsec_ed->sa_life_seconds)
    {
      /* Use our lifetime. */
      lifesec = ed->ipsec_ed->sa_life_seconds;
    }

  /* Set the (possibly) modified lifetimes to the IPSec exchange data. */
  ed->ipsec_ed->sa_life_seconds = lifesec;
  ed->ipsec_ed->sa_life_kbytes = lifekb;

  SSH_DEBUG(SSH_D_LOWOK, ("New lifetimes sec=%d, kb=%d",
                          (int) lifesec, (int) lifekb));

  /* If we changed the proposed lifetimes, we must send a responder lifetime
     notification. */
  if (lifesec != proposed_life_sec || lifekb != proposed_life_kb)
    {
      /* We did change the lifetimes. */
      return TRUE;
    }
  return FALSE;
}

void
ikev2_fb_free_sa_indexes(SshIkeIpsecSelectedSAIndexes selected,
                         int number_of_sas)
{
  int i, j;

  if (selected == NULL)
    return;

  for (i = 0; i < number_of_sas; i++)
    {
      ssh_free(selected[i].transform_indexes);
      ssh_free(selected[i].spi_sizes);

      /* Free SPI if it is allocated. */
      if (selected[i].spis)
        {
          for (j = 0; j < selected[i].number_of_protocols; j++)
            ssh_free(selected[i].spis[j]);

          ssh_free(selected[i].spis);
        }
    }
  ssh_free(selected);
}


Boolean
ikev2_fb_select_ipsec_transform_index(SshIkev2PayloadTransform
                                      transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX],
                                      SshIkev2ProtocolIdentifiers
                                      selected_sa_protocol,
                                      SshIkeNegotiation negotiation,
                                      SshIkePayloadSA sav1,
                                      Boolean allow_ipcomp,
                                      SshUInt8 ipcomp_algorithm,
                                      int *proposal_index,
                                      int *ipsec_transform_index,
                                      int *ipcomp_transform_index)
{
  SshIkePayloadPProtocol proto;
  SshIkePayloadP prop;
  Boolean ipcomp_present, ipcomp_matched;
  int iprop, iproto, itrans;
  int ipsec_proto_count;

  /* Check all proposals, as SSH IPsec Express builds multiple
     proposals each having 1 or 2 protocols each having just one
     transform, instead of the usual one proposals, 1 or 2 protocols
     and multiple transforms. */

  for (iprop = 0; iprop < sav1->number_of_proposals; iprop++)
    {
      prop = &sav1->proposals[iprop];

      /* Check if this proposal contains an IPcomp protocol. If 'allow_ipcomp'
         is FALSE we do not consider proposals that contain IPcomp. */
      if (!allow_ipcomp)
        {
          ipcomp_present = FALSE;
          for (iproto = 0; iproto < prop->number_of_protocols; iproto++)
            {
              proto = &prop->protocols[iproto];
              if (proto->protocol_id == SSH_IKE_PROTOCOL_IPCOMP)
                {
                  ipcomp_present = TRUE;
                  break;
                }
            }
          if (ipcomp_present)
            {
              SSH_DEBUG(SSH_D_HIGHOK, ("Ignoring proposal containing IPcomp "
                                       "protocol"));
              continue;
            }
        }
      else
        {
          /* When 'allow_ipcomp' is TRUE the proposal must contain an IPcomp
             protocol one of whose transform identifiers must be equal to
             'ipcomp_algorithm' */
          ipcomp_matched = FALSE;
          for (iproto = 0; iproto < prop->number_of_protocols; iproto++)
            {
              proto = &prop->protocols[iproto];
              if (proto->protocol_id == SSH_IKE_PROTOCOL_IPCOMP)
                {
                  /* Check all transformations. */
                  for (itrans = 0;
                       itrans < proto->number_of_transforms;
                       itrans++)
                    {
                      SshIkePayloadT trans = &proto->transforms[itrans];
                      if (trans->transform_id.ipcomp == ipcomp_algorithm)
                        {
                          /* Found a matching transform, record its index. */
                          *ipcomp_transform_index = itrans;
                          ipcomp_matched = TRUE;
                        }
                    }
                }
            }

          if (!ipcomp_matched)
            {
              SSH_DEBUG(SSH_D_HIGHOK,
                        ("Ignoring non-matching IPcomp proposal"));
              continue;
            }
        }

      /* Make sure that a proposal with multiple ipsec protocol
         e.g. ESP-AH bundle does not get selected.
       */
      ipsec_proto_count = 0;
      for (iproto = 0; iproto < prop->number_of_protocols; iproto++)
        {
          proto = &prop->protocols[iproto];
          if (proto->protocol_id == SSH_IKE_PROTOCOL_IPSEC_AH ||
              proto->protocol_id == SSH_IKE_PROTOCOL_IPSEC_ESP)
            {
              ipsec_proto_count++;
            }
        }

      if (ipsec_proto_count != 1)
        {
          SSH_DEBUG(SSH_D_HIGHOK, ("Ignoring proposal #%d, multiple"
                                   "IPsec protocols", iprop));
          continue;
        }

      for (iproto = 0; iproto < prop->number_of_protocols; iproto++)
        {
          proto = &prop->protocols[iproto];

          /* IPcomp transforms were checked above */
          if (proto->protocol_id == SSH_IKE_PROTOCOL_IPCOMP)
            continue;

          SSH_ASSERT(proto->protocol_id == SSH_IKE_PROTOCOL_IPSEC_ESP ||
                     proto->protocol_id == SSH_IKE_PROTOCOL_IPSEC_AH);

          /* Check all transformations. */
          for (itrans = 0; itrans < proto->number_of_transforms; itrans++)
            {
              SshIkePayloadT trans = &proto->transforms[itrans];
              struct SshIkeIpsecAttributesRec attrs;

              ssh_ike_clear_ipsec_attrs(&attrs);
              if (!ssh_ike_read_ipsec_attrs(negotiation, trans, &attrs))
                return FALSE;

              /* The long sequence attributes must match */
              if (attrs.longseq_size == IPSEC_VALUES_SA_LONGSEQ_64)
                {
                  if (transforms[SSH_IKEV2_TRANSFORM_TYPE_ESN] == NULL ||
                      transforms[SSH_IKEV2_TRANSFORM_TYPE_ESN]->id !=
                      SSH_IKEV2_TRANSFORM_ESN_ESN)
                    continue;
                }
              else
                {
                  if (transforms[SSH_IKEV2_TRANSFORM_TYPE_ESN] != NULL &&
                      transforms[SSH_IKEV2_TRANSFORM_TYPE_ESN]->id ==
                      SSH_IKEV2_TRANSFORM_ESN_ESN)
                    continue;
                }

              /* PFS group if present must match */
              if (attrs.group_desc)
                {
                  if (transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H] == NULL ||
                      transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H]->id !=
                      ikev2_fb_v1_group_id_to_v2_id((int) attrs.group_desc))
                    continue;
                }

              if (proto->protocol_id == SSH_IKE_PROTOCOL_IPSEC_AH)
                {
                  if (selected_sa_protocol != SSH_IKEV2_PROTOCOL_ID_AH)
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW,
                                ("Selected protocol did not match."));
                      continue;
                    }

                  SSH_ASSERT(attrs.auth_algorithm != 0);
                  SSH_ASSERT(transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG]
                             != NULL);

                  /* Authentication algorithm must agree. */
                  if (ikev2_fb_v1_ah_id_to_v2_id(trans->transform_id.ipsec_ah)
                      != transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG]->id)
                    continue;


                  if (attrs.key_length &&
                      (0x800e << 16 | attrs.key_length) !=
                      transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG]
                      ->transform_attribute)
                    continue;
                }

              if (proto->protocol_id == SSH_IKE_PROTOCOL_IPSEC_ESP)
                {
                  if (selected_sa_protocol != SSH_IKEV2_PROTOCOL_ID_ESP)
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW,
                                ("Selected protocol did not match."));
                      continue;
                    }

                  /* Encryption algorithm if present must agree. */
                  if (trans->transform_id.ipsec_esp)
                    {
                      if (transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR] == NULL ||
                          transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR]->id !=
                          ikev2_fb_v1_esp_id_to_v2_id(trans->transform_id
                                                      .ipsec_esp))
                        continue;

                      if (attrs.key_length &&
                          (0x800e << 16 | attrs.key_length) !=
                          transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR]
                          ->transform_attribute)
                        continue;
                    }

                  /* Authentication algorithm, if present, must agree. */
                  if (attrs.auth_algorithm != 0 &&
                      (transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG] == NULL ||
                       transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG]->id !=
                       ikev2_fb_v1_auth_id_to_v2_id(attrs.auth_algorithm)))
                    continue;
                }

              /* All attributes match, return the transform index. */
              *ipsec_transform_index = itrans;
              *proposal_index = iprop;
              return TRUE;
            }
        }
    }
  return FALSE;
}


Boolean
ikev2_fb_select_ike_transform_index(
                           SshIkev2PayloadTransform
                           transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX],
                           SshIkeNegotiation negotiation,
                           SshIkePayloadSA sav1,
                           int *transform_index)
{
  SshIkePayloadPProtocol proto;
  SshIkePayloadP prop;
  int itrans;

  SSH_ASSERT(sav1->number_of_proposals == 1);
  prop = &sav1->proposals[0];

  SSH_ASSERT(transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR] != NULL);
  SSH_ASSERT(transforms[SSH_IKEV2_TRANSFORM_TYPE_PRF] != NULL);
  SSH_ASSERT(transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H] != NULL);

  SSH_ASSERT(prop->number_of_protocols == 1);

  proto = &prop->protocols[0];
  SSH_ASSERT(proto->protocol_id == SSH_IKE_PROTOCOL_ISAKMP);

  /* Check all transformations. */
  for (itrans = 0; itrans < proto->number_of_transforms; itrans++)
    {
      SshIkePayloadT transform = &proto->transforms[itrans];
      struct SshIkeAttributesRec attrs;

      /* Check transform ID. */
      if (transform->transform_id.generic != SSH_IKE_ISAKMP_TRANSFORM_KEY_IKE)
        return FALSE;

      /* Read attributes. */
      ssh_ike_clear_isakmp_attrs(&attrs);

      if (!ssh_ike_read_isakmp_attrs(negotiation, transform, &attrs))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid transform in IKE proposal: "
                                 "transform is malformed or it contains "
                                 "unsupported attributes"));
          continue;
        }

      /* The Diffie-Hellman groups must match */
      if (ikev2_fb_v1_group_id_to_v2_id(attrs.group_desc->descriptor) !=
          transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H]->id)
        continue;

      /* The encryption algorithm and key length must match */
      if (ikev2_fb_v1_encr_id_to_v2_id(attrs.encryption_algorithm) !=
          transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR]->id)
        continue;

      if (attrs.key_length &&
          (0x800e << 16 | attrs.key_length) !=
          transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR]->transform_attribute)
        continue;

      /* The hash algorithm must match */
      if (ikev2_fb_v1_hash_id_to_v2_prf_id(attrs.hash_algorithm) !=
          transforms[SSH_IKEV2_TRANSFORM_TYPE_PRF]->id)
        continue;

      /* All attributes match, return the transform index. */
      *transform_index = itrans;
      return TRUE;
    }
  return FALSE;
}

#endif /* SSHDIST_IKEV1 */
