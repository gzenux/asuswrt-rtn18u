/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Validator search key handling routines. Search by public key. This
   is expensive as it requires ability to encode public key into linear
   buffer (and for certain keys this is even impossible).
*/

#include "sshincludes.h"
#include "cmi.h"
#include "cmi-internal.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertCMiKey"

Boolean ssh_cm_key_kid_create(SshPublicKey public_key, Boolean ike,
                              unsigned char **buf_ret,
                              size_t *len_ret)
{
  SshX509CertificateStruct c;
  const SshX509PkAlgorithmDefStruct *pkalg;

  if (public_key == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Public key not provided."));
      return FALSE;
    }

  if ((pkalg = ssh_x509_public_key_algorithm(public_key)) != NULL)
    {
      c.subject_pkey.pk_type = pkalg->algorithm;
      c.subject_pkey.public_key = public_key;

      if (ike)
        {
          if ((*buf_ret =
               ssh_x509_cert_compute_key_identifier_ike(&c, "sha1", len_ret))
              != NULL)
            return TRUE;
        }
      else
        {
          if ((*buf_ret =
               ssh_x509_cert_compute_key_identifier(&c,
                                                    SSH_CM_HASH_ALGORITHM,
                                                    len_ret)) != NULL)
            return TRUE;
        }
    }
  return FALSE;
}

Boolean
ssh_cm_key_set_x509_key_identifier(SshCertDBKey **key,
                                   const unsigned char *kid, size_t kid_len)
{
  unsigned char *pkid;

  pkid = ssh_memdup(kid, kid_len);

  return ssh_certdb_key_push(key,
                             SSH_CM_KEY_TYPE_PUBLIC_KEY_ID,
                             pkid, pkid ? kid_len : 0, FALSE);
}

Boolean
ssh_cm_key_set_public_key(SshCertDBKey **key, SshPublicKey public_key)
{
  unsigned char *key_digest;
  size_t digest_len;

  if (!ssh_cm_key_kid_create(public_key, FALSE, &key_digest, &digest_len))
    return FALSE;

  if (!ssh_certdb_key_push(key,
                           SSH_CM_KEY_TYPE_PUBLIC_KEY_ID,
                           key_digest, digest_len, FALSE))
    return FALSE;

  if (!ssh_cm_key_kid_create(public_key, TRUE, &key_digest, &digest_len))
    return FALSE;

  if (!ssh_certdb_key_push(key,
                           SSH_CM_KEY_TYPE_PUBLIC_KEY_ID,
                           key_digest, digest_len, FALSE))
    return FALSE;

  return TRUE;
}
#endif /* SSHDIST_CERT */
