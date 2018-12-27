/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Decode and encode routines for x509 signatures.
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"
#include "oid.h"
#include "sshmp.h"

#define SSH_DEBUG_MODULE "SshX509Signature"

#ifdef SSHDIST_CERT
SshAsn1Node ssh_x509_encode_sigalg(SshAsn1Context context,
                                   SshPrivateKey issuer_key)
{
  const SshOidStruct *oids;
  SshAsn1Node alg_id;
  SshAsn1Status status;
  const SshX509PkAlgorithmDefStruct *algorithm;

  if (issuer_key == NULL)
    return NULL;

  /* Return a node to the signature algorithm identifier. */
  algorithm = ssh_x509_private_key_algorithm(issuer_key);
  if (algorithm == NULL)
    return NULL;

  SSH_TRACE(8, ("Signature algorithm: %s", algorithm->sign_name));
  oids = ssh_oid_find_by_std_name_of_type(algorithm->sign_name, SSH_OID_SIG);
  if (oids == NULL)
    return NULL;

  status =
    ssh_asn1_create_node(context, &alg_id,
                         "(sequence ()"
                         "  (object-identifier ())"
                         "  (null ()))",
                         oids->oid);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;

  return alg_id;
}

unsigned char *ssh_x509_decode_signature(SshAsn1Context context,
                                         unsigned char *signature,
                                         size_t signature_len,
                                         SshX509PkAlgorithm signature_type,
                                         size_t *out_len)
{
  SshMPIntegerStruct r, s;
  unsigned char *out;
  SshAsn1Status status;
  SshAsn1Tree   tree;
  size_t        lenr, lens;

  if (out_len)
    *out_len = 0;

  switch (signature_type)
    {
    case SSH_X509_PKALG_RSA:
      if ((out = ssh_memdup(signature, signature_len/8)) != NULL)
        if (out_len)
          *out_len = signature_len/8;
      return out;

    case SSH_X509_PKALG_DSA:
#ifdef SSHDIST_CRYPT_ECP
    case SSH_X509_PKALG_ECDSA:
#endif /* SSHDIST_CRYPT_ECP */
      status = ssh_asn1_decode(context, signature, signature_len/8, &tree);
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;

      ssh_mprz_init(&s);
      ssh_mprz_init(&r);
      status = ssh_asn1_read_tree(context, tree,
                                  "(sequence ()"
                                  " (integer ())"
                                  " (integer ()))", &r, &s);
      if (status != SSH_ASN1_STATUS_OK)
        {
          ssh_mprz_clear(&s);
          ssh_mprz_clear(&r);
          return NULL;
        }

      lenr = (ssh_mprz_get_size(&r, 2) + 7)/8;
      lens = (ssh_mprz_get_size(&s, 2) + 7)/8;
      if (lenr < lens)
        lenr = lens;
      if ((out = ssh_malloc(lenr*2)) != NULL)
        {
          ssh_mprz_get_buf(out, lenr, &r);
          ssh_mprz_get_buf(out + lenr, lenr, &s);
          if (out_len)
            *out_len = lenr*2;
        }
      ssh_mprz_clear(&r);
      ssh_mprz_clear(&s);

      return out;

    default:
      break;
    }
  return NULL;
}

unsigned char *
ssh_x509_encode_signature(SshAsn1Context context,
                          const unsigned char *signature, size_t signature_len,
                          SshPrivateKey private_key,
                          size_t *out_len)
{
  SshMPIntegerStruct r, s;
  SshAsn1Node   node;
  unsigned char *out;
  SshAsn1Status status;
  size_t        len;
  const SshX509PkAlgorithmDefStruct *algorithm;

  algorithm = ssh_x509_private_key_algorithm(private_key);
  if (algorithm == NULL)
    return NULL;

  *out_len = 0;
  switch (algorithm->algorithm)
    {
    case SSH_X509_PKALG_RSA:
      *out_len = signature_len*8;
      if ((out = ssh_memdup(signature, signature_len)) == NULL)
        *out_len = 0;
      return out;
      break;

    case SSH_X509_PKALG_DSA:
#ifdef SSHDIST_CRYPT_ECP
    case SSH_X509_PKALG_ECDSA:
#endif /* SSHDIST_CRYPT_ECP */
      /* We don't like odd signature lengths. Best ones always are
         divisible by 2^n! */
      if (signature_len & 1)
        return NULL;

      len = signature_len / 2;

      ssh_mprz_init(&s);
      ssh_mprz_init(&r);

      ssh_mprz_set_buf(&r, signature, len);
      ssh_mprz_set_buf(&s, signature + len, len);

      status = ssh_asn1_create_node(context, &node,
                                    "(sequence ()"
                                    "(integer ())"
                                    "(integer ()))",
                                    &r, &s);

      out = NULL;

      if (status != SSH_ASN1_STATUS_OK)
        goto dsa_failed;

      status = ssh_asn1_encode_node(context, node);
      if (status != SSH_ASN1_STATUS_OK)
        goto dsa_failed;

      status = ssh_asn1_node_get_data(node, &out, out_len);
      if (status != SSH_ASN1_STATUS_OK)
        goto dsa_failed;

      *out_len *= 8;

    dsa_failed:
      ssh_mprz_clear(&r);
      ssh_mprz_clear(&s);

      return out;
      break;

    default:
      break;
    }
  return NULL;
}

/* Some other signature related routines. */
#endif /* SSHDIST_CERT */
