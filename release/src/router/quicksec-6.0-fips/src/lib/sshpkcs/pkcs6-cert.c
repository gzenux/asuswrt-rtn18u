/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements PKCS#6 extented certificate encoding and validation.
   Extented certificates are obsolete, and should not be used at all.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshasn1.h"
#include "x509.h"
#include "oid.h"
#include "x509internal.h"
#include "pkcs6.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshPkcs6"

/* Write a function that makes extended certificates such that

   extendedCert ::= CHOICE {
     certificate ...,
     extendedCertificate [1] ... } */

SshPkcs6Status
ssh_pkcs6_cert_encode_asn1(SshAsn1Context context,
                           unsigned char *cert, size_t cert_length,
                           SshGList attr,
                           SshPrivateKey  issuer_key,
                           SshAsn1Node *extended_cert)
{
  SshPkcs6Status rv;
  SshAsn1Status  status;
  SshAsn1Node    node, cert_node, attr_node, sign_method;
  SshMPIntegerStruct version;
  unsigned char *buf;
  size_t         buf_len;
  unsigned char *signature;
  size_t         signature_len;
  unsigned char *bs_signature = NULL;
  size_t         bs_signature_len;

  /* First write the extended certificate information. */

  /* Decode the certificate. */
  status = ssh_asn1_decode_node(context, cert, cert_length, &cert_node);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_PKCS6_ASN1_DECODING_FAILED;

  /* Encode attributes. */
  rv = ssh_pkcs6_attr_encode_asn1(context, attr, &attr_node);
  if (rv != SSH_PKCS6_OK)
    return rv;

  /* Initialize the version number. */
  ssh_mprz_init_set_ui(&version, 0);

  /* Write up the tbs sequence. */
  status = ssh_asn1_create_node(context, &node,
                                "(sequence ()"
                                " (integer ())"
                                " (any ())"
                                " (any ()))",
                                &version,
                                cert_node, attr_node);
  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_mprz_clear(&version);
      return SSH_PKCS6_ASN1_ENCODING_FAILED;
    }

  /* Clear version, not needed any longer. */
  ssh_mprz_clear(&version);

  /* Create a signature algorithm. */
  sign_method = ssh_x509_encode_sigalg(context, issuer_key);
  if (sign_method == NULL)
    return SSH_PKCS6_SIGN_METHOD_NIL;

  /* We need to form now the octet-string for signing. */

  /* First encode. */
  status = ssh_asn1_encode_node(context, node);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_PKCS6_ASN1_ENCODING_FAILED;

  /* Then retrieve the data. */
  status = ssh_asn1_node_get_data(node, &buf, &buf_len);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_PKCS6_ASN1_ENCODING_FAILED;

  if (ssh_private_key_max_signature_input_len(issuer_key) != (size_t)-1 &&
      ssh_private_key_max_signature_input_len(issuer_key) < buf_len)
    {
      ssh_free(buf);
      return SSH_PKCS6_SIGNATURE_INPUT_SIZE_TOO_SHORT;
    }
  signature_len = ssh_private_key_max_signature_output_len(issuer_key);
  if ((signature = ssh_malloc(signature_len)) != NULL)
    {
      /* Now we need to sign the buffer. */
      if (ssh_private_key_sign(issuer_key,
                               buf, buf_len,
                               signature, signature_len,
                               &signature_len) != SSH_CRYPTO_OK)
        {
          ssh_free(buf);
          ssh_free(signature);
          return SSH_PKCS6_SIGNING_FAILED;
        }

      bs_signature = ssh_x509_encode_signature(context,
                                               signature, signature_len,
                                               issuer_key,
                                               &bs_signature_len);
      ssh_free(signature);
      ssh_free(buf);
      buf = NULL;
    }

  if (bs_signature == NULL)
    {
      ssh_free(buf);
      return SSH_PKCS6_SIGNATURE_ENCODING_FAILED;
    }

  status = ssh_asn1_create_node(context, extended_cert,
                                "(sequence ()"
                                " (any ())"     /* TBS data. */
                                " (any ())"     /* signature algorithm */
                                " (bit-string ()))",
                                node,
                                sign_method,
                                bs_signature, bs_signature_len);
  ssh_free(bs_signature);

  if (status != SSH_ASN1_STATUS_OK)
    return SSH_PKCS6_ASN1_ENCODING_FAILED;
  return SSH_PKCS6_OK;
}

SshPkcs6Status
ssh_pkcs6_cert_encode(unsigned char *cert, size_t cert_length,
                      SshGList attr,
                      SshPrivateKey key,
                      unsigned char **ber_buf, size_t *ber_length)
{
  SshAsn1Context context;
  SshAsn1Status status;
  SshAsn1Node   extended_cert;
  SshPkcs6Status rv;

  SSH_DEBUG(5, ("Certificate encoding."));

  /* Initialize the ASN.1 context. */
  if ((context = ssh_asn1_init()) == NULL)
    return SSH_PKCS6_FAILURE;

  /* Make a PKCS6 extended certificate. */
  rv = ssh_pkcs6_cert_encode_asn1(context,
                                  cert, cert_length, attr, key,
                                  &extended_cert);
  if (rv != SSH_PKCS6_OK)
    {
      ssh_asn1_free(context);
      return rv;
    }

  /* Encode, and convert to octet string. */
  status = ssh_asn1_encode_node(context, extended_cert);
  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(context);
      return SSH_PKCS6_ASN1_ENCODING_FAILED;
    }

  /* Get the BER bytes. */
  status = ssh_asn1_node_get_data(extended_cert, ber_buf, ber_length);
  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(context);
      return SSH_PKCS6_ASN1_ENCODING_FAILED;
    }

  ssh_asn1_free(context);
  return SSH_PKCS6_OK;
}

SshPkcs6Status
ssh_pkcs6_cert_decode(unsigned char *ber_buf, size_t ber_length,
                      SshPkcs6Cert cert)
{
  SshAsn1Status status;
  SshAsn1Context context;
  SshAsn1Node   extended_cert;
  SshPkcs6Status rv;

  SSH_DEBUG(5, ("Certificate decoding."));

  /* Initialize the ASN.1 module. */
  if ((context = ssh_asn1_init()) == NULL)
    return SSH_PKCS6_FAILURE;

  /* Decode the BER blob. */
  status =
    ssh_asn1_decode_node(context, ber_buf, ber_length, &extended_cert);
  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(context);
      return SSH_PKCS6_ASN1_DECODING_FAILED;
    }

  /* Decode the extended certificate. */
  rv = ssh_pkcs6_cert_decode_asn1(context, extended_cert, cert);
  if (rv != SSH_PKCS6_OK)
    {
      ssh_asn1_free(context);
      return rv;
    }

  ssh_asn1_free(context);
  return SSH_PKCS6_OK;
}
#endif /* SSHDIST_CERT */
